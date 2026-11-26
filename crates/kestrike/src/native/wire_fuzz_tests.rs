//! Native wire acceptance fuzzed against an independent literal acceptor.
//! An input mutates a valid inbound datagram's descriptor fields, its
//! header bytes, its length and its payload; the real [`Wire::accept`] and
//! [`literal`], written from the acceptance rules alone, must name the same
//! peer and payload range or the same first refusal. An accepted range must
//! be exactly `FRAME_OVERHEAD..len`, and the bytes it exposes then meet the
//! real frame parser, its body crc32c and authentication: the client's
//! original payload from the client's peer passes all three, and any other
//! payload, or that payload from another peer's address, fails one of them
//! before it could take effect.

use std::ops::Range;

use spdk_sys as sys;

use super::wire::{Refused, RxMeta, Station, Wire};
use crate::net::{Direction, FRAME_OVERHEAD, KeyEntry, KeyRing, PeerId, parse};
use crate::sim::fuzz::{Class, MAX_INPUT, Target};
use crate::storage::{Crc32c, EngineBudget};

/// The first byte of every input; four-byte mutations follow it.
pub(crate) const FORMAT: u8 = 1;

/// The most mutations one input applies.
const MAX_OPS: usize = 64;

/// The wire target.
pub(crate) static WIRE: Target = Target {
    name: "wire",
    run: wire,
    seeds,
};

const OWNER: Station = Station {
    mac: [2, 0, 0, 0, 0, 1],
    ip: [10, 0, 0, 1],
    port: 7000,
    ports: 1,
};
const CLIENT: Station = Station {
    mac: [2, 0, 0, 0, 0, 2],
    ip: [10, 0, 0, 2],
    port: 9000,
    ports: 8,
};
/// The configured peers, in [`PeerId`] order: one sharing the client's
/// address with the ports just below its range, the client, and one on
/// another address with the client's ports.
const PEERS: [Station; 3] = [
    Station {
        port: 8992,
        ..CLIENT
    },
    CLIENT,
    Station {
        mac: [2, 0, 0, 0, 0, 3],
        ip: [10, 0, 0, 3],
        ..CLIENT
    },
];

const GOOD: u64 = (sys::RTE_MBUF_F_RX_IP_CKSUM_GOOD | sys::RTE_MBUF_F_RX_L4_CKSUM_GOOD) as u64;
const PTYPE: u32 = sys::RTE_PTYPE_L2_ETHER | sys::RTE_PTYPE_L3_IPV4 | sys::RTE_PTYPE_L4_UDP;

/// The endpoint the frame's tag covers.
const ENDPOINT: u32 = 7;
const KEY: [u8; 32] = [0x3c; 32];

/// The client's peer.
const PEER: PeerId = PeerId(1);

/// The pinned GET frame's principal and key epoch.
fn pinned() -> (Vec<u8>, u32, u32) {
    let bytes = include_bytes!("../../fuzz/corpus/frame/v3-get").to_vec();
    let header = parse(Crc32c::detect(), &bytes, false)
        .expect("a canonical frame")
        .header();
    (bytes, header.principal, header.key_epoch)
}

/// The owner's key ring: one principal per peer, the client's the pinned
/// frame's, each under its own key, at the frame's key epoch.
fn ring() -> KeyRing {
    let (_, principal, epoch) = pinned();
    let principals = [principal + 1, principal, principal + 2];
    let keys = [[0x11; 32], KEY, [0x22; 32]];
    let entries: Vec<KeyEntry<'_>> = principals
        .iter()
        .zip(&keys)
        .map(|(&principal, key)| KeyEntry { principal, key })
        .collect();
    KeyRing::load(&principals, &entries, epoch, &mut EngineBudget::unlimited()).expect("a ring")
}

/// The pinned GET frame, its tag set under [`KEY`] for the client.
fn payload() -> Vec<u8> {
    let (mut bytes, _, _) = pinned();
    let frame = parse(Crc32c::detect(), &bytes, false).expect("a canonical frame");
    let tag = ring()
        .tag(
            PEER,
            &frame
                .mac_input(ENDPOINT, Direction::ClientToOwner)
                .expect("a GET's MAC input"),
        )
        .expect("a ring peer");
    bytes[176..192].copy_from_slice(&tag);
    bytes
}

/// Whether `exposed` from `peer` passes the real frame parser, its body
/// crc32c and authentication under the owner's ring: the checks that stand
/// before any effect.
fn takes_effect(exposed: &[u8], peer: PeerId) -> bool {
    let crc = Crc32c::detect();
    parse(crc, exposed, false).is_ok_and(|parsed| {
        parsed.check_body(crc).is_ok()
            && ring()
                .authenticate(&parsed, peer, ENDPOINT, Direction::ClientToOwner)
                .is_ok()
    })
}

fn owner() -> Wire<'static> {
    Wire::new(OWNER, &PEERS, &mut EngineBudget::unlimited()).expect("a wire")
}

/// The valid inbound datagram every input mutates: the payload from the
/// client's first port to the owner, with GOOD descriptor fields.
pub(crate) fn valid() -> (RxMeta, Vec<u8>) {
    let payload = payload();
    let client = Wire::new(CLIENT, &[OWNER], &mut EngineBudget::unlimited()).expect("a wire");
    let mut headers = [0; FRAME_OVERHEAD];
    client.encode(
        &mut headers,
        &OWNER,
        CLIENT.port,
        OWNER.port,
        payload.len() as u16,
    );
    let bytes = [headers.as_slice(), &payload].concat();
    let meta = RxMeta {
        ol_flags: GOOD,
        packet_type: PTYPE,
        nb_segs: 1,
        pkt_len: bytes.len() as u32,
        data_len: bytes.len() as u16,
    };
    (meta, bytes)
}

/// An acceptor: the peer and payload range, or the first refusal.
pub(crate) type Acceptor = fn(&Wire<'_>, &RxMeta, &[u8]) -> Result<(PeerId, Range<usize>), Refused>;

/// The real acceptor.
fn real(wire: &Wire<'_>, meta: &RxMeta, frame: &[u8]) -> Result<(PeerId, Range<usize>), Refused> {
    wire.accept(meta, frame)
}

/// A reference acceptor written from the acceptance rules alone, in their
/// order: one buffer whose descriptor lengths match the frame, IPv4 and UDP
/// with no tunnel, GOOD checksum fields, the 42 header bytes, an IPv4 UDP
/// header without options, both length fields exact, no fragment, this
/// host's MAC, address and base port, then the one configured peer whose
/// address and port range hold the source.
fn literal(meta: &RxMeta, frame: &[u8]) -> Result<(PeerId, Range<usize>), Refused> {
    let len = frame.len();
    if meta.nb_segs != 1 || meta.pkt_len as usize != len || usize::from(meta.data_len) != len {
        return Err(Refused::Segments);
    }
    let kind = meta.packet_type;
    if kind & sys::RTE_PTYPE_L3_MASK != sys::RTE_PTYPE_L3_IPV4
        || kind & sys::RTE_PTYPE_L4_MASK != sys::RTE_PTYPE_L4_UDP
        || kind & sys::RTE_PTYPE_TUNNEL_MASK != 0
    {
        return Err(Refused::PacketType);
    }
    let ip_mask = u64::from(sys::RTE_MBUF_F_RX_IP_CKSUM_MASK);
    if meta.ol_flags & ip_mask != u64::from(sys::RTE_MBUF_F_RX_IP_CKSUM_GOOD) {
        return Err(Refused::IpChecksum);
    }
    let l4_mask = u64::from(sys::RTE_MBUF_F_RX_L4_CKSUM_MASK);
    if meta.ol_flags & l4_mask != u64::from(sys::RTE_MBUF_F_RX_L4_CKSUM_GOOD) {
        return Err(Refused::L4Checksum);
    }
    if len < 42 {
        return Err(Refused::Length);
    }
    let word = |at: usize| usize::from(frame[at]) << 8 | usize::from(frame[at + 1]);
    if frame[12..14] != [0x08, 0x00] || frame[14] != 0x45 || frame[23] != 17 {
        return Err(Refused::Header);
    }
    if word(16) != len - 14 || word(38) != len - 34 {
        return Err(Refused::Length);
    }
    if word(20) & 0x3fff != 0 {
        return Err(Refused::Fragment);
    }
    if frame[0..6] != OWNER.mac || frame[30..34] != OWNER.ip || word(36) != usize::from(OWNER.port)
    {
        return Err(Refused::Destination);
    }
    let source = word(34);
    let mut owners = (0..PEERS.len()).filter(|&at| {
        let (peer, first) = (&PEERS[at], usize::from(PEERS[at].port));
        frame[26..30] == peer.ip && (first..first + usize::from(peer.ports)).contains(&source)
    });
    let (Some(peer), None) = (owners.next(), owners.next()) else {
        return Err(Refused::Source);
    };
    Ok((PeerId(peer as u16), 42..len))
}

/// The datagram `ops` make from the valid one, or `None` for more ops than
/// the bound; a trailing partial op is ignored. Each op names its
/// family in its first byte: a checksum-flag bit, a packet-type bit, the
/// segment count, the descriptor lengths, a header byte, the frame's
/// length, a payload byte, or both length fields made to match the frame.
/// The first family flips any offload-flag bit, checksum fields included.
pub(crate) fn mutated(ops: &[u8]) -> Option<(RxMeta, Vec<u8>)> {
    let (mut meta, mut frame) = valid();
    let chunks = ops.as_chunks::<4>().0;
    if chunks.len() > MAX_OPS {
        return None;
    }
    for &[op, a, b, c] in chunks {
        match op % 8 {
            0 => meta.ol_flags ^= 1 << (a % 64),
            1 => meta.packet_type ^= 1 << (a % 32),
            2 => meta.nb_segs = u16::from(a % 3),
            3 => {
                meta.data_len = meta.data_len.wrapping_add(i16::from(a as i8) as u16);
                if c & 1 == 1 {
                    meta.pkt_len = meta.pkt_len.wrapping_add(i32::from(b as i8) as u32);
                } else {
                    meta.pkt_len = u32::from(meta.data_len);
                }
            }
            4 if !frame.is_empty() => {
                let at = usize::from(a) % FRAME_OVERHEAD.min(frame.len());
                frame[at] = b;
            }
            5 => {
                if b & 1 == 1 {
                    frame.extend(std::iter::repeat_n(c, usize::from(a)));
                } else {
                    frame.truncate((usize::from(a) << 8 | usize::from(c)) % (frame.len() + 1));
                }
                meta.data_len = frame.len() as u16;
                meta.pkt_len = frame.len() as u32;
            }
            6 if frame.len() > FRAME_OVERHEAD => {
                let span = frame.len() - FRAME_OVERHEAD;
                let at = FRAME_OVERHEAD + (usize::from(a) << 8 | usize::from(b)) % span;
                frame[at] ^= c | 1;
            }
            7 if frame.len() >= FRAME_OVERHEAD => {
                let len = frame.len();
                frame[16..18].copy_from_slice(&((len - 14) as u16).to_be_bytes());
                frame[38..40].copy_from_slice(&((len - 34) as u16).to_be_bytes());
            }
            _ => {}
        }
    }
    Some((meta, frame))
}

/// Judges one wire input against the literal acceptor.
fn wire(input: &[u8]) -> Class {
    judge(input, real, takes_effect)
}

/// [`wire`] with `acceptor` in place of the real one and `effect` in place
/// of the downstream checks: an accepted range must be exactly the UDP
/// payload, the acceptor must agree with [`literal`], and `effect` must let
/// only the client's original payload from the client's peer through.
fn judge(input: &[u8], acceptor: Acceptor, effect: fn(&[u8], PeerId) -> bool) -> Class {
    if input.len() > MAX_INPUT {
        return Class::Invalid("the input passes its byte bound");
    }
    let [format, ops @ ..] = input else {
        return Class::Invalid("the input holds no format byte");
    };
    if *format != FORMAT {
        return Class::Invalid("the input names another format");
    }
    let Some((meta, frame)) = mutated(ops) else {
        return Class::Invalid("the ops pass their bound");
    };
    let failure = |claim: String| Class::Failure {
        claim,
        bundle: Vec::new(),
    };
    // The wire judgment reads the input through its last whole op.
    let pass = || Class::Pass {
        run: input[..input.len() - ops.len() % 4].to_vec(),
    };
    let wire = owner();
    let ours = acceptor(&wire, &meta, &frame);
    if let Ok((_, range)) = &ours
        && *range != (FRAME_OVERHEAD..frame.len())
    {
        return failure(format!(
            "an accepted range {range:?} of a {}-byte frame",
            frame.len()
        ));
    }
    let theirs = literal(&meta, &frame);
    if ours != theirs {
        return failure(format!(
            "the acceptor judged {ours:?}; the literal acceptor {theirs:?}"
        ));
    }
    let Ok((peer, range)) = ours else {
        return pass();
    };
    let exposed = &frame[range];
    // Only the client's own payload from the client's peer may take effect:
    // authentication binds the frame's principal to the peer it came from.
    let honest = exposed == payload().as_slice() && peer == PEER;
    match (honest, effect(exposed, peer)) {
        (true, true) | (false, false) => pass(),
        (true, false) => failure("the client's own payload failed downstream".into()),
        (false, true) => {
            failure("changed payload bytes passed parsing, crc and authentication".into())
        }
    }
}

/// Seeds: the valid datagram and one mutation of each family.
pub(crate) fn seeds() -> Vec<(String, Vec<u8>)> {
    let ops: [(&str, &[u8]); 11] = [
        ("valid", &[]),
        ("ip-checksum", &[0, 7, 0, 0]),
        ("packet-type", &[1, 5, 0, 0]),
        ("segments", &[2, 2, 0, 0]),
        ("lengths", &[3, 2, 0, 0]),
        ("destination", &[4, 0, 9, 0]),
        ("source-port", &[4, 35, 0xe0, 0]),
        ("source-address", &[4, 29, 3, 0]),
        ("fragment", &[4, 20, 0x21, 0]),
        ("short", &[5, 0, 0, 60, 7, 0, 0, 0]),
        ("payload", &[6, 0, 3, 1]),
    ];
    ops.iter()
        .map(|(name, ops)| {
            let mut input = vec![FORMAT];
            input.extend_from_slice(ops);
            (format!("{name}.input"), input)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    //! The wire target's literal acceptor on each refusal and on each
    //! peer, its exact range and downstream checks, and the controls a
    //! broken acceptor or a broken downstream check fails.

    use super::super::wire::WireError;
    use super::*;

    /// Every seed agrees, and the valid datagram exposes exactly the
    /// payload, which takes effect for the client's peer alone.
    #[test]
    fn every_seed_agrees_and_the_valid_payload_takes_effect() {
        let (meta, frame) = valid();
        let (peer, range) = owner().accept(&meta, &frame).unwrap();
        assert_eq!((peer, range.clone()), (PEER, FRAME_OVERHEAD..frame.len()));
        assert_eq!(&frame[range.clone()], payload().as_slice());
        assert!(takes_effect(&frame[range.clone()], PEER));
        assert!(!takes_effect(&frame[range], PeerId(0)));
        for (name, input) in seeds() {
            let whole = Class::Pass { run: input.clone() };
            assert_eq!((WIRE.run)(&input), whole, "{name}");
            let mut partial = input.clone();
            partial.extend([9, 9, 9]);
            assert_eq!((WIRE.run)(&partial), whole, "{name} with a partial op");
        }
    }

    /// Each refusal is reached in the documented order, and the literal
    /// acceptor names the same one.
    #[test]
    fn each_refusal_is_reached_in_order() {
        let cases: [(&[u8], Result<(), Refused>); 11] = [
            (&[2, 2, 0, 0], Err(Refused::Segments)),
            (&[1, 5, 0, 0], Err(Refused::PacketType)),
            (&[0, 7, 0, 0], Err(Refused::IpChecksum)),
            (&[0, 3, 0, 0], Err(Refused::L4Checksum)),
            (&[5, 0, 0, 30], Err(Refused::Length)),
            (&[4, 12, 0x86, 0], Err(Refused::Header)),
            (&[5, 0, 0, 60], Err(Refused::Length)),
            (&[4, 20, 0x21, 0], Err(Refused::Fragment)),
            (&[4, 0, 9, 0], Err(Refused::Destination)),
            (&[4, 29, 9, 0], Err(Refused::Source)),
            (&[4, 20, 0x21, 0, 4, 0, 9, 0], Err(Refused::Fragment)),
        ];
        let wire = owner();
        for (ops, expected) in cases {
            let (meta, frame) = mutated(ops).unwrap();
            let (ours, theirs) = (wire.accept(&meta, &frame), literal(&meta, &frame));
            assert_eq!(ours.clone().map(|_| ()), expected, "{ops:?}");
            assert_eq!(ours, theirs, "{ops:?}");
        }
    }

    /// A source maps to the one peer whose address and port range hold
    /// it: the client's ports to the client, the ports just below them on
    /// the same address to the first peer, the client's ports on the third
    /// address to the third peer, and a port between ranges to none; the
    /// literal acceptor agrees on each. A peer table whose ranges overlap
    /// on one address builds no wire, so no source has two owners.
    #[test]
    fn each_source_maps_to_its_one_peer() {
        let overlapping = [
            CLIENT,
            Station {
                port: CLIENT.port + CLIENT.ports - 1,
                ..CLIENT
            },
        ];
        let refused = Wire::new(OWNER, &overlapping, &mut EngineBudget::unlimited());
        assert!(matches!(refused, Err(WireError::Overlap)));
        let cases: [(&[u8], Result<u16, Refused>); 4] = [
            (&[4, 35, 0x2b, 0], Ok(1)),
            (&[4, 35, 0x20, 0], Ok(0)),
            (&[4, 29, 3, 0], Ok(2)),
            (&[4, 35, 0x40, 0], Err(Refused::Source)),
        ];
        let wire = owner();
        for (ops, expected) in cases {
            let (meta, frame) = mutated(ops).unwrap();
            let (ours, theirs) = (wire.accept(&meta, &frame), literal(&meta, &frame));
            assert_eq!(ours.clone().map(|(peer, _)| peer.0), expected, "{ops:?}");
            assert_eq!(ours, theirs, "{ops:?}");
        }
    }

    /// A broken acceptor fails the judge on an input the real acceptor
    /// handles: one that skips the fragment check, one that exposes the
    /// UDP header's last byte, one that checks the destination before the
    /// fragment bits, and one that accepts every frame.
    #[test]
    fn a_broken_acceptor_fails_the_judge() {
        fn no_fragment(
            wire: &Wire<'_>,
            meta: &RxMeta,
            frame: &[u8],
        ) -> Result<(PeerId, Range<usize>), Refused> {
            let mut unfragmented = frame.to_vec();
            if unfragmented.len() > 21 {
                unfragmented[20] &= 0xc0;
                unfragmented[21] = 0;
            }
            wire.accept(meta, &unfragmented)
        }
        fn wide(
            wire: &Wire<'_>,
            meta: &RxMeta,
            frame: &[u8],
        ) -> Result<(PeerId, Range<usize>), Refused> {
            wire.accept(meta, frame)
                .map(|(peer, range)| (peer, range.start - 1..range.end))
        }
        fn destination_first(
            wire: &Wire<'_>,
            meta: &RxMeta,
            frame: &[u8],
        ) -> Result<(PeerId, Range<usize>), Refused> {
            match frame.get(..6) {
                Some(mac) if mac != OWNER.mac => Err(Refused::Destination),
                _ => wire.accept(meta, frame),
            }
        }
        fn open(_: &Wire<'_>, _: &RxMeta, frame: &[u8]) -> Result<(PeerId, Range<usize>), Refused> {
            Ok((PEER, FRAME_OVERHEAD.min(frame.len())..frame.len()))
        }
        let claim = |class: Class| match class {
            Class::Failure { claim, .. } => claim,
            other => format!("{other:?}"),
        };
        let fragment = [FORMAT, 4, 20, 0x21, 0];
        assert!(
            claim(judge(&fragment, no_fragment, takes_effect))
                .starts_with("the acceptor judged Ok")
        );
        assert_eq!(
            judge(&fragment, real, takes_effect),
            Class::Pass {
                run: fragment.to_vec()
            }
        );
        assert_eq!(
            claim(judge(&[FORMAT], wide, takes_effect)),
            format!(
                "an accepted range 41..{} of a {0}-byte frame",
                valid().1.len()
            )
        );
        let both = [FORMAT, 4, 20, 0x21, 0, 4, 0, 9, 0];
        assert_eq!(
            claim(judge(&both, destination_first, takes_effect)),
            "the acceptor judged Err(Destination); the literal acceptor Err(Fragment)"
        );
        assert_eq!(
            judge(&both, real, takes_effect),
            Class::Pass { run: both.to_vec() }
        );
        let destination = [FORMAT, 4, 0, 9, 0];
        assert!(claim(judge(&destination, open, takes_effect)).contains("Err(Destination)"));
        assert_eq!(
            judge(&destination, real, takes_effect),
            Class::Pass {
                run: destination.to_vec()
            }
        );
    }

    /// A payload byte changed in the header, its crc field or the tag
    /// passes the wire and is rejected before any effect, and the judge
    /// passes each such input; a downstream check that skips the tag would
    /// let the tag change through, and the judge fails it.
    #[test]
    fn a_changed_accepted_payload_never_takes_effect() {
        for offset in [0u8, 40, 100, 120, 160, 180] {
            let input = [FORMAT, 6, 0, offset, 1];
            let (meta, frame) = mutated(&input[1..]).unwrap();
            assert!(owner().accept(&meta, &frame).is_ok(), "offset {offset}");
            assert_eq!(
                judge(&input, real, takes_effect),
                Class::Pass {
                    run: input.to_vec()
                },
                "offset {offset}"
            );
        }
        fn untagged(exposed: &[u8], _: PeerId) -> bool {
            let crc = Crc32c::detect();
            parse(crc, exposed, false).is_ok_and(|parsed| parsed.check_body(crc).is_ok())
        }
        let tag = [FORMAT, 6, 0, 180, 1];
        assert_eq!(
            judge(&tag, real, untagged),
            Class::Failure {
                claim: "changed payload bytes passed parsing, crc and authentication".into(),
                bundle: Vec::new(),
            }
        );
    }
}
