//! Receive validation and header encoding: a frame is accepted only as one complete IPv4/UDP packet in one buffer with GOOD checksum fields, exact lengths, this host's destination and a configured peer's source, and its accepted range is exactly the UDP payload.

use spdk_sys as sys;

use super::wire::{Refused, RxMeta, Station, Wire, WireError};
use crate::net::{FRAME_OVERHEAD, PeerId};
use crate::storage::EngineBudget;

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
const OTHER: Station = Station {
    mac: [2, 0, 0, 0, 0, 3],
    ip: [10, 0, 0, 3],
    port: 9000,
    ports: 8,
};

const GOOD: u64 = (sys::RTE_MBUF_F_RX_IP_CKSUM_GOOD | sys::RTE_MBUF_F_RX_L4_CKSUM_GOOD) as u64;
const PTYPE: u32 = sys::RTE_PTYPE_L2_ETHER | sys::RTE_PTYPE_L3_IPV4 | sys::RTE_PTYPE_L4_UDP;

fn frame(port: u16, payload: &[u8]) -> (RxMeta, Vec<u8>) {
    frame_from(CLIENT, port, payload)
}

fn frame_from(source: Station, port: u16, payload: &[u8]) -> (RxMeta, Vec<u8>) {
    let client = Wire::new(source, &[OWNER], &mut EngineBudget::unlimited()).unwrap();
    let mut headers = [0; FRAME_OVERHEAD];
    client.encode(&mut headers, &OWNER, port, OWNER.port, payload.len() as u16);
    let bytes = [headers.as_slice(), payload].concat();
    let meta = RxMeta {
        ol_flags: GOOD,
        packet_type: PTYPE,
        nb_segs: 1,
        pkt_len: bytes.len() as u32,
        data_len: bytes.len() as u16,
    };
    (meta, bytes)
}

fn owner() -> Wire<'static> {
    Wire::new(OWNER, &[OTHER, CLIENT], &mut EngineBudget::unlimited()).unwrap()
}

/// A frame from any of a peer's configured source ports maps to its one peer, with exactly the UDP payload accepted.
#[test]
fn a_valid_frame_yields_its_peer_and_exact_payload() {
    for port in [9000, 9003, 9007] {
        let (meta, bytes) = frame(port, b"v1 frame bytes");
        let (peer, range) = owner().accept(&meta, &bytes).unwrap();
        assert_eq!(peer, PeerId(1), "port {port}");
        assert_eq!(&bytes[range], b"v1 frame bytes");
    }
}

/// A source maps to the peer whose address matches and whose range holds its port, wherever that peer sits in the configured order; a source in a gap between ranges, below every range or past every range maps to no peer.
#[test]
fn a_source_maps_to_the_one_peer_whose_range_holds_its_port() {
    let at = |ip: u8, port: u16, ports: u16| Station {
        ip: [10, 0, 0, ip],
        port,
        ports,
        ..CLIENT
    };
    let peers = [
        at(9, 9100, 4),
        at(2, 9020, 4),
        at(2, 9000, 8),
        at(4, 9000, 1),
        at(2, 9010, 2),
    ];
    let wire = Wire::new(OWNER, &peers, &mut EngineBudget::unlimited()).unwrap();
    for ip in [2, 3, 4, 9, 10] {
        for port in 8990..9110 {
            let (meta, bytes) = frame_from(at(ip, 1, 1), port, b"x");
            let owner = peers
                .iter()
                .position(|p| p.ip[3] == ip && (p.port..p.port + p.ports).contains(&port));
            let expected = owner.map(|at| PeerId(at as u16)).ok_or(Refused::Source);
            let got = wire.accept(&meta, &bytes).map(|(peer, _)| peer);
            assert_eq!(got, expected, "source 10.0.0.{ip}:{port}");
        }
    }
}

/// Each invalid field is refused with its own reason, in check order.
#[test]
fn each_invalid_frame_is_refused_with_its_reason() {
    let wire = owner();
    let refused = |change: &dyn Fn(&mut RxMeta, &mut Vec<u8>)| {
        let (mut meta, mut bytes) = frame(9000, &[7; 64]);
        change(&mut meta, &mut bytes);
        wire.accept(&meta, &bytes).err()
    };
    let set = |at: usize, value: u8| move |_: &mut RxMeta, bytes: &mut Vec<u8>| bytes[at] = value;
    assert_eq!(
        refused(&|meta, _| meta.nb_segs = 2),
        Some(Refused::Segments)
    );
    assert_eq!(
        refused(&|meta, _| meta.pkt_len += 1),
        Some(Refused::Segments)
    );
    assert_eq!(
        refused(&|meta, _| meta.packet_type = sys::RTE_PTYPE_L3_IPV4 | sys::RTE_PTYPE_L4_TCP),
        Some(Refused::PacketType)
    );
    assert_eq!(
        refused(&|meta, _| meta.packet_type = sys::RTE_PTYPE_L3_IPV4_EXT | sys::RTE_PTYPE_L4_UDP),
        Some(Refused::PacketType)
    );
    assert_eq!(
        refused(&|meta, _| meta.packet_type |= sys::RTE_PTYPE_TUNNEL_VXLAN),
        Some(Refused::PacketType)
    );
    for ip in [
        0,
        sys::RTE_MBUF_F_RX_IP_CKSUM_BAD,
        sys::RTE_MBUF_F_RX_IP_CKSUM_NONE,
    ] {
        let flags = u64::from(ip | sys::RTE_MBUF_F_RX_L4_CKSUM_GOOD);
        assert_eq!(
            refused(&|meta, _| meta.ol_flags = flags),
            Some(Refused::IpChecksum),
            "IP checksum field {ip:#x}"
        );
    }
    for l4 in [
        0,
        sys::RTE_MBUF_F_RX_L4_CKSUM_BAD,
        sys::RTE_MBUF_F_RX_L4_CKSUM_NONE,
    ] {
        let flags = u64::from(sys::RTE_MBUF_F_RX_IP_CKSUM_GOOD | l4);
        assert_eq!(
            refused(&|meta, _| meta.ol_flags = flags),
            Some(Refused::L4Checksum),
            "L4 checksum field {l4:#x}"
        );
    }
    let short = |meta: &mut RxMeta, bytes: &mut Vec<u8>| {
        bytes.truncate(FRAME_OVERHEAD - 1);
        meta.data_len = bytes.len() as u16;
        meta.pkt_len = bytes.len() as u32;
    };
    assert_eq!(refused(&short), Some(Refused::Length));
    assert_eq!(refused(&set(12, 0x86)), Some(Refused::Header), "not IPv4");
    assert_eq!(
        refused(&set(14, 0x46)),
        Some(Refused::Header),
        "IPv4 options"
    );
    assert_eq!(refused(&set(23, 6)), Some(Refused::Header), "not UDP");
    let trailing = |meta: &mut RxMeta, bytes: &mut Vec<u8>| {
        bytes.push(0);
        meta.data_len += 1;
        meta.pkt_len += 1;
    };
    assert_eq!(
        refused(&trailing),
        Some(Refused::Length),
        "a trailing byte past the UDP length"
    );
    assert_eq!(
        refused(&set(39, 0)),
        Some(Refused::Length),
        "a UDP length that disagrees"
    );
    assert_eq!(
        refused(&set(20, 0x60)),
        Some(Refused::Fragment),
        "more fragments"
    );
    assert_eq!(
        refused(&set(21, 1)),
        Some(Refused::Fragment),
        "a nonzero offset"
    );
    assert_eq!(
        refused(&set(0, 9)),
        Some(Refused::Destination),
        "another MAC"
    );
    assert_eq!(
        refused(&set(33, 9)),
        Some(Refused::Destination),
        "another address"
    );
    assert_eq!(
        refused(&set(37, 0x59)),
        Some(Refused::Destination),
        "another port"
    );
    assert_eq!(
        refused(&set(29, 9)),
        Some(Refused::Source),
        "an unconfigured address"
    );
    let (meta, bytes) = frame(9008, &[7; 64]);
    assert_eq!(
        wire.accept(&meta, &bytes).err(),
        Some(Refused::Source),
        "a port past the peer's range"
    );
}

/// Encoded headers state the exact lengths, don't-fragment, UDP, both addresses and both ports, with the checksums left zero for the device.
#[test]
fn encoded_headers_state_exact_lengths_and_leave_checksums_to_the_device() {
    let (_, bytes) = frame(9002, &[1; 100]);
    assert_eq!(&bytes[0..6], &OWNER.mac);
    assert_eq!(&bytes[6..12], &CLIENT.mac);
    assert_eq!(u16::from_be_bytes([bytes[16], bytes[17]]), 20 + 8 + 100);
    assert_eq!(u16::from_be_bytes([bytes[38], bytes[39]]), 8 + 100);
    assert_eq!(bytes[20], 0x40, "don't fragment");
    assert_eq!(&bytes[24..26], &[0, 0]);
    assert_eq!(&bytes[40..42], &[0, 0]);
    assert_eq!(u16::from_be_bytes([bytes[34], bytes[35]]), 9002);
    assert_eq!(u16::from_be_bytes([bytes[36], bytes[37]]), 7000);
}

/// A peer's headers from the template equal the encoding from the local first port to the peer's first port for every payload length, and an unknown peer leaves the buffer as it was.
#[test]
fn templated_headers_match_the_encoding_for_each_peer() {
    let wire = owner();
    for (id, peer) in [(0, OTHER), (1, CLIENT)] {
        for payload_len in [0u16, 1, 192, 8192, u16::MAX - 28] {
            let mut encoded = [0xee; FRAME_OVERHEAD];
            wire.encode(&mut encoded, &peer, OWNER.port, peer.port, payload_len);
            let mut templated = [0xee; FRAME_OVERHEAD];
            assert_eq!(
                wire.headers(&mut templated, PeerId(id), payload_len),
                Some(())
            );
            assert_eq!(templated, encoded, "peer {id}, payload {payload_len}");
        }
    }
    let mut untouched = [0xee; FRAME_OVERHEAD];
    assert_eq!(wire.headers(&mut untouched, PeerId(2), 10), None);
    assert_eq!(untouched, [0xee; FRAME_OVERHEAD]);
}

/// The descriptor checks refuse without the frame's bytes, in the documented order, and the frame checks resume from the headers.
#[test]
fn descriptor_and_frame_checks_split_the_refusal_order() {
    let wire = owner();
    let (meta, bytes) = frame(9001, b"split");
    assert_eq!(Wire::accept_descriptor(&meta, bytes.len()), Ok(()));
    assert_eq!(
        Wire::accept_descriptor(&meta, bytes.len() + 1),
        Err(Refused::Segments)
    );
    let bad = RxMeta {
        ol_flags: GOOD & !u64::from(sys::RTE_MBUF_F_RX_L4_CKSUM_MASK)
            | u64::from(sys::RTE_MBUF_F_RX_L4_CKSUM_BAD),
        ..meta
    };
    assert_eq!(
        Wire::accept_descriptor(&bad, bytes.len()),
        Err(Refused::L4Checksum)
    );
    let short = RxMeta {
        pkt_len: FRAME_OVERHEAD as u32 - 1,
        data_len: FRAME_OVERHEAD as u16 - 1,
        ..meta
    };
    assert_eq!(
        Wire::accept_descriptor(&short, FRAME_OVERHEAD - 1),
        Err(Refused::Length)
    );
    assert_eq!(
        wire.accept_frame(&bytes),
        Ok((PeerId(1), FRAME_OVERHEAD..bytes.len()))
    );
    assert_eq!(
        wire.accept_frame(&bytes[..FRAME_OVERHEAD - 1]),
        Err(Refused::Length)
    );
    let mut elsewhere = bytes.clone();
    elsewhere[37] ^= 1;
    assert_eq!(wire.accept_frame(&elsewhere), Err(Refused::Destination));
}

/// Addressing refuses an empty or overflowing port range, two peers whose address and port ranges overlap, and more peers than a peer ID names; peers on one address with disjoint ranges are accepted.
#[test]
fn addressing_refuses_ambiguous_or_unaddressable_stations() {
    let empty = Station { ports: 0, ..CLIENT };
    let overflowing = Station {
        port: u16::MAX,
        ports: 2,
        ..CLIENT
    };
    assert_eq!(
        Wire::new(OWNER, &[empty], &mut EngineBudget::unlimited()).err(),
        Some(WireError::Ports)
    );
    assert_eq!(
        Wire::new(overflowing, &[OWNER], &mut EngineBudget::unlimited()).err(),
        Some(WireError::Ports)
    );
    let shifted = Station {
        port: 9007,
        ..CLIENT
    };
    assert_eq!(
        Wire::new(OWNER, &[CLIENT, shifted], &mut EngineBudget::unlimited()).err(),
        Some(WireError::Overlap)
    );
    assert_eq!(
        Wire::new(
            OWNER,
            &[shifted, OTHER, CLIENT],
            &mut EngineBudget::unlimited()
        )
        .err(),
        Some(WireError::Overlap),
        "overlapping peers apart in the configured order"
    );
    let beside = Station {
        port: 9008,
        ..CLIENT
    };
    assert!(Wire::new(OWNER, &[CLIENT, beside], &mut EngineBudget::unlimited()).is_ok());
    let many = vec![CLIENT; usize::from(u16::MAX) + 2];
    let distinct: Vec<Station> = many
        .iter()
        .enumerate()
        .map(|(at, s)| Station {
            ip: (at as u32).to_be_bytes(),
            ports: 1,
            ..*s
        })
        .collect();
    assert_eq!(
        Wire::new(OWNER, &distinct, &mut EngineBudget::unlimited()).err(),
        Some(WireError::Peers)
    );
}

/// A payload longer than an IPv4 datagram carries is refused with the buffer as it was.
#[test]
fn headers_refuse_a_payload_past_the_ipv4_length() {
    let wire = owner();
    let mut untouched = [0xee; FRAME_OVERHEAD];
    assert_eq!(wire.headers(&mut untouched, PeerId(0), u16::MAX - 27), None);
    assert_eq!(untouched, [0xee; FRAME_OVERHEAD]);
}

/// A frame to one of this host's own source ports past its base port is refused as `Destination`: peers address the base port only.
#[test]
fn only_the_base_port_receives() {
    let local = Station { ports: 8, ..OWNER };
    let wire = Wire::new(local, &[CLIENT], &mut EngineBudget::unlimited()).unwrap();
    let owners = [local];
    let client = Wire::new(CLIENT, &owners, &mut EngineBudget::unlimited()).unwrap();
    for (dst, accepted) in [(7000, true), (7001, false), (7007, false)] {
        let mut headers = [0; FRAME_OVERHEAD];
        client.encode(&mut headers, &local, 9000, dst, 4);
        let bytes = [headers.as_slice(), b"data"].concat();
        let meta = RxMeta {
            ol_flags: GOOD,
            packet_type: PTYPE,
            nb_segs: 1,
            pkt_len: bytes.len() as u32,
            data_len: bytes.len() as u16,
        };
        let outcome = wire.accept(&meta, &bytes);
        assert_eq!(outcome.is_ok(), accepted, "port {dst}");
        if !accepted {
            assert_eq!(outcome.err(), Some(Refused::Destination));
        }
    }
}

/// Among hundreds of peers, some sharing an address on disjoint port ranges, a frame from each
/// configured port maps to its own peer, and an unconfigured address or port carries none.
#[test]
fn many_peers_each_map_from_their_own_ports() {
    let peers: Vec<Station> = (0..600u16)
        .map(|at| Station {
            mac: [2, 0, 0, 0, (at >> 8) as u8, at as u8],
            ip: [10, 1, ((at / 3) >> 8) as u8, (at / 3) as u8],
            port: 9000 + 8 * (at % 3),
            ports: 8,
        })
        .collect();
    let wire = Wire::new(OWNER, &peers, &mut EngineBudget::unlimited()).unwrap();
    let from = |ip: [u8; 4], port: u16| {
        let peer = Station {
            ip,
            port,
            ports: 1,
            ..CLIENT
        };
        let sender = Wire::new(
            peer,
            std::slice::from_ref(&OWNER),
            &mut EngineBudget::unlimited(),
        )
        .unwrap();
        let mut headers = [0; FRAME_OVERHEAD];
        sender.encode(&mut headers, &OWNER, port, OWNER.port, 4);
        let bytes = [headers.as_slice(), b"data"].concat();
        let meta = RxMeta {
            ol_flags: GOOD,
            packet_type: PTYPE,
            nb_segs: 1,
            pkt_len: bytes.len() as u32,
            data_len: bytes.len() as u16,
        };
        wire.accept(&meta, &bytes).map(|(peer, _)| peer)
    };
    for (at, peer) in peers.iter().enumerate() {
        for port in peer.port..peer.port + peer.ports {
            assert_eq!(
                from(peer.ip, port),
                Ok(PeerId(at as u16)),
                "peer {at} port {port}"
            );
        }
    }
    assert_eq!(
        from([10, 1, 0, 0], 9024),
        Err(Refused::Source),
        "past the shared address's ranges"
    );
    assert_eq!(
        from([10, 1, 0, 0], 8999),
        Err(Refused::Source),
        "below them"
    );
    assert_eq!(
        from([10, 1, 9, 9], 9000),
        Err(Refused::Source),
        "an unconfigured address"
    );
}

/// Addressing charges exactly the bytes its source table and header
/// templates allocate, once: an exact budget fits, a budget one byte short
/// refuses before allocating with the budget unchanged, more peers than a
/// peer ID names refuse before the charge, and an overlap found after the
/// tables were built frees them with the budget unchanged.
#[test]
fn addressing_charges_its_tables_exactly_or_leaves_the_budget() {
    let peers = [CLIENT, OTHER];
    let charge = Wire::charge(peers.len()).unwrap();
    let mut exact = EngineBudget::new(charge);
    let bytes = crate::instrument::allocated_bytes();
    let wire = Wire::new(OWNER, &peers, &mut exact).unwrap();
    assert_eq!(
        crate::instrument::allocated_bytes() - bytes,
        charge,
        "the charge is the bytes the tables allocate"
    );
    assert_eq!(exact.used(), charge);
    assert_eq!(wire.peers(), 2);

    let mut short = EngineBudget::new(charge - 1);
    let allocations = crate::instrument::allocations();
    assert!(matches!(
        Wire::new(OWNER, &peers, &mut short),
        Err(WireError::Budget(_))
    ));
    assert_eq!(crate::instrument::allocations(), allocations);
    assert_eq!(short, EngineBudget::new(charge - 1));

    assert!(Wire::charge(crate::net::MAX_PEERS).is_some());
    assert_eq!(Wire::charge(crate::net::MAX_PEERS + 1), None);
    let shifted = Station {
        port: 9007,
        ..CLIENT
    };
    let mut budget = EngineBudget::unlimited();
    let (bytes, freed) = (
        crate::instrument::allocated_bytes(),
        crate::instrument::deallocated_bytes(),
    );
    assert_eq!(
        Wire::new(OWNER, &[CLIENT, shifted], &mut budget).err(),
        Some(WireError::Overlap)
    );
    assert_eq!(
        crate::instrument::deallocated_bytes() - freed,
        crate::instrument::allocated_bytes() - bytes,
        "the refused tables are freed"
    );
    assert_eq!(budget.used(), 0);
}

/// A peer on the one shared address holding `ports` ports from `port`.
fn peer(mac: u8, port: u16, ports: u16) -> Station {
    Station {
        mac: [2, 0, 0, 0, 0, mac],
        ip: [10, 0, 0, 2],
        port,
        ports,
    }
}

/// A port range as its first port and its number of ports.
type Ports = (u16, u16);

/// Two peers on the one shared address holding the ranges `first` and `second`, in that order.
fn pair(first: Ports, second: Ports) -> [Station; 2] {
    [peer(2, first.0, first.1), peer(3, second.0, second.1)]
}

/// Whether some port is in both ranges, counted port by port.
fn share_a_port(a: Ports, b: Ports) -> bool {
    let ports = |(first, count): Ports| u32::from(first)..u32::from(first) + u32::from(count);
    ports(a).any(|port| ports(b).contains(&port))
}

/// Asserts the premises of a table of range pairs: each row's first range starts no later than its second, and
/// its last column says whether the two ranges share a port, counted port by port in either order.
fn recounted(cases: &[(Ports, Ports, bool)]) {
    for &(lower, higher, shares) in cases {
        assert!(lower.0 <= higher.0, "{lower:?} starts before {higher:?}");
        assert_eq!(
            share_a_port(lower, higher),
            shares,
            "{lower:?} and {higher:?}"
        );
        assert_eq!(
            share_a_port(higher, lower),
            shares,
            "{higher:?} and {lower:?}"
        );
    }
}

/// A budget with 1000 bytes already charged, so a budget a refusal left unchanged is not an empty one.
fn charged() -> EngineBudget {
    let mut budget = EngineBudget::new(usize::MAX);
    budget.charge(1000).unwrap();
    budget
}

/// Whether `Wire::new` refuses `peers`, configured in the order given, as an overlap, charging `budget`. An
/// accepted pair holds both peers under their configured ids and adds exactly two peers' charge to the budget,
/// with its limit unchanged; a refused pair leaves the budget as it was.
fn refused_as_overlap(peers: [Station; 2], mut budget: EngineBudget) -> bool {
    let before = budget;
    let outcome = Wire::new(OWNER, &peers, &mut budget);
    let [first, second] = peers.map(|peer| (peer.ip, peer.port, peer.ports));
    let case = format!("{first:?} then {second:?}");
    match outcome {
        Ok(wire) => {
            assert_eq!(wire.peers(), 2, "{case}");
            assert_eq!(
                [wire.peer(PeerId(0)), wire.peer(PeerId(1))],
                [Some(&peers[0]), Some(&peers[1])],
                "{case}: each peer under its configured id"
            );
            assert_eq!(
                (budget.used(), budget.limit()),
                (before.used() + Wire::charge(2).unwrap(), before.limit()),
                "{case}: two peers' charge, and the limit unchanged"
            );
            false
        }
        Err(refusal) => {
            assert_eq!(refusal, WireError::Overlap, "{case}");
            assert_eq!(
                budget.used(),
                before.used(),
                "{case}: a refusal charges nothing"
            );
            assert_eq!(
                budget, before,
                "{case}: a refusal leaves the budget as it was"
            );
            true
        }
    }
}

/// Pairs of port ranges, the range with the lower first port first, and whether the two share a port.
const RANGES: [(Ports, Ports, bool); 13] = [
    // The lower range ends one port below the higher range's first port; the third pair starts at port 0.
    ((7000, 4), (7004, 4), false),
    ((9000, 1), (9001, 1), false),
    ((0, 1), (1, 1), false),
    // The higher range ends at port 65535, then is port 65535 alone.
    ((65528, 4), (65532, 4), false),
    ((65000, 535), (65535, 1), false),
    // A gap of one port, then of many, lies between the ranges.
    ((7000, 4), (7005, 4), false),
    ((1024, 16), (40000, 16), false),
    // The ranges share exactly one port; the second pair's higher range ends at port 65535.
    ((7000, 4), (7003, 4), true),
    ((65528, 5), (65532, 4), true),
    // One range holds the other, inside it and then at its last port.
    ((7000, 10), (7003, 2), true),
    ((7000, 10), (7009, 1), true),
    // The two ranges coincide, then start at one port with different lengths.
    ((7000, 4), (7000, 4), true),
    ((7000, 1), (7000, 4), true),
];

/// Two peers on one address are refused as an overlap exactly when their port ranges share a port, whichever range is configured first, since only a shared port lets a frame's source name either peer. Ranges that only touch, up to port 65535, or lie apart are accepted; ranges that share one port, nest or coincide are refused with the budget unchanged.
/// An accepted pair holds both peers under their configured ids and charges exactly two peers' tables. The first
/// table runs each pair over an empty budget and the second over a budget with bytes already charged, which tells
/// an unchanged budget from an emptied one. Each table's last column is recounted port by port.
#[test]
fn same_address_ranges_are_an_overlap_only_when_they_share_a_port_in_either_order() {
    // Each case is two ranges and whether they share a port.
    let cases: [(Ports, Ports, bool); 9] = [
        // The lower range ends one port below the higher range's first port.
        ((100, 10), (110, 10), false),
        ((100, 1), (101, 1), false),
        // The higher range ends at port 65535.
        ((65520, 10), (65530, 6), false),
        ((65534, 1), (65535, 1), false),
        // A gap lies between the ranges.
        ((100, 10), (200, 10), false),
        // The ranges share exactly one port.
        ((100, 11), (110, 10), true),
        ((65520, 11), (65530, 6), true),
        // One range holds the other; then the two ranges coincide.
        ((100, 20), (105, 2), true),
        ((100, 10), (100, 10), true),
    ];
    recounted(&cases);
    recounted(&RANGES);
    let empty = cases.map(|case| (case, EngineBudget::new(1 << 20)));
    let precharged = RANGES.map(|case| (case, charged()));
    for ((low, high, shared), budget) in empty.into_iter().chain(precharged) {
        assert_eq!(
            refused_as_overlap(pair(low, high), budget),
            shared,
            "{low:?} then {high:?}"
        );
        assert_eq!(
            refused_as_overlap(pair(high, low), budget),
            shared,
            "{high:?} then {low:?}"
        );
    }
}

/// The pairs of the charged table on two addresses name no common source, so every pair is accepted in either
/// configured order, the lower range on one address and the higher on the other.
#[test]
fn the_same_ranges_on_two_addresses_are_accepted() {
    recounted(&RANGES);
    let apart = |peer: Station| Station {
        ip: OTHER.ip,
        ..peer
    };
    for (lower, higher, _) in RANGES {
        let [first, second] = pair(lower, higher);
        assert!(
            !refused_as_overlap([first, apart(second)], charged()),
            "{lower:?} then {higher:?}"
        );
        let [first, second] = pair(higher, lower);
        assert!(
            !refused_as_overlap([apart(first), second], charged()),
            "{higher:?} then {lower:?}"
        );
    }
}
