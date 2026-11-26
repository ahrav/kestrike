//! A receive descriptor reports the IP checksum and the L4 checksum as two
//! two-bit fields of `ol_flags`, each UNKNOWN, BAD, GOOD or NONE. Three tests
//! over `native::wire` state the rule on a descriptor and a frame
//! that pass every other check: the descriptor checks pass only when both
//! fields are GOOD; any other value of the IP field refuses
//! `Refused::IpChecksum`, and with the IP field GOOD any other value of the L4
//! field refuses `Refused::L4Checksum`; flag bits outside the two fields change
//! no verdict; and `Wire::accept` gives the same verdicts for the whole frame.
//!
//! The expected verdict of each pair of field values is computed here from the
//! values alone, so the tests hold `accept_descriptor` to the stated rule.

use std::ops::Range;

use spdk_sys as sys;

use super::{Refused, RxMeta, Station, Wire};
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

const PAYLOAD: &[u8] = b"v1 frame bytes";
const PTYPE: u32 = sys::RTE_PTYPE_L2_ETHER | sys::RTE_PTYPE_L3_IPV4 | sys::RTE_PTYPE_L4_UDP;

/// One checksum field of `ol_flags`: its mask and its four values.
#[derive(Clone, Copy)]
struct Field {
    mask: u64,
    unknown: u64,
    bad: u64,
    good: u64,
    none: u64,
}

impl Field {
    /// The field's four values with their names, GOOD first.
    fn values(self) -> [(&'static str, u64); 4] {
        [
            ("GOOD", self.good),
            ("UNKNOWN", self.unknown),
            ("BAD", self.bad),
            ("NONE", self.none),
        ]
    }
}

const IP: Field = Field {
    mask: sys::RTE_MBUF_F_RX_IP_CKSUM_MASK as u64,
    unknown: sys::RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN as u64,
    bad: sys::RTE_MBUF_F_RX_IP_CKSUM_BAD as u64,
    good: sys::RTE_MBUF_F_RX_IP_CKSUM_GOOD as u64,
    none: sys::RTE_MBUF_F_RX_IP_CKSUM_NONE as u64,
};
const L4: Field = Field {
    mask: sys::RTE_MBUF_F_RX_L4_CKSUM_MASK as u64,
    unknown: sys::RTE_MBUF_F_RX_L4_CKSUM_UNKNOWN as u64,
    bad: sys::RTE_MBUF_F_RX_L4_CKSUM_BAD as u64,
    good: sys::RTE_MBUF_F_RX_L4_CKSUM_GOOD as u64,
    none: sys::RTE_MBUF_F_RX_L4_CKSUM_NONE as u64,
};

/// The premise the tests' inputs rest on: each field is two bits, its four
/// values are the four settings of those bits with UNKNOWN zero and NONE both
/// bits, and the two fields share no bit. A layout that departs from this
/// makes the inputs below something other than the twelve non-GOOD
/// descriptors, so it stops the test under the premise's name.
fn premise_two_disjoint_two_bit_fields() {
    for (name, field) in [("IP", IP), ("L4", L4)] {
        assert_eq!(
            field.mask.count_ones(),
            2,
            "premise: the {name} checksum field is two bits"
        );
        assert_eq!(field.unknown, 0, "premise: {name} UNKNOWN is zero");
        assert_eq!(field.none, field.mask, "premise: {name} NONE is both bits");
        assert_eq!(
            field.bad | field.good,
            field.mask,
            "premise: {name} BAD and GOOD are the field's two bits"
        );
        assert_eq!(
            field.bad & field.good,
            0,
            "premise: {name} BAD and GOOD are one bit each"
        );
    }
    assert_eq!(IP.mask & L4.mask, 0, "premise: the two fields share no bit");
}

/// The verdict the property states for a descriptor whose two fields hold
/// `ip` and `l4` and that passes every other check: the IP field is judged
/// first, and only GOOD in both passes.
fn stated(ip: u64, l4: u64) -> Result<(), Refused> {
    if ip != IP.good {
        Err(Refused::IpChecksum)
    } else if l4 != L4.good {
        Err(Refused::L4Checksum)
    } else {
        Ok(())
    }
}

/// A frame from the client's first port to the owner, with a descriptor of one
/// segment, the IPv4/UDP packet type and `ol_flags`.
fn frame(ol_flags: u64) -> (RxMeta, Vec<u8>) {
    let client = Wire::new(CLIENT, &[OWNER], &mut EngineBudget::unlimited())
        .expect("the client's addressing is valid");
    let mut headers = [0; FRAME_OVERHEAD];
    client.encode(
        &mut headers,
        &OWNER,
        CLIENT.port,
        OWNER.port,
        PAYLOAD.len() as u16,
    );
    let bytes = [headers.as_slice(), PAYLOAD].concat();
    let meta = RxMeta {
        ol_flags,
        packet_type: PTYPE,
        nb_segs: 1,
        pkt_len: bytes.len() as u32,
        data_len: bytes.len() as u16,
    };
    (meta, bytes)
}

/// Every pair of field values with its names, the both-GOOD pair first.
fn pairs() -> Vec<(String, u64, u64)> {
    IP.values()
        .into_iter()
        .flat_map(|(ip_name, ip)| {
            L4.values()
                .into_iter()
                .map(move |(l4_name, l4)| (format!("IP {ip_name}, L4 {l4_name}"), ip, l4))
        })
        .collect()
}

/// The descriptor checks pass with both fields GOOD. With the IP field GOOD,
/// each of UNKNOWN, BAD and NONE in the L4 field refuses `L4Checksum`; each of
/// UNKNOWN, BAD and NONE in the IP field refuses `IpChecksum`, whatever the L4
/// field holds.
#[test]
fn only_good_in_both_checksum_fields_passes_the_descriptor_checks() {
    premise_two_disjoint_two_bit_fields();
    let (good, bytes) = frame(IP.good | L4.good);
    assert_eq!(
        Wire::accept_descriptor(&good, bytes.len()),
        Ok(()),
        "premise: the descriptor passes every check with both fields GOOD"
    );
    for (l4_name, l4) in [("UNKNOWN", L4.unknown), ("BAD", L4.bad), ("NONE", L4.none)] {
        let meta = RxMeta {
            ol_flags: IP.good | l4,
            ..good
        };
        assert_eq!(
            Wire::accept_descriptor(&meta, bytes.len()),
            Err(Refused::L4Checksum),
            "IP GOOD, L4 {l4_name}"
        );
    }
    for (ip_name, ip) in [("UNKNOWN", IP.unknown), ("BAD", IP.bad), ("NONE", IP.none)] {
        let meta = RxMeta {
            ol_flags: ip | L4.good,
            ..good
        };
        assert_eq!(
            Wire::accept_descriptor(&meta, bytes.len()),
            Err(Refused::IpChecksum),
            "IP {ip_name}, L4 GOOD"
        );
    }
    for (names, ip, l4) in pairs() {
        let meta = RxMeta {
            ol_flags: ip | l4,
            ..good
        };
        assert_eq!(
            Wire::accept_descriptor(&meta, bytes.len()),
            stated(ip, l4),
            "{names}"
        );
    }
}

/// A flag bit outside the two checksum fields changes no verdict: each of the
/// sixty such bits alone, and all of them together, leave every pair of field
/// values with the verdict it has alone.
#[test]
fn flag_bits_outside_the_checksum_fields_change_no_verdict() {
    premise_two_disjoint_two_bit_fields();
    let outside = !(IP.mask | L4.mask);
    let strays = (0..u64::BITS)
        .map(|bit| 1u64 << bit)
        .filter(|bit| bit & outside != 0)
        .chain([outside]);
    let (good, bytes) = frame(IP.good | L4.good);
    for stray in strays {
        for (names, ip, l4) in pairs() {
            let meta = RxMeta {
                ol_flags: ip | l4 | stray,
                ..good
            };
            assert_eq!(
                Wire::accept_descriptor(&meta, bytes.len()),
                stated(ip, l4),
                "{names}, other flags {stray:#x}"
            );
        }
    }
}

/// `Wire::accept` gives a whole frame the descriptor's verdict: with both
/// fields GOOD the frame yields its peer and exactly its UDP payload, and every
/// other pair of field values refuses the frame with the reason the descriptor
/// checks give, with or without flag bits outside the two fields.
#[test]
fn accept_refuses_a_whole_frame_whose_checksum_fields_are_not_both_good() {
    premise_two_disjoint_two_bit_fields();
    let owner = Wire::new(OWNER, &[CLIENT], &mut EngineBudget::unlimited())
        .expect("the owner's addressing is valid");
    let outside = !(IP.mask | L4.mask);
    for stray in [0, outside] {
        for (names, ip, l4) in pairs() {
            let (meta, bytes) = frame(ip | l4 | stray);
            let expected: Result<(PeerId, Range<usize>), Refused> =
                stated(ip, l4).map(|()| (PeerId(0), FRAME_OVERHEAD..bytes.len()));
            let accepted = owner.accept(&meta, &bytes);
            assert_eq!(accepted, expected, "{names}, other flags {stray:#x}");
            if let Ok((_, range)) = accepted {
                assert_eq!(&bytes[range], PAYLOAD, "{names}: the accepted range");
            }
        }
    }
}
