//! Checked extent geometry against an independent oracle: a byte walk that
//! cuts the payload into extents of at most 253,952 bytes, the record
//! format's local header formula written out from its fields, and charges
//! summed extent by extent. Every listed edge length is checked under three
//! window lengths, and a planted payload-only charge or shifted coverage
//! fails the same check. The payload translation is checked against a
//! 128-bit oracle at the payload's edges, at offsets near the top of `u64`
//! and at lengths up to `u32::MAX`.

use std::ops::Range;

use super::geometry::{
    EXTENT_CHARGE_LIMIT, EXTENT_LIMIT, EXTENT_PAYLOAD, OBJECT_LIMIT, payload_device_start,
};
use super::layout::{IO_UNIT, ObjectGeometry};
use super::record::{RecordConfig, ValidRecordConfig};

const P: u64 = 253_952;

fn record(chunk_len: u32) -> ValidRecordConfig {
    RecordConfig { chunk_len }.validate().unwrap()
}

/// One extent as the oracle derives it: its coverage, its local header
/// (108 fixed bytes and a four-byte chunk-table entry per window the payload
/// can overlap, plus one) and its charge in units.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Extent {
    coverage: Range<u64>,
    header: u64,
    units: u64,
}

/// The oracle's extents for `len` payload bytes under `chunk_len`-byte
/// windows, found by walking the payload rather than dividing it.
fn oracle(len: u64, chunk_len: u64) -> Vec<Extent> {
    let mut extents = Vec::new();
    let mut start = 0;
    loop {
        let end = (start + P).min(len);
        let payload = end - start;
        let mut windows = 0;
        while windows * chunk_len < payload {
            windows += 1;
        }
        let header = 108 + 4 * (windows + 1);
        let mut units = 0;
        while units * (IO_UNIT as u64) < header + payload {
            units += 1;
        }
        extents.push(Extent {
            coverage: start..end,
            header,
            units,
        });
        if end == len {
            return extents;
        }
        start = end;
    }
}

/// Checks a candidate geometry of `len` bytes, given as its extent count and
/// per-extent coverage, header and charge, and its total charge, against
/// the oracle, then checks that the coverages partition `[0, len)` in order
/// and that every extent charges at most 256 KiB.
fn check(len: u64, chunk_len: u64, extents: u32, extent: impl Fn(u32) -> Extent, total_units: u64) {
    let expected = oracle(len, chunk_len);
    assert_eq!(extents as usize, expected.len(), "extent count at {len}");
    let mut next = 0;
    let mut sum = 0;
    for (index, want) in expected.iter().enumerate() {
        let got = extent(index as u32);
        assert_eq!(
            got.coverage, want.coverage,
            "coverage of extent {index} at {len}"
        );
        assert_eq!(got.header, want.header, "header of extent {index} at {len}");
        assert_eq!(got.units, want.units, "charge of extent {index} at {len}");
        assert_eq!(
            got.coverage.start, next,
            "a gap or overlap before extent {index}"
        );
        assert!(got.coverage.end > got.coverage.start || len == 0);
        assert!(got.units * IO_UNIT as u64 <= EXTENT_CHARGE_LIMIT);
        next = got.coverage.end;
        sum += got.units;
    }
    assert_eq!(next, len, "the extents end short of the payload at {len}");
    assert_eq!(total_units, sum, "charge of the whole object at {len}");
}

fn check_geometry(len: u64, chunk_len: u32) {
    let geometry = ObjectGeometry::new(len, &record(chunk_len)).unwrap();
    check(
        len,
        u64::from(chunk_len),
        geometry.extents(),
        |index| Extent {
            coverage: geometry.coverage(index),
            header: geometry.header_bytes(index),
            units: geometry.units(index),
        },
        geometry.total_units(),
    );
}

/// The edges the geometry must match the oracle at.
fn edges() -> Vec<u64> {
    let cap = OBJECT_LIMIT;
    vec![
        0,
        1,
        P - 1,
        P,
        P + 1,
        2 * P - 1,
        2 * P,
        2 * P + 1,
        cap - 1,
        cap,
    ]
}

/// At every edge, under one-unit, two-unit and one-extent windows, the geometry's
/// extent count, coverages, local headers and charges equal the oracle's,
/// the coverages partition the payload and the charges sum to the total.
#[test]
fn the_geometry_matches_the_oracle_at_every_edge() {
    for chunk_len in [4096, 8192, 262_144] {
        for len in edges() {
            check_geometry(len, chunk_len);
        }
    }
}

/// `P + 1` payload bytes take two extents, the second holding the last
/// byte; a payload of `P + 10` bytes, metadata and body together, matches
/// the oracle.
#[test]
fn one_byte_past_one_extent_takes_two() {
    let config = record(8192);
    let two = ObjectGeometry::new(P + 1, &config).unwrap();
    assert_eq!(two.extents(), 2);
    assert_eq!(two.coverage(1), P..P + 1);
    check_geometry(P + 10, 8192);
}

/// The 512 MiB ceiling: 2,115 extents charging 545,533,952 bytes, their
/// locators 16,920 bytes, full extents at 252 KiB; one byte more and the
/// widest representable length refuse.
#[test]
fn the_ceiling_admits_2115_extents_and_one_byte_more_refuses() {
    for chunk_len in [4096, 8192, 262_144] {
        let config = record(chunk_len);
        let cap = ObjectGeometry::new(OBJECT_LIMIT, &config).unwrap();
        assert_eq!(u64::from(cap.extents()), EXTENT_LIMIT);
        assert_eq!(cap.extents(), 2115);
        assert_eq!(cap.total_units() * IO_UNIT as u64, 545_533_952);
        assert_eq!(8 * u64::from(cap.extents()), 16_920);
        assert_eq!(cap.units(0) * IO_UNIT as u64, 252 * 1024);
        assert_eq!(ObjectGeometry::new(OBJECT_LIMIT + 1, &config), None);
        assert_eq!(ObjectGeometry::new(u64::MAX, &config), None);
    }
    assert_eq!(EXTENT_PAYLOAD, P);
}

/// An empty object has one empty extent that still charges its header's
/// unit, so every object's charge is positive.
#[test]
fn an_empty_object_is_one_empty_extent_of_one_unit() {
    let empty = ObjectGeometry::new(0, &record(8192)).unwrap();
    assert_eq!(empty.extents(), 1);
    assert_eq!(empty.coverage(0), 0..0);
    assert_eq!(
        (empty.header_bytes(0), empty.units(0), empty.total_units()),
        (112, 1, 1)
    );
}

/// The planted control: a charge that counts payload bytes alone and
/// forgets each extent's local header undercounts, and the oracle check
/// rejects it.
#[test]
#[should_panic(expected = "charge of extent 0")]
fn negative_control_a_payload_only_charge_fails_the_oracle() {
    let geometry = ObjectGeometry::new(2 * P, &record(8192)).unwrap();
    check(
        2 * P,
        8192,
        geometry.extents(),
        |index| {
            let coverage = geometry.coverage(index);
            Extent {
                header: geometry.header_bytes(index),
                units: (coverage.end - coverage.start).div_ceil(IO_UNIT as u64),
                coverage,
            }
        },
        geometry.total_units(),
    );
}

/// The planted coverage control: a geometry whose second extent starts one
/// byte late leaves a gap the oracle check rejects.
#[test]
#[should_panic(expected = "coverage of extent 1")]
fn negative_control_a_shifted_coverage_fails_the_oracle() {
    let geometry = ObjectGeometry::new(2 * P + 1, &record(8192)).unwrap();
    check(
        2 * P + 1,
        8192,
        geometry.extents(),
        |index| {
            let mut coverage = geometry.coverage(index);
            if index == 1 {
                coverage.start += 1;
            }
            Extent {
                coverage,
                header: geometry.header_bytes(index),
                units: geometry.units(index),
            }
        },
        geometry.total_units(),
    );
}

/// `payload_device_start` returns `(M + u) * IO_UNIT + offset` exactly when
/// unit `u` lies in the payload and the range ends at or before the volume's
/// last byte, computed in 128 bits, for one-unit payloads behind a one-unit
/// and a `2^37 - 1`-unit prefix and for 64-unit and `2^37 - 1`-unit
/// payloads, starts at and past the payload's last unit, ranges that end
/// exactly at the volume's end or one sector past it, offsets at the top of
/// `u64` and lengths up to `u32::MAX`.
#[test]
fn payload_translation_matches_a_wide_oracle_at_the_payload_and_integer_edges() {
    let unit = IO_UNIT as u64;
    let (mut accepted, mut refused, mut exact_end) = (0, 0, 0);
    for (metadata, volume) in [(1, 2), (3, 67), (1, 1 << 37), ((1 << 37) - 1, 1 << 37)] {
        let payload = volume - metadata;
        for start_unit in [0, payload / 2, payload - 1, payload, payload + 1, u64::MAX] {
            let room = payload.saturating_sub(start_unit) * unit;
            let offsets = [
                0,
                unit,
                room.saturating_sub(unit),
                room.saturating_sub(512),
                room,
                room + 1,
                u64::MAX - unit + 1,
                u64::MAX,
            ];
            for offset in offsets {
                for len in [0, 512, IO_UNIT as u32, 3 * IO_UNIT as u32, u32::MAX] {
                    let start =
                        (u128::from(metadata) + u128::from(start_unit)) * 4096 + u128::from(offset);
                    let end = start + u128::from(len);
                    let fits = start_unit < payload && end <= u128::from(volume) * 4096;
                    assert_eq!(
                        payload_device_start(metadata, volume, start_unit, offset, len),
                        fits.then_some(start as u64),
                        "M {metadata}, V {volume}, unit {start_unit}, offset {offset}, len {len}"
                    );
                    if fits {
                        accepted += 1;
                        exact_end += usize::from(len > 0 && end == u128::from(volume) * 4096);
                    } else {
                        refused += 1;
                    }
                }
            }
        }
    }
    assert!(accepted > 0 && refused > 0 && exact_end > 0);
}
