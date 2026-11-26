//! Layout checks at every chunk length a `u32` holds, at the payload lengths where its windows, table entries and chunk counts change.
//!
//! The Kani proofs in `layout.rs` cover every payload length for the chunk-length bands whose proofs finish within a lane's budget, and the Verus-verified contracts of `record::arithmetic` cover every chunk length.
//! The first test checks the boundary payloads of every chunk length.
//! The planted-mutant tests show that the division rule those proofs state rejects a rounded-down reciprocal, a unit count shifted by one byte, and two off-by-one local chunk counts; Verus proves the window count's product stays below `2^64`.

use super::layout::{CHUNK_TABLE, CRC_BYTES, RecordConfig, header_bytes};

/// The largest payload: full `u32` metadata and body lengths.
const MAX_PAYLOAD: u64 = 2 * u32::MAX as u64;

/// `boundary_payloads` probes empty and one-byte payloads, window and table-entry boundaries for windows 1 to 3 under chunk length `c`, the boundary where the header first ends at `c`, and payloads near [`MAX_PAYLOAD`].
fn boundary_payloads(c: u64) -> Vec<u64> {
    let mut payloads = vec![0, 1, 2, MAX_PAYLOAD - 1, MAX_PAYLOAD];
    for k in 1..=3u64 {
        let header = CHUNK_TABLE as u64 + CRC_BYTES as u64 * (k + 1);
        for edge in [k * c - header.min(k * c), k * c] {
            payloads.extend([edge.saturating_sub(1), edge, edge + 1]);
        }
    }
    let filled = (c - CHUNK_TABLE as u64 - CRC_BYTES as u64) / CRC_BYTES as u64;
    assert_eq!(CHUNK_TABLE as u64 + CRC_BYTES as u64 * (filled + 1), c);
    let edge = (filled - 1) * c;
    payloads.extend([edge.saturating_sub(1), edge, edge + 1]);
    let top = MAX_PAYLOAD / c * c;
    payloads.extend([top - 1, top, top.saturating_sub(c)]);
    payloads.retain(|&p| p <= MAX_PAYLOAD);
    payloads.sort_unstable();
    payloads.dedup();
    payloads
}

/// For every chunk length and each boundary payload: the header holds `ceil(P / c) + 1` entries, the chunks number at most that and none for an empty payload, the first, second, second-to-last and last chunks lie in consecutive windows from 0 to `P`, chunks `0..count` span the payload, and the record length names `P` back.
#[test]
fn every_chunk_length_lays_out_its_boundary_payloads() {
    for units in 1..=u32::MAX / 4096 {
        let config = RecordConfig {
            chunk_len: units * 4096,
        }
        .validate()
        .expect("a unit multiple is valid");
        let c = u64::from(config.chunk_len());
        for payload in boundary_payloads(c) {
            let (metadata_len, body_len) = ((payload / 2) as u32, (payload - payload / 2) as u32);
            let layout = config.layout(metadata_len, body_len);
            let header = layout.header_bytes() as u64;
            let entries = payload.div_ceil(c) + 1;
            let count = layout.chunk_count();
            assert_eq!(
                header,
                header_bytes(payload, c),
                "chunk {c}, payload {payload}"
            );
            assert_eq!(
                header,
                CHUNK_TABLE as u64 + CRC_BYTES as u64 * entries,
                "chunk {c}, payload {payload}"
            );
            assert_eq!(
                layout.first_window(),
                header / c,
                "chunk {c}, payload {payload}"
            );
            assert!(
                u64::from(count) <= entries && (count == 0) == (payload == 0),
                "chunk {c}, payload {payload}"
            );
            assert_eq!(
                config.payload_of(layout.record_len()),
                Some(payload),
                "chunk {c}, payload {payload}"
            );
            assert!(
                layout.chunk(count).is_none(),
                "chunk {c}, payload {payload}"
            );
            if count == 0 {
                continue;
            }
            assert_eq!(
                layout.chunks(0, count),
                0..payload,
                "chunk {c}, payload {payload}"
            );
            for index in [0, 1, count.saturating_sub(2), count - 1] {
                if index >= count {
                    continue;
                }
                let chunk = layout.chunk(index).expect("below the chunk count");
                let window = layout.first_window() + u64::from(index);
                assert!(
                    chunk.start < chunk.end,
                    "chunk {c}, payload {payload}, chunk {index}"
                );
                let start = if index == 0 { 0 } else { window * c - header };
                let end = ((window + 1) * c - header).min(payload);
                assert_eq!(
                    chunk,
                    start..end,
                    "chunk {c}, payload {payload}, chunk {index}"
                );
            }
        }
    }
}

/// Every chunk length's stride reciprocal meets Lemire's exactness bound for
/// every dividend below `2^32`.
///
/// With stride `s`, the reciprocal is `R = ceil(2^64 / s) = (2^64 + e) / s`
/// for some `0 < e < s`. A dividend `d = q * s + r` (`r < s`) gives
/// `d * R = q * 2^64 + q * e + r * R`, so `(d * R) >> 64` is `q` exactly when
/// `q * e + r * R < 2^64`. The sum grows with `q` and `r`, so its largest
/// value below `d = 2^32` comes at the last quotient, with the remainder
/// that `2^32 - 1` leaves, or at the quotient before it, with `r = s - 1`;
/// this test checks both for every stride.
#[test]
fn every_stride_reciprocal_meets_the_exactness_bound() {
    for units in 1..=u32::MAX / 4096 {
        let config = RecordConfig {
            chunk_len: units * 4096,
        }
        .validate()
        .expect("a unit multiple is valid");
        let s = u128::from(config.chunk_len()) + CRC_BYTES as u128;
        let r = u128::from(config.pricer().stride_inverse());
        let excess = r * s - (1 << 64);
        assert!(r * s > 1 << 64 && excess < s, "chunk units {units}");
        let top = (1u128 << 32) - 1;
        let last = top / s;
        let at_last = last * excess + (top - last * s) * r;
        let before = last.saturating_sub(1) * excess + (s - 1) * r;
        assert!(at_last < 1 << 64 && before < 1 << 64, "chunk units {units}");
    }
}

/// The pricer and the configuration's division name the same payload at
/// every record length within 16 bytes of the first three table-entry
/// boundaries and of the four nearest the `2^32` handover, across the fixed
/// fields and the handover, and at the two largest lengths, for sampled and
/// edge chunk lengths. The lengths include ones that name a payload and gaps
/// that name none.
#[test]
fn the_pricer_names_what_division_names_at_every_boundary() {
    let sampled = (1..=u32::MAX / 4096).step_by(4099);
    let edges = [
        1,
        2,
        3,
        4,
        7,
        16,
        17,
        64,
        255,
        256,
        4096,
        65535,
        524_288,
        u32::MAX / 4096,
    ];
    for units in sampled.chain(edges) {
        let config = RecordConfig {
            chunk_len: units * 4096,
        }
        .validate()
        .expect("a unit multiple is valid");
        let c = u64::from(config.chunk_len());
        let s = c + CRC_BYTES as u64;
        let fixed = header_bytes(0, c);
        let handover = fixed + (1 << 32);
        let last = (1u64 << 32) / s;
        let mut lengths: Vec<u64> = (0..fixed + 16).collect();
        for entries in [1, 2, 3, last.saturating_sub(1), last, last + 1, last + 2] {
            let end = fixed + entries * s;
            lengths.extend(end.saturating_sub(16)..=end + 16);
        }
        lengths.extend(handover - 16..=handover + 16);
        lengths.extend([u64::MAX - 1, u64::MAX]);
        let pricer = config.pricer();
        for len in lengths {
            assert_eq!(
                pricer.payload_of(len),
                config.payload_of(len),
                "chunk {c}, record length {len}"
            );
        }
    }
}

/// The division rule the window-count proofs state: `q` windows of `c` bytes are the fewest that hold `bytes`.
fn fewest_windows(bytes: u64, c: u64, q: u64) -> bool {
    q * c >= bytes && (q == 0 || (q - 1) * c < bytes)
}

/// The byte counts at and beside the first three multiples of `c`.
fn window_edges(c: u64) -> impl Iterator<Item = u64> {
    (1..=3u64).flat_map(move |k| [k * c - 1, k * c, k * c + 1])
}

/// The production window count meets the division rule at every edge of the low window lengths, and each planted mutant of its multiply-shift breaks it at one: a reciprocal rounded down undercounts past a whole window, and a unit count without its minus one counts an extra window at a whole window.
#[test]
fn a_planted_window_count_mutant_fails_the_division_rule() {
    let (mut floor_fails, mut shifted_fails) = (false, false);
    for units in 1..64u64 {
        let c = units * 4096;
        let config = RecordConfig {
            chunk_len: c as u32,
        }
        .validate()
        .unwrap();
        let ceiling_reciprocal = (1u64 << 42).div_ceil(units);
        for bytes in window_edges(c) {
            assert!(
                fewest_windows(bytes, c, config.windows(bytes)),
                "units {units}, bytes {bytes}"
            );
            let n = (bytes + c - 1) / 4096;
            floor_fails |= !fewest_windows(bytes, c, (n * ((1u64 << 42) / units)) >> 42);
            shifted_fails |=
                !fewest_windows(bytes, c, (((bytes + c) / 4096) * ceiling_reciprocal) >> 42);
        }
    }
    assert!(
        floor_fails,
        "a reciprocal rounded down met the division rule at every edge"
    );
    assert!(
        shifted_fails,
        "a unit count without its minus one met the division rule at every edge"
    );
}

/// The local layout's chunk count meets the division rule at every edge of the low window lengths where its header ends inside window 0, and each planted mutant breaks it at one: a count that adds the extra window at an exact fit, and one that reads the table's entry count as the window count.
#[test]
fn a_planted_local_count_mutant_fails_the_division_rule() {
    let (mut exact_fails, mut entries_fail) = (false, false);
    for units in 1..64u64 {
        let c = units * 4096;
        let config = RecordConfig {
            chunk_len: c as u32,
        }
        .validate()
        .unwrap();
        let fit = |entries: u64| CHUNK_TABLE as u64 + CRC_BYTES as u64 * entries;
        for payload in
            window_edges(c).flat_map(|edge| [edge - fit(2), edge - fit(3), edge - fit(4), edge])
        {
            let header = header_bytes(payload, c);
            if header >= c || payload > u64::from(u32::MAX) {
                continue;
            }
            let record = header + payload;
            let rule = |count: u64| count > 0 && (count - 1) * c < record && record <= count * c;
            let local = config.local_layout(0, payload as u32, header);
            assert!(
                rule(u64::from(local.chunk_count())),
                "units {units}, payload {payload}"
            );
            let q = (header - CHUNK_TABLE as u64 - CRC_BYTES as u64) / CRC_BYTES as u64;
            exact_fails |= !rule(q + u64::from(record >= q * c));
            entries_fail |= !rule(q + 1 + u64::from(record > (q + 1) * c));
        }
    }
    assert!(
        exact_fails,
        "a count adding a window at an exact fit met the division rule at every edge"
    );
    assert!(
        entries_fail,
        "a count from the entry count met the division rule at every edge"
    );
}
