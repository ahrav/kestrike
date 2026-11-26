//! Every record layout the device path checks and hands off uses one arithmetic, the division rule, at every
//! admitted chunk length and every payload of two `u32` lengths.
//!
//! An oracle written here from plain 128-bit division, sharing no code with `record::arithmetic`, states the
//! rule: a payload of `p` bytes under `c`-byte windows fills `ceil(p / c)` windows, its header is
//! `108 + 4 * (ceil(p / c) + 1)` bytes, its first payload byte lies in window `floor(header / c)`, its payload
//! lies in `ceil((header + p) / c) - first` windows, and its record is `header + p` bytes. The tests compare
//! every length function the device path uses with that oracle: the multiply-shift
//! `ValidRecordConfig::windows` and `header_bytes`, the dividing `arithmetic::header_bytes`, `layout`,
//! `local_layout`, and both `payload_of` forms. The chunk lengths are 1 to 9 units of 4096 bytes and larger
//! unit counts that are mostly not powers of two, 2^20 - 1 (the largest a `u32` admits) among them. The byte
//! counts lie at and beside every boundary of a sample of windows (the first windows, powers of two and their
//! neighbours, the last windows below 2^33): 0, 1, a window end minus one, exact and plus one, one unit past a
//! window end and its neighbours, the payloads whose record ends exactly on a window end, the two largest sums
//! of two `u32` lengths, and a fixed pseudo-random sample.
//!
//! Each test collects its disagreements into a list and asserts once that the list is empty.

use super::arithmetic;
use super::layout::{RecordConfig, RecordLayout, ValidRecordConfig};

/// The device transfer unit in bytes.
const UNIT: u128 = 4096;

/// `2^33`: every sum of two `u32` lengths is below it.
const BOUND: u128 = 1 << 33;

/// The largest sum of two `u32` lengths.
const LARGEST: u128 = 2 * (u32::MAX as u128);

/// Window lengths in units: 1 to 9, then larger counts. Only 16, 1024 and 2^19 are powers of two; the last
/// entry is the largest unit count whose byte length fits a `u32`.
const UNITS: [u128; 25] = [
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    13,
    16,
    100,
    1000,
    1024,
    4095,
    4097,
    65_535,
    65_537,
    (1 << 19) - 1,
    1 << 19,
    (1 << 19) + 1,
    (1 << 20) - 3,
    (1 << 20) - 1,
];

/// How many disagreements a test keeps for its message.
const KEPT: usize = 8;

/// `ceil(a / b)` by quotient and remainder.
fn ceil_div(a: u128, b: u128) -> u128 {
    a / b + u128::from(!a.is_multiple_of(b))
}

/// What the division rule gives a record of `payload` bytes under `chunk`-byte windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rule {
    /// `ceil(payload / chunk)`.
    windows: u128,
    /// The fixed fields and `windows + 1` table entries.
    header: u128,
    /// The window that holds the first payload byte.
    first: u128,
    /// The windows that hold a payload byte.
    count: u128,
    /// Header plus payload.
    record: u128,
}

fn rule(payload: u128, chunk: u128) -> Rule {
    let windows = ceil_div(payload, chunk);
    let header = 108 + 4 * (windows + 1);
    let first = header / chunk;
    let count = if payload == 0 {
        0
    } else {
        ceil_div(header + payload, chunk) - first
    };
    Rule {
        windows,
        header,
        first,
        count,
        record: header + payload,
    }
}

/// The payload bytes of the `index`-th window that holds a payload byte, as offsets into the payload.
fn rule_chunk(rule: &Rule, chunk: u128, index: u128) -> (u128, u128) {
    let window = rule.first + index;
    let start = (window * chunk).max(rule.header);
    let end = ((window + 1) * chunk).min(rule.record);
    (start - rule.header, end - rule.header)
}

fn config(units: u128) -> (ValidRecordConfig, u128) {
    let chunk = units * UNIT;
    let chunk_len =
        u32::try_from(chunk).expect("a unit count below 2^20 gives a u32 window length");
    let valid = RecordConfig { chunk_len }
        .validate()
        .expect("a positive multiple of the unit is admitted");
    (valid, chunk)
}

/// The window indexes whose boundaries a test visits under `chunk`-byte windows: the first windows, powers
/// of two with their neighbours, and the last three windows that start below 2^33.
fn window_indexes(chunk: u128) -> Vec<u128> {
    let last = (BOUND - 1) / chunk;
    let mut indexes = vec![
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 100, 1023, 1024, 1025,
    ];
    indexes.extend([
        (1 << 20) - 1,
        1 << 20,
        (1 << 20) + 1,
        (1 << 21) - 1,
        1 << 21,
    ]);
    indexes.extend([last.saturating_sub(2), last.saturating_sub(1), last]);
    indexes.retain(|index| *index <= last);
    indexes.sort_unstable();
    indexes.dedup();
    indexes
}

/// The byte counts a test visits under `chunk`-byte windows, each at most `limit`, sorted and distinct.
fn byte_counts(chunk: u128, limit: u128) -> Vec<u128> {
    let mut counts = vec![
        0,
        1,
        UNIT - 1,
        UNIT,
        UNIT + 1,
        LARGEST - 1,
        LARGEST,
        BOUND - 1,
    ];
    for index in window_indexes(chunk) {
        let end = index * chunk;
        // A window end minus one, exact and plus one, then one unit past it with its neighbours.
        counts.extend([end + 1, end + UNIT - 1, end + UNIT, end + UNIT + 1]);
        if end > 0 {
            counts.extend([end - 1, end]);
            // Payloads in window `index` share one header, so these three end their record one byte before,
            // exactly on and one byte past the window's end whenever that header is shorter than a window.
            let header = rule(end - 1, chunk).header;
            if let Some(fit) = end.checked_sub(header) {
                counts.extend([fit.saturating_sub(1), fit, fit + 1]);
            }
        }
    }
    // A fixed pseudo-random sample below 2^33 (a 64-bit linear congruential sequence, its high bits used).
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15 ^ (chunk as u64);
    for _ in 0..256 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        counts.push(u128::from(state >> 31));
    }
    counts.retain(|count| *count <= limit);
    counts.sort_unstable();
    counts.dedup();
    counts
}

/// Two `u32` lengths that sum to `payload`, the first as large as it can be.
fn split(payload: u128) -> (u32, u32) {
    let first = payload.min(u128::from(u32::MAX));
    (
        first as u32,
        u32::try_from(payload - first).expect("a payload of two u32 lengths"),
    )
}

/// Keeps the first [`KEPT`] disagreements and counts the rest.
struct Disagreements {
    kept: Vec<String>,
    total: usize,
}

impl Disagreements {
    fn new() -> Self {
        Self {
            kept: Vec::new(),
            total: 0,
        }
    }

    fn check(&mut self, agrees: bool, describe: impl FnOnce() -> String) {
        if !agrees {
            self.total += 1;
            if self.kept.len() < KEPT {
                self.kept.push(describe());
            }
        }
    }

    fn assert_none(self, claim: &str) {
        assert!(
            self.total == 0,
            "{claim}: {} disagreements, the first {}:\n{}",
            self.total,
            self.kept.len(),
            self.kept.join("\n")
        );
    }
}

/// `ValidRecordConfig::windows`, the multiply-shift, is `ceil(bytes / chunk_len)` at every visited byte
/// count below 2^33 under every visited window length.
#[test]
fn the_multiply_shift_window_count_is_the_ceiling_quotient_at_every_boundary() {
    let mut found = Disagreements::new();
    let mut compared = 0u64;
    for units in UNITS {
        let (valid, chunk) = config(units);
        for bytes in byte_counts(chunk, BOUND - 1) {
            let expected = ceil_div(bytes, chunk);
            let got = u128::from(valid.windows(bytes as u64));
            compared += 1;
            found.check(got == expected, || {
                format!("units {units}, bytes {bytes}: windows {got}, ceil(bytes / chunk_len) {expected}")
            });
        }
    }
    assert!(
        compared > 25 * 64,
        "every window length was visited: {compared} comparisons"
    );
    found.assert_none("the window count is ceil(bytes / chunk_len)");
}

/// The header of a payload is `108 + 4 * (ceil(payload / chunk_len) + 1)` bytes by the multiply-shift
/// `ValidRecordConfig::header_bytes` and by the dividing `arithmetic::header_bytes` alike, at every visited
/// payload of two `u32` lengths.
#[test]
fn both_header_lengths_are_the_fixed_fields_and_one_entry_past_the_ceiling_quotient() {
    let mut found = Disagreements::new();
    let mut compared = 0u64;
    for units in UNITS {
        let (valid, chunk) = config(units);
        for payload in byte_counts(chunk, LARGEST) {
            let expected = 108 + 4 * (ceil_div(payload, chunk) + 1);
            let shifted = u128::from(valid.header_bytes(payload as u64));
            let divided = u128::from(arithmetic::header_bytes(payload as u64, chunk as u64));
            compared += 1;
            found.check(shifted == expected && divided == expected, || {
                format!(
                    "units {units}, payload {payload}: multiply-shift header {shifted}, dividing header {divided}, rule {expected}"
                )
            });
        }
    }
    assert!(
        compared > 25 * 64,
        "every window length was visited: {compared} comparisons"
    );
    found.assert_none("the header is 108 + 4 * (ceil(payload / chunk_len) + 1) bytes");
}

/// What `layout` reports, as the rule's values, with its first, middle and last chunk and the absent chunk
/// past the last.
fn reported(layout: &RecordLayout) -> (Rule, Vec<Option<(u128, u128)>>) {
    let count = layout.chunk_count();
    let chunks = [0, count / 2, count.saturating_sub(1), count]
        .into_iter()
        .map(|index| {
            layout
                .chunk(index)
                .map(|range| (u128::from(range.start), u128::from(range.end)))
        })
        .collect();
    let rule = Rule {
        windows: u128::from((layout.header_bytes() as u64 - 108) / 4 - 1),
        header: layout.header_bytes() as u128,
        first: u128::from(layout.first_window()),
        count: u128::from(count),
        record: u128::from(layout.record_len()),
    };
    (rule, chunks)
}

/// `layout` places header, first window, chunk count, record length, record units and chunks where the
/// division rule places them, for both splits of each visited payload into two `u32` lengths. Where the
/// header is shorter than a window, the header the device path hands to `local_layout`, the multiply-shift
/// `header_bytes`, is the rule's header, and `local_layout` gives the same layout as `layout`.
#[test]
fn layout_and_local_layout_place_every_part_where_division_places_it() {
    let mut found = Disagreements::new();
    let (mut compared, mut local, mut beyond_first_window) = (0u64, 0u64, 0u64);
    for units in UNITS {
        let (valid, chunk) = config(units);
        for payload in byte_counts(chunk, LARGEST) {
            let expected = rule(payload, chunk);
            let count = expected.count;
            let expected_chunks: Vec<Option<(u128, u128)>> =
                [0, count / 2, count.saturating_sub(1)]
                    .into_iter()
                    .map(|index| (index < count).then(|| rule_chunk(&expected, chunk, index)))
                    .chain([None])
                    .collect();
            let (metadata, body) = split(payload);
            for (metadata_len, body_len) in [(metadata, body), (body, metadata)] {
                let layout = valid.layout(metadata_len, body_len);
                let (got, chunks) = reported(&layout);
                let lengths = (
                    layout.metadata_len(),
                    layout.body_len(),
                    u128::from(layout.payload_len()),
                    u128::from(layout.chunk_len()),
                    u128::from(layout.record_units()),
                );
                let expected_lengths = (
                    metadata_len,
                    body_len,
                    payload,
                    chunk,
                    ceil_div(expected.record, UNIT),
                );
                compared += 1;
                found.check(
                    got == expected && chunks == expected_chunks && lengths == expected_lengths,
                    || {
                        format!(
                            "units {units}, lengths ({metadata_len}, {body_len}): layout {got:?} {chunks:?} {lengths:?}, rule {expected:?} {expected_chunks:?} {expected_lengths:?}"
                        )
                    },
                );
                beyond_first_window += u64::from(expected.first > 0);
                if expected.header >= chunk {
                    continue;
                }
                // The device path computes a local record's header by the multiply-shift and hands it to
                // `local_layout`, whose precondition is that it equals the dividing header.
                let handed = valid.header_bytes(payload as u64);
                local += 1;
                if u128::from(handed) != expected.header {
                    found.check(false, || {
                        format!(
                            "units {units}, payload {payload}: the header handed to local_layout is {handed}, the rule's is {}",
                            expected.header
                        )
                    });
                    continue;
                }
                let placed = valid.local_layout(metadata_len, body_len, handed);
                found.check(placed == layout && reported(&placed).0 == expected, || {
                    format!(
                        "units {units}, lengths ({metadata_len}, {body_len}): local_layout {placed:?}, layout {layout:?}, rule {expected:?}"
                    )
                });
            }
        }
    }
    assert!(
        compared > 25 * 128 && local > 25 * 64 && beyond_first_window > 64,
        "layouts {compared}, local layouts {local}, layouts whose payload starts past window 0 {beyond_first_window}"
    );
    found.assert_none("layout and local_layout follow the division rule");
}

/// A record length names the payload whose header plus payload it is, and no other length names a payload:
/// `header + payload` grows by one byte with the payload and by five where the payload passes a window end,
/// so the four lengths after a window-exact record, and every length below the empty record's 112 bytes,
/// name none. `ValidRecordConfig::payload_of`, `arithmetic::payload_of` and `RecordPricer::payload_of`
/// answer alike.
#[test]
fn a_record_length_names_exactly_the_payload_division_gives_it() {
    let mut found = Disagreements::new();
    let (mut named, mut unnamed) = (0u64, 0u64);
    for units in UNITS {
        let (valid, chunk) = config(units);
        let pricer = valid.pricer();
        let mut ask = |record: u128, expected: Option<u128>| {
            let record = record as u64;
            let expected = expected.map(|payload| payload as u64);
            let got = (
                valid.payload_of(record),
                arithmetic::payload_of(record, chunk as u64),
                pricer.payload_of(record),
            );
            found.check(got == (expected, expected, expected), || {
                format!(
                    "units {units}, record length {record}: payload_of {got:?}, rule {expected:?}"
                )
            });
        };
        for record in [0, 1, 107, 108, 111] {
            ask(record, None);
            unnamed += 1;
        }
        for payload in byte_counts(chunk, LARGEST) {
            let record = rule(payload, chunk).record;
            ask(record, Some(payload));
            named += 1;
            if payload % chunk == 0 && payload < LARGEST {
                let next = rule(payload + 1, chunk).record;
                assert_eq!(
                    next,
                    record + 5,
                    "the oracle: one more entry and one more byte"
                );
                for gap in 1..=4 {
                    ask(record + gap, None);
                    unnamed += 1;
                }
            }
        }
    }
    assert!(
        named > 25 * 64 && unnamed > 25 * 32,
        "record lengths that name a payload {named}, that name none {unnamed}"
    );
    found.assert_none("a record length names the payload the division rule gives");
}
