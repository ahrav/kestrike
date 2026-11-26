//! Fragment geometry checks: `FragmentGeometry::buffers` against buffer boundaries built one command at a time, and the fragment count and fragment ranges of a transfer against counts written out and a ceiling computed in `u128`.

use std::ops::Range;

use super::geometry::{
    FRAGMENT_LEN, FragmentGeometry, GeometryError, GeometryInputs, GeometryRefusal,
};

/// The payload ranges a read of `payload` bytes under a `header`-byte header leaves in each backing buffer: the first holds `span - header` bytes and each later one `span`, the last ending at the payload's end.
fn boundaries(span: u64, header: u64, payload: u64) -> Vec<Range<u64>> {
    let mut buffers = Vec::new();
    let mut start = 0;
    let mut len = span - header;
    while start < payload {
        let end = (start + len).min(payload);
        buffers.push(start..end);
        start = end;
        len = span;
    }
    buffers
}

/// Every geometry of the grid is admitted exactly when its command span holds a whole fragment and its first command holds the largest header plus one chunk.
/// For each admitted one, every fragment of every sampled payload meets one or two consecutive buffers, which `buffers` names; each refused one returns its inputs.
#[test]
fn the_geometry_grid_admits_exactly_the_two_buffer_configurations() {
    let (mut admitted, mut below, mut header_first) = (0, 0, 0);
    let header_maxes = [84, 4095, 4096, 8191, 8192, 16388];
    let transfers: Vec<u32> = (1..=16).map(|k| k * 4096).chain([1 << 20]).collect();
    for chunk in (1..=8).map(|k| k * 4096) {
        for buffer in (1..=16).map(|k| k * 4096) {
            for &transfer in &transfers {
                for header_max in header_maxes {
                    let inputs = GeometryInputs {
                        record_chunk_len: chunk,
                        response_buffer_len: buffer,
                        device_max_transfer: transfer,
                        header_max,
                    };
                    let span = buffer.min(transfer) / chunk * chunk;
                    // The read path's attach rule: the first command holds every window through the one holding the first payload byte under the largest header, `(header_max / chunk + 1) * chunk` bytes, so it carries the header and the first chunk.
                    // The fragment bound below is checked against buffer boundaries built one command at a time, apart from this rule.
                    let holds_header = (header_max / chunk + 1) * chunk <= span;
                    match FragmentGeometry::new(inputs) {
                        Ok(geometry) => {
                            assert!(span >= FRAGMENT_LEN && holds_header, "{inputs:?}");
                            assert_eq!((geometry.span(), geometry.inputs()), (span, inputs));
                            admitted += 1;
                            check_fragments(&geometry, header_max);
                        }
                        Err(GeometryError {
                            inputs: returned,
                            reason,
                        }) => {
                            assert_eq!(returned, inputs);
                            match reason {
                                GeometryRefusal::SpanBelowFragment { span: found } => {
                                    assert!(span < FRAGMENT_LEN);
                                    assert_eq!(found, span);
                                    below += 1;
                                }
                                GeometryRefusal::HeaderFirst { .. } => {
                                    assert!(span >= FRAGMENT_LEN && !holds_header);
                                    header_first += 1;
                                }
                                GeometryRefusal::ChunkLen => panic!("{inputs:?}"),
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(admitted > 0 && below > 0 && header_first > 0);
}

/// Checks every fragment of sampled payloads under headers from zero up to the geometry's largest, so a large header's short first buffer is covered.
fn check_fragments(geometry: &FragmentGeometry, header_max: u32) {
    let span = u64::from(geometry.span());
    let mut checked = 0;
    for header in [0, header_max / 2, header_max] {
        for payload in [1u64, 100, 8191, 8192, 8193, 15_743, 3 * 8192 + 1, 332_211] {
            let buffers = boundaries(span, u64::from(header), payload);
            let fragments = FragmentGeometry::fragments(payload);
            assert_eq!(fragments, payload.div_ceil(8192));
            for index in 0..fragments as u32 {
                let fragment = FragmentGeometry::fragment(index, payload);
                let met: Vec<u64> = (0..buffers.len() as u64)
                    .filter(|&k| {
                        let buffer = &buffers[k as usize];
                        buffer.start < fragment.end && fragment.start < buffer.end
                    })
                    .collect();
                assert!(
                    (1..=2).contains(&met.len()),
                    "{geometry:?} header {header} payload {payload} fragment {index}: {met:?}"
                );
                assert!(met.windows(2).all(|pair| pair[1] == pair[0] + 1));
                let named = geometry.buffers(header, fragment.clone());
                assert_eq!(
                    named,
                    met[0]..met[met.len() - 1] + 1,
                    "{geometry:?} header {header} {fragment:?}"
                );
                checked += 1;
            }
        }
    }
    assert!(checked > 0, "{geometry:?}");
}

/// An object of several extents reads each extent's record with its own
/// local header, so its buffers restart at every extent boundary. Every
/// extent's payload is a whole number of fragments, so every fragment lies
/// in one extent and meets one or two consecutive buffers of it, whatever
/// header each extent carries up to the largest.
#[test]
fn every_fragment_of_a_multi_extent_object_meets_at_most_two_buffers_of_one_extent() {
    let full = crate::storage::EXTENT_PAYLOAD;
    assert!(full.is_multiple_of(u64::from(FRAGMENT_LEN)));
    let mut checked = 0;
    for chunk in [4096, 8192, 32_768] {
        for buffer in [8192, 16_384, 65_536] {
            let inputs = GeometryInputs {
                record_chunk_len: chunk,
                response_buffer_len: buffer,
                device_max_transfer: 1 << 20,
                header_max: 4096,
            };
            let Ok(geometry) = FragmentGeometry::new(inputs) else {
                continue;
            };
            let span = u64::from(geometry.span());
            for payload in [full + 1, 2 * full + 100, 3 * full] {
                for header in [100, 2048, 4096] {
                    // Each extent's buffers, as payload ranges of the object.
                    let mut buffers = Vec::new();
                    let mut offset = 0;
                    while offset < payload {
                        let len = full.min(payload - offset);
                        for range in boundaries(span, header, len) {
                            buffers.push(offset + range.start..offset + range.end);
                        }
                        offset += len;
                    }
                    for index in 0..FragmentGeometry::fragments(payload) as u32 {
                        let fragment = FragmentGeometry::fragment(index, payload);
                        assert_eq!(
                            fragment.start / full,
                            (fragment.end - 1) / full,
                            "one extent"
                        );
                        let met: Vec<usize> = (0..buffers.len())
                            .filter(|&k| {
                                buffers[k].start < fragment.end && fragment.start < buffers[k].end
                            })
                            .collect();
                        assert!(
                            (1..=2).contains(&met.len()),
                            "{inputs:?} {payload} {header} {index}: {met:?}"
                        );
                        assert!(met.windows(2).all(|pair| pair[1] == pair[0] + 1));
                        checked += 1;
                    }
                }
            }
        }
    }
    assert!(checked > 0);
}

/// A chunk length that is zero or not a multiple of 4096 is refused first, with the inputs returned.
#[test]
fn a_chunk_length_off_the_unit_is_refused_first() {
    for chunk in [0, 4095, 6144] {
        let inputs = GeometryInputs {
            record_chunk_len: chunk,
            response_buffer_len: 0,
            device_max_transfer: 0,
            header_max: 0,
        };
        assert_eq!(
            FragmentGeometry::new(inputs),
            Err(GeometryError {
                inputs,
                reason: GeometryRefusal::ChunkLen
            })
        );
    }
}

/// The fragments of a transfer, walked from index 0 to the count as a sender walks them, lie end to end from byte 0 to `total`: each is nonempty and starts at `index * 8192`, where the one before it ended, every fragment but the last is 8192 bytes, the last carries the exact remainder, and an empty transfer has none.
#[test]
fn fragments_tile_the_transfer_with_an_exact_final_remainder() {
    assert_eq!(FragmentGeometry::fragments(0), 0);
    for total in [
        1u64,
        2,
        8191,
        8192,
        8193,
        16383,
        16384,
        16385,
        3 * 8192 - 1,
        3 * 8192,
        332_211,
        257 * 8192 + 4096,
        4096 * 8192,
        4096 * 8192 + 1,
        5000 * 8192 - 1,
    ] {
        let count = FragmentGeometry::fragments(total) as u32;
        let mut next = 0;
        for index in 0..count {
            let range = FragmentGeometry::fragment(index, total);
            assert_eq!(range.start, next, "total {total} fragment {index}");
            assert_eq!(range.start, u64::from(index) * 8192);
            assert!(range.end > range.start, "total {total} fragment {index}");
            let last = index + 1 == count;
            assert_eq!(
                range.end - range.start == 8192,
                !last || total.is_multiple_of(8192)
            );
            assert!(range.end - range.start <= 8192);
            next = range.end;
        }
        assert_eq!(next, total);
    }
}

/// The fragment length as the count and u32-limit tests below state it. Their expected values use this literal,
/// and the count test ties it to the constant the crate exports.
const LEN: u64 = 8192;

/// The largest fragment count the frame's u32 count field holds.
const COUNT_MAX: u64 = u32::MAX as u64;

/// `ceil(total / 8192)`, computed in `u128`.
fn ceiling(total: u64) -> u64 {
    u128::from(total).div_ceil(8192) as u64
}

/// What is wrong with the fragments `indexes` of a `total`-byte transfer of `count` fragments, one line
/// per fault: a start other than `index * 8192`, an empty range, a length other than 8192 before the
/// last fragment, or a last fragment that is longer than 8192 bytes or ends elsewhere than at `total`.
fn faults(total: u64, count: u64, indexes: impl Iterator<Item = u64>) -> Vec<String> {
    let mut faults = Vec::new();
    for index in indexes {
        let range = FragmentGeometry::fragment(index as u32, total);
        let last = index + 1 == count;
        if range.start != index * LEN {
            faults.push(format!(
                "total {total}: fragment {index} starts at {}",
                range.start
            ));
        }
        if range.end <= range.start {
            faults.push(format!(
                "total {total}: fragment {index} is empty: {range:?}"
            ));
        }
        if !last && range.end != range.start + LEN {
            faults.push(format!(
                "total {total}: fragment {index} is not 8192 bytes: {range:?}"
            ));
        }
        if last && (range.end != total || range.end.saturating_sub(range.start) > LEN) {
            faults.push(format!(
                "total {total}: the last fragment {index} is {range:?}"
            ));
        }
    }
    faults
}

/// The count is `ceil(total / 8192)`: zero for the empty transfer, one through 8192 bytes, two from 8193,
/// and the same rule at the largest u32 count and at the top of `u64`.
#[test]
fn the_fragment_count_is_the_ceiling_of_total_over_8192() {
    assert_eq!(u64::from(FRAGMENT_LEN), LEN);
    let written_out: [(u64, u64); 16] = [
        (0, 0),
        (1, 1),
        (8191, 1),
        (8192, 1),
        (8193, 2),
        (16383, 2),
        (16384, 2),
        (16385, 3),
        (1000 * 8192, 1000),
        (1000 * 8192 + 1, 1001),
        (4_294_967_294 * 8192 + 1, 4_294_967_295),
        (4_294_967_295 * 8192, 4_294_967_295),
        (4_294_967_295 * 8192 + 1, 4_294_967_296),
        (u64::MAX - 8191, (1 << 51) - 1),
        (u64::MAX - 8190, 1 << 51),
        (u64::MAX, 1 << 51),
    ];
    let seen: Vec<(u64, u64)> = written_out
        .iter()
        .map(|&(total, _)| (total, FragmentGeometry::fragments(total)))
        .collect();
    assert_eq!(seen, written_out, "(total, fragments) at the boundaries");
    // At and above multiples of 8192, against the ceiling computed in u128.
    let bases = [
        0,
        1,
        2,
        3,
        1000,
        65_535,
        COUNT_MAX - 1,
        COUNT_MAX,
        1 << 40,
        (1 << 51) - 1,
    ];
    let mut differing = Vec::new();
    for base in bases {
        for offset in [0, 1, 2, 4095, 4096, 4097, 8190, 8191] {
            let total = base * LEN + offset;
            let (count, expected) = (FragmentGeometry::fragments(total), ceiling(total));
            if count != expected {
                differing.push((total, count, expected));
            }
        }
    }
    assert_eq!(differing, Vec::new(), "(total, fragments, ceiling)");
}

/// A transfer whose count is the largest a u32 holds, or one below it, has its first fragment at byte 0
/// and its last three fragments at `index * 8192`, the last ending at `total`.
#[test]
fn a_transfer_at_the_u32_count_limit_ends_its_last_fragment_at_total() {
    let totals = [
        (COUNT_MAX - 1) * LEN,
        (COUNT_MAX - 1) * LEN + 1,
        COUNT_MAX * LEN - 1,
        COUNT_MAX * LEN,
    ];
    let mut found = Vec::new();
    let mut ends = Vec::new();
    for total in totals {
        let count = FragmentGeometry::fragments(total);
        if count == 0 || count > COUNT_MAX {
            found.push(format!(
                "total {total}: {count} fragments do not fit a u32 count"
            ));
            continue;
        }
        found.extend(faults(total, count, (0..1).chain(count - 3..count)));
        ends.push(FragmentGeometry::fragment((count - 1) as u32, total).end);
    }
    assert_eq!(found, Vec::<String>::new());
    assert_eq!(
        ends, totals,
        "the byte each transfer's last fragment ends at"
    );
}

/// `buffers` names the buffer index `offset / span` for a header-free record at every span the geometry admits, including offsets next to a span multiple and next to `u64::MAX`.
#[test]
fn buffer_indices_match_division_for_every_span() {
    for windows in 2..=u32::MAX / 4096 {
        let span = windows * 4096;
        let geometry = FragmentGeometry::new(GeometryInputs {
            record_chunk_len: 4096,
            response_buffer_len: span,
            device_max_transfer: span,
            header_max: 0,
        })
        .expect("a span of whole windows is admitted");
        let span = u64::from(span);
        let top = (u64::MAX - 1) / span * span;
        for offset in [span - 1, span, 2 * span - 1, top - 1, top, u64::MAX - 1] {
            assert_eq!(
                geometry.buffers(0, offset..offset + 1),
                offset / span..offset / span + 1,
                "span {span}, offset {offset}"
            );
        }
    }
}

/// `buffers` names the buffer index `offset / span` at sampled multiples `k * span` of twelve spans, one byte below and one byte above each, and a range from byte 0 ends in buffer `k - 1` at `k * span` and reaches buffer `k` one byte later.
///
/// A reciprocal below `2^72 / w` gives `k - 1` at an exact multiple, and the largest multiple of the span below `2^64` has the largest dividend, where a reciprocal too far above `2^72 / w` would give `k + 1`. Eight of the spans are a count of windows that is no power of two, so `2^72 / w` is not whole; four are powers of two.
#[test]
fn buffer_indices_match_division_at_and_beside_sampled_span_multiples() {
    let uneven = [3, 5, 6, 7, 12, 1000, 999_983, (1 << 20) - 1];
    let even = [2, 4, 1 << 10, 1 << 19];
    for windows in uneven.into_iter().chain(even) {
        let span: u32 = windows * 4096;
        let geometry = FragmentGeometry::new(GeometryInputs {
            record_chunk_len: 4096,
            response_buffer_len: span,
            device_max_transfer: span,
            header_max: 0,
        })
        .expect("a span of whole windows is admitted");
        assert_eq!(geometry.span(), span);
        let span = u64::from(span);
        let multiples = (0..=64).chain([
            1000,
            65_535,
            1 << 20,
            (1 << 32) - 1,
            (1 << 32) + 1,
            u64::MAX / span,
        ]);
        for k in multiples {
            let multiple = k * span;
            let beside = [multiple.checked_sub(1), Some(multiple), Some(multiple + 1)];
            for offset in beside.into_iter().flatten() {
                assert_eq!(
                    geometry.buffers(0, offset..offset + 1),
                    offset / span..offset / span + 1,
                    "span {span}, offset {offset}"
                );
            }
            if k > 0 {
                assert_eq!(
                    (
                        geometry.buffers(0, 0..multiple),
                        geometry.buffers(0, 0..multiple + 1)
                    ),
                    (0..k, 0..k + 1),
                    "span {span}, {k} spans"
                );
            }
        }
    }
}

/// Every admitted span's reciprocal meets Lemire's exactness bound for every `u64` dividend.
///
/// With `w = span / 4096`, the reciprocal is `R = ceil(2^72 / w) = (2^72 + e) / w` for some `0 <= e < w`.
/// A dividend's `d = bytes >> 12 = q * w + r` (`r < w`) gives `d * R = q * 2^72 + q * e + r * R`, so the span count `(d * R) >> 72` is `q = bytes / span` exactly when `q * e + r * R < 2^72`.
/// `d` is below `2^52`, so `q <= (2^52 - 1) / w` and the sum is at most `q_max * e + (w - 1) * R`; this test checks that bound below `2^72` for every `w`, extending the Kani proof's bounded dividends to all of `u64`.
#[test]
fn every_span_reciprocal_meets_the_exactness_bound() {
    for windows in 2..=u32::MAX / 4096 {
        let geometry = FragmentGeometry::new(GeometryInputs {
            record_chunk_len: 4096,
            response_buffer_len: windows * 4096,
            device_max_transfer: windows * 4096,
            header_max: 0,
        })
        .expect("a span of whole windows is admitted");
        let (w, r) = (u128::from(windows), geometry.reciprocal());
        let excess = r * w - (1 << 72);
        assert!(r * w >= 1 << 72 && excess < w, "span units {windows}");
        let largest = ((1u128 << 52) - 1) / w;
        assert!(
            largest * excess + (w - 1) * r < 1 << 72,
            "span units {windows}"
        );
    }
}

/// The backing buffers payload range `a..b` lies in under span `span` and
/// header `h`, in `u128`: the first buffer holds `span - h` payload bytes
/// and every later one `span`; an empty or reversed range lies in none.
fn wide_buffers(span: u64, h: u32, a: u64, b: u64) -> std::ops::Range<u128> {
    let (s, first) = (u128::from(span), u128::from(span - u64::from(h)));
    let index = |p: u128| if p < first { 0 } else { 1 + (p - first) / s };
    match a < b {
        true => index(u128::from(a))..index(u128::from(b) - 1) + 1,
        false => 0..0,
    }
}

/// Maps every range between offsets at the first and later buffer
/// boundaries and at the top of `u64`, empty and reversed ones included, to
/// the buffers the `u128` model gives, for five admitted geometries, some
/// with `header_max == span - 1`, under each of headers 0, 1,
/// `header_max / 2` and `header_max` that the geometry admits.
/// The test checks each sampled header against boundary offsets from every
/// sampled header in the same geometry, including those within a header's
/// length of `u64::MAX`. It independently checks buffer ranges at
/// `header_max`'s first boundary.
#[test]
fn ib_buffer_index_boundaries_match_the_wide_model_to_the_top_of_u64() {
    let shapes = [
        (4096, 16_384, 1 << 20, 0),
        (4096, 16_384, 1 << 20, 16_383),
        (8192, 65_536, 1 << 20, 4096),
        (65_536, 1 << 20, 1 << 20, (1 << 20) - 1),
        (4096, 12_288, 8192, 8191),
    ];
    let (mut checked, mut top, mut widest_header) = (0, 0, false);
    for (record_chunk_len, response_buffer_len, device_max_transfer, header_max) in shapes {
        let inputs = GeometryInputs {
            record_chunk_len,
            response_buffer_len,
            device_max_transfer,
            header_max,
        };
        let geometry = FragmentGeometry::new(inputs).expect("an admitted geometry");
        let span = u64::from(geometry.span());
        widest_header |= u64::from(header_max) == span - 1;
        let mut headers = vec![0, 1, header_max / 2, header_max];
        headers.retain(|&h| h <= header_max);
        headers.dedup();
        let mut points: Vec<u64> = Vec::new();
        for &h in &headers {
            let first = span - u64::from(h);
            let last = first + (u64::MAX - first) / span * span;
            let below = u64::MAX - u64::from(h);
            points.extend(
                [
                    Some(0),
                    Some(1),
                    first.checked_sub(1),
                    Some(first),
                    Some(first + 1),
                    Some(first + span - 1),
                    Some(first + span),
                    Some(first + span + 1),
                    Some(first + 2 * span),
                    u64::MAX.checked_sub(span),
                    // The last buffer boundary below the top of `u64`, and
                    // either side of it.
                    last.checked_sub(1),
                    Some(last),
                    last.checked_add(1),
                    below.checked_sub(1),
                    Some(below),
                    below.checked_add(1),
                    Some(u64::MAX - u64::from(h / 2)),
                    Some(u64::MAX - 1),
                    Some(u64::MAX),
                ]
                .into_iter()
                .flatten(),
            );
        }
        points.sort_unstable();
        points.dedup();
        for h in headers {
            for &a in &points {
                for &b in &points {
                    let got = geometry.buffers(h, a..b);
                    assert_eq!(
                        u128::from(got.start)..u128::from(got.end),
                        wide_buffers(span, h, a, b),
                        "{inputs:?} h {h} {a}..{b}"
                    );
                    checked += 1;
                    top += usize::from(b == u64::MAX && a < b);
                }
            }
        }
        let first = span - u64::from(header_max);
        assert_eq!(geometry.buffers(header_max, 0..first), 0..1);
        assert_eq!(geometry.buffers(header_max, 0..first + 1), 0..2);
        assert_eq!(geometry.buffers(header_max, first..first + span), 1..2);
        assert_eq!(geometry.buffers(header_max, first..first + span + 1), 1..3);
    }
    assert!(checked > 0 && top > 0);
    assert!(widest_header, "a geometry has header_max == span - 1");
}
