//! The window derivation against the one-shot checksum of the same bytes, over three window lengths and the chunk shapes and ranges the read path produces: whole chunks, empty ranges, single bytes, 8192-byte fragments and random ranges.

use super::super::seeded::SplitMix64;
use super::Crc32c;
use super::window::{take_folded, window_crc};

fn seeded(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = SplitMix64::new(seed);
    (0..len).map(|_| rng.next_u64() as u8).collect()
}

/// The verified checksums of the windows a chunk spans, as the header's table holds them.
fn table(crc: Crc32c, window_len: usize, chunk: &std::ops::Range<usize>, bytes: &[u8]) -> Vec<u32> {
    let first = chunk.start / window_len;
    let last = (chunk.end - 1) / window_len;
    (first..=last)
        .map(|window| {
            let whole =
                (window * window_len).max(chunk.start)..((window + 1) * window_len).min(chunk.end);
            crc.checksum(&bytes[whole])
        })
        .collect()
}

/// Every range of a chunk derives to the checksum of its bytes: whole windows, heads, tails, interiors and ranges spanning several windows, in chunks that start after a header and end inside a window, for the table mechanism and the detected one.
#[test]
fn a_derived_range_checksum_equals_the_checksum_of_its_bytes() {
    let mut rng = SplitMix64::new(41);
    let bytes = seeded(6 * 8192, 43);
    let mechanisms = [
        ("table", super::crc32c::TABLE),
        ("detected", Crc32c::detect()),
    ];
    for (name, crc) in mechanisms {
        for window_len in [4096usize, 8192, 16_384] {
            for chunk in [
                0..bytes.len(),
                596..bytes.len(),
                2132..5 * 8192 + 100,
                window_len..3 * window_len,
                window_len + 7..window_len + 9,
                0..1,
                0..window_len - 1,
            ] {
                let crcs = table(crc, window_len, &chunk, &bytes);
                let mut ranges = vec![
                    chunk.clone(),
                    chunk.start..chunk.start,
                    chunk.end..chunk.end,
                    chunk.start..chunk.start + 1,
                    chunk.end - 1..chunk.end,
                ];
                for fragment in 0..=(chunk.end - chunk.start) / 8192 {
                    let start = chunk.start + fragment * 8192;
                    let end = (start + 8192).min(chunk.end);
                    if start < end {
                        ranges.push(start..end);
                    }
                }
                for _ in 0..24 {
                    let a = chunk.start + rng.below((chunk.end - chunk.start + 1) as u64) as usize;
                    let b = chunk.start + rng.below((chunk.end - chunk.start + 1) as u64) as usize;
                    ranges.push(a.min(b)..a.max(b));
                }
                let mut runs = super::ZeroRuns::new();
                for within in ranges {
                    assert_eq!(
                        window_crc(
                            crc,
                            &mut runs,
                            window_len,
                            &chunk,
                            &crcs,
                            &bytes,
                            within.clone()
                        ),
                        crc.checksum(&bytes[within.clone()]),
                        "{name} window {window_len} chunk {chunk:?} within {within:?}"
                    );
                }
            }
        }
    }
}

/// A fragment's derivation folds at most the fragment's own bytes and equals their checksum, for windows shorter and longer than a fragment and payloads starting anywhere in their window: a first command's chunk starts after the header, and a later command's chunk starts at a window boundary with its fragment boundaries offset by the header.
#[test]
fn a_fragment_derivation_folds_at_most_its_own_bytes() {
    const FRAGMENT: usize = 8192;
    let crc = Crc32c::detect();
    let bytes = seeded(3 * 65_536, 47);
    let shapes = [
        (65_536, 148..bytes.len(), 148),
        (65_536, 0..bytes.len(), 148),
        (16_384, 596..bytes.len(), 596),
        (8192, 596..bytes.len(), 596),
        (8192, 6228..bytes.len(), 6228),
        (8192, 0..bytes.len(), 6228),
        (4096, 2132..bytes.len(), 2132),
    ];
    for (window_len, chunk, boundary) in shapes {
        let crcs = table(crc, window_len, &chunk, &bytes);
        let mut runs = super::ZeroRuns::new();
        let mut start = chunk.start;
        while start < chunk.end {
            let next = start + FRAGMENT - (start + FRAGMENT - boundary % FRAGMENT) % FRAGMENT;
            let end = next.min(chunk.end);
            take_folded();
            let derived = window_crc(
                crc,
                &mut runs,
                window_len,
                &chunk,
                &crcs,
                &bytes,
                start..end,
            );
            let folded = take_folded();
            assert_eq!(
                derived,
                crc.checksum(&bytes[start..end]),
                "window {window_len} chunk {chunk:?} fragment {start}..{end}"
            );
            assert!(
                folded <= end - start,
                "window {window_len} chunk {chunk:?} fragment {start}..{end} folded {folded} bytes"
            );
            start = end;
        }
    }
}
