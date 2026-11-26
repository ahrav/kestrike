//! CRC32C linearity lets [`window_crc`] derive whole-window contributions from verified checksums and tail contributions from verified checksums plus head bytes.

use std::ops::Range;

use super::crc32c::{Crc32c, ZeroRuns};

/// `window_crc` returns the CRC32C of `bytes[within]`. Windows start at multiples of `window_len` in `bytes`. Callers supply a verified `chunk` containing `within`; `window_crcs[k]` holds the verified checksum of window `chunk.start / window_len + k` intersected with `chunk`. The zero runs of the lengths met come from `runs`, which keeps them for the next call.
///
/// Whole-window overlaps with `within` use window checksums. For a tail longer than its head, derive the tail's zero-initialized register by xoring the window's zero-initialized register with the head's zero-initialized register advanced by the tail length. Other overlaps fold their bytes. Each derivation folds at most `within`'s length in bytes.
pub(crate) fn window_crc(
    crc: Crc32c,
    runs: &mut ZeroRuns,
    window_len: usize,
    chunk: &Range<usize>,
    window_crcs: &[u32],
    bytes: &[u8],
    within: Range<usize>,
) -> u32 {
    debug_assert!(chunk.start <= within.start && within.end <= chunk.end);
    let first_window = chunk.start / window_len;
    let mut from_zero = 0;
    let mut at = within.start;
    let mut window = at / window_len;
    while at < within.end {
        let whole =
            (window * window_len).max(chunk.start)..((window + 1) * window_len).min(chunk.end);
        let part = at..whole.end.min(within.end);
        let part_run = runs.run(crc, (part.end - part.start) as u64);
        let piece = if part == whole {
            crc.from_zero(window_crcs[window - first_window], &part_run)
        } else if part.end != whole.end || part.end - part.start <= part.start - whole.start {
            fold(crc, &bytes[part.clone()])
        } else {
            let whole_run = runs.run(crc, (whole.end - whole.start) as u64);
            let head = fold(crc, &bytes[whole.start..part.start]);
            crc.from_zero(window_crcs[window - first_window], &whole_run) ^ part_run.advance(head)
        };
        from_zero = crc.append(from_zero, &part_run, piece);
        at = part.end;
        window += 1;
    }
    crc.checksum_of(
        from_zero,
        &runs.run(crc, (within.end - within.start) as u64),
    )
}

#[inline(always)]
fn fold(crc: Crc32c, bytes: &[u8]) -> u32 {
    #[cfg(test)]
    FOLDED.with(|total| total.set(total.get() + bytes.len()));
    crc.fold_from_zero(bytes)
}

#[cfg(test)]
thread_local! {
    /// Bytes [`window_crc`] folded on this thread, so a test can bound a derivation's reads.
    static FOLDED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn take_folded() -> usize {
    FOLDED.with(|total| total.replace(0))
}
