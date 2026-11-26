//! The record format's length arithmetic: how many windows a byte count
//! fills, how long a record's header is, which window holds its first
//! payload byte, how many windows hold payload, and which payload length a
//! record length names.
//!
//! A window is `chunk_len = units * UNIT` bytes for `1 <= units < 2^20`,
//! every positive `u32` multiple of [`UNIT`]. A record of `payload` bytes
//! has a header of [`FIXED`] fixed bytes followed by a chunk table of
//! `ceil(payload / chunk_len) + 1` entries of [`ENTRY`] bytes each, and the
//! payload follows the header. Every payload
//! of two `u32` lengths lies below [`PAYLOAD_BOUND`].
//!
//! Verus checks these value-only functions against their contracts;
//! `layout` applies them to a validated record configuration.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// Bytes of a record header's fixed fields; its chunk table starts here.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub(crate) const FIXED: u64 = 108;

/// Bytes of one chunk-table entry, a crc32c.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub(crate) const ENTRY: u64 = 4;

/// The device transfer unit; every window is a whole number of units.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub(crate) const UNIT: u64 = 4096;

/// `2^33`: every payload of two `u32` lengths is shorter.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub(crate) const PAYLOAD_BOUND: u64 = 0x2_0000_0000;

/// `2^42`, the scale of [`windows`]' reciprocal: `N + L` for unit counts
/// below `2^22` and windows below `2^20` units, which makes the
/// multiply-shift exact.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub(crate) const SCALE: u64 = 0x400_0000_0000;

/// `ceil(dividend / divisor)`: the fewest `divisor`-byte pieces that hold
/// `dividend` bytes.
#[cfg_attr(verus_keep_ghost, verus_spec(q =>
    requires 0 < divisor,
    ensures q == crate::proof::ceiling(dividend as int, divisor as int),
))]
#[inline(always)]
const fn ceiling(dividend: u64, divisor: u64) -> u64 {
    #[cfg(verus_keep_ghost)]
    proof! {
        crate::proof::ceiling_below(dividend as int, divisor as int);
    }
    if dividend == 0 {
        0
    } else {
        (dividend - 1) / divisor + 1
    }
}

/// The multiplier [`windows`] scales its unit count by for a window of
/// `units` units: `ceil(2^42 / units)`.
#[cfg_attr(verus_keep_ghost, verus_spec(reciprocal =>
    requires 1 <= units < 0x10_0000,
    ensures
        reciprocal * units >= SCALE,
        (reciprocal - 1) * units < SCALE,
))]
pub(crate) fn reciprocal(units: u64) -> u64 {
    #[cfg(verus_keep_ghost)]
    proof! {
        crate::proof::ceiling_bounds(SCALE as int, units as int);
    }
    ceiling(SCALE, units)
}

/// `ceil(bytes / chunk_len)` for `bytes` below [`PAYLOAD_BOUND`], from the
/// [`reciprocal`] of the window's `units = chunk_len / UNIT`.
///
/// The quotient is `floor(n / units)` for `n = floor((bytes + chunk_len -
/// 1) / UNIT)`, below `2^21 + units < 2^22`. The reciprocal gives that
/// quotient as `(n * reciprocal) >> 42` for every `n` below `2^22` (Lemire,
/// Kaser and Kurz, "Faster remainder by direct computation", 2019, Lemma 1
/// with `N = 22` and `L = 20`, since `units < 2^20`); the product stays
/// below `2^64`.
#[cfg_attr(verus_keep_ghost, verus_spec(q =>
    requires
        UNIT <= chunk_len < 0x1_0000_0000,
        chunk_len % UNIT == 0,
        reciprocal * (chunk_len / UNIT) >= SCALE,
        (reciprocal - 1) * (chunk_len / UNIT) < SCALE,
        bytes < PAYLOAD_BOUND,
    ensures
        q * chunk_len >= bytes,
        q == 0 || (q - 1) * chunk_len < bytes,
))]
#[inline(always)]
pub(crate) fn windows(bytes: u64, chunk_len: u64, reciprocal: u64) -> u64 {
    #[cfg(verus_keep_ghost)]
    proof! {
        crate::proof::unit_multiple(chunk_len as int);
        crate::proof::lemire_windows(bytes as int, chunk_len as int / 4096, reciprocal as int);
    }
    let n = (bytes + chunk_len - 1) / UNIT;
    let product = n * reciprocal;
    #[cfg(verus_keep_ghost)]
    proof! {
        crate::proof::shift_42_is_division(product);
    }
    product >> 42
}

/// Header bytes of a record whose payload fills `windows` windows: the
/// fixed fields and `windows + 1` table entries.
#[cfg_attr(verus_keep_ghost, verus_spec(header =>
    requires windows <= 0x10_0000_0000_0000,
    ensures header == FIXED + ENTRY * (windows + 1),
))]
#[inline(always)]
pub(crate) const fn table_header(windows: u64) -> u64 {
    FIXED + (windows + 1) * ENTRY
}

/// Header bytes of a record with `payload` payload bytes under
/// `chunk_len`-byte windows: the fixed fields and a chunk table of
/// `ceil(payload / chunk_len) + 1` entries, an upper bound on the windows a
/// payload of that length can overlap.
#[cfg_attr(verus_keep_ghost, verus_spec(header =>
    requires UNIT <= chunk_len,
    ensures header == crate::proof::header(payload as int, chunk_len as int),
))]
#[inline(always)]
pub(crate) const fn header_bytes(payload: u64, chunk_len: u64) -> u64 {
    #[cfg(verus_keep_ghost)]
    proof! {
        crate::proof::header_bounds(payload as int, chunk_len as int);
    }
    table_header(ceiling(payload, chunk_len))
}

/// A record's header bytes, the window that holds its first payload byte,
/// and the count of windows that hold a payload byte, for `payload` bytes
/// under `chunk_len`-byte windows.
///
/// Window `k` is record bytes `[k * chunk_len, (k + 1) * chunk_len)` and the
/// payload starts at the header's end. An empty payload has a count of 0.
/// A header reaches `chunk_len` only for payloads longer than
/// `(chunk_len / 4 - 29) * chunk_len` bytes; every payload of at most that
/// length has first window 0.
#[cfg_attr(verus_keep_ghost, verus_spec(counts =>
    requires
        0 < chunk_len < 0x1_0000_0000,
        chunk_len % UNIT == 0,
        payload < PAYLOAD_BOUND,
    ensures
        ({
            let (header, first, count) = counts;
            let entries = (header - FIXED) / (ENTRY as int);
            &&& header == crate::proof::header(payload as int, chunk_len as int)
            &&& header == FIXED + ENTRY * entries
            &&& entries >= 1
            &&& (entries - 1) * chunk_len >= payload
            &&& (entries == 1 || (entries - 2) * chunk_len < payload)
            &&& first * chunk_len <= header < (first + 1) * chunk_len
            &&& count <= entries
            &&& (count == 0) == (payload == 0)
            &&& (count > 0 ==> (first + count - 1) * chunk_len < header + payload
                <= (first + count) * chunk_len)
            &&& (count > 0 ==> count == crate::proof::ceiling(header + payload, chunk_len as int) - first)
            &&& header < 0x1_0000_0000
        }),
))]
#[inline(always)]
pub(crate) fn extent_counts(payload: u64, chunk_len: u64) -> (u64, u64, u64) {
    let header = header_bytes(payload, chunk_len);
    #[cfg(verus_keep_ghost)]
    proof! {
        crate::proof::header_bounds(payload as int, chunk_len as int);
        crate::proof::ceiling_below(payload as int, chunk_len as int);
        if header < chunk_len {
            vstd::arithmetic::div_mod::lemma_basic_div(header as int, chunk_len as int);
        }
        crate::proof::extent_counts_hold(payload as int, chunk_len as int, header as int, header as int / chunk_len as int);
    }
    let last = (header + payload - 1) / chunk_len;
    // The `header < chunk_len` branch saves the first window's division.
    let (first, count) = if header < chunk_len {
        (0, last + 1)
    } else {
        let first = header / chunk_len;
        (first, last - first + 1)
    };
    let count = if payload == 0 { 0 } else { count };
    (header, first, count)
}

/// [`extent_counts`]' count of windows that hold a payload byte, computed
/// from the table entries of a `header` that equals
/// `header_bytes(payload, chunk_len)` and ends inside window 0.
///
/// The header's `q + 1` entries give `q = ceil(payload / chunk_len)`, so a
/// nonempty payload lies in `q` windows, or in `q + 1` when
/// `header + payload` exceeds `q * chunk_len`.
#[cfg_attr(verus_keep_ghost, verus_spec(count =>
    requires
        UNIT <= chunk_len < 0x1_0000_0000,
        payload < PAYLOAD_BOUND,
        header == crate::proof::header(payload as int, chunk_len as int),
        header < chunk_len,
    ensures
        (count == 0) == (payload == 0),
        count > 0 ==> (count - 1) * chunk_len < header + payload <= count * chunk_len,
        count > 0 ==> count == crate::proof::ceiling(header + payload, chunk_len as int),
))]
#[inline(always)]
pub(crate) fn local_count(payload: u64, chunk_len: u64, header: u64) -> u64 {
    #[cfg(verus_keep_ghost)]
    proof! {
        crate::proof::local_count_holds(payload as int, chunk_len as int, header as int);
    }
    let q = (header - FIXED - ENTRY) / ENTRY;
    if payload == 0 {
        0
    } else {
        q + (header + payload > q * chunk_len) as u64
    }
}

/// The payload length of a record `record_len` bytes long under
/// `chunk_len`-byte windows, or `None` when no payload length gives that
/// record length. `header_bytes(P) + P` grows strictly with `P`, by
/// `chunk_len + ENTRY` bytes per table entry, so a record length names at
/// most one payload length.
#[cfg_attr(verus_keep_ghost, verus_spec(named =>
    requires UNIT <= chunk_len < 0x1_0000_0000,
    ensures
        forall|p: u64| #![trigger crate::proof::record_len(p as int, chunk_len as int)]
            crate::proof::record_len(p as int, chunk_len as int) == record_len ==> named == Some(p),
        named matches Some(p) ==> crate::proof::record_len(p as int, chunk_len as int) == record_len,
))]
pub(crate) fn payload_of(record_len: u64, chunk_len: u64) -> Option<u64> {
    let fixed = FIXED + ENTRY;
    if record_len < fixed {
        return None;
    }
    let rest = record_len - fixed;
    let entries = ceiling(rest, chunk_len + ENTRY);
    #[cfg(verus_keep_ghost)]
    proof! {
        crate::proof::entries_fit(rest as int, chunk_len as int);
        crate::proof::payload_names(record_len as int, chunk_len as int);
    }
    if rest < entries * ENTRY {
        return None;
    }
    let payload = rest - entries * ENTRY;
    #[cfg(verus_keep_ghost)]
    proof! {
        crate::proof::header_fits(payload as int, chunk_len as int, entries as int);
    }
    if header_bytes(payload, chunk_len) + payload == record_len {
        Some(payload)
    } else {
        None
    }
}
