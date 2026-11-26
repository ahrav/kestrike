//! Record configuration and the layout of one record: its header bytes, then metadata, then body, padded once to the unit.
//!
//! A record's payload is the part of its object's payload, metadata followed by body, that its extent covers: `payload_len = metadata_len + body_len` bytes for an object of one extent. It starts directly after the header's `header_bytes`.
//! `header_bytes` depends on the payload length under the configured `chunk_len`: the fixed fields plus a chunk table of `ceil(payload_len / chunk_len) + 1` entries, an upper bound on the record-aligned windows a payload of that length can overlap.
//! Window `k` is record bytes `[k * chunk_len, (k + 1) * chunk_len)`; chunk `i` covers the payload bytes of the `i`-th window that holds a payload byte, so every chunk lies in one window and every chunk boundary after the first lies at a multiple of `chunk_len` from the record start.
//! Table entries past `chunk_count` are zero.
//! The record spans `ceil((header_bytes + payload_len) / IO_UNIT)` units; the tail past the last payload byte is padding.

use std::ops::Range;

use super::super::layout::IO_UNIT;
pub(crate) use super::arithmetic::header_bytes;
use super::arithmetic::{self, ENTRY, FIXED, table_header};

/// [`arithmetic::FIXED`] as a byte offset.
pub(crate) const CHUNK_TABLE: usize = FIXED as usize;

/// [`arithmetic::ENTRY`] as a byte count.
pub(crate) const CRC_BYTES: usize = ENTRY as usize;

/// The end, in bytes from the record start, of the window that holds the
/// last header byte and the first payload byte of a record whose header is
/// `header` bytes under `chunk_len`-byte windows: `(floor(header /
/// chunk_len) + 1) * chunk_len`. `chunk_len` is positive.
pub(crate) const fn first_window_end(header: u64, chunk_len: u64) -> u64 {
    (header / chunk_len + 1) * chunk_len
}

const UNIT: u64 = arithmetic::UNIT;

// The verified arithmetic divides by its own unit, so it is the device's.
const _: () = assert!(arithmetic::UNIT == IO_UNIT as u64);

/// Record parameters, each required: the length of every record-aligned window, and so of every chunk but the first and last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordConfig {
    pub chunk_len: u32,
}

/// A [`RecordConfig`] that passed [`RecordConfig::validate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidRecordConfig {
    chunk_len: u32,
    /// [`arithmetic::reciprocal`] of `chunk_len / IO_UNIT`, the multiplier
    /// [`windows`](Self::windows) multiplies its unit count by.
    reciprocal: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordConfigError {
    ZeroChunkLen,
    /// `chunk_len` is not a multiple of [`IO_UNIT`].
    ChunkLenNotUnitMultiple {
        chunk_len: u32,
    },
}

/// Where each part of one record lies, derived from its lengths and a validated configuration.
///
/// The record is one extent of its object: `metadata_len` and `body_len` are the whole object's, and the record's own payload is the `payload_len` bytes of the object's payload the extent covers, all of it for an object of one extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordLayout {
    metadata_len: u32,
    body_len: u32,
    payload_len: u64,
    chunk_len: u32,
    chunk_count: u32,
    header_bytes: u32,
    /// The window that holds the first payload byte: `header_bytes / chunk_len`.
    first_window: u32,
}

impl RecordConfig {
    /// Accepts a positive `chunk_len` that is a multiple of [`IO_UNIT`].
    ///
    /// # Errors
    ///
    /// `ZeroChunkLen`, then `ChunkLenNotUnitMultiple`.
    pub fn validate(&self) -> Result<ValidRecordConfig, RecordConfigError> {
        if self.chunk_len == 0 {
            return Err(RecordConfigError::ZeroChunkLen);
        }
        if !u64::from(self.chunk_len).is_multiple_of(UNIT) {
            return Err(RecordConfigError::ChunkLenNotUnitMultiple {
                chunk_len: self.chunk_len,
            });
        }
        Ok(ValidRecordConfig {
            chunk_len: self.chunk_len,
            reciprocal: arithmetic::reciprocal(u64::from(self.chunk_len) / UNIT),
        })
    }
}

impl ValidRecordConfig {
    pub fn chunk_len(&self) -> u32 {
        self.chunk_len
    }

    /// `ceil(bytes / chunk_len)`, for `bytes` below `2^33`, which holds every
    /// payload of two `u32` lengths, by [`arithmetic::windows`]' multiply-shift.
    #[inline(always)]
    pub(crate) fn windows(&self, bytes: u64) -> u64 {
        debug_assert!(bytes < arithmetic::PAYLOAD_BOUND);
        arithmetic::windows(bytes, u64::from(self.chunk_len), self.reciprocal)
    }

    /// [`header_bytes`] of a payload of `payload_len` bytes, below `2^33`,
    /// under this configuration's window.
    #[inline(always)]
    pub(crate) fn header_bytes(&self, payload_len: u64) -> u64 {
        table_header(self.windows(payload_len))
    }

    /// The layout [`layout`](Self::layout) derives for these lengths, given
    /// the record's [`header_bytes`] as `header`, which is shorter than
    /// `chunk_len` so the header ends inside window 0. Every local header
    /// meets this: the configuration's compile-time check bounds it below one
    /// unit, the shortest window. Debug builds assert both conditions. The
    /// count is [`arithmetic::local_count`]'s.
    #[inline(always)]
    pub(crate) fn local_layout(
        &self,
        metadata_len: u32,
        body_len: u32,
        header: u64,
    ) -> RecordLayout {
        let payload = u64::from(metadata_len) + u64::from(body_len);
        let chunk_len = u64::from(self.chunk_len);
        debug_assert_eq!(header, header_bytes(payload, chunk_len));
        debug_assert!(header < chunk_len);
        let chunk_count = arithmetic::local_count(payload, chunk_len, header);
        RecordLayout {
            metadata_len,
            body_len,
            payload_len: payload,
            chunk_len: self.chunk_len,
            chunk_count: chunk_count as u32,
            header_bytes: header as u32,
            first_window: 0,
        }
    }

    /// The layout of a record with `metadata_len` metadata and `body_len` body bytes.
    pub fn layout(&self, metadata_len: u32, body_len: u32) -> RecordLayout {
        let payload = u64::from(metadata_len) + u64::from(body_len);
        self.extent_layout(metadata_len, body_len, payload)
    }

    /// The layout of one extent's record of an object with `metadata_len` metadata and `body_len` body bytes, whose own payload is `payload` bytes of the object's.
    pub(crate) fn extent_layout(
        &self,
        metadata_len: u32,
        body_len: u32,
        payload: u64,
    ) -> RecordLayout {
        let (header, first_window, chunk_count) =
            arithmetic::extent_counts(payload, u64::from(self.chunk_len));
        RecordLayout {
            metadata_len,
            body_len,
            payload_len: payload,
            chunk_len: self.chunk_len,
            chunk_count: chunk_count as u32,
            header_bytes: header as u32,
            first_window: first_window as u32,
        }
    }

    /// The payload length of a record `record_len` bytes long, or `None` when
    /// no payload length gives that record length: [`arithmetic::payload_of`].
    pub(crate) fn payload_of(&self, record_len: u64) -> Option<u64> {
        arithmetic::payload_of(record_len, u64::from(self.chunk_len))
    }

    /// The [`RecordPricer`] for this configuration, with its stride
    /// reciprocal computed once.
    pub(crate) fn pricer(&self) -> RecordPricer {
        let stride = u64::from(self.chunk_len) + CRC_BYTES as u64;
        RecordPricer {
            config: *self,
            stride_inverse: u64::MAX / stride + 1,
        }
    }
}

/// [`ValidRecordConfig::payload_of`] with the stride division replaced by a
/// multiply by a precomputed reciprocal. Both name the same payload for
/// every record length.
///
/// Past the header's fixed part `header_bytes(0)`, a record of `e` further
/// entries holds `rest = P + 4e` bytes with `ceil(P / chunk_len) = e`, so
/// `e = ceil(rest / s)` for the stride `s = chunk_len + 4`. For `e > 0`, the
/// length names `P` exactly when `(e - 1) * chunk_len < P <= e * chunk_len`;
/// for `e == 0`, it names `P == 0`.
///
/// A `u32` multiple of 4096 keeps `chunk_len <= 2^32 - 4096`, so `s < 2^32`.
/// For `rest < 2^32`, `(rest * stride_inverse) >> 64` yields
/// `floor(rest / s)` (Lemire, Kaser and Kurz, "Faster remainder by direct
/// computation", 2019, Lemma 1 with `N = 32`); a longer `rest` takes the
/// division form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecordPricer {
    config: ValidRecordConfig,
    /// `ceil(2^64 / s)` for `s = chunk_len + CRC_BYTES`, computed as
    /// `u64::MAX / s + 1`: `s / 4 = chunk_len / 4 + 1` is odd and above one,
    /// so `s` never divides `2^64`.
    stride_inverse: u64,
}

impl RecordPricer {
    /// The payload length of a record `record_len` bytes long, or `None`
    /// when no payload length gives that record length, as
    /// [`ValidRecordConfig::payload_of`] gives it.
    pub(crate) fn payload_of(&self, record_len: u64) -> Option<u64> {
        let chunk = u64::from(self.config.chunk_len);
        let rest = record_len.checked_sub(header_bytes(0, chunk))?;
        if rest >> 32 != 0 {
            return self.config.payload_of(record_len);
        }
        let stride = chunk + CRC_BYTES as u64;
        let quotient = ((u128::from(rest) * u128::from(self.stride_inverse)) >> 64) as u64;
        let entries = quotient + u64::from(quotient * stride != rest);
        let payload = rest.checked_sub(entries * CRC_BYTES as u64)?;
        let names = if entries == 0 {
            payload == 0
        } else {
            (entries - 1) * chunk < payload && payload <= entries * chunk
        };
        names.then_some(payload)
    }

    #[cfg(test)]
    pub(super) fn stride_inverse(&self) -> u64 {
        self.stride_inverse
    }
}

impl RecordLayout {
    /// The whole object's metadata bytes.
    pub fn metadata_len(&self) -> u32 {
        self.metadata_len
    }

    /// The whole object's body bytes.
    pub fn body_len(&self) -> u32 {
        self.body_len
    }

    pub fn chunk_len(&self) -> u32 {
        self.chunk_len
    }

    /// Record-aligned windows that hold a payload byte.
    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    /// The record's own payload bytes: the object's metadata plus body for an object of one extent, else the part of them the extent covers.
    pub fn payload_len(&self) -> u64 {
        self.payload_len
    }

    /// Encoded header bytes: the fixed fields and the whole chunk table; the payload starts here.
    pub fn header_bytes(&self) -> usize {
        self.header_bytes as usize
    }

    /// Header plus payload bytes: the record's bytes before its padding.
    pub fn record_len(&self) -> u64 {
        u64::from(self.header_bytes) + self.payload_len()
    }

    /// The units the record fills: `ceil(record_len / IO_UNIT)`.
    pub fn record_units(&self) -> u64 {
        self.record_len().div_ceil(UNIT)
    }

    /// The window that holds the first payload byte.
    pub(crate) fn first_window(&self) -> u64 {
        u64::from(self.first_window)
    }

    /// The payload bytes chunk `index` covers, or `None` past the last chunk.
    pub fn chunk(&self, index: u32) -> Option<Range<u64>> {
        (index < self.chunk_count).then(|| self.chunks(index, index + 1))
    }

    /// The payload bytes chunks `from..to` cover, with `from < to <= chunk_count()`.
    pub(crate) fn chunks(&self, from: u32, to: u32) -> Range<u64> {
        let (header, chunk_len) = (u64::from(self.header_bytes), u64::from(self.chunk_len));
        let window = self.first_window();
        let start = ((window + u64::from(from)) * chunk_len).max(header);
        let end = ((window + u64::from(to)) * chunk_len).min(self.record_len());
        start - header..end - header
    }
}

/// Bounded proofs over the production record layout arithmetic.
///
/// A header that `claimed_layout` in `storage::record::header` admits has
/// the layout `extent_layout(metadata_len, body_len, p)` for its extent's
/// coverage `p`, at most `EXTENT_PAYLOAD` bytes of the whole lengths'
/// payload. Every field that layout derives, the header bytes, the first
/// window and the chunk count and ranges, depends on `p` alone, so it
/// equals `layout(0, p)`'s, one of the layouts these harnesses range over
/// through every pair of `u32` lengths; the whole lengths themselves are
/// carried, never derived from. The volume tick path checks and hands off
/// chunks by that layout, so these proofs cover every layout a verified
/// header names.
///
/// Each harness runs with `cargo kani -p kestrike --exact --harness <name>`;
/// its cover statements prove the assumptions leave the boundary cases
/// reachable, and Kani's default unwind, overflow and arithmetic checks stay
/// enabled. A proof over every admitted chunk length at once does not finish
/// within hours, so each property runs once per band of chunk lengths, in
/// units of [`IO_UNIT`]. The chunk tiling bands cover `1..2^20`, every chunk
/// length a `u32` holds. The total and record-length bands cover the low and
/// high chunk lengths and every power of two; the window-count and local
/// layout bands cover the low chunk lengths. The lengths between them are the
/// gaps `verification/kani/expected.json` declares. Each gap names the
/// contracts that close it: Verus-verified `record::arithmetic` contracts,
/// which hold at every chunk length, and for the local layout the chunk
/// tiling proof, with the trusted rows each family's `trusts` lists.
/// `layout_tests` checks every chunk length's boundary
/// payloads. `scripts/test-judge-kani.py` checks that a family's
/// bands and gaps tile `1..2^20`.
#[cfg(kani)]
mod verification {
    use super::*;

    /// One proof per band: `$name` checks `$check` over chunk lengths of
    /// `$lo..$hi` units.
    macro_rules! bands {
        ($check:ident: $($name:ident => ($lo:literal, $hi:literal)),* $(,)?) => {
            $(
                #[kani::proof]
                fn $name() {
                    $check($lo, $hi)
                }
            )*
        };
    }

    /// A validated configuration whose chunk length is `lo..hi` units.
    fn config_in(lo: u32, hi: u32) -> ValidRecordConfig {
        let units: u32 = kani::any();
        kani::assume(lo <= units && units < hi);
        let config = RecordConfig {
            chunk_len: units * UNIT as u32,
        }
        .validate();
        assert!(config.is_ok());
        config.unwrap_or_else(|_| unreachable!("asserted valid"))
    }

    /// For full `u32` metadata and body lengths, the layout is total: its
    /// header holds the fixed fields and `ceil(P / c) + 1` table entries,
    /// the first payload byte lies in window `first_window`, at most that
    /// many chunks hold payload and none when the payload is empty, and the
    /// record is the header and the payload.
    fn the_layout_is_total(lo: u32, hi: u32) {
        let config = config_in(lo, hi);
        let (metadata_len, body_len): (u32, u32) = (kani::any(), kani::any());
        let layout = config.layout(metadata_len, body_len);
        let c = u64::from(config.chunk_len());
        let payload = u64::from(metadata_len) + u64::from(body_len);
        let header = layout.header_bytes() as u64;
        let entries = (header - CHUNK_TABLE as u64) / CRC_BYTES as u64;
        let count = u64::from(layout.chunk_count());
        kani::cover!(payload == 0);
        kani::cover!(metadata_len == u32::MAX && body_len == u32::MAX);
        kani::cover!(payload > 0 && count == entries);
        kani::cover!(payload > 0 && count + 1 == entries);
        assert_eq!(header, header_bytes(payload, c));
        assert_eq!(header, CHUNK_TABLE as u64 + CRC_BYTES as u64 * entries);
        assert!(entries >= 1 && (entries - 1) * c >= payload);
        assert!(entries == 1 || (entries - 2) * c < payload);
        assert!(layout.first_window() * c <= header && header < (layout.first_window() + 1) * c);
        assert!(count <= entries);
        assert_eq!(count == 0, payload == 0);
        assert_eq!(layout.record_len(), header + payload);
    }

    /// Chunk `i` covers nonempty payload bytes inside window
    /// `first_window + i`, the chunks tile `0..P` in order from 0 to `P`,
    /// no chunk follows the last, and chunks `i..to` span from chunk `i`'s
    /// start to chunk `to - 1`'s end.
    fn the_chunks_tile_the_payload(lo: u32, hi: u32) {
        let config = config_in(lo, hi);
        let layout = config.layout(kani::any(), kani::any());
        let c = u64::from(config.chunk_len());
        let header = layout.header_bytes() as u64;
        let count = layout.chunk_count();
        assert!(layout.chunk(count).is_none());
        let index: u32 = kani::any();
        kani::assume(index < count);
        let Some(chunk) = layout.chunk(index) else {
            unreachable!("index is below the chunk count")
        };
        let window = layout.first_window() + u64::from(index);
        kani::cover!(index + 1 == count && chunk.end - chunk.start < c);
        kani::cover!(index + 1 == count && chunk.end - chunk.start == 1);
        kani::cover!(index + 1 == count && header + chunk.end == (window + 1) * c);
        kani::cover!(index > 0 && index + 1 < count);
        assert!(chunk.start < chunk.end && chunk.end <= layout.payload_len());
        assert!(header + chunk.start >= window * c);
        assert!(header + chunk.end <= (window + 1) * c);
        if index == 0 {
            assert_eq!(chunk.start, 0);
        } else {
            assert_eq!(header + chunk.start, window * c);
        }
        if index + 1 == count {
            assert_eq!(chunk.end, layout.payload_len());
        } else {
            assert_eq!(header + chunk.end, (window + 1) * c);
        }
        let to: u32 = kani::any();
        kani::assume(index < to && to <= count);
        let span = layout.chunks(index, to);
        assert_eq!(span.start, chunk.start);
        assert_eq!(span.end, layout.chunks(to - 1, to).end);
    }

    /// The record length of every layout names its payload length back.
    fn the_record_length_names_the_payload(lo: u32, hi: u32) {
        let config = config_in(lo, hi);
        let (metadata_len, body_len): (u32, u32) = (kani::any(), kani::any());
        let layout = config.layout(metadata_len, body_len);
        kani::cover!(layout.payload_len() == 0);
        kani::cover!(metadata_len == u32::MAX && body_len == u32::MAX);
        assert_eq!(
            config.payload_of(layout.record_len()),
            Some(layout.payload_len())
        );
    }

    /// `windows` is the least count of `c`-byte windows that holds `bytes`,
    /// `ceil(bytes / c)` stated as its division inequalities, for every
    /// `bytes` below `2^33`.
    fn windows_is_the_ceiling_quotient(lo: u32, hi: u32) {
        let config = config_in(lo, hi);
        let c = u64::from(config.chunk_len());
        let bytes: u64 = kani::any();
        kani::assume(bytes < 1 << 33);
        let windows = config.windows(bytes);
        kani::cover!(bytes == 0);
        kani::cover!(bytes == 2 * u64::from(u32::MAX));
        kani::cover!(bytes > 0 && windows * c == bytes);
        kani::cover!(windows > 1 && (windows - 1) * c + 1 == bytes);
        kani::cover!(windows * c == bytes + 1);
        assert!(windows <= (1 << 33) / UNIT);
        assert!(windows * c >= bytes);
        assert!(windows == 0 || (windows - 1) * c < bytes);
    }

    /// For any `u32` lengths whose correct header is shorter than `c`, the
    /// local layout equals the one the division rule derives: the header
    /// of `q + 1` table entries for the least `q` with `q * c >= P`, the
    /// first window 0, the record of header and payload, the chunk count
    /// of windows up to the one holding the last payload byte, and chunk
    /// `i` the payload bytes window `i` holds.
    fn local_layout_is_the_division_layout(lo: u32, hi: u32) {
        let config = config_in(lo, hi);
        let c = u64::from(config.chunk_len());
        let (metadata_len, body_len): (u32, u32) = (kani::any(), kani::any());
        let payload = u64::from(metadata_len) + u64::from(body_len);
        let q: u64 = kani::any();
        kani::assume(q <= 1 << 22);
        kani::assume(q * c >= payload && (q == 0 || (q - 1) * c < payload));
        let header = CHUNK_TABLE as u64 + (q + 1) * CRC_BYTES as u64;
        kani::assume(header < c);
        let count: u64 = kani::any();
        kani::assume(count <= q + 1);
        kani::assume(if payload == 0 {
            count == 0
        } else {
            count > 0 && (count - 1) * c < header + payload && header + payload <= count * c
        });
        let layout = config.local_layout(metadata_len, body_len, header);
        kani::cover!(payload == 0);
        kani::cover!(metadata_len > 0 && body_len > 0);
        kani::cover!(header + CRC_BYTES as u64 == c);
        kani::cover!(payload > 0 && header + payload == count * c);
        kani::cover!(count > 1 && header + payload == (count - 1) * c + 1);
        assert_eq!(
            (layout.metadata_len(), layout.body_len(), layout.chunk_len()),
            (metadata_len, body_len, config.chunk_len())
        );
        assert_eq!(layout.header_bytes() as u64, header);
        assert_eq!(layout.first_window(), 0);
        assert_eq!(layout.payload_len(), payload);
        assert_eq!(layout.record_len(), header + payload);
        assert_eq!(u64::from(layout.chunk_count()), count);
        assert!(layout.chunk(layout.chunk_count()).is_none());
        let index: u32 = kani::any();
        kani::assume(u64::from(index) < count);
        let window = u64::from(index);
        let start = if index == 0 { 0 } else { window * c - header };
        let end = if u64::from(index) + 1 == count {
            payload
        } else {
            (window + 1) * c - header
        };
        assert_eq!(layout.chunk(index), Some(start..end));
    }

    include!("layout_kani_bands.rs");
}
