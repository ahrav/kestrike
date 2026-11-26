//! The checked mapping from 8192-byte wire fragments onto a read's backing response buffers.
//!
//! A read's first command starts at the record's first byte and spans `span` bytes, so its buffer carries `span - header_bytes` payload bytes; every later command carries `span` payload bytes, the last one ending at the record's end.
//! A [`FragmentGeometry`] exists only when `span >= FRAGMENT_LEN` and the first command holds every window through the one holding the first payload byte under the largest admissible header, `(header_max / chunk + 1) * chunk` bytes, which makes every fragment intersect at most two consecutive backing buffers: a fragment that starts in buffer `k` ends in `k` or `k + 1`, because every buffer after the first holds at least one whole fragment's length, except the last, which ends at the payload's end, as the transfer's last fragment does.
//! Two consecutive backing buffers therefore hold any fragment, so a read that reserves [`BUFFERS_PER_READ`] whole backing buffers across its pending, in-flight, retained and draining custody can send every fragment from the buffers it spans.

use std::ops::Range;

use crate::storage::ReadSpan;

/// Bytes of every wire fragment except a transfer's last, which carries the exact remainder.
pub const FRAGMENT_LEN: u32 = 8192;

// Every extent before an object's last carries a whole number of
// fragments, so each fragment lies in one extent, whose buffers start with its
// own local header; the two-buffer bound holds within each extent.
const _: () = assert!(crate::storage::EXTENT_PAYLOAD.is_multiple_of(FRAGMENT_LEN as u64));

/// The most backing buffers one fragment intersects, and so the whole response buffers a network read reserves while it holds one command; a read that reads ahead reserves one more per command ahead.
pub const BUFFERS_PER_READ: u32 = 2;

/// The storage geometry a [`FragmentGeometry`] is checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeometryInputs {
    /// The record chunk and read window length; a positive multiple of 4096.
    pub record_chunk_len: u32,
    pub response_buffer_len: u32,
    pub device_max_transfer: u32,
    /// Header bytes of the largest admissible record.
    pub header_max: u32,
}

/// Why the inputs admit no geometry; the error returns them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeometryError {
    pub inputs: GeometryInputs,
    pub reason: GeometryRefusal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeometryRefusal {
    /// The chunk length is zero or not a multiple of 4096.
    ChunkLen,
    /// `floor(min(response_buffer_len, device_max_transfer) / record_chunk_len) * record_chunk_len` is below [`FRAGMENT_LEN`].
    SpanBelowFragment { span: u32 },
    /// The span is below `(header_max / record_chunk_len + 1) * record_chunk_len`, the windows through the one that holds the first payload byte under the largest header.
    HeaderFirst { needed: u64, span: u32 },
}

/// A checked fragment-to-buffer mapping: a read's commands span `span` bytes, at least one fragment's length, and its first command holds every window through the first payload byte under the largest header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentGeometry {
    inputs: GeometryInputs,
    span: u32,
    reciprocal: u128,
}

impl FragmentGeometry {
    /// Checks `inputs`, deriving the command span as the read path does.
    ///
    /// # Errors
    ///
    /// In this order: `ChunkLen`, `SpanBelowFragment`, then `HeaderFirst`; each returns `inputs`.
    pub fn new(inputs: GeometryInputs) -> Result<Self, GeometryError> {
        let refuse = |reason| Err(GeometryError { inputs, reason });
        let chunk = inputs.record_chunk_len;
        if chunk == 0 || !chunk.is_multiple_of(4096) {
            return refuse(GeometryRefusal::ChunkLen);
        }
        let read = ReadSpan::new(
            chunk,
            inputs.response_buffer_len,
            inputs.device_max_transfer,
            u64::from(inputs.header_max),
        );
        let span = read.windows() * chunk;
        if span < FRAGMENT_LEN {
            return refuse(GeometryRefusal::SpanBelowFragment { span });
        }
        if !read.holds_header() {
            return refuse(GeometryRefusal::HeaderFirst {
                needed: read.needed(),
                span,
            });
        }
        let windows = u128::from(span / 4096);
        Ok(Self {
            inputs,
            span,
            reciprocal: (1u128 << 72).div_ceil(windows),
        })
    }

    pub fn inputs(&self) -> GeometryInputs {
        self.inputs
    }

    /// Bytes one read command spans, whole windows.
    pub fn span(&self) -> u32 {
        self.span
    }

    /// The backing buffers, by command index, that payload bytes `range` of a record whose header takes `header_bytes` bytes lie in; an empty range lies in none.
    /// `header_bytes` is at most the geometry's largest header.
    pub fn buffers(&self, header_bytes: u32, range: Range<u64>) -> Range<u64> {
        debug_assert!(header_bytes <= self.inputs.header_max);
        if range.is_empty() {
            return 0..0;
        }
        let first = u64::from(self.span - header_bytes);
        let index = |offset: u64| {
            offset
                .checked_sub(first)
                .map_or(0, |later| 1 + self.spans(later))
        };
        index(range.start)..index(range.end - 1) + 1
    }

    /// The reciprocal `ceil(2^72 / (span / 4096))` [`spans`](Self::spans) multiplies by.
    #[cfg(test)]
    pub(super) fn reciprocal(&self) -> u128 {
        self.reciprocal
    }

    /// `floor(bytes / span)`. The span is a multiple of 4096, so this is `floor((bytes >> 12) / w)` for `w = span / 4096 < 2^20`, and for a dividend below `2^52` the reciprocal `ceil(2^72 / w)` gives the exact quotient as `(dividend * reciprocal) >> 72` (Lemire, Kaser and Kurz, "Faster remainder by direct computation", 2019, Lemma 1 with `N = 52` and `L = 20`, since `w <= 2^20`); the product stays below `2^124`.
    fn spans(&self, bytes: u64) -> u64 {
        ((u128::from(bytes >> 12) * self.reciprocal) >> 72) as u64
    }

    /// The payload bytes fragment `index` of a `total`-byte transfer covers; `index` is below `fragments(total)`.
    #[inline]
    pub fn fragment(index: u32, total: u64) -> Range<u64> {
        debug_assert!(u64::from(index) < Self::fragments(total));
        let start = u64::from(index) * u64::from(FRAGMENT_LEN);
        start..(start + u64::from(FRAGMENT_LEN)).min(total)
    }

    /// Fragments of a `total`-byte transfer: `ceil(total / FRAGMENT_LEN)`, zero for an empty one.
    #[inline]
    pub fn fragments(total: u64) -> u64 {
        total.div_ceil(u64::from(FRAGMENT_LEN))
    }
}

/// The byte counts below which the Kani proof checks `spans`, whose dividend is `bytes >> 12`.
#[cfg(kani)]
const QUOTIENT_PROOF_BYTES: u64 = 1 << 24;

/// Bounded proofs over the production geometry arithmetic.
///
/// Each harness runs with `cargo kani -p kestrike --exact --harness
/// <name>`; its cover statements prove the assumptions leave the boundary
/// cases reachable, and Kani's default unwind, overflow and arithmetic checks
/// stay enabled.
#[cfg(kani)]
mod verification {
    use super::*;

    /// A geometry whose span is `windows * 4096`: one-window chunks, a
    /// buffer and transfer limit equal to the span and an empty header, so
    /// [`FragmentGeometry::new`] admits every `windows` in `2..2^20`.
    fn spanning(windows: u32) -> FragmentGeometry {
        let span = windows * 4096;
        let inputs = GeometryInputs {
            record_chunk_len: 4096,
            response_buffer_len: span,
            device_max_transfer: span,
            header_max: 0,
        };
        let geometry = FragmentGeometry::new(inputs);
        assert!(geometry.is_ok());
        geometry.unwrap_or_else(|_| unreachable!("asserted admitted"))
    }

    /// The reciprocal division is exact for every admitted span, a multiple
    /// of 4096 from 8192 up with `span / 4096` below `2^20`, and every
    /// byte count below [`QUOTIENT_PROOF_BYTES`]: the span count is
    /// `bytes / span`. The search grows about 3.5 times per dividend bit, so
    /// the proof stops at 24 bits; `geometry_tests` checks Lemire's
    /// exactness bound for every admitted span, which carries the claim to
    /// every `u64` dividend.
    #[kani::proof]
    fn span_count_is_the_quotient_for_every_admitted_span() {
        let windows: u32 = kani::any();
        kani::assume((2..1 << 20).contains(&windows));
        let geometry = spanning(windows);
        let span = u64::from(geometry.span());
        let bytes: u64 = kani::any();
        kani::assume(bytes < QUOTIENT_PROOF_BYTES);
        kani::cover!(windows == 2 && bytes == QUOTIENT_PROOF_BYTES - 1);
        kani::cover!(windows == (1 << 20) - 1);
        kani::cover!(bytes > 0 && bytes.is_multiple_of(span));
        kani::cover!(bytes % span == span - 1);
        assert_eq!(span, u64::from(windows) * 4096);
        assert_eq!(geometry.spans(bytes), bytes / span);
    }

    /// One proof per band: `$name` checks the constructor over chunk lengths
    /// of `$lo..$hi` units of 4096 bytes. The bands tile `1..2^20`, and
    /// `scripts/test-judge-kani.py` checks that tiling.
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

    /// A chunk length off the 4096 multiple is refused first, whatever the
    /// other inputs, and the refusal returns them.
    #[kani::proof]
    fn the_constructor_refuses_a_chunk_length_off_the_unit() {
        let inputs = GeometryInputs {
            record_chunk_len: kani::any(),
            response_buffer_len: kani::any(),
            device_max_transfer: kani::any(),
            header_max: kani::any(),
        };
        kani::assume(inputs.record_chunk_len == 0 || inputs.record_chunk_len % 4096 != 0);
        kani::cover!(inputs.record_chunk_len == 0);
        kani::cover!(inputs.record_chunk_len == 4095);
        let refused = FragmentGeometry::new(inputs);
        assert_eq!(
            refused,
            Err(GeometryError {
                inputs,
                reason: GeometryRefusal::ChunkLen,
            })
        );
    }

    /// For a chunk length of `lo..hi` units and any buffer, transfer and
    /// header limits, the constructor admits exactly the documented
    /// geometries and names the first failed check. The span lies within one
    /// chunk length below the smaller limit, and `geometry_tests` pins it to a
    /// whole number of windows, a remainder check that would cost this proof
    /// more than a lane's budget; it admits when the
    /// span holds a fragment and a header of `header_max` bytes ends before
    /// it, so the first command holds the window of the first payload byte.
    /// Otherwise it reports the short span, or the window end `needed` the
    /// largest header requires.
    fn the_constructor_admits_exactly_the_documented_geometries(lo: u32, hi: u32) {
        let units: u32 = kani::any();
        kani::assume(lo <= units && units < hi);
        let inputs = GeometryInputs {
            record_chunk_len: units * 4096,
            response_buffer_len: kani::any(),
            device_max_transfer: kani::any(),
            header_max: kani::any(),
        };
        let chunk = u64::from(inputs.record_chunk_len);
        let limit = u64::from(inputs.response_buffer_len.min(inputs.device_max_transfer));
        let header_max = u64::from(inputs.header_max);
        let fragment = u64::from(FRAGMENT_LEN);
        let result = FragmentGeometry::new(inputs);
        kani::cover!(result.is_ok());
        kani::cover!(matches!(
            result,
            Err(GeometryError {
                reason: GeometryRefusal::SpanBelowFragment { .. },
                ..
            })
        ));
        kani::cover!(matches!(
            result,
            Err(GeometryError {
                reason: GeometryRefusal::HeaderFirst { .. },
                ..
            })
        ));
        match result {
            Ok(geometry) => {
                let span = u64::from(geometry.span());
                assert!(span <= limit && limit - span < chunk);
                assert!(span >= fragment && header_max < span);
                assert_eq!(geometry.inputs(), inputs);
            }
            Err(GeometryError {
                inputs: returned,
                reason,
            }) => {
                assert_eq!(returned, inputs);
                match reason {
                    GeometryRefusal::ChunkLen => {
                        unreachable!("a unit multiple passes the chunk check")
                    }
                    GeometryRefusal::SpanBelowFragment { span } => {
                        let span = u64::from(span);
                        assert!(span <= limit && limit - span < chunk && span < fragment);
                    }
                    GeometryRefusal::HeaderFirst { needed, span } => {
                        let span = u64::from(span);
                        assert!(span <= limit && limit - span < chunk && span >= fragment);
                        assert!(
                            header_max < needed && needed - chunk <= header_max && needed > span
                        );
                    }
                }
            }
        }
    }

    include!("geometry_kani_bands.rs");

    /// The fragments of a transfer number `ceil(total / 8192)`, for every
    /// `u64` total. Each fragment a `u32` index names starts at `index *
    /// 8192`, is nonempty and 8192 bytes long until the last, which ends at
    /// `total` with the remainder; when the count fits the frame's `u32`
    /// index and count fields, those fragments tile `0..total` in order.
    #[kani::proof]
    fn fragments_tile_the_transfer() {
        let total: u64 = kani::any();
        let count = FragmentGeometry::fragments(total);
        let len = u64::from(FRAGMENT_LEN);
        kani::cover!(total == 0);
        kani::cover!(total == u64::MAX);
        assert!(count == 0 || (count - 1) * len < total);
        assert!(u128::from(count) * u128::from(len) >= u128::from(total));
        assert!(u128::from(count) * u128::from(len) < u128::from(total) + u128::from(len));
        let index: u32 = kani::any();
        kani::assume(u64::from(index) < count);
        let fragment = FragmentGeometry::fragment(index, total);
        kani::cover!(u64::from(index) + 1 == count && fragment.end - fragment.start < len);
        kani::cover!(u64::from(index) + 1 == count && fragment.end - fragment.start == len);
        kani::cover!(u64::from(index) + 1 == count && fragment.end - fragment.start == 1);
        assert_eq!(fragment.start, u64::from(index) * len);
        assert!(fragment.start < fragment.end && fragment.end <= total);
        if u64::from(index) + 1 < count {
            assert_eq!(fragment.end, fragment.start + len);
        } else {
            assert_eq!(fragment.end, total);
        }
    }
}
