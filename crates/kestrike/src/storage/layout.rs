//! Checked byte layout of one metadata/body allocation, the extents its
//! payload needs and the units they charge.
//!
//! [`ObjectGeometry`] is the one source of an object's extent count, each
//! extent's payload coverage, local header length and charge, and the
//! object's total charge: the `geometry` module's checked arithmetic over
//! the local header lengths the record format derives. An allocation's
//! extent holds its record: the header's bytes, then metadata, then body,
//! padded once to a whole [`IO_UNIT`]. The header's length depends on the
//! payload length and the window length alone ([`ValidRecordConfig::layout`]),
//! so every byte offset is known when the extent is reserved; the layout
//! keeps that [`RecordLayout`], built by `ValidRecordConfig::local_layout`
//! from the geometry's header and equal to [`ValidRecordConfig::layout`]'s
//! for the same lengths.
//! The body follows the metadata immediately. An empty allocation still
//! carries its header and spans one unit, so its charge is always positive.
//! A layout describes one extent's record, at most 256 KiB, so every offset
//! into it fits `isize::MAX`. [`AllocationLayout::new`] lays out an object
//! whose geometry is one extent and refuses one that needs more with
//! [`LayoutError::MultipleExtents`]; [`AllocationLayout::of_extent`] lays
//! out one extent's record of an object of several, whose `payload()` is the
//! whole object's.

use std::ops::Range;

use super::geometry::{
    EXTENT_LIMIT, EXTENT_PAYLOAD, OBJECT_LIMIT, extent_count, extent_span, extent_units,
    object_units,
};
use super::record::{RecordLayout, ValidRecordConfig};

/// Device transfer unit and the extent allocator's granule; every buffer
/// length and every allocation charge is a multiple of 4096 bytes.
pub const IO_UNIT: usize = 4096;

/// The smallest device block a device geometry admits; device range lengths are whole sectors, so a read can end at its record's last device block.
pub const SECTOR: usize = 512;

/// `record_len` treats `tail == 0` as a full `IO_UNIT` and panics when `units == 0`.
#[inline(always)]
pub(crate) fn record_len(units: u32, tail: u16) -> u64 {
    assert!(units >= 1, "a held record's locator spans no unit");
    let unit = IO_UNIT as u64;
    let last = match u64::from(tail) {
        0 => unit,
        tail => tail,
    };
    (u64::from(units) - 1) * unit + last
}

/// Why a metadata/body request cannot be laid out.
///
/// Each variant is a distinct refusal; none mutates any state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    /// A length was not known. Final storage requires known bounded lengths.
    UnknownLength,
    /// `metadata_len` exceeds the configured metadata cap `Mmax`.
    MetadataTooLarge { len: usize, cap: usize },
    /// `body_len` exceeds the configured body cap `Bmax`.
    BodyTooLarge { len: usize, cap: usize },
    /// A length does not fit the header's 32-bit length field.
    CapacityOverflow,
    /// The object's geometry needs `extents` extents, and the one-extent
    /// layout holds one; a fill reservation returns it for such an object
    /// only on a volume without a sequence arena.
    MultipleExtents { extents: u32 },
}

/// The ordered extents of one object of `len` payload bytes under a
/// validated record format: `N = max(1, ceil(len / P))` extents, extent `i`
/// covering payload bytes `[i * P, min((i + 1) * P, len))` behind its own
/// local header of `header_bytes(payload_i, chunk_len)` bytes, and charging
/// that header plus its payload in whole units. The geometry holds the
/// record format and sizes each header with `ValidRecordConfig::header_bytes`,
/// the format's precomputed reciprocal division.
///
/// Only [`ObjectGeometry::new`] constructs one, and it refuses a length past
/// [`OBJECT_LIMIT`], so every value has at most [`EXTENT_LIMIT`] extents.
/// Every local header fits [`LOCAL_HEADER_LIMIT`](super::geometry::LOCAL_HEADER_LIMIT)
/// and is shorter than one unit, so it ends inside its record's first window,
/// under every validated record format: configuration checks at compile time
/// the header of a full extent under the shortest window, one unit, and the
/// header grows with the payload and shrinks with the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ObjectGeometry {
    len: u64,
    record: ValidRecordConfig,
    extents: u64,
}

impl ObjectGeometry {
    /// The geometry of an object of `len` payload bytes, or `None` when
    /// `len` exceeds [`OBJECT_LIMIT`].
    #[inline]
    pub(crate) fn new(len: u64, record: &ValidRecordConfig) -> Option<Self> {
        (len <= OBJECT_LIMIT).then(|| {
            let extents = extent_count(len);
            debug_assert!(extents <= EXTENT_LIMIT);
            Self {
                len,
                record: *record,
                extents,
            }
        })
    }

    /// Extents the object needs, at least one.
    #[inline]
    pub fn extents(&self) -> u32 {
        self.extents as u32
    }

    /// The payload bytes extent `index` covers.
    ///
    /// # Panics
    ///
    /// If `index` is not below [`extents`](Self::extents).
    #[inline]
    pub fn coverage(&self, index: u32) -> Range<u64> {
        let index = self.checked(index);
        let (start, end) = extent_span(self.len, index);
        start..end
    }

    /// Bytes of extent `index`'s local header: its fixed fields and a chunk
    /// table sized for the extent's own payload.
    ///
    /// # Panics
    ///
    /// As for [`extent`](Self::extent).
    #[inline]
    pub fn header_bytes(&self, index: u32) -> u64 {
        self.extent(index).header
    }

    /// Units extent `index` charges: its local header plus its payload,
    /// rounded up to whole units.
    ///
    /// # Panics
    ///
    /// As for [`extent`](Self::extent).
    #[inline]
    pub fn units(&self, index: u32) -> u64 {
        self.extent(index).units
    }

    /// Extent `index`'s payload coverage, local header bytes and charge.
    ///
    /// # Panics
    ///
    /// As for [`coverage`](Self::coverage), or if the local header exceeds
    /// [`LOCAL_HEADER_LIMIT`](super::geometry::LOCAL_HEADER_LIMIT), which
    /// configuration's compile-time check excludes.
    #[inline]
    pub fn extent(&self, index: u32) -> ExtentGeometry {
        let coverage = self.coverage(index);
        let payload = coverage.end - coverage.start;
        let header = self.record.header_bytes(payload);
        assert!(
            header <= super::geometry::LOCAL_HEADER_LIMIT,
            "a local header past the limit validation checks"
        );
        ExtentGeometry {
            coverage,
            header,
            units: extent_units(header, payload),
        }
    }

    /// Units the whole object charges: every extent's charge summed. Every
    /// extent but the last carries a full [`EXTENT_PAYLOAD`], so each of
    /// those charges the first extent's units.
    #[inline]
    pub fn total_units(&self) -> u64 {
        let last = self.extents() - 1;
        let full = if last == 0 { 0 } else { self.units(0) };
        object_units(self.extents, full, self.units(last))
    }

    #[inline]
    fn checked(&self, index: u32) -> u64 {
        let index = u64::from(index);
        assert!(
            index < self.extents,
            "an extent index past the object's extents"
        );
        index
    }
}

/// One extent of an [`ObjectGeometry`]: the payload bytes it covers, its
/// local header's bytes and the whole units the header and payload charge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExtentGeometry {
    /// The object payload bytes the extent covers.
    pub coverage: Range<u64>,
    /// Bytes of the extent's local header.
    pub header: u64,
    /// Units the extent charges: the header plus the covered payload,
    /// rounded up to whole units.
    pub units: u64,
}

impl ExtentGeometry {
    /// Payload bytes the extent covers.
    pub fn payload(&self) -> u64 {
        self.coverage.end - self.coverage.start
    }

    /// Bytes of the extent's record: its local header and its payload.
    pub fn record_len(&self) -> u64 {
        self.header + self.payload()
    }
}

/// A checked layout of one allocation's record.
///
/// The crate-private `AllocationLayout::new` lays out an object whose
/// geometry is one extent, so its `units()` is that extent's charge as the
/// object geometry computes it, the smallest positive unit count holding the
/// header and payload. `AllocationLayout::of_extent` lays out one extent's
/// record within a multi-extent object and charges that record's units. The
/// 8-byte alignment pads the 28 bytes of fields to 32, four whole 8-byte
/// words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(align(8))]
pub struct AllocationLayout {
    record: RecordLayout,
    /// The record's units: the geometry's charge of the one extent.
    units: u32,
}

impl AllocationLayout {
    /// Lays out the header `record` sizes, then `metadata_len` then `body_len` bytes, in whole units.
    ///
    /// # Errors
    ///
    /// - `UnknownLength` if either length is `None`.
    /// - `MetadataTooLarge` if `metadata_len > metadata_cap`, checked before
    ///   the body so it is reported even when the body also exceeds its cap.
    /// - `BodyTooLarge` if `body_len > body_cap`.
    /// - `CapacityOverflow` if either length exceeds `u32::MAX`.
    /// - `MultipleExtents` if the payload needs more than one extent.
    #[inline(always)]
    pub(crate) fn new(
        metadata_len: Option<usize>,
        body_len: Option<usize>,
        metadata_cap: usize,
        body_cap: usize,
        record: &ValidRecordConfig,
    ) -> Result<Self, LayoutError> {
        let (metadata, body) = checked_lengths(metadata_len, body_len, metadata_cap, body_cap)?;
        let geometry = one_extent(metadata, body, record)?;
        // One extent: at most `EXTENT_PAYLOAD` payload bytes behind its
        // header, so the extent and every offset fit `isize::MAX`, and its
        // header is shorter than one unit, so it ends inside window 0 as
        // `local_layout` requires.
        let extent = geometry.extent(0);
        let record = record.local_layout(metadata, body, extent.header);
        // The record's units are the geometry's charge of its one extent.
        let units = record.record_units();
        debug_assert_eq!(extent.units, units);
        Ok(Self {
            record,
            units: units as u32,
        })
    }

    /// The layout of one extent's record `record` of an object of several
    /// extents, charged its record's units.
    pub(crate) fn of_extent(record: RecordLayout) -> Self {
        Self {
            units: record.record_units() as u32,
            record,
        }
    }

    /// The record layout: header bytes, lengths and chunks.
    pub(crate) fn record(&self) -> &RecordLayout {
        &self.record
    }

    pub fn metadata_len(&self) -> usize {
        self.record.metadata_len() as usize
    }

    pub fn body_len(&self) -> usize {
        self.record.body_len() as usize
    }

    /// Logical bytes: the whole object's metadata plus body, the payload the
    /// ledger counts, for an extent's layout of a sequence as for one extent.
    pub fn payload(&self) -> usize {
        self.metadata_len() + self.body_len()
    }

    /// Units the extent charges: `ceil((header_bytes + record payload) /
    /// IO_UNIT)`, which for an object of one extent is
    /// `ceil((header_bytes + metadata_len + body_len) / IO_UNIT)`.
    pub fn units(&self) -> usize {
        self.units as usize
    }
}

/// The geometry of an object of `metadata + body` payload bytes when it is
/// one extent, exactly when the length is at most [`EXTENT_PAYLOAD`]. For
/// `len > EXTENT_PAYLOAD`, `one_extent` returns `MultipleExtents` with the
/// geometry's extent count when `len <= OBJECT_LIMIT` and `div_ceil`
/// otherwise, because [`extent_count`] requires `len <= OBJECT_LIMIT`.
///
/// # Errors
///
/// `MultipleExtents` if the payload needs more than one extent.
#[inline]
fn one_extent(
    metadata: u32,
    body: u32,
    record: &ValidRecordConfig,
) -> Result<ObjectGeometry, LayoutError> {
    let len = u64::from(metadata) + u64::from(body);
    if len > EXTENT_PAYLOAD {
        let extents = ObjectGeometry::new(len, record)
            .map_or(len.div_ceil(EXTENT_PAYLOAD), |geometry| {
                u64::from(geometry.extents())
            });
        return Err(LayoutError::MultipleExtents {
            extents: extents as u32,
        });
    }
    let Some(geometry) = ObjectGeometry::new(len, record) else {
        unreachable!("one extent's payload lies within OBJECT_LIMIT");
    };
    debug_assert_eq!(geometry.extents(), 1);
    Ok(geometry)
}

/// The geometry of an object of `metadata_len` and `body_len` bytes under
/// the caps, of any extent count up to the object ceiling.
///
/// # Errors
///
/// `UnknownLength`, `MetadataTooLarge`, `BodyTooLarge` or
/// `CapacityOverflow`, as for [`AllocationLayout::new`].
///
/// # Panics
///
/// If the summed length passes the object limit, which validated caps
/// exclude.
pub(crate) fn object_geometry(
    metadata_len: Option<usize>,
    body_len: Option<usize>,
    metadata_cap: usize,
    body_cap: usize,
    record: &ValidRecordConfig,
) -> Result<ObjectGeometry, LayoutError> {
    let (metadata, body) = checked_lengths(metadata_len, body_len, metadata_cap, body_cap)?;
    let len = u64::from(metadata) + u64::from(body);
    Ok(ObjectGeometry::new(len, record)
        .expect("validated caps bound an object by the object limit"))
}

#[inline]
fn checked_lengths(
    metadata_len: Option<usize>,
    body_len: Option<usize>,
    metadata_cap: usize,
    body_cap: usize,
) -> Result<(u32, u32), LayoutError> {
    let metadata_len = metadata_len.ok_or(LayoutError::UnknownLength)?;
    let body_len = body_len.ok_or(LayoutError::UnknownLength)?;
    if metadata_len > metadata_cap {
        return Err(LayoutError::MetadataTooLarge {
            len: metadata_len,
            cap: metadata_cap,
        });
    }
    if body_len > body_cap {
        return Err(LayoutError::BodyTooLarge {
            len: body_len,
            cap: body_cap,
        });
    }
    let (Ok(metadata), Ok(body)) = (u32::try_from(metadata_len), u32::try_from(body_len)) else {
        return Err(LayoutError::CapacityOverflow);
    };
    Ok((metadata, body))
}

#[cfg(test)]
mod tests {
    use super::super::record::{RecordConfig, header_bytes};
    use super::*;

    const CHUNK: u32 = 8192;

    fn config() -> ValidRecordConfig {
        RecordConfig { chunk_len: CHUNK }.validate().unwrap()
    }

    fn layout(m: usize, b: usize) -> AllocationLayout {
        layout_under(m, b, &config())
    }

    fn layout_under(m: usize, b: usize, record: &ValidRecordConfig) -> AllocationLayout {
        AllocationLayout::new(Some(m), Some(b), usize::MAX, usize::MAX, record).unwrap()
    }

    fn metadata_offset(l: &AllocationLayout) -> usize {
        l.record().header_bytes()
    }

    fn extent(l: &AllocationLayout) -> usize {
        l.units() * IO_UNIT
    }

    fn fields(l: &AllocationLayout) -> (usize, usize, usize, usize, usize) {
        (
            metadata_offset(l),
            l.metadata_len(),
            metadata_offset(l) + l.metadata_len(),
            l.body_len(),
            extent(l),
        )
    }

    /// The header precedes the metadata and the body follows the metadata
    /// with no gap; a table of `ceil(L / chunk_len) + 1` entries sizes it.
    #[test]
    fn the_header_comes_first_and_the_body_follows_the_metadata() {
        assert_eq!(fields(&layout(3, 5)), (112 + 4, 3, 116 + 3, 5, IO_UNIT));
        assert_eq!(fields(&layout(1, 0)), (116, 1, 117, 0, IO_UNIT));
        assert_eq!(layout(3, 5).payload(), 8);
        assert_eq!(metadata_offset(&layout(0, 0)), 112);
        let two_windows = layout(0, CHUNK as usize + 1);
        assert_eq!(metadata_offset(&two_windows), 108 + 3 * 4);
        assert_eq!(header_bytes(0, 4096), 112);
        assert_eq!(header_bytes(4096, 4096), 116);
        assert_eq!(header_bytes(4097, 4096), 120);
    }

    /// Around every unit and window boundary the header's length adds, the
    /// layout's offsets, extent and units match the header-size rule applied
    /// by hand.
    #[test]
    fn offsets_and_extent_follow_the_header_rule_across_boundaries() {
        let c = CHUNK as usize;
        let edges = [
            0,
            1,
            IO_UNIT - 116,
            IO_UNIT - 112,
            c - 116,
            c - 115,
            c,
            c + 1,
            2 * c - 120,
        ];
        for edge in edges {
            for payload in edge.saturating_sub(2)..edge + 3 {
                let metadata = payload.min(3);
                let l = layout(metadata, payload - metadata);
                let header = header_bytes(payload as u64, u64::from(CHUNK)) as usize;
                let bytes = (header + payload).next_multiple_of(IO_UNIT);
                assert_eq!(
                    (metadata_offset(&l), extent(&l), l.units()),
                    (header, bytes, bytes / IO_UNIT),
                    "payload {payload}"
                );
            }
        }
    }

    /// The extent is the header plus payload rounded up to a whole unit.
    #[test]
    fn extent_rounds_header_and_payload_up_to_whole_units() {
        let header = metadata_offset(&layout(0, 0));
        assert_eq!(extent(&layout(0, IO_UNIT - 116)), IO_UNIT);
        assert_eq!(layout(0, IO_UNIT - 115).units(), 2);
        assert_eq!(layout(IO_UNIT, 0).units(), 2);
        assert_eq!(layout(0, 0).units(), 1);
        assert_eq!(header, 112);
    }

    #[test]
    fn caps_are_inclusive_and_checked_independently() {
        let ok = AllocationLayout::new(Some(4), Some(9), 4, 9, &config()).unwrap();
        assert_eq!(fields(&ok), (116, 4, 120, 9, IO_UNIT));
        assert_eq!(
            AllocationLayout::new(Some(5), Some(9), 4, 9, &config()),
            Err(LayoutError::MetadataTooLarge { len: 5, cap: 4 })
        );
        assert_eq!(
            AllocationLayout::new(Some(4), Some(10), 4, 9, &config()),
            Err(LayoutError::BodyTooLarge { len: 10, cap: 9 })
        );
        assert_eq!(
            AllocationLayout::new(Some(5), Some(10), 4, 9, &config()),
            Err(LayoutError::MetadataTooLarge { len: 5, cap: 4 })
        );
        assert_eq!(
            AllocationLayout::new(Some(1), Some(0), 0, 0, &config()),
            Err(LayoutError::MetadataTooLarge { len: 1, cap: 0 })
        );
    }

    #[test]
    fn unknown_length_is_refused_before_caps() {
        assert_eq!(
            AllocationLayout::new(None, Some(1), 0, 0, &config()),
            Err(LayoutError::UnknownLength)
        );
        assert_eq!(
            AllocationLayout::new(Some(1), None, 0, 0, &config()),
            Err(LayoutError::UnknownLength)
        );
    }

    /// A length past the header's 32-bit field is refused, and so are the
    /// widest lengths that fit it, which need more than one extent.
    #[test]
    fn a_length_past_the_header_field_is_overflow() {
        let max = u32::MAX as usize;
        let new = |m, b| AllocationLayout::new(Some(m), Some(b), usize::MAX, usize::MAX, &config());
        assert_eq!(new(max + 1, 0), Err(LayoutError::CapacityOverflow));
        assert_eq!(new(0, max + 1), Err(LayoutError::CapacityOverflow));
        let extents = (2 * max as u64).div_ceil(EXTENT_PAYLOAD) as u32;
        assert_eq!(new(max, max), Err(LayoutError::MultipleExtents { extents }));
    }

    /// Metadata and body together decide whether a layout is one extent: a
    /// payload past one extent refuses whether the extent boundary falls in
    /// the metadata or the body, including one byte past, and a payload of
    /// exactly one extent lays out in 63 units, whether the metadata or the
    /// body carries most of it.
    #[test]
    fn metadata_and_body_together_decide_one_extent() {
        let p = EXTENT_PAYLOAD as usize;
        let new = |m, b| AllocationLayout::new(Some(m), Some(b), usize::MAX, usize::MAX, &config());
        let two = Err(LayoutError::MultipleExtents { extents: 2 });
        assert_eq!(new(p - 10, 20), two);
        assert_eq!(new(p + 1, 0), two);
        assert_eq!(new(10, p - 9), two);
        assert_eq!(new(p - 10, 10).unwrap().units(), 63);
        assert_eq!(new(0, p).unwrap().units(), 63);
    }

    /// Window lengths in units: the shortest, small and uneven multiples, and
    /// the longest a `u32` `chunk_len` holds.
    const WINDOW_UNITS: [u32; 6] = [1, 2, 3, 16, 64, (1 << 20) - 1];

    /// For every one-extent payload length, with the metadata empty, short,
    /// or the whole payload, the allocation's record layout and units equal
    /// what [`ValidRecordConfig::layout`] derives under each window.
    #[test]
    fn every_one_extent_payload_lays_out_as_its_record() {
        for units in WINDOW_UNITS {
            let record = RecordConfig {
                chunk_len: units * IO_UNIT as u32,
            }
            .validate()
            .unwrap();
            for payload in 0..=EXTENT_PAYLOAD as usize {
                for metadata in [0, payload.min(64), payload] {
                    let body = payload - metadata;
                    let l = layout_under(metadata, body, &record);
                    let derived = record.layout(metadata as u32, body as u32);
                    assert_eq!(
                        (*l.record(), l.units() as u64),
                        (derived, derived.record_units()),
                        "window {units} units, payload ({metadata}, {body})"
                    );
                }
            }
        }
    }

    /// Under every validated window, the reciprocal header equals the
    /// `div_ceil` header rule at an empty payload and at each payload within
    /// `2^33 - 1` one byte either side of the first three window multiples,
    /// [`EXTENT_PAYLOAD`], the last window multiple below `2^33`, and
    /// `2^33 - 1`.
    #[test]
    fn the_reciprocal_header_matches_the_header_rule_for_every_window() {
        for units in 1..=u32::MAX / IO_UNIT as u32 {
            let record = RecordConfig {
                chunk_len: units * IO_UNIT as u32,
            }
            .validate()
            .unwrap();
            let c = u64::from(record.chunk_len());
            let top = (1u64 << 33) - 1;
            let edges = [c, 2 * c, 3 * c, EXTENT_PAYLOAD, top / c * c, top];
            for edge in edges {
                for payload in [edge - 1, edge, edge + 1].into_iter().filter(|&p| p <= top) {
                    assert_eq!(
                        record.header_bytes(payload),
                        header_bytes(payload, c),
                        "window {units} units, payload {payload}"
                    );
                }
            }
            assert_eq!(record.header_bytes(0), header_bytes(0, c));
        }
    }
}
