//! Checked extent geometry of one object: how many extents its payload
//! needs, which payload bytes each extent covers, and how many units each
//! extent and the whole object charge.
//!
//! An object of `L` payload bytes, metadata then body, is stored in
//! `N = max(1, ceil(L / P))` extents of at most [`EXTENT_PAYLOAD`] payload
//! bytes `P` each, in order: extent `i` covers payload bytes
//! `[i * P, min((i + 1) * P, L))`, so the extents partition `[0, L)` and an
//! empty object holds one empty extent. Each extent starts with its own
//! local header of at most [`LOCAL_HEADER_LIMIT`] bytes and charges its
//! header plus payload rounded up to whole units, at most
//! [`EXTENT_CHARGE_LIMIT`] bytes. The combined ceiling [`OBJECT_LIMIT`] of
//! 512 MiB bounds `N` by [`EXTENT_LIMIT`].
//!
//! The verifier checks these value-only functions against their contracts;
//! `layout::ObjectGeometry` applies them with the local header lengths the
//! record format derives.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// Payload bytes one extent carries: 248 KiB, which leaves a full extent's
/// header and padding inside [`EXTENT_CHARGE_LIMIT`].
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const EXTENT_PAYLOAD: u64 = 253_952;

/// The most bytes one extent charges, header and padding included: 256 KiB.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const EXTENT_CHARGE_LIMIT: u64 = 262_144;

/// The most bytes one extent's local header, chunk table included, spans.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const LOCAL_HEADER_LIMIT: u64 = 4096;

/// The combined ceiling on an object's metadata plus body bytes: 512 MiB.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const OBJECT_LIMIT: u64 = 536_870_912;

/// Extents of an object at [`OBJECT_LIMIT`]: `ceil(OBJECT_LIMIT / EXTENT_PAYLOAD)`.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const EXTENT_LIMIT: u64 = 2115;

/// The charging granule in bytes, the device transfer unit.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const UNIT_BYTES: u64 = 4096;

/// The most units one extent spans, [`EXTENT_CHARGE_LIMIT`] in units: 64.
pub(crate) const DIRECT_UNITS: u32 = (EXTENT_CHARGE_LIMIT / UNIT_BYTES) as u32;

/// Extents an object of `len` payload bytes needs: one for an empty object,
/// otherwise the fewest that hold `len` bytes at [`EXTENT_PAYLOAD`] each.
#[cfg_attr(verus_keep_ghost, verus_spec(n =>
    requires len <= OBJECT_LIMIT,
    ensures
        1 <= n <= EXTENT_LIMIT,
        len <= n * EXTENT_PAYLOAD,
        n == 1 || (n - 1) * EXTENT_PAYLOAD < len,
))]
#[inline(always)]
pub(crate) fn extent_count(len: u64) -> u64 {
    let whole = len / EXTENT_PAYLOAD;
    if whole * EXTENT_PAYLOAD < len || whole == 0 {
        whole + 1
    } else {
        whole
    }
}

/// The payload bytes extent `index` of an object of `len` bytes covers, as
/// its start and end: `[index * P, min((index + 1) * P, len))`. Every extent
/// below [`extent_count`] starts at or below `len`; a coverage that starts
/// below `len` is nonempty, and none is longer than [`EXTENT_PAYLOAD`].
#[cfg_attr(verus_keep_ghost, verus_spec(span =>
    requires len <= OBJECT_LIMIT, index < EXTENT_LIMIT, index * EXTENT_PAYLOAD <= len,
    ensures
        span.0 == index * EXTENT_PAYLOAD,
        span.1 as int == vstd::math::min((index + 1) * EXTENT_PAYLOAD, len as int),
        span.0 <= span.1,
        span.0 < len ==> span.0 < span.1,
        span.1 <= span.0 + EXTENT_PAYLOAD,
))]
#[inline(always)]
pub(crate) fn extent_span(len: u64, index: u64) -> (u64, u64) {
    let start = index * EXTENT_PAYLOAD;
    (start, (start + EXTENT_PAYLOAD).min(len))
}

/// Units one extent charges for a local header of `header` bytes and
/// `payload` payload bytes: the fewest whole units that hold both, at least
/// one, since every local header holds its fixed fields, and at most
/// [`EXTENT_CHARGE_LIMIT`] bytes.
#[cfg_attr(verus_keep_ghost, verus_spec(units =>
    requires 0 < header <= LOCAL_HEADER_LIMIT, payload <= EXTENT_PAYLOAD,
    ensures
        1 <= units,
        header + payload <= units * UNIT_BYTES,
        (units - 1) * UNIT_BYTES < header + payload,
        units * UNIT_BYTES <= EXTENT_CHARGE_LIMIT,
))]
#[inline(always)]
pub(crate) fn extent_units(header: u64, payload: u64) -> u64 {
    let bytes = header + payload;
    let whole = bytes / UNIT_BYTES;
    if whole * UNIT_BYTES < bytes {
        whole + 1
    } else {
        whole
    }
}

/// Units an object of `extents` extents charges when every extent but the
/// last charges `full` units and the last charges `last`.
#[cfg_attr(verus_keep_ghost, verus_spec(total =>
    requires
        1 <= extents <= EXTENT_LIMIT,
        full * UNIT_BYTES <= EXTENT_CHARGE_LIMIT,
        last * UNIT_BYTES <= EXTENT_CHARGE_LIMIT,
    ensures total == (extents - 1) * full + last,
))]
#[inline(always)]
pub(crate) fn object_units(extents: u64, full: u64, last: u64) -> u64 {
    #[cfg(verus_keep_ghost)]
    proof! {
        assert((extents - 1) * full <= (EXTENT_LIMIT - 1) * (EXTENT_CHARGE_LIMIT / UNIT_BYTES))
            by (nonlinear_arith)
            requires
                1 <= extents <= EXTENT_LIMIT,
                full * UNIT_BYTES <= EXTENT_CHARGE_LIMIT;
    }
    (extents - 1) * full + last
}

/// The device byte where `len` bytes at byte `offset` of payload unit
/// `start_unit` begin, on a volume of `volume_units` units whose first
/// `metadata_units` hold recovery metadata: `(metadata_units + start_unit)
/// * UNIT_BYTES + offset`, or `None` unless `start_unit` names a payload
/// unit and the whole range ends at or before the volume's last byte. Every
/// range it accepts lies in the payload bytes
/// `[metadata_units * UNIT_BYTES, volume_units * UNIT_BYTES)`.
#[cfg_attr(verus_keep_ghost, verus_spec(start =>
    requires metadata_units < volume_units <= 0x20_0000_0000,
    ensures
        start matches Some(s) ==> {
            &&& s == (metadata_units + start_unit) * UNIT_BYTES + offset
            &&& metadata_units * UNIT_BYTES <= s
            &&& s + len <= volume_units * UNIT_BYTES
        },
        start is None <==> !(start_unit < volume_units - metadata_units
            && (metadata_units + start_unit) * UNIT_BYTES + offset + len <= volume_units * UNIT_BYTES),
))]
#[inline(always)]
pub(crate) fn payload_device_start(
    metadata_units: u64,
    volume_units: u64,
    start_unit: u64,
    offset: u64,
    len: u32,
) -> Option<u64> {
    if start_unit >= volume_units - metadata_units {
        return None;
    }
    let room = (volume_units - metadata_units - start_unit) * UNIT_BYTES;
    if offset > room || len as u64 > room - offset {
        return None;
    }
    Some((metadata_units + start_unit) * UNIT_BYTES + offset)
}
