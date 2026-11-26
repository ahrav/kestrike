//! The record target's admitted geometries: a chunk length from
//! [`CHUNK_LENS`] and metadata and body lengths each from
//! [`Geometry::lengths`], selected by one geometry byte. An object of
//! such lengths spans one or two extents, so a geometry also reaches the
//! nonzero extent position.
//!
//! The geometry modes judge them against the literal parser: they mutate
//! each extent's record, raw or resealed, and judge header verification
//! and `claim_header` on every one, then the volume read of a published
//! one-extent object under the geometry's chunk length and lengths. A
//! refusal the literal parser names with the same fields is a pass, so
//! malformed bytes stay in the corpus.

use super::super::IO_UNIT;
use super::super::config::StorageConfig;
use super::super::owner::Storage;
use super::super::publish_tests::{PAGE, index_config, storage_config, storage_from};
use super::super::test_platform::TestPlatform;
use super::super::writable_tests::bytes as content;
use super::claim_fuzz_tests::judge_claim;
use super::fuzz_tests::{
    ACCEPTING, EXTENT_BYTES, Expected, IDENTITY, REFUSING, apply, coverage, disagree, header_len,
    literal, read_back_from, read_bytes, read_disagreement, verified,
};
use super::header::encode_header;
use super::{Crc32c, ExtentPosition, RecordConfig};
use crate::sim::fuzz::Class;

/// The record chunk lengths the target exercises: 1, 2, 4 and 16 units,
/// each an admitted positive multiple of the unit.
pub(crate) const CHUNK_LENS: [u32; 4] = [4096, 8192, 16384, 65536];

/// One admitted geometry: the record chunk length and the object's
/// metadata and body lengths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Geometry {
    pub(crate) chunk_len: u32,
    pub(crate) metadata: u32,
    pub(crate) body: u32,
}

impl Geometry {
    /// The lengths each of metadata and body takes under chunk length `c`:
    /// empty, one byte, one window and one byte either side of it, one
    /// byte past two windows, and one byte short of three.
    pub(crate) fn lengths(c: u32) -> [u32; 7] {
        [0, 1, c - 1, c, c + 1, 2 * c + 1, 3 * c - 1]
    }

    /// The geometry `byte` selects: its low two bits the chunk length, the
    /// next three the metadata length and the top three the body length,
    /// each length index taken modulo seven.
    pub(crate) fn of(byte: u8) -> Self {
        let chunk_len = CHUNK_LENS[usize::from(byte & 3)];
        let lengths = Self::lengths(chunk_len);
        Self {
            chunk_len,
            metadata: lengths[usize::from(byte >> 2 & 7) % 7],
            body: lengths[usize::from(byte >> 5) % 7],
        }
    }

    /// The object's extents: one, or two when its payload passes one
    /// extent's 248 KiB.
    pub(crate) fn extents(&self) -> u32 {
        (u64::from(self.metadata) + u64::from(self.body))
            .div_ceil(EXTENT_BYTES)
            .max(1) as u32
    }

    /// The payload bytes of extent `index`'s record.
    pub(crate) fn coverage(&self, index: u32) -> u64 {
        coverage(self.metadata, self.body, index).expect("an extent of the object")
    }

    /// The header bytes and the record bytes before padding of extent
    /// `index`, by the format's arithmetic.
    pub(crate) fn record_len(&self, index: u32) -> (u64, u64) {
        let payload = self.coverage(index);
        let header = header_len(payload, self.chunk_len);
        (header, header + payload)
    }

    /// Extent `index`'s valid record, padded to its units, and what it is
    /// judged against: the target's identity at the extent's index and
    /// payload offset.
    pub(crate) fn record(&self, index: u32) -> (Expected, Vec<u8>) {
        let config = RecordConfig {
            chunk_len: self.chunk_len,
        }
        .validate()
        .expect("an admitted chunk length");
        let layout = config.extent_layout(self.metadata, self.body, self.coverage(index));
        let mut bytes = vec![0; layout.record_units() as usize * IO_UNIT];
        let payload = layout.header_bytes()..layout.record_len() as usize;
        for (at, byte) in bytes[payload].iter_mut().enumerate() {
            *byte = (at * 31 % 251) as u8;
        }
        let position = ExtentPosition {
            index,
            offset: u64::from(index) * EXTENT_BYTES,
        };
        encode_header(Crc32c::detect(), &layout, &IDENTITY, position, &mut bytes)
            .expect("room for the record");
        let expected = Expected {
            identity: IDENTITY,
            reader: IDENTITY.session,
            index,
            offset: position.offset,
            chunk_len: self.chunk_len,
            units: layout.record_units() as u32,
            end: None,
        };
        (expected, bytes)
    }

    /// A storage whose records chunk every `chunk_len` bytes and whose
    /// objects hold up to this geometry's metadata and body.
    fn storage(&self) -> Storage<TestPlatform> {
        let mut volume = crate::storage::test_volume(128 * IO_UNIT, 8);
        volume.record = RecordConfig {
            chunk_len: self.chunk_len,
        };
        let config = StorageConfig {
            body_cap: self.body as usize,
            metadata_cap: Some(self.metadata as usize),
            object_rights: 8,
            volume,
            ..storage_config(8)
        };
        let index = crate::index::IndexConfig {
            fills: &[2],
            ..index_config(&[8], (1, 1), 1)
        };
        let storage = storage_from(&config, &index, TestPlatform::heap(PAGE));
        storage.platform.ticks(&[Some(1)]);
        storage
    }
}

/// The geometry modes: the geometry `input[0]` selects, each of its
/// extents' records mutated by the ops after it, resealed when `reseal`
/// is set, judged by header verification and `claim_header`, and a
/// one-extent object's published record by the volume read. A pass's run
/// is the geometry byte and the whole ops.
pub(crate) fn geometry_mode(input: &[u8], reseal: bool) -> Class {
    let [byte, ops @ ..] = input else {
        return Class::Invalid("the input holds no geometry byte");
    };
    let geometry = Geometry::of(*byte);
    for index in 0..geometry.extents() {
        let (expected, record) = geometry.record(index);
        let Some(bytes) = apply(record, reseal, ops, geometry.chunk_len) else {
            return Class::Invalid("the ops pass their bound");
        };
        for reader in ACCEPTING.into_iter().chain(REFUSING) {
            let expected = Expected { reader, ..expected };
            let ours = verified(&bytes, &expected);
            let theirs = literal(&bytes, &expected).header;
            if ours != theirs {
                return disagree(
                    &format!("header verification of extent {index} under reader {reader:#x}"),
                    &ours,
                    &theirs,
                );
            }
        }
        if let Err(failure) = judge_claim(&bytes, geometry.chunk_len) {
            return failure;
        }
    }
    if geometry.extents() > 1 {
        return Class::Pass {
            run: read_bytes(input, 1),
        };
    }
    let payload = content(geometry.coverage(0) as usize, 3);
    let (read, image, expected) = read_back_from(
        &geometry.storage(),
        geometry.metadata as usize,
        &payload,
        |pristine, chunk_len| {
            apply(pristine, reseal, ops, chunk_len).expect("ops the standalone records took")
        },
    );
    let wanted = literal(&image, &expected);
    if read != wanted {
        return read_disagreement(&read, &wanted);
    }
    Class::Pass {
        run: read_bytes(input, 1),
    }
}

/// Seeds of the geometry modes: for a one-extent and a two-extent
/// geometry, the valid records raw, an offset change resealed, and an
/// image byte flipped raw.
pub(crate) fn seeds() -> Vec<(String, Vec<u8>)> {
    let mut seeds = Vec::new();
    // Chunk length 65536 with metadata and body of three windows less one
    // byte holds two extents; chunk length 8192 with one byte of metadata
    // and a body one byte past one window holds one.
    for (name, byte) in [("two-extents", 0b1101_1011u8), ("one-extent", 0b1000_0101)] {
        for (mode, ops) in [
            (5, &[][..]),
            (6, &[1, 8, 1, 0][..]),
            (5, &[3, 9, 200, 1][..]),
        ] {
            let mut input = vec![super::fuzz_tests::FORMAT, mode, byte];
            input.extend_from_slice(ops);
            let n = seeds.len();
            seeds.push((format!("ib-record-claims-{name}-{n}-{mode}.input"), input));
        }
    }
    seeds
}

#[cfg(test)]
mod tests {
    //! Witnesses that every geometry byte selects an admitted geometry, that
    //! a valid header at a nonzero extent position verifies and claims as
    //! the literal parser says, and that published one-extent geometries
    //! read back what the literal parser exposes.

    use super::super::HeaderMismatch;
    use super::super::fuzz_tests::{FORMAT, RECORD};
    use super::*;

    /// Every geometry byte selects an admitted chunk length and lengths of
    /// at most two extents, the two-extent seed geometry included.
    #[test]
    fn every_geometry_byte_selects_an_admitted_geometry() {
        let mut extents = [0; 3];
        for byte in 0..=255 {
            let geometry = Geometry::of(byte);
            assert!(CHUNK_LENS.contains(&geometry.chunk_len));
            let lengths = Geometry::lengths(geometry.chunk_len);
            assert!(lengths.contains(&geometry.metadata) && lengths.contains(&geometry.body));
            extents[geometry.extents() as usize] += 1;
        }
        assert_eq!(extents[0], 0);
        assert!(extents[1] > 0 && extents[2] > 0, "{extents:?}");
        assert_eq!(Geometry::of(0b1101_1011).extents(), 2);
        assert_eq!(Geometry::of(0b1000_0101).extents(), 1);
    }

    /// A valid header at extent 1, payload offset 248 KiB, verifies at its
    /// own position, and `claim_header` accepts it with the claim the
    /// literal parser derives, whose payload is the extent's coverage. An
    /// offset change resealed under a fresh header crc leaves the context
    /// crc stale, and both refuse it there: once the header crc is
    /// resealed, the context crc binds the offset.
    #[test]
    fn ib_record_claims_valid_header_at_nonzero_position() {
        let geometry = Geometry::of(0b1101_1011);
        let (expected, record) = geometry.record(1);
        assert_eq!((expected.index, expected.offset), (1, 253_952));
        assert_eq!(verified(&record, &expected), Ok(()));
        let claim = judge_claim(&record, geometry.chunk_len)
            .expect("an agreed claim")
            .expect("a valid claim");
        assert_eq!(claim.lengths, (3 * 65536 - 1, 3 * 65536 - 1));
        assert_eq!(claim.payload, 2 * (3 * 65536 - 1) - 253_952);
        assert_eq!(claim.identity, IDENTITY);
        let moved = apply(record, true, &[1, 8, 1, 0], geometry.chunk_len).unwrap();
        assert!(matches!(
            judge_claim(&moved, geometry.chunk_len),
            Ok(Err(HeaderMismatch::ContextCrc { .. }))
        ));
    }

    /// A one-extent object published under its geometry's chunk length
    /// and lengths reads back whole, and an image byte flipped raw and
    /// resealed passes both geometry modes.
    #[test]
    fn a_published_geometry_reads_back_what_the_literal_parser_exposes() {
        for byte in [0b1000_0101u8, 0b0010_0100, 0b0101_0110, 0b0000_1011] {
            let geometry = Geometry::of(byte);
            assert_eq!(geometry.extents(), 1, "{geometry:?}");
            let payload = content(geometry.coverage(0) as usize, 3);
            let (read, image, expected) = read_back_from(
                &geometry.storage(),
                geometry.metadata as usize,
                &payload,
                |image, _| image,
            );
            assert_eq!((read.header, read.chunk), (Ok(()), None), "{geometry:?}");
            assert_eq!(read.exposed, payload, "{geometry:?}");
            assert_eq!(read, literal(&image, &expected), "{geometry:?}");
            for mode in [5, 6] {
                let input = [FORMAT, mode, byte, 3, 9, 200, 1];
                assert!(
                    matches!((RECORD.run)(&input), Class::Pass { .. }),
                    "{geometry:?}"
                );
            }
        }
    }
}
