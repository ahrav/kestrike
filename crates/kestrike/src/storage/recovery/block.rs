//! Metadata block framing: each metadata block is `layout.unit` bytes, opens with a fixed header and is sealed by one crc32c over the whole block.
//!
//! The header holds, little-endian at the offsets the constants below name, the magic, the version, the role, the recorded layout (the block length `U` in bytes and the prefix `M` in units), the 128-bit format ID, the writer generation, the role sequence, the block's own index in the prefix and the crc32c, computed with its own four bytes read as zero.
//! The remaining header bytes are zero, and the encoder writes zero to every payload byte outside the role's fields; the crc covers those bytes and the decoder reads none of them, so a field placed there needs a new [`VERSION`]. The payload starts at [`PAYLOAD`].
//! A role's fields lie in the payload bytes before [`HEAD`] and in the block's last [`TRAILER`] bytes, which every block holds because [`tile`](super::layout::tile) admits only a block of at least one transfer unit, and [`seal`] writes zero to every byte between them.
//! The crc32c folds the block's first [`HEAD`] bytes, a zero run carries that crc past every byte after the head, and the bytes from an offset to the block's end fold from a zero register, where every byte between the head and that offset is zero: [`seal`] takes the trailer's start, and [`open`] takes the start of the first whole [`CHUNK`]-byte chunk after the head that holds a nonzero byte, or the end of the last whole chunk when each whole chunk is zero. Either way it equals the crc32c of the whole block with the crc field read as zero.
//! The issuance prefix, bytes 0..48 from the magic through the writer generation, keeps these offsets in every encoding version, so a reader of any version can read the generation a block carries.
//!
//! WHOLE-OR-ABSENT: [`open`] admits a block only when its magic, version, recorded layout, crc, role, format ID, generation and self-index all match, checked in that order; a version other than [`VERSION`] is `Unsupported` whatever follows it.
//! The version and layout fields are read before the crc, so a block whose version bytes 8..10 or layout bytes 12..24 were damaged reads as unsupported or foreign, which refuses the attach, where damage elsewhere reads as invalid.

use super::super::record::Crc32c;

pub(crate) const MAGIC: [u8; 8] = *b"IMGCMETA";
/// The encoding version. A set high bit marks a provisional encoding, which only builds of the same version read; every version keeps the issuance prefix's offsets.
pub(crate) const VERSION: u16 = 0x8003;
pub(crate) const PAYLOAD: usize = 72;
/// The end of a block's head: the header and the role's leading fields.
pub(crate) const HEAD: usize = 144;
/// The bytes at a block's end that hold the role's trailing field.
pub(crate) const TRAILER: usize = 8;
/// The granularity at which [`dirty`] locates the first nonzero byte after the head.
const CHUNK: usize = 128;

const VERSION_AT: usize = 8;
const ROLE_AT: usize = 10;
const UNIT_AT: usize = 12;
const UNITS_AT: usize = 16;
const FORMAT_AT: usize = 24;
const GENERATION_AT: usize = 40;
const SEQUENCE_AT: usize = 48;
const INDEX_AT: usize = 56;
const CRC_AT: usize = 64;

/// A volume's 128-bit format ID: drawn once when the volume is formatted and carried by every metadata block of that formatting; always nonzero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatId(pub(crate) [u8; 16]);

/// The metadata prefix's recorded layout: blocks of `unit` bytes tiling `metadata_units` units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Layout {
    pub(crate) unit: u32,
    pub(crate) metadata_units: u64,
}

/// A block's role byte. [`open`] refuses a block whose role byte differs from the role its caller names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Root = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    pub(crate) role: Role,
    pub(crate) format: FormatId,
    pub(crate) generation: u64,
    pub(crate) sequence: u64,
    pub(crate) index: u64,
}

/// The reason [`open`] rejects a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Undecodable {
    /// The block has another length, or a field failed its check: the magic, the crc, the role, a zero format ID or generation, or the self-index; for a root, also a payload field `root::decode` refuses.
    Invalid,
    /// The magic matched and the version differs from [`VERSION`].
    Unsupported { version: u16 },
    /// The magic and version matched and the recorded layout names another block length or prefix.
    ForeignLayout,
}

/// Writes `header` and `layout` into `block`, a whole block whose fields the caller already wrote between [`PAYLOAD`] and [`HEAD`] and in its last [`TRAILER`] bytes, zeroes the header's unused bytes and every byte between the head and the trailer, and seals the block with its crc32c.
///
/// # Panics
///
/// When `block.len()` differs from `layout.unit` or is shorter than the head and the trailer together.
pub(crate) fn seal(crc: Crc32c, layout: Layout, header: Header, block: &mut [u8]) {
    frame(layout, header, block);
    let trailer = block.len() - TRAILER;
    block[HEAD..trailer].fill(0);
    let sum = checksum(crc, block, trailer);
    block[CRC_AT..CRC_AT + 4].copy_from_slice(&sum.to_le_bytes());
}

/// Writes `header` and `layout` into `block`'s header bytes, zeroing the unused ones and the crc field.
fn frame(layout: Layout, header: Header, block: &mut [u8]) {
    assert_eq!(
        block.len(),
        layout.unit as usize,
        "a metadata block is one unit"
    );
    block[..PAYLOAD].fill(0);
    block[..VERSION_AT].copy_from_slice(&MAGIC);
    block[VERSION_AT..ROLE_AT].copy_from_slice(&VERSION.to_le_bytes());
    block[ROLE_AT] = header.role as u8;
    block[UNIT_AT..UNITS_AT].copy_from_slice(&layout.unit.to_le_bytes());
    block[UNITS_AT..FORMAT_AT].copy_from_slice(&layout.metadata_units.to_le_bytes());
    block[FORMAT_AT..GENERATION_AT].copy_from_slice(&header.format.0);
    block[GENERATION_AT..SEQUENCE_AT].copy_from_slice(&header.generation.to_le_bytes());
    block[SEQUENCE_AT..INDEX_AT].copy_from_slice(&header.sequence.to_le_bytes());
    block[INDEX_AT..CRC_AT].copy_from_slice(&header.index.to_le_bytes());
}

/// Decodes the header of `block`, read at block `index` under `layout`, checking its fields in the WHOLE-OR-ABSENT order and requiring `role`; returns its format ID, writer generation and role sequence.
///
/// # Errors
///
/// `Invalid` for a block of another length or a wrong magic; `Unsupported` for another version; `ForeignLayout` for another recorded layout; then `Invalid` for a wrong crc, role, zero format ID, zero generation or self-index.
///
/// # Panics
///
/// When a block of `layout.unit` bytes is shorter than [`HEAD`] and a check reads past its end: the magic, version and layout checks read its first 24 bytes in that order, and a block that passes them is read through the head.
pub(crate) fn open(
    crc: Crc32c,
    layout: Layout,
    block: &[u8],
    role: Role,
    index: u64,
) -> Result<(FormatId, u64, u64), Undecodable> {
    if block.len() != layout.unit as usize || block[..VERSION_AT] != MAGIC {
        return Err(Undecodable::Invalid);
    }
    let version = u16::from_le_bytes(field(block, VERSION_AT));
    if version != VERSION {
        return Err(Undecodable::Unsupported { version });
    }
    if u32::from_le_bytes(field(block, UNIT_AT)) != layout.unit
        || u64::from_le_bytes(field(block, UNITS_AT)) != layout.metadata_units
    {
        return Err(Undecodable::ForeignLayout);
    }
    if u32::from_le_bytes(field(block, CRC_AT)) != checksum(crc, block, dirty(block)) {
        return Err(Undecodable::Invalid);
    }
    let format = FormatId(field(block, FORMAT_AT));
    let generation = u64::from_le_bytes(field(block, GENERATION_AT));
    if block[ROLE_AT] != role as u8
        || format.0 == [0; 16]
        || generation == 0
        || u64::from_le_bytes(field(block, INDEX_AT)) != index
    {
        return Err(Undecodable::Invalid);
    }
    Ok((
        format,
        generation,
        u64::from_le_bytes(field(block, SEQUENCE_AT)),
    ))
}

/// The offset from which `block`'s bytes after [`HEAD`] may be nonzero: the start of the first [`CHUNK`]-byte chunk after the head that holds a nonzero byte, or the end of the last whole chunk.
fn dirty(block: &[u8]) -> usize {
    let (chunks, _) = block[HEAD..].as_chunks::<CHUNK>();
    let zeros = chunks.iter().take_while(|chunk| zero(*chunk)).count();
    HEAD + CHUNK * zeros
}

/// The crc32c of the whole `block` with the crc field read as zero, for a block whose bytes from [`HEAD`] to `dirty` are zero: the head folds, a zero run carries its crc past the bytes after it, and of those bytes only the ones from `dirty` on fold.
fn checksum(crc: Crc32c, block: &[u8], dirty: usize) -> u32 {
    debug_assert!(zero(&block[HEAD..dirty]));
    let mut running = crc.start();
    running.update(&block[..CRC_AT]);
    running.update(&[0; 4]);
    running.update(&block[CRC_AT + 4..HEAD]);
    let rest = crc.zero_run((block.len() - HEAD) as u64);
    let tail = crc.checksum_of(crc.fold_from_zero(&block[dirty..]), &rest);
    crc.combine(running.finish(), &rest, tail)
}

/// Whether every byte of `bytes` is zero.
pub(crate) fn zero(bytes: &[u8]) -> bool {
    let (words, rest) = bytes.as_chunks::<8>();
    words
        .iter()
        .fold(0, |any, word| any | u64::from_ne_bytes(*word))
        == 0
        && rest.iter().all(|&byte| byte == 0)
}

pub(crate) fn field<const N: usize>(block: &[u8], at: usize) -> [u8; N] {
    let mut bytes = [0; N];
    bytes.copy_from_slice(&block[at..at + N]);
    bytes
}
