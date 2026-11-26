//! The host-local record: one 512-byte sector naming this attachment's host ID, its reservation key and the binding to (instance, volume, control-plane attachment ID), sealed by a crc32c. The volume record enrolls the record's pair for the attachment's attach event before Register.
//!
//! Version 2 lays out a little-endian `u32` version, three zero-padded 64-byte identifiers (instance, volume, attachment), the 16-byte host ID, the `u64` key, zero padding to byte 508, and the crc32c of bytes 0 to 508 at bytes 508 to 512. Decoding checks the length and the version before the crc, and the fields after it, so a torn sector refuses `Torn` and a record of another format refuses before its bytes are trusted.

use super::assignment::{AssignmentError, Reader, is_zero, text};
use super::evidence::Pair;
use super::identity::{Exhid, Key, is_volume};

/// The record's length: one sector.
pub const RECORD_BYTES: usize = 512;
const VERSION: u32 = 2;
const CRC_AT: usize = RECORD_BYTES - 4;

/// What the record binds the attachment to, all three from the authenticated assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub instance: String,
    pub volume: String,
    /// The control-plane attachment ID.
    pub attachment: String,
}

/// One host-local record. The only constructors are [`LocalRecord::fresh`], which draws the host ID, and [`LocalRecord::decode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRecord {
    binding: Binding,
    pair: Pair,
}

/// The record check that refused the bytes, in decode order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    Length,
    Version,
    /// The crc32c does not match the sector, as a torn or damaged write leaves it.
    Torn,
    Field,
}

impl From<AssignmentError> for RecordError {
    fn from(_: AssignmentError) -> Self {
        Self::Field
    }
}

/// Host-ID draws before a fresh record refuses: each draw that returns all zeros is redrawn.
const DRAWS: usize = 4;

impl LocalRecord {
    /// A fresh attachment's record: `binding`, `key`, and a host ID from `draw`, redrawn while a draw returns all zeros; `None` after the first failed draw or four zero draws.
    pub fn fresh(
        binding: Binding,
        key: Key,
        mut draw: impl FnMut() -> Option<[u8; 16]>,
    ) -> Option<Self> {
        for _ in 0..DRAWS {
            if let Ok(exhid) = Exhid::new(draw()?) {
                return Some(Self {
                    binding,
                    pair: Pair { exhid, key },
                });
            }
        }
        None
    }

    pub fn binding(&self) -> &Binding {
        &self.binding
    }

    /// The host ID and this attachment's reservation key.
    pub fn pair(&self) -> Pair {
        self.pair
    }

    /// The record's sector.
    ///
    /// # Errors
    ///
    /// `Field` for an identifier that is empty, longer than 63 bytes or outside the identifier alphabet, or a volume ID that is not an EBS volume ID in its `vol-` form.
    pub fn encode(&self) -> Result<[u8; RECORD_BYTES], RecordError> {
        if !is_volume(&self.binding.volume) {
            return Err(RecordError::Field);
        }
        let mut out = Vec::with_capacity(RECORD_BYTES);
        out.extend_from_slice(&VERSION.to_le_bytes());
        text(&mut out, &self.binding.instance)?;
        text(&mut out, &self.binding.volume)?;
        text(&mut out, &self.binding.attachment)?;
        out.extend_from_slice(&self.pair.exhid.bytes());
        out.extend_from_slice(&self.pair.key.encode().to_le_bytes());
        out.resize(CRC_AT, 0);
        let crc = crate::storage::Crc32c::detect().checksum(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        Ok(out.try_into().expect("one sector"))
    }

    /// Decodes a sector, checking its length, then its version, then its crc32c, then its fields.
    ///
    /// # Errors
    ///
    /// `Length`, `Version`, `Torn` and `Field` name the first failed check; `Field` includes a nonzero padding byte, a zero host ID, a malformed key and a volume ID that is not an EBS volume ID in its `vol-` form.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() != RECORD_BYTES {
            return Err(RecordError::Length);
        }
        if bytes[..4] != VERSION.to_le_bytes() {
            return Err(RecordError::Version);
        }
        let stored = u32::from_le_bytes(bytes[CRC_AT..].try_into().expect("four crc bytes"));
        if crate::storage::Crc32c::detect().checksum(&bytes[..CRC_AT]) != stored {
            return Err(RecordError::Torn);
        }
        let mut r = Reader(&bytes[4..CRC_AT]);
        let binding = Binding {
            instance: r.text()?,
            volume: r.text()?,
            attachment: r.text()?,
        };
        let exhid = Exhid::new(r.take()?).map_err(|_| RecordError::Field)?;
        let key = Key::decode(r.u64()?).map_err(|_| RecordError::Field)?;
        if !is_zero(r.0) || !is_volume(&binding.volume) {
            return Err(RecordError::Field);
        }
        Ok(Self {
            binding,
            pair: Pair { exhid, key },
        })
    }
}
