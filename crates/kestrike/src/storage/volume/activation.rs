//! The activation record at unit 0 and the step that writes it once and reads it back before recovery or serving.
//!
//! - The record holds the magic `IMGCACT1`, version 1, the volume's name field, `g` and `a` as little-endian `u32`, the session `g·2^32 + a` as a little-endian `u64`, and a crc32c over the 4 KiB unit with the crc field read as zero; every other byte is zero.
//! - ONE-WRITE: [`ActivationStep::start`] submits the one write of unit 0 and panics on a second call.
//! - The caller calls [`ActivationStep::written`] at the write's successful completion and [`ActivationStep::read`] at each read-back's completion.
//! - A torn or empty read-back triggers one retry; a second torn or empty read-back ends the step with [`Action::Refused`]. A whole record ends it with `Refused` immediately if it identifies another volume or tenure or violates `encode`'s record format. `Refused` refuses the activating attempt; the record carries no authority, so the fresh path requests no volume replacement for it and the next start restarts on the same volume.
//! - The crc32c folds the header, then the bytes from the start of the tail's first 128-byte chunk that holds a nonzero byte to the unit's end, from the tail's first byte when that chunk is the unit's first; zero runs carry it across the crc field and the zero bytes before them, so it equals the crc32c of the whole unit with the crc field read as zero.
//! - A read-back holding the header and crc the step wrote, then a zero tail, is the one record [`Activation::decode`] accepts as the step's own activation, so the step activates on a byte comparison with the unit it wrote; [`Activation::decode`] judges every other returned unit, and a read that returns no bytes counts as torn.

use super::super::device::IO_UNIT;
use super::super::record::Crc32c;
use super::super::recovery::{Session, field, zero};
use crate::failover::records::{VOLUME, VolumeId};
use crate::net::ownership::{ActivatedEpoch, ShardGeneration, session_of};

pub const UNIT: u64 = 0;
pub const RECORD_LEN: usize = 4096;

const MAGIC: [u8; 8] = *b"IMGCACT1";
const VERSION: u16 = 1;
const VERSION_AT: usize = 8;
const VOLUME_AT: usize = 10;
const GENERATION_AT: usize = VOLUME_AT + VOLUME;
const EPOCH_AT: usize = GENERATION_AT + 4;
const SESSION_AT: usize = EPOCH_AT + 4;
const CRC_AT: usize = SESSION_AT + 8;
const TAIL_AT: usize = CRC_AT + 4;
/// The granularity at which [`dirty`] locates the tail's first nonzero byte; the crc32c folds from that chunk's start, or from [`TAIL_AT`] in the unit's first chunk, to the unit's end.
const CHUNK: usize = 128;
/// The bytes [`clear`] folds per step: eight words.
const BLOCK: usize = 64;

const _: () = assert!(
    RECORD_LEN == IO_UNIT
        && TAIL_AT <= BLOCK
        && BLOCK == size_of::<[u64; 8]>()
        && CHUNK.is_multiple_of(BLOCK)
        && RECORD_LEN.is_multiple_of(CHUNK)
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Activation {
    volume: VolumeId,
    generation: ShardGeneration,
    epoch: ActivatedEpoch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Damage {
    /// The bytes are a length other than [`RECORD_LEN`] or fail the crc32c.
    Torn,
    /// The crc32c matches, and the magic, version, volume, `(g, a)`, session or zero bytes differ from every record `encode` writes.
    Invalid,
}

impl Activation {
    pub fn of(volume: VolumeId, session: &Session) -> Self {
        Self {
            volume,
            generation: session.generation(),
            epoch: session.epoch(),
        }
    }

    fn session(&self) -> u64 {
        session_of(self.generation.get() as u32, self.epoch.get())
    }

    pub fn encode(&self, crc: Crc32c, record: &mut [u8; RECORD_LEN]) {
        record[..VERSION_AT].copy_from_slice(&MAGIC);
        record[VERSION_AT..VOLUME_AT].copy_from_slice(&VERSION.to_le_bytes());
        record[VOLUME_AT..GENERATION_AT].copy_from_slice(&self.volume.field());
        record[GENERATION_AT..EPOCH_AT]
            .copy_from_slice(&(self.generation.get() as u32).to_le_bytes());
        record[EPOCH_AT..SESSION_AT].copy_from_slice(&self.epoch.get().to_le_bytes());
        record[SESSION_AT..CRC_AT].copy_from_slice(&self.session().to_le_bytes());
        // Zeroing the crc field and the tail after the header puts the 4 KiB fill between the header's narrow stores and `checksum`'s word loads of the header, so those stores can drain before the loads.
        record[CRC_AT..].fill(0);
        let sum = checksum(crc, record, RECORD_LEN);
        record[CRC_AT..CRC_AT + 4].copy_from_slice(&sum.to_le_bytes());
    }

    /// # Errors
    ///
    /// [`Damage::Torn`] before [`Damage::Invalid`].
    pub fn decode(crc: Crc32c, bytes: &[u8]) -> Result<Self, Damage> {
        let record: &[u8; RECORD_LEN] = bytes.try_into().map_err(|_| Damage::Torn)?;
        let dirty = dirty(record);
        if checksum(crc, record, dirty) != u32::from_le_bytes(field(record, CRC_AT)) {
            return Err(Damage::Torn);
        }
        if dirty < RECORD_LEN {
            return Err(Damage::Invalid);
        }
        fields(record).ok_or(Damage::Invalid)
    }
}

/// For a CRC-valid record with a zero tail, `fields` returns its activation only if the header matches `encode`'s format and `g` and `a` are in the domain of a [`Session`].
fn fields(record: &[u8; RECORD_LEN]) -> Option<Activation> {
    if record[..VERSION_AT] != MAGIC || u16::from_le_bytes(field(record, VERSION_AT)) != VERSION {
        return None;
    }
    let generation = u32::from_le_bytes(field(record, GENERATION_AT));
    let found = Activation {
        volume: VolumeId::from_field(&field(record, VOLUME_AT))?,
        generation: ShardGeneration::new(u64::from(generation))
            .filter(|generation| generation.get() != u64::from(u32::MAX))?,
        epoch: ActivatedEpoch::new(u32::from_le_bytes(field(record, EPOCH_AT)))
            .filter(|epoch| epoch.is_activated())?,
    };
    (u64::from_le_bytes(field(record, SESSION_AT)) == found.session()).then_some(found)
}

/// The offset where `record`'s nonzero tail bytes may start: [`TAIL_AT`] when the first [`CHUNK`] holds one, the start of the first later chunk that holds one, or [`RECORD_LEN`] for a zero tail.
fn dirty(record: &[u8; RECORD_LEN]) -> usize {
    if !zero(&record[TAIL_AT..CHUNK]) {
        return TAIL_AT;
    }
    let (chunks, _) = record[CHUNK..].as_chunks::<CHUNK>();
    chunks
        .iter()
        .position(|chunk| !zero(chunk))
        .map_or(RECORD_LEN, |index| CHUNK * (index + 1))
}

/// Whether `record`'s tail is zero: the tail bytes of the first [`BLOCK`], then every later block folded into eight word accumulators to the unit's end.
fn clear(record: &[u8; RECORD_LEN]) -> bool {
    let (blocks, _) = record[BLOCK..].as_chunks::<BLOCK>();
    let any = blocks.iter().fold([0u64; 8], |mut any, block| {
        for (any, word) in any.iter_mut().zip(block.as_chunks::<8>().0) {
            *any |= u64::from_ne_bytes(*word);
        }
        any
    });
    zero(&record[TAIL_AT..BLOCK]) && any.iter().fold(0, |all, word| all | word) == 0
}

/// The crc32c of `record` with its crc field read as zero, for a record whose bytes from [`TAIL_AT`] to `dirty` are zero: zero runs carry the header's crc past the crc field and those bytes, and of the bytes after the header only those from `dirty` on are folded.
fn checksum(crc: Crc32c, record: &[u8; RECORD_LEN], dirty: usize) -> u32 {
    debug_assert!(zero(&record[TAIL_AT..dirty]));
    let zeros = crc.zero_run((dirty - CRC_AT) as u64);
    let header = crc.combine(
        crc.checksum(&record[..CRC_AT]),
        &zeros,
        crc.checksum_of(0, &zeros),
    );
    if dirty == RECORD_LEN {
        return header;
    }
    let rest = crc.zero_run((RECORD_LEN - dirty) as u64);
    crc.combine(header, &rest, crc.checksum(&record[dirty..]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Write { unit: u64 },
    Read { unit: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The read-back failed to decode: a second torn read, or an invalid whole record on any read.
    Damaged(Damage),
    /// The read-back decoded the record of another volume or another tenure `(g, a)`.
    Foreign(Activation),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Submit(Command),
    Activated,
    Refused(Fault),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Unstarted,
    Writing,
    Reading { retried: bool },
    Ended,
}

/// The activation step of one tenure, whose record carries the session the step was built from.
#[derive(Debug)]
pub struct ActivationStep {
    own: Activation,
    /// The header and crc `start` wrote; zero before `start`.
    written: [u8; TAIL_AT],
    stage: Stage,
}

impl ActivationStep {
    pub fn new(volume: VolumeId, session: &Session) -> Self {
        Self {
            own: Activation::of(volume, session),
            written: [0; TAIL_AT],
            stage: Stage::Unstarted,
        }
    }

    /// Encodes the step's record into `record`, the write's buffer, and submits the write of unit 0.
    ///
    /// # Panics
    ///
    /// On a second call.
    pub fn start(&mut self, crc: Crc32c, record: &mut [u8; RECORD_LEN]) -> Action {
        assert_eq!(
            self.stage,
            Stage::Unstarted,
            "the activation record is written once"
        );
        self.own.encode(crc, record);
        self.written.copy_from_slice(&record[..TAIL_AT]);
        self.stage = Stage::Writing;
        Action::Submit(Command::Write { unit: UNIT })
    }

    /// Submits the read-back of unit 0; the caller calls it at the write's successful completion.
    ///
    /// # Panics
    ///
    /// Before `start` or after the write's first completion.
    pub fn written(&mut self) -> Action {
        assert_eq!(self.stage, Stage::Writing, "a write precedes the read-back");
        self.stage = Stage::Reading { retried: false };
        Action::Submit(Command::Read { unit: UNIT })
    }

    /// Judges a read-back's completion: `bytes` is the unit read, or `None` for a read that returned no bytes.
    ///
    /// # Panics
    ///
    /// Outside a submitted read-back.
    pub fn read(&mut self, crc: Crc32c, bytes: Option<&[u8]>) -> Action {
        let Stage::Reading { retried } = self.stage else {
            panic!("a read-back follows the write")
        };
        let found = match bytes {
            Some(bytes) if self.holds_own(bytes) => {
                self.stage = Stage::Ended;
                return Action::Activated;
            }
            Some(bytes) => Activation::decode(crc, bytes),
            None => Err(Damage::Torn),
        };
        let action = match found {
            Ok(found) => Action::Refused(Fault::Foreign(found)),
            Err(Damage::Torn) if !retried => {
                self.stage = Stage::Reading { retried: true };
                return Action::Submit(Command::Read { unit: UNIT });
            }
            Err(damage) => Action::Refused(Fault::Damaged(damage)),
        };
        self.stage = Stage::Ended;
        action
    }

    /// Whether `bytes` are the unit `start` wrote; [`Activation::decode`] returns the step's own activation for exactly these bytes, because it accepts only the one record `encode` writes for an activation.
    fn holds_own(&self, bytes: &[u8]) -> bool {
        <&[u8; RECORD_LEN]>::try_from(bytes)
            .is_ok_and(|record| record[..TAIL_AT] == self.written && clear(record))
    }
}
