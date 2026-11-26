//! The packed address of one held extent and where its record ends: a 37-bit start and a 24-bit length, in [`IO_UNIT`](super::super::IO_UNIT)s, and a 3-bit tail, in one `u64`.
//!
//! Construction refuses a start at or above `2^37` or a length at or above `2^24`, so every locator decodes to the values it was built from.
//! The tail counts the [`TAIL_SECTOR`]-byte sectors the extent's record fills in its last unit, eight stored as zero, so a reader can end its read at the record's last sector; a locator with a zero tail ends at the extent's end.
//! The tail is a read bound only: a record's lengths come from its verified header, and a header that claims bytes past the bound fails its length check.

/// Units a locator start can name: `2^37`, so a volume of at most this many units, 512 TiB, is fully addressable.
pub const LOCATOR_START_LIMIT: u64 = 1 << START_BITS;

/// Exclusive bound on a locator length in units: `2^24`.
pub const LOCATOR_LEN_LIMIT: u32 = 1 << LEN_BITS;

/// Bytes of one tail step: the [`SECTOR`](super::super::SECTOR), the smallest device block a geometry admits.
pub const TAIL_SECTOR: u64 = super::super::SECTOR as u64;

const START_BITS: u32 = 37;
const TAIL_BITS: u32 = 3;
const LEN_BITS: u32 = 24;
const LEN_SHIFT: u32 = START_BITS + TAIL_BITS;
const UNIT: u64 = super::super::IO_UNIT as u64;
const SECTORS_PER_UNIT: u64 = UNIT / TAIL_SECTOR;

/// One held extent: units `start..start + len` of the volume, and the sectors its record fills in its last unit.
///
/// The start occupies the low 37 bits, the tail the next 3 and the length the high 24 bits of [`bits`](Self::bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtentLocator(u64);

/// A locator field does not fit its packed width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocatorError {
    /// `start_unit >= 2^37`.
    Start { start_unit: u64 },
    /// `len_units >= 2^24`.
    Len { len_units: u32 },
}

impl ExtentLocator {
    /// # Errors
    ///
    /// `Start` when `start_unit >= 2^37`, else `Len` when `len_units >= 2^24`.
    pub fn new(start_unit: u64, len_units: u32) -> Result<Self, LocatorError> {
        if start_unit >= LOCATOR_START_LIMIT {
            return Err(LocatorError::Start { start_unit });
        }
        if len_units >= LOCATOR_LEN_LIMIT {
            return Err(LocatorError::Len { len_units });
        }
        Ok(Self(pack(start_unit, len_units)))
    }

    /// The locator packed in `bits`; every `u64` decodes to fields inside both limits.
    pub(crate) fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub fn bits(self) -> u64 {
        self.0
    }

    pub fn start_unit(self) -> u64 {
        self.0 & (LOCATOR_START_LIMIT - 1)
    }

    pub fn len_units(self) -> u32 {
        (self.0 >> LEN_SHIFT) as u32
    }

    /// This extent with its tail set for a record of `record_len` bytes from the extent's start.
    /// A record that fills the extent's units ends in its last unit; a `record_len` outside that unit leaves a zero tail, which bounds the read at the extent's end.
    pub(crate) fn ending_at(self, record_len: u64) -> Self {
        let units = u64::from(self.len_units());
        let last = units.saturating_sub(1) * UNIT;
        let tail = if units == 0 || record_len <= last || record_len > units * UNIT {
            0
        } else {
            (record_len - last).div_ceil(TAIL_SECTOR) % SECTORS_PER_UNIT
        };
        let cleared = self.0 & !(((1 << TAIL_BITS) - 1) << START_BITS);
        Self(cleared | (tail << START_BITS))
    }

    /// Bytes from the extent's start through its record's last tail sector, or the extent's whole length when the tail is zero.
    pub fn record_end(self) -> u64 {
        let units = u64::from(self.len_units());
        let tail = (self.0 >> START_BITS) & ((1 << TAIL_BITS) - 1);
        if tail == 0 {
            units * UNIT
        } else {
            (units - 1) * UNIT + tail * TAIL_SECTOR
        }
    }
}

/// The start in the low 37 bits, a zero tail and the length above it; callers keep both inside their limits.
pub(super) const fn pack(start_unit: u64, len_units: u32) -> u64 {
    start_unit | ((len_units as u64) << LEN_SHIFT)
}
