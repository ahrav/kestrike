//! The metadata area an attached volume writes, and `Persisted`, the evidence that one of its blocks reached the device.
//!
//! EVIDENCE-ORDER: a [`Persisted`] exists only for a successful write terminal of a mapped metadata command whose recorded range lies in the metadata prefix and qualifies under the attach-time persistence profile; every later metadata write that depends on a block is submitted only after that block's `Persisted`.
//! ONE-QUALIFIED-WRITE-PER-BLOCK: each metadata block is one `U`-byte write at a `U`-aligned device offset inside `[0, M * IO_UNIT)`, and attach admits only a layout whose every block qualifies.

use super::super::device::{DeviceRange, PersistenceProfile, Terminal};
use super::block::Layout;
use super::layout::{TileRefusal, UNIT_BYTES, tile};

/// The metadata prefix of an attached volume, tiled in blocks of the profile's unit, every block qualifying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Area {
    layout: Layout,
    profile: PersistenceProfile,
}

/// The reason [`Area::new`] refuses a metadata prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AreaRefusal {
    /// The prefix fails [`tile`]'s check; `unit` is the profile's unit in bytes.
    Layout { refusal: TileRefusal, unit: u64 },
    /// Block `block` fails the profile's `qualifies`.
    Unqualified { block: u64 },
}

impl Area {
    /// The area of `metadata_units` units under `profile`, every block of which qualifies.
    ///
    /// # Errors
    ///
    /// `Layout` with [`tile`]'s refusal, then `Unqualified` naming the first block whose range fails `qualifies`.
    pub(crate) fn new(
        profile: PersistenceProfile,
        metadata_units: u64,
    ) -> Result<Self, AreaRefusal> {
        let unit = profile.unit() * u64::from(profile.sector_size());
        let blocks =
            tile(metadata_units, unit).map_err(|refusal| AreaRefusal::Layout { refusal, unit })?;
        let Ok(unit) = u32::try_from(unit) else {
            unreachable!("derive bounds the unit by the driver's 32-bit command limit")
        };
        let area = Self {
            layout: Layout {
                unit,
                metadata_units,
            },
            profile,
        };
        if let Some(block) = (0..blocks).find(|&block| area.range(block).is_none()) {
            return Err(AreaRefusal::Unqualified { block });
        }
        Ok(area)
    }

    pub(crate) fn layout(&self) -> Layout {
        self.layout
    }

    /// The device range of prefix unit `unit`, one [`UNIT_BYTES`] unit at `unit * UNIT_BYTES`, when it lies inside the
    /// metadata area and the profile qualifies it.
    pub(crate) fn unit_range(&self, unit: u64) -> Option<DeviceRange> {
        self.ranged(unit, UNIT_BYTES as u32)
    }

    /// Block `block`'s device range: `U` bytes at `block * U`, when the range lies in `[0, M * IO_UNIT)` and qualifies under the profile.
    pub(crate) fn range(&self, block: u64) -> Option<DeviceRange> {
        self.ranged(block, self.layout.unit)
    }

    /// The `len` bytes at `index * len`, when they lie in `[0, M * IO_UNIT)` and qualify under the profile.
    fn ranged(&self, index: u64, len: u32) -> Option<DeviceRange> {
        let start = index.checked_mul(u64::from(len))?;
        let range = DeviceRange::new(start, len).ok()?;
        (range.end() <= self.layout.metadata_units * UNIT_BYTES && self.profile.qualifies(range))
            .then_some(range)
    }
}

/// A submitted metadata command as the volume recorded it: the block, the generation its bytes carry, and its device range. A checkpoint-unit command records its prefix unit as the block, with generation zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Recorded {
    pub(crate) block: u64,
    pub(crate) generation: u64,
    pub(crate) range: DeviceRange,
}

/// Evidence that the metadata command `recorded` names landed: its block holds the bytes of its generation on the device, under the profile's completion assumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Persisted(Recorded);

impl Persisted {
    /// The evidence `terminal` gives for `recorded`, the metadata command its token mapped to: present for a `Written` terminal of a range [`Area::range`] gives for the recorded block.
    pub(crate) fn of(terminal: &Terminal<'_>, recorded: &Recorded, area: &Area) -> Option<Self> {
        (matches!(terminal, Terminal::Written { .. })
            && area.range(recorded.block) == Some(recorded.range))
        .then_some(Self(*recorded))
    }

    pub(crate) fn recorded(&self) -> &Recorded {
        &self.0
    }
}
