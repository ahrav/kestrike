//! The SPDK driver's effective limits, derived from the namespace and the
//! I/O qpair's native capacity before any command is accepted.

use super::super::config::IO_UNIT;

/// Largest command the driver issues.
pub(crate) const MAX_COMMAND: u32 = 256 << 10;

/// What SPDK reports for the selected namespace and qpair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceFacts {
    pub(crate) active: bool,
    pub(crate) sector_size: u32,
    pub(crate) sectors: u64,
    pub(crate) metadata_size: u32,
    pub(crate) protection_type: u32,
    /// The namespace's largest transfer in bytes.
    pub(crate) max_transfer: u32,
    /// The optimal I/O boundary in sectors; SPDK splits a command at it. Zero for none.
    pub(crate) boundary: u32,
    /// The controller's configured I/O queue size, in entries.
    pub(crate) max_queue_size: u32,
}

/// The limits the driver enforces and the qpair sizing that backs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    pub(crate) sector_size: u32,
    /// `log2(sector_size)`: the sector size divides 4 KiB, so it is a power of
    /// two and a byte offset or length becomes sectors by this shift.
    pub(crate) sector_shift: u32,
    pub(crate) capacity: u64,
    /// Largest command in bytes: a positive [`IO_UNIT`] multiple, at most [`MAX_COMMAND`].
    pub(crate) transfer: u32,
    /// Commands the driver keeps accepted at once.
    pub(crate) depth: u32,
    pub(crate) io_queue_size: u32,
    pub(crate) io_queue_requests: u32,
}

/// Why a namespace or qpair cannot back the driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitsError {
    Inactive,
    /// The namespace carries metadata or protection information.
    Formatted,
    /// The sector size is zero or does not divide 4 KiB.
    SectorSize(u32),
    /// The capacity is below 4 KiB or overflows `u64`.
    ZeroCapacity,
    /// The largest transfer is zero, not sector-aligned, or below 4 KiB.
    Transfer(u32),
    /// The qpair cannot hold one command's trackers, or the requested depth is zero.
    Depth,
}

impl NamespaceFacts {
    /// Derives the limits for `requested` outstanding commands.
    ///
    /// A command splits into at most `ceil(transfer / boundary) + 1` child
    /// requests when the namespace reports a boundary, each holding a tracker,
    /// plus its parent request; the depth is capped so every accepted command
    /// fits the PCIe qpair's trackers and the request pool. The qpair keeps
    /// `clamp(entries / 4, 1, 128)` entries as completion headroom, so it has
    /// `entries - clamp(entries / 4, 1, 128)` trackers.
    ///
    /// # Errors
    ///
    /// In this order: `Inactive`, `Formatted`, `SectorSize`, `ZeroCapacity`, `Transfer`, `Depth`.
    pub(crate) fn limits(&self, requested: u32) -> Result<Limits, LimitsError> {
        let unit = IO_UNIT as u32;
        if !self.active {
            return Err(LimitsError::Inactive);
        }
        if self.metadata_size != 0 || self.protection_type != 0 {
            return Err(LimitsError::Formatted);
        }
        if self.sector_size == 0 || !unit.is_multiple_of(self.sector_size) {
            return Err(LimitsError::SectorSize(self.sector_size));
        }
        let capacity = self
            .sectors
            .checked_mul(u64::from(self.sector_size))
            .ok_or(LimitsError::ZeroCapacity)?;
        if capacity < u64::from(unit) {
            return Err(LimitsError::ZeroCapacity);
        }
        if self.max_transfer == 0 || !self.max_transfer.is_multiple_of(self.sector_size) {
            return Err(LimitsError::Transfer(self.max_transfer));
        }
        let transfer = self.max_transfer.min(MAX_COMMAND) / unit * unit;
        if transfer == 0 {
            return Err(LimitsError::Transfer(self.max_transfer));
        }
        let (trackers_per, requests_per) =
            match u64::from(self.boundary) * u64::from(self.sector_size) {
                0 => (1, 1),
                bytes => {
                    let children =
                        u32::try_from(u64::from(transfer).div_ceil(bytes) + 1).unwrap_or(u32::MAX);
                    (children, children.saturating_add(1))
                }
            };
        let trackers = self.max_queue_size
            - (self.max_queue_size / 4)
                .clamp(1, 128)
                .min(self.max_queue_size);
        let depth = requested.min(trackers / trackers_per);
        if depth == 0 {
            return Err(LimitsError::Depth);
        }
        Ok(Limits {
            sector_size: self.sector_size,
            sector_shift: self.sector_size.trailing_zeros(),
            capacity: capacity / u64::from(unit) * u64::from(unit),
            transfer,
            depth,
            io_queue_size: self.max_queue_size,
            io_queue_requests: depth.saturating_mul(requests_per),
        })
    }
}
