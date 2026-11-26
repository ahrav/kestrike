//! Device ranges and device geometry, checked in whole [`IO_UNIT`]s and [`SECTOR`]s.
//!
//! A [`DeviceRange`] is refused at construction unless its start is a unit multiple, its length a positive sector multiple, and its end fits `u64`; a command table refuses a length that is not a multiple of its device's block size.
//! A [`DeviceGeometry`] is what a driver reports; [`DeviceGeometry::validate`] rounds capacity and maximum transfer down to the unit and refuses a block size or a limit the substrate cannot use.
//! Limits a particular driver adds, such as scatter-gather segment rules, stay that driver's own refusals.

use super::config::{IO_UNIT, SECTOR};

const UNIT: u64 = IO_UNIT as u64;

/// A byte range on the device: `start..start + len`, `start` an [`IO_UNIT`] multiple and `len` a positive [`SECTOR`] multiple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceRange {
    start: u64,
    len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRangeError {
    MisalignedStart {
        start: u64,
    },
    ZeroLength,
    MisalignedLength {
        len: u32,
    },
    /// `start + len` does not fit `u64`.
    Overflow {
        start: u64,
        len: u32,
    },
}

impl DeviceRange {
    /// # Errors
    ///
    /// In this order: `MisalignedStart`, `ZeroLength`, `MisalignedLength`, then `Overflow`.
    pub fn new(start: u64, len: u32) -> Result<Self, DeviceRangeError> {
        if !start.is_multiple_of(UNIT) {
            return Err(DeviceRangeError::MisalignedStart { start });
        }
        if len == 0 {
            return Err(DeviceRangeError::ZeroLength);
        }
        if !len.is_multiple_of(SECTOR as u32) {
            return Err(DeviceRangeError::MisalignedLength { len });
        }
        if start.checked_add(u64::from(len)).is_none() {
            return Err(DeviceRangeError::Overflow { start, len });
        }
        Ok(Self { start, len })
    }

    pub fn start(&self) -> u64 {
        self.start
    }

    /// Bytes in the range, a positive [`SECTOR`] multiple.
    pub fn byte_len(&self) -> u32 {
        self.len
    }

    /// One past the last byte; construction proved it fits.
    pub fn end(&self) -> u64 {
        self.start + u64::from(self.len)
    }
}

/// A device's shape as its driver reports it. A caller validates it once through [`DeviceGeometry::validate`] and treats the result as constant (I7 on [`Disk`](super::Disk)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceGeometry {
    /// Addressable bytes; only whole [`IO_UNIT`]s of it are usable.
    pub capacity: u64,
    /// Largest transfer one command may carry, in bytes; only whole units of it are usable.
    pub max_transfer: u32,
    /// The device's logical block size in bytes.
    pub block_size: u32,
    /// Commands the driver can hold outstanding at once, net of any entry its hardware queue must keep empty.
    pub queue_depth: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceGeometryError {
    /// The block size is not a power of two from 512 to 4096.
    BlockSize {
        block_size: u32,
    },
    /// Capacity rounds down to zero units.
    ZeroCapacity {
        capacity: u64,
    },
    /// Maximum transfer rounds down to zero units.
    ZeroMaxTransfer {
        max_transfer: u32,
    },
    ZeroQueueDepth,
}

/// A [`DeviceGeometry`] after [`DeviceGeometry::validate`]: capacity and maximum transfer are positive [`IO_UNIT`] multiples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidDeviceGeometry {
    capacity: u64,
    max_transfer: u32,
    block_size: u32,
    queue_depth: u32,
}

impl DeviceGeometry {
    /// Rounds capacity and maximum transfer down to [`IO_UNIT`] and checks every field.
    ///
    /// # Errors
    ///
    /// In this order: `BlockSize`, `ZeroCapacity`, `ZeroMaxTransfer`, then `ZeroQueueDepth`.
    pub fn validate(&self) -> Result<ValidDeviceGeometry, DeviceGeometryError> {
        if !self.block_size.is_power_of_two()
            || !(SECTOR as u32..=IO_UNIT as u32).contains(&self.block_size)
        {
            return Err(DeviceGeometryError::BlockSize {
                block_size: self.block_size,
            });
        }
        let capacity = self.capacity - self.capacity % UNIT;
        if capacity == 0 {
            return Err(DeviceGeometryError::ZeroCapacity {
                capacity: self.capacity,
            });
        }
        let max_transfer = self.max_transfer - self.max_transfer % IO_UNIT as u32;
        if max_transfer == 0 {
            return Err(DeviceGeometryError::ZeroMaxTransfer {
                max_transfer: self.max_transfer,
            });
        }
        if self.queue_depth == 0 {
            return Err(DeviceGeometryError::ZeroQueueDepth);
        }
        Ok(ValidDeviceGeometry {
            capacity,
            max_transfer,
            block_size: self.block_size,
            queue_depth: self.queue_depth,
        })
    }
}

impl ValidDeviceGeometry {
    /// Usable bytes, a positive [`IO_UNIT`] multiple.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Usable bytes per command, a positive [`IO_UNIT`] multiple.
    pub fn max_transfer(&self) -> u32 {
        self.max_transfer
    }

    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    pub fn queue_depth(&self) -> u32 {
        self.queue_depth
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceGeometry, DeviceGeometryError, DeviceRange, DeviceRangeError};

    #[test]
    fn device_ranges_refuse_each_fault_distinctly() {
        let cases = [
            (1, 4096, DeviceRangeError::MisalignedStart { start: 1 }),
            (512, 4096, DeviceRangeError::MisalignedStart { start: 512 }),
            (4096, 0, DeviceRangeError::ZeroLength),
            (0, 513, DeviceRangeError::MisalignedLength { len: 513 }),
            (0, 4097, DeviceRangeError::MisalignedLength { len: 4097 }),
            (
                u64::MAX - 4095,
                8192,
                DeviceRangeError::Overflow {
                    start: u64::MAX - 4095,
                    len: 8192,
                },
            ),
        ];
        for (start, len, error) in cases {
            assert_eq!(DeviceRange::new(start, len), Err(error), "{start} {len}");
        }
        // The highest unit-aligned range whose end still fits `u64`.
        let top = u64::MAX - 4095 - 4096;
        let range = DeviceRange::new(top, 4096).unwrap();
        assert_eq!(
            (range.start(), range.byte_len(), range.end()),
            (top, 4096, u64::MAX - 4095)
        );
    }

    fn geometry(
        capacity: u64,
        max_transfer: u32,
        block_size: u32,
        queue_depth: u32,
    ) -> DeviceGeometry {
        DeviceGeometry {
            capacity,
            max_transfer,
            block_size,
            queue_depth,
        }
    }

    #[test]
    fn geometry_accepts_power_of_two_block_sizes_from_512_to_4096() {
        for block_size in [512, 1024, 2048, 4096] {
            let valid = geometry(1 << 30, 1 << 20, block_size, 32)
                .validate()
                .unwrap();
            assert_eq!(valid.block_size(), block_size);
        }
        for block_size in [0, 256, 3000, 8192] {
            assert_eq!(
                geometry(1 << 30, 1 << 20, block_size, 32).validate(),
                Err(DeviceGeometryError::BlockSize { block_size })
            );
        }
    }

    #[test]
    fn geometry_rounds_down_to_the_unit_and_refuses_what_rounds_to_zero() {
        let valid = geometry(3 * 4096 + 100, 2 * 4096 + 1, 512, 7)
            .validate()
            .unwrap();
        assert_eq!(valid.capacity(), 3 * 4096);
        assert_eq!(valid.max_transfer(), 2 * 4096);
        assert_eq!(valid.queue_depth(), 7);
        assert_eq!(
            geometry(4095, 4096, 512, 1).validate(),
            Err(DeviceGeometryError::ZeroCapacity { capacity: 4095 })
        );
        assert_eq!(
            geometry(4096, 4095, 512, 1).validate(),
            Err(DeviceGeometryError::ZeroMaxTransfer { max_transfer: 4095 })
        );
        assert_eq!(
            geometry(4096, 4096, 512, 0).validate(),
            Err(DeviceGeometryError::ZeroQueueDepth)
        );
    }
}
