//! Owned NVMe Identify data: the controller and namespace structures a driver
//! copies at attach, and their decoding into stable facts.
//!
//! - An [`IdentifyRaw`] owns both 4096-byte structures and the namespace ID
//!   they describe, so its bytes stay readable after the native controller
//!   detaches or its native memory is reused.
//! - [`IdentifyFacts::decode`] is a pure function of an [`IdentifyRaw`]: it
//!   reads the bytes through the typed bindings, and zero-based fields keep
//!   the value the device reported.
//! - An [`IdentifySnapshot`] keeps the raw bytes beside the decoding the
//!   driver derived from them and the transfer limits it derived at attach.

use std::mem::{offset_of, size_of};

use spdk_sys as sys;

/// Bytes in one Identify data structure.
pub const IDENTIFY_LEN: usize = 4096;

const _: () = assert!(size_of::<sys::spdk_nvme_ctrlr_data>() == IDENTIFY_LEN);
const _: () = assert!(size_of::<sys::spdk_nvme_ns_data>() == IDENTIFY_LEN);
const _: () = assert!(offset_of!(sys::spdk_nvme_ns_data, vendor_specific) + 3712 == IDENTIFY_LEN);

/// Owned copies of a controller's and one namespace's Identify data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifyRaw {
    nsid: u32,
    controller: Box<[u8; IDENTIFY_LEN]>,
    namespace: Box<[u8; IDENTIFY_LEN]>,
}

/// Borrowed Identify evidence that may be partial, such as bytes read back
/// from a receipt: a structure is absent or has another length when it was
/// not captured whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentifyRecord<'a> {
    pub nsid: u32,
    pub controller: Option<&'a [u8]>,
    pub namespace: Option<&'a [u8]>,
}

impl IdentifyRaw {
    /// Copies both structures out of native memory, or returns `None` when
    /// `namespace` is null.
    ///
    /// # Safety
    ///
    /// `namespace` is null or points at a readable structure that nothing
    /// writes for the duration of the call.
    pub(crate) unsafe fn capture(
        controller: &sys::spdk_nvme_ctrlr_data,
        namespace: *const sys::spdk_nvme_ns_data,
        nsid: u32,
    ) -> Option<Self> {
        if namespace.is_null() {
            return None;
        }
        // SAFETY: both structures are `IDENTIFY_LEN` bytes of plain data with no padding: the controller binding is `repr(C, packed)`, and the namespace binding's fields tile its bytes, as its last field's offset assertion above and the per-target C/Rust layout tables check. `namespace` is readable and unwritten by the caller's contract.
        let (controller, namespace) = unsafe {
            (
                std::ptr::from_ref(controller)
                    .cast::<[u8; IDENTIFY_LEN]>()
                    .read(),
                namespace.cast::<[u8; IDENTIFY_LEN]>().read(),
            )
        };
        Some(Self {
            nsid,
            controller: Box::new(controller),
            namespace: Box::new(namespace),
        })
    }

    /// Owned copies of `record`'s structures, when both are present and whole.
    pub fn from_record(record: IdentifyRecord<'_>) -> Option<Self> {
        let whole = |bytes: Option<&[u8]>| bytes?.try_into().ok().map(Box::new);
        Some(Self {
            nsid: record.nsid,
            controller: whole(record.controller)?,
            namespace: whole(record.namespace)?,
        })
    }

    /// Both structures from bytes a caller already holds.
    #[cfg(test)]
    pub(crate) fn from_parts(
        nsid: u32,
        controller: Box<[u8; IDENTIFY_LEN]>,
        namespace: Box<[u8; IDENTIFY_LEN]>,
    ) -> Self {
        Self {
            nsid,
            controller,
            namespace,
        }
    }

    /// The structures as a complete record.
    pub fn record(&self) -> IdentifyRecord<'_> {
        IdentifyRecord {
            nsid: self.nsid,
            controller: Some(&self.controller[..]),
            namespace: Some(&self.namespace[..]),
        }
    }

    pub(crate) fn ctratt(&self) -> u32 {
        let at = std::mem::offset_of!(sys::spdk_nvme_ctrlr_data, ctratt);
        u32::from_le_bytes(
            self.controller[at..at + 4]
                .try_into()
                .expect("four CTRATT bytes"),
        )
    }

    pub fn controller(&self) -> &[u8; IDENTIFY_LEN] {
        &self.controller
    }

    pub fn namespace(&self) -> &[u8; IDENTIFY_LEN] {
        &self.namespace
    }
}

/// The NVMe version the controller reports in its Identify data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvmeVersion {
    pub major: u16,
    pub minor: u8,
    pub tertiary: u8,
}

/// The controller's volatile write cache field (VWC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolatileWriteCache {
    /// Bit 0: a volatile write cache is present.
    pub present: bool,
    /// Bits 2:1: how a flush with the broadcast namespace ID behaves.
    pub flush_broadcast: u8,
}

/// The namespace's atomicity and boundary fields. Each zero-based field
/// holds the reported value, which is one less than the size it describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceAtomics {
    /// NSFEAT bit 1: NAWUN, NAWUPF and NACWU apply to this namespace in place
    /// of the controller's AWUN, AWUPF and ACWU.
    pub applies: bool,
    /// Atomic write unit normal, zero-based, in logical blocks.
    pub nawun: u16,
    /// Atomic write unit power fail, zero-based, in logical blocks.
    pub nawupf: u16,
    /// Atomic compare and write unit, zero-based, in logical blocks.
    pub nacwu: u16,
    /// Atomic boundary size normal, zero-based, in logical blocks; zero means no boundary.
    pub nabsn: u16,
    /// Atomic boundary offset, in logical blocks.
    pub nabo: u16,
    /// Atomic boundary size power fail, zero-based, in logical blocks; zero means no boundary.
    pub nabspf: u16,
    /// Optimal I/O boundary, in logical blocks; zero means none reported.
    pub noiob: u16,
}

/// What the controller and namespace Identify data report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifyFacts {
    /// The PCI vendor ID (VID), controller bytes 0 and 1.
    pub vendor_id: u16,
    pub serial: String,
    pub model: String,
    pub firmware: String,
    pub version: NvmeVersion,
    pub volatile_write_cache: VolatileWriteCache,
    /// Optional NVM command support (ONCS), as reported.
    pub oncs: u16,
    /// Controller attributes (CTRATT); bit 0 selects extended host identifiers and extended Reports.
    pub ctratt: u32,
    /// Maximum data transfer size (MDTS) as a power of two in minimum memory pages; zero means no limit.
    pub mdts: u8,
    /// Atomic write unit normal, zero-based, in logical blocks.
    pub awun: u16,
    /// Atomic write unit power fail, zero-based, in logical blocks.
    pub awupf: u16,
    /// Atomic compare and write unit, zero-based, in logical blocks.
    pub acwu: u16,
    pub nsid: u32,
    /// Namespace size (NSZE) in logical blocks.
    pub sectors: u64,
    /// The active LBA format's index.
    pub lba_format: u8,
    /// The active format's logical block size in bytes.
    pub sector_size: u32,
    /// The active format's metadata bytes per logical block.
    pub metadata_size: u16,
    pub atomics: NamespaceAtomics,
    /// NSFEAT bit 6, read from namespace byte 24: the controller reports
    /// multiple atomicity mode for the namespace's atomic fields.
    pub atomicity_mode: bool,
}

/// Why Identify bytes do not decode into facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifyMalformed {
    /// The serial, model or firmware field holds a byte outside printable ASCII.
    Text,
    /// The active format index exceeds the namespace's last format.
    LbaFormat { index: u8, last: u8 },
    /// The active format's block size exponent is below 9 or above 31.
    SectorSize(u8),
}

/// The text of a fixed-width ASCII Identify field, without trailing NULs and
/// padding spaces. Attach matches the serial and model through this rule, and
/// decoding derives every text fact through it.
///
/// # Errors
///
/// `Text` when a byte before the padding is outside printable ASCII.
pub(crate) fn identify_text(field: &[u8]) -> Result<String, IdentifyMalformed> {
    let end = field
        .iter()
        .rposition(|&b| b != 0 && b != b' ')
        .map_or(0, |i| i + 1);
    let field = &field[..end];
    if !field.iter().all(|b| (b' '..=b'~').contains(b)) {
        return Err(IdentifyMalformed::Text);
    }
    Ok(field.iter().copied().map(char::from).collect())
}

impl IdentifyFacts {
    /// Decodes `raw` through the typed controller and namespace bindings.
    ///
    /// # Errors
    ///
    /// In this order: [`IdentifyMalformed::Text`], `LbaFormat`, `SectorSize`.
    pub fn decode(raw: &IdentifyRaw) -> Result<Self, IdentifyMalformed> {
        // SAFETY: both bindings are plain integer, array, bitfield and union fields of exactly `IDENTIFY_LEN` bytes, so every byte pattern is a valid value, and the reads are unaligned.
        let (c, n) = unsafe {
            (
                raw.controller
                    .as_ptr()
                    .cast::<sys::spdk_nvme_ctrlr_data>()
                    .read_unaligned(),
                raw.namespace
                    .as_ptr()
                    .cast::<sys::spdk_nvme_ns_data>()
                    .read_unaligned(),
            )
        };
        let (sn, mn) = (c.sn.map(|b| b as u8), c.mn.map(|b| b as u8));
        let (serial, model, firmware) = (
            identify_text(&sn)?,
            identify_text(&mn)?,
            identify_text(&c.fr)?,
        );
        // SAFETY: every variant of the version register union is a 32-bit integer view.
        let version = unsafe { c.ver.bits };
        let (vwc, flbas, nsfeat) = (c.vwc, n.flbas, n.nsfeat);
        // NLBAF is zero-based; values >= 16 indicate at least 17 formats, and
        // FLBAS bits 6:5 then carry the index's high bits.
        let msb = if n.nlbaf >= 16 {
            flbas.msb_format() << 4
        } else {
            0
        };
        let index = flbas.format() | msb;
        if index > n.nlbaf {
            return Err(IdentifyMalformed::LbaFormat {
                index,
                last: n.nlbaf,
            });
        }
        let format = n.lbaf[usize::from(index)];
        let lbads = format.lbads() as u8;
        if !(9..=31).contains(&lbads) {
            return Err(IdentifyMalformed::SectorSize(lbads));
        }
        // The ONCS binding exposes one accessor per flag, so the reported word is read at its typed offset.
        let oncs = offset_of!(sys::spdk_nvme_ctrlr_data, oncs);
        Ok(Self {
            vendor_id: u16::from_le_bytes([raw.controller[0], raw.controller[1]]),
            serial,
            model,
            firmware,
            version: NvmeVersion {
                major: version.mjr() as u16,
                minor: version.mnr() as u8,
                tertiary: version.ter() as u8,
            },
            volatile_write_cache: VolatileWriteCache {
                present: vwc.present() == 1,
                flush_broadcast: vwc.flush_broadcast(),
            },
            oncs: u16::from_le_bytes([raw.controller[oncs], raw.controller[oncs + 1]]),
            ctratt: raw.ctratt(),
            mdts: c.mdts,
            awun: c.awun,
            awupf: c.awupf,
            acwu: c.acwu,
            nsid: raw.nsid,
            sectors: n.nsze,
            lba_format: index,
            sector_size: 1 << lbads,
            metadata_size: format.ms() as u16,
            atomics: NamespaceAtomics {
                applies: nsfeat.ns_atomic_write_unit() == 1,
                nawun: n.nawun,
                nawupf: n.nawupf,
                nacwu: n.nacwu,
                nabsn: n.nabsn,
                nabo: n.nabo,
                nabspf: n.nabspf,
                noiob: n.noiob,
            },
            atomicity_mode: raw.namespace[24] >> 6 & 1 == 1,
        })
    }
}

/// The transfer limits a driver derived at attach from its native layer's
/// namespace accessors, which also apply the controller's MDTS and memory
/// page size; they are attach observations, not part of the Identify decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferLimits {
    /// The namespace's largest transfer in bytes.
    pub namespace_max: u32,
    /// The optimal I/O boundary in logical blocks the native layer splits commands at; zero for none.
    pub boundary: u32,
    /// The largest command the driver issues, in bytes.
    pub command: u32,
}

/// The device a driver attached, as the binding recorded it and attach
/// verified it against the live controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachedIdentity {
    /// The controller serial, the volume ID's `vol` form.
    pub serial: String,
    pub nsid: u32,
    pub sector_size: u32,
    /// Namespace capacity in bytes.
    pub capacity: u64,
}

/// What a driver established at attach: the device it attached and the
/// Identify data it captured there. Both stay constant for the driver's life
/// and readable after it detaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachFacts {
    pub identity: AttachedIdentity,
    pub identify: IdentifySnapshot,
}

/// The Identify data a driver captured at attach, with its decoding and the
/// driver's transfer limits. `decoded` is [`IdentifyFacts::decode`] of `raw`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifySnapshot {
    raw: IdentifyRaw,
    decoded: Result<IdentifyFacts, IdentifyMalformed>,
    transfer: TransferLimits,
}

impl IdentifySnapshot {
    /// Decodes `raw` and keeps both beside `transfer`.
    pub fn new(raw: IdentifyRaw, transfer: TransferLimits) -> Self {
        let decoded = IdentifyFacts::decode(&raw);
        Self {
            raw,
            decoded,
            transfer,
        }
    }

    pub fn raw(&self) -> &IdentifyRaw {
        &self.raw
    }

    /// The decoded facts, or why the bytes did not decode.
    pub fn decoded(&self) -> Result<&IdentifyFacts, IdentifyMalformed> {
        self.decoded.as_ref().map_err(|&malformed| malformed)
    }

    pub fn transfer(&self) -> TransferLimits {
        self.transfer
    }
}
