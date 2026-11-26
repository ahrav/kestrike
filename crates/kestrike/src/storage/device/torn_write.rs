//! The EBS torn-write-prevention fields in the namespace's vendor-specific
//! Identify data. The fields exist only for a controller whose PCI vendor ID
//! and model text name an EBS volume, so decoding returns `None` for any
//! other controller.
//!
//! NTWPU and NTWPG are two-byte and NTWPB a four-byte little-endian count of
//! logical blocks at namespace bytes 640 to 647; each is zero-based, so the
//! size it describes is the value plus one, and an NTWPB of zero reports no
//! boundary.

use super::identify::{IDENTIFY_LEN, IdentifyFacts, IdentifyRaw};
use crate::bind::ControllerIdentity;

/// Namespace byte where the vendor-specific data starts.
const VENDOR_SPECIFIC: usize = 384;

const _: () = assert!(VENDOR_SPECIFIC + 264 <= IDENTIFY_LEN);

/// The EBS torn-write-prevention fields as the namespace reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TornWriteFields {
    /// NTWPU, zero-based, in logical blocks.
    pub unit: u16,
    /// NTWPG, zero-based, in logical blocks.
    pub granularity: u16,
    /// NTWPB, zero-based, in logical blocks; zero means no boundary.
    pub boundary: u32,
}

impl TornWriteFields {
    /// The fields of `raw`'s namespace page, or `None` unless `facts` carry
    /// the EBS vendor ID and model text.
    pub fn decode(raw: &IdentifyRaw, facts: &IdentifyFacts) -> Option<Self> {
        let ebs = ControllerIdentity::EBS;
        if facts.vendor_id != ebs.pci.0 || facts.model != ebs.model {
            return None;
        }
        let page = raw.namespace();
        let at = |offset: usize| VENDOR_SPECIFIC + offset;
        Some(Self {
            unit: u16::from_le_bytes([page[at(256)], page[at(257)]]),
            granularity: u16::from_le_bytes([page[at(258)], page[at(259)]]),
            boundary: u32::from_le_bytes([
                page[at(260)],
                page[at(261)],
                page[at(262)],
                page[at(263)],
            ]),
        })
    }
}
