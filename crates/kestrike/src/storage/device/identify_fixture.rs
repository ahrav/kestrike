//! Identify pages built by hand for EBS-like devices: each fixture writes
//! the fields it names at their NVMe and EBS byte offsets, plus a fixed
//! serial, firmware, version and MDTS and the size `facts_sized` takes, and
//! zeroes every other byte.

use super::identify::{
    AttachFacts, AttachedIdentity, IDENTIFY_LEN, IdentifyRaw, IdentifySnapshot, TransferLimits,
};

pub(crate) const SERIAL: &str = "vol0123456789abcdef0";
const EBS_MODEL: &str = "Amazon Elastic Block Store";
/// 64 GiB of 512-byte blocks.
pub(crate) const SECTORS: u64 = 1 << 27;

/// The Identify fields a fixture sets beside its fixed serial, firmware, version and MDTS and its size.
#[derive(Clone, Copy)]
pub(crate) struct Fields {
    pub(crate) vid: u16,
    pub(crate) model: &'static str,
    pub(crate) vwc: u8,
    pub(crate) awupf: u16,
    pub(crate) nsfeat: u8,
    pub(crate) lbads: u8,
    pub(crate) nawupf: u16,
    pub(crate) nabo: u16,
    pub(crate) nabspf: u16,
    /// NTWPU, NTWPG and NTWPB, written at namespace bytes 640 to 647.
    pub(crate) vendor: Option<(u16, u16, u32)>,
    pub(crate) limits: TransferLimits,
}

/// An EBS volume with VWC 0, NSFEAT 0x12 (bits 1 and 4),
/// NAWUPF 31, NABO 0, NABSPF 31, NTWPU 31, NTWPG 7, NTWPB 31, 512-byte
/// blocks, no stripe and 256 KiB commands.
pub(crate) const EBS: Fields = Fields {
    vid: 0x1d0f,
    model: EBS_MODEL,
    vwc: 0,
    awupf: 0,
    nsfeat: 0x12,
    lbads: 9,
    nawupf: 31,
    nabo: 0,
    nabspf: 31,
    vendor: Some((31, 7, 31)),
    limits: TransferLimits {
        namespace_max: 262_144,
        boundary: 0,
        command: 262_144,
    },
};

fn put(page: &mut [u8; IDENTIFY_LEN], at: usize, bytes: &[u8]) {
    page[at..at + bytes.len()].copy_from_slice(bytes);
}

fn padded(text: &str, width: usize) -> Vec<u8> {
    let mut field = text.as_bytes().to_vec();
    field.resize(width, b' ');
    field
}

/// [`facts_sized`] over the 64 GiB [`SECTORS`].
pub(crate) fn facts(fields: Fields) -> AttachFacts {
    facts_sized(fields, SECTORS)
}

/// The facts of a device of `sectors` 512-byte blocks whose Identify pages
/// carry `fields`, with an identity that matches the pages.
pub(crate) fn facts_sized(fields: Fields, sectors: u64) -> AttachFacts {
    let mut c = Box::new([0u8; IDENTIFY_LEN]);
    put(&mut c, 0, &fields.vid.to_le_bytes());
    put(&mut c, 4, &padded(SERIAL, 20));
    put(&mut c, 24, &padded(fields.model, 40));
    put(&mut c, 64, &padded("2.0", 8));
    put(&mut c, 80, &0x0001_0400u32.to_le_bytes());
    c[77] = 6;
    c[525] = fields.vwc;
    put(&mut c, 528, &fields.awupf.to_le_bytes());
    let sector_size = 1u32 << fields.lbads;
    let sectors = sectors * 512 / u64::from(sector_size);
    let mut n = Box::new([0u8; IDENTIFY_LEN]);
    put(&mut n, 0, &sectors.to_le_bytes());
    put(&mut n, 8, &sectors.to_le_bytes());
    n[24] = fields.nsfeat;
    put(&mut n, 36, &fields.nawupf.to_le_bytes());
    put(&mut n, 42, &fields.nabo.to_le_bytes());
    put(&mut n, 44, &fields.nabspf.to_le_bytes());
    put(&mut n, 128, &(u32::from(fields.lbads) << 16).to_le_bytes());
    if let Some((unit, granularity, boundary)) = fields.vendor {
        put(&mut n, 640, &unit.to_le_bytes());
        put(&mut n, 642, &granularity.to_le_bytes());
        put(&mut n, 644, &boundary.to_le_bytes());
    }
    AttachFacts {
        identity: AttachedIdentity {
            serial: SERIAL.to_owned(),
            nsid: 1,
            sector_size,
            capacity: sectors * u64::from(sector_size),
        },
        identify: IdentifySnapshot::new(IdentifyRaw::from_parts(1, c, n), fields.limits),
    }
}
