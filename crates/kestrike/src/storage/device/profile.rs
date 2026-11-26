//! The persistence profile of an attached device and the eligibility
//! predicate it starts from.
//!
//! [`completion_is_durable`] decides from Identify evidence alone whether a
//! device is eligible for the `completion-without-volatile-cache` profile, a
//! profile under which a device's successful write completion may stand for
//! persistence; its result is an eligibility decision only. A
//! [`PersistenceProfile`] exists only for [`AttachFacts`] that pass the
//! predicate and whose atomic geometry is self-consistent: it states the
//! device's atomic unit, granularity and boundaries, the driver's split
//! limits, and which [`DeviceRange`]s qualify for an atomicity claim.
//!
//! Landing rule, per child command the driver issues: a write whose range
//! [`qualifies`](PersistenceProfile::qualifies) leaves all old or all new
//! bytes in its range after a crash, a reset or an error status; any other
//! write may leave arbitrary bytes in its range until a successful
//! completion; and a write without an observed completion may still land
//! until the driver's quiesce reports `QuiesceStatus::Stopped`, an assumed
//! end of the landing window. The profile claims eligibility and geometry;
//! whether a completion implies backend durability is the backend service
//! contract's assumption, which [`ProfileKind`] names.

use super::config::IO_UNIT;
use super::geometry::DeviceRange;
use super::identify::{
    AttachFacts, AttachedIdentity, IdentifyFacts, IdentifyMalformed, IdentifyRaw, IdentifyRecord,
    TransferLimits,
};
use super::torn_write::TornWriteFields;

/// Why Identify evidence leaves a device ineligible for the profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileRefusal {
    /// A structure is absent or not whole.
    Incomplete,
    Malformed(IdentifyMalformed),
    /// The evidence describes another device than the attached one, such as a record from an earlier attach.
    Mismatch,
    /// The controller reports a volatile write cache, so a completion may precede persistence.
    VolatileWriteCache,
}

/// Whether `record` admits the `completion-without-volatile-cache` profile for `attached`:
/// both structures whole, decodable, describing the attached serial,
/// namespace, block size and capacity, and reporting no volatile write cache.
///
/// # Errors
///
/// The first failed condition, in the order above.
pub fn completion_is_durable(
    record: IdentifyRecord<'_>,
    attached: &AttachedIdentity,
) -> Result<(), ProfileRefusal> {
    let raw = IdentifyRaw::from_record(record).ok_or(ProfileRefusal::Incomplete)?;
    let facts = IdentifyFacts::decode(&raw).map_err(ProfileRefusal::Malformed)?;
    let capacity = facts.sectors.checked_mul(u64::from(facts.sector_size));
    if facts.serial != attached.serial
        || facts.nsid != attached.nsid
        || facts.sector_size != attached.sector_size
        || capacity != Some(attached.capacity)
    {
        return Err(ProfileRefusal::Mismatch);
    }
    if facts.volatile_write_cache.present {
        return Err(ProfileRefusal::VolatileWriteCache);
    }
    Ok(())
}

/// The kinds of persistence profile a device can derive.
///
/// A profile claims eligibility and geometry only. Its persistence claim
/// rests on the backend service contract: that a successful write
/// completion on a device with no volatile write cache means the backend
/// stored the bytes. Identify data cannot show that, and the claim stays an
/// assumption until the backend owner accepts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileKind {
    /// No volatile write cache: a successful completion may stand for persistence.
    CompletionWithoutVolatileCache,
}

impl ProfileKind {
    /// The profile's stable name, which receipts and oracle rows quote.
    pub fn name(self) -> &'static str {
        match self {
            Self::CompletionWithoutVolatileCache => "completion-without-volatile-cache",
        }
    }
}

/// An atomic boundary, in logical blocks: a write crossing `offset + k * period`
/// for any `k >= 0` carries no atomicity claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Boundary {
    pub offset: u64,
    pub period: u64,
}

/// Which Identify fields supplied the profile's atomic unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitSource {
    /// Neither source reports a unit above one block.
    OneBlock,
    /// The NVM command set fields alone.
    Standard,
    /// The EBS torn-write-prevention fields alone.
    Vendor,
    /// Both sources, which agree on the unit.
    Both,
}

/// Why eligible Identify evidence still yields no profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicsRefusal {
    /// Both sources report a unit above one block, and the units differ.
    UnitsDisagree { standard: u64, vendor: u64 },
    /// The standard boundary's offset NABO is not below its period NABSPF + 1.
    BoundaryOffset { offset: u64, period: u64 },
    /// The sector size does not divide 4096 bytes.
    SectorSize { sector_size: u32 },
    /// One atomic unit spans more bytes than the driver's largest command.
    UnitExceedsCommand { unit_bytes: u64, command: u32 },
    /// The unit is not the granularity times a power of two.
    UnitNotGranularityPower { unit: u64, granularity: u64 },
    /// The driver's stripe is neither zero nor a power of two.
    StripeNotPowerOfTwo { stripe: u32 },
    /// Each of the first `QUALIFY_PROBES` unit-sized ranges below capacity
    /// whose start is aligned to both the unit and [`IO_UNIT`] crosses a
    /// reported boundary or the driver's stripe.
    NoQualifyingRange,
}

/// Why [`PersistenceProfile::derive`] refused, in the order it checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeriveRefusal {
    /// The eligibility predicate's refusal, unchanged.
    Ineligible(ProfileRefusal),
    /// Eligible evidence whose atomic geometry is inconsistent or unissuable.
    Atomics(AtomicsRefusal),
}

/// The maximum number of starts aligned to both the unit and [`IO_UNIT`]
/// that [`PersistenceProfile::derive`] examines for a qualifying range. If
/// the first qualifying range lies beyond this search limit, `derive`
/// returns `NoQualifyingRange`.
const QUALIFY_PROBES: u64 = 1 << 16;

/// One source's atomic geometry, in logical blocks.
#[derive(Debug, Clone, Copy)]
struct Candidate {
    unit: u64,
    granularity: u64,
    boundary: Option<Boundary>,
}

/// Requires `value != 0`: zero's 64 trailing zeros overflow the shift.
fn odd_factor(value: u64) -> u64 {
    value >> value.trailing_zeros()
}

/// The standard candidate: NAWUPF + 1 when NSFEAT bit 1 applies the
/// namespace fields and NAWUPF is nonzero, else AWUPF + 1, at granularity
/// one block, with the boundary `(NABO, NABSPF + 1)` when NSFEAT bit 1
/// applies the namespace fields and NABSPF is nonzero.
fn standard_candidate(decoded: &IdentifyFacts) -> Candidate {
    let atomics = decoded.atomics;
    let unit = if atomics.applies && atomics.nawupf != 0 {
        u64::from(atomics.nawupf) + 1
    } else {
        u64::from(decoded.awupf) + 1
    };
    Candidate {
        unit,
        granularity: 1,
        boundary: (atomics.applies && atomics.nabspf != 0).then_some(Boundary {
            offset: u64::from(atomics.nabo),
            period: u64::from(atomics.nabspf) + 1,
        }),
    }
}

/// The vendor candidate: NTWPU + 1 at granularity NTWPG + 1, with the
/// boundary NTWPB + 1 at offset 0 when NTWPB is nonzero.
fn vendor_candidate(fields: TornWriteFields) -> Candidate {
    Candidate {
        unit: u64::from(fields.unit) + 1,
        granularity: u64::from(fields.granularity) + 1,
        boundary: (fields.boundary != 0).then_some(Boundary {
            offset: 0,
            period: u64::from(fields.boundary) + 1,
        }),
    }
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// A range whose length is `unit` divided by a power of two and whose start
/// is a multiple of that length fits between consecutive multiples of
/// `unit`. A boundary whose instances are all multiples of `unit` therefore
/// maps to `None`; any other maps to bytes.
fn binding(boundary: Option<Boundary>, sector: u64, unit: u64) -> Option<Boundary> {
    let Boundary { offset, period } = boundary?;
    let (offset, period) = (offset * sector, period * sector);
    (!(offset.is_multiple_of(unit) && period.is_multiple_of(unit)))
        .then_some(Boundary { offset, period })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ByteGeometry {
    /// The granularity, the shortest qualifying length.
    granule: u64,
    /// The unit, the longest qualifying length: the granule times a power of two.
    unit: u64,
    capacity: u64,
    boundaries: [Option<Boundary>; 2],
    /// The driver's stripe in bytes, a power of two, present when the
    /// driver reports a stripe that is not a unit multiple, by the rule of
    /// [`binding`].
    stripe: Option<u64>,
}

impl ByteGeometry {
    fn admits(&self, len: u64) -> bool {
        len.is_multiple_of(self.granule)
            && (len / self.granule).is_power_of_two()
            && len <= self.unit
    }

    fn crosses(&self, start: u64, len: u64) -> bool {
        let end = start + len;
        let crosses = |boundary: &Boundary| {
            let Boundary { offset, period } = *boundary;
            if start < offset {
                offset < end
            } else {
                (start - offset) % period + len > period
            }
        };
        self.boundaries.iter().flatten().any(crosses)
            || self
                .stripe
                .is_some_and(|stripe| (start & (stripe - 1)) + len > stripe)
    }
}

/// The persistence profile of one attached device, derived once from the
/// [`AttachFacts`] its driver returned; [`derive`](Self::derive) is the only
/// constructor. Sizes are in logical blocks of [`sector_size`](Self::sector_size)
/// bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistenceProfile {
    kind: ProfileKind,
    unit: u64,
    granularity: u64,
    standard: Option<Boundary>,
    vendor: Option<Boundary>,
    unit_source: UnitSource,
    sector_size: u32,
    limits: TransferLimits,
    identity: AttachedIdentity,
    atomicity_mode: bool,
    bytes: ByteGeometry,
}

impl PersistenceProfile {
    /// The profile `facts` support. A source reports a candidate only above
    /// one block; with none the unit is one block, with one it is that
    /// source's, and with both the units must agree and the vendor
    /// granularity applies. Every boundary a source reports applies, whether
    /// or not that source reports a unit.
    ///
    /// # Errors
    ///
    /// [`completion_is_durable`]'s refusal first, as `Ineligible`; then, as
    /// `Atomics`: `UnitsDisagree`, `BoundaryOffset`, `SectorSize`,
    /// `UnitExceedsCommand`, `UnitNotGranularityPower`,
    /// `StripeNotPowerOfTwo` and `NoQualifyingRange`, in that order.
    pub fn derive(facts: &AttachFacts) -> Result<Self, DeriveRefusal> {
        let raw = facts.identify.raw();
        completion_is_durable(raw.record(), &facts.identity).map_err(DeriveRefusal::Ineligible)?;
        // The predicate decoded the same bytes, so this refusal is unreachable here.
        let decoded = facts
            .identify
            .decoded()
            .map_err(|malformed| DeriveRefusal::Ineligible(ProfileRefusal::Malformed(malformed)))?;
        let refuse = |refusal| Err(DeriveRefusal::Atomics(refusal));
        let reported_standard = standard_candidate(decoded);
        let reported_vendor = TornWriteFields::decode(raw, decoded).map(vendor_candidate);
        let standard = Some(reported_standard).filter(|candidate| candidate.unit > 1);
        let vendor = reported_vendor.filter(|candidate| candidate.unit > 1);
        let (geometry, unit_source) = match (standard, vendor) {
            (None, None) => (
                Candidate {
                    unit: 1,
                    granularity: 1,
                    boundary: None,
                },
                UnitSource::OneBlock,
            ),
            (Some(standard), None) => (standard, UnitSource::Standard),
            (None, Some(vendor)) => (vendor, UnitSource::Vendor),
            (Some(standard), Some(vendor)) => {
                if standard.unit != vendor.unit {
                    return refuse(AtomicsRefusal::UnitsDisagree {
                        standard: standard.unit,
                        vendor: vendor.unit,
                    });
                }
                (vendor, UnitSource::Both)
            }
        };
        let standard_boundary = reported_standard.boundary;
        let vendor_boundary = reported_vendor.and_then(|candidate| candidate.boundary);
        if let Some(Boundary { offset, period }) =
            standard_boundary.filter(|b| b.offset >= b.period)
        {
            return refuse(AtomicsRefusal::BoundaryOffset { offset, period });
        }
        let sector_size = decoded.sector_size;
        if 4096 % sector_size != 0 {
            return refuse(AtomicsRefusal::SectorSize { sector_size });
        }
        let limits = facts.identify.transfer();
        let Candidate {
            unit, granularity, ..
        } = geometry;
        let unit_bytes = unit * u64::from(sector_size);
        if unit_bytes > u64::from(limits.command) {
            return refuse(AtomicsRefusal::UnitExceedsCommand {
                unit_bytes,
                command: limits.command,
            });
        }
        if odd_factor(unit) != odd_factor(granularity) || unit < granularity {
            return refuse(AtomicsRefusal::UnitNotGranularityPower { unit, granularity });
        }
        if limits.boundary != 0 && !limits.boundary.is_power_of_two() {
            return refuse(AtomicsRefusal::StripeNotPowerOfTwo {
                stripe: limits.boundary,
            });
        }
        let sector = u64::from(sector_size);
        let granule = granularity * sector;
        let bytes = ByteGeometry {
            granule,
            unit: unit_bytes,
            capacity: facts.identity.capacity,
            boundaries: [
                binding(standard_boundary, sector, unit_bytes),
                binding(vendor_boundary, sector, unit_bytes),
            ],
            stripe: (limits.boundary != 0)
                .then(|| u64::from(limits.boundary) * sector)
                .filter(|stripe| !stripe.is_multiple_of(unit_bytes)),
        };
        let profile = Self {
            kind: ProfileKind::CompletionWithoutVolatileCache,
            unit,
            granularity,
            standard: standard_boundary,
            vendor: vendor_boundary,
            unit_source,
            sector_size,
            limits,
            identity: facts.identity.clone(),
            atomicity_mode: decoded.atomicity_mode,
            bytes,
        };
        if !profile.has_qualifying_unit() {
            return refuse(AtomicsRefusal::NoQualifyingRange);
        }
        Ok(profile)
    }

    /// Whether one of the first [`QUALIFY_PROBES`] unit-length ranges that
    /// start on a multiple of `stride` and end within capacity qualifies.
    /// A unit-length range qualifies only at a start aligned to the unit, and
    /// a [`DeviceRange`] starts on an [`IO_UNIT`] multiple, so `stride` is
    /// their least common multiple. Whether the range at `k * stride` crosses
    /// a constraint of period `p` depends on `k * stride` modulo `p`, which
    /// repeats in `k` every `p / gcd(stride, p)` steps, so the scan covers the
    /// least common multiple of those cycles, capped at [`QUALIFY_PROBES`].
    fn has_qualifying_unit(&self) -> bool {
        let bytes = &self.bytes;
        let unit = bytes.unit;
        let io_unit = IO_UNIT as u64;
        let stride = unit / gcd(unit, io_unit) * io_unit;
        let periods = bytes.boundaries.iter().flatten().map(|b| b.period);
        let cycle = periods.chain(bytes.stripe).fold(1, |cycle, period| {
            let repeat = period / gcd(stride, period);
            (cycle / gcd(cycle, repeat))
                .saturating_mul(repeat)
                .min(QUALIFY_PROBES)
        });
        let starts = bytes
            .capacity
            .checked_sub(unit)
            .map_or(0, |room| room / stride + 1);
        (0..starts.min(cycle)).any(|k| !bytes.crosses(k * stride, unit))
    }

    /// Whether a write of `range` carries this profile's atomicity claim:
    /// its length is whole sectors, the granularity times a power of two
    /// and at most the unit, which [`derive`](Self::derive) proved fits one
    /// command; its start is aligned to its length; it fits within one stripe
    /// and within one span between consecutive instances of each boundary;
    /// and it ends within the namespace. The result depends only on the
    /// range and the derived geometry.
    pub fn qualifies(&self, range: DeviceRange) -> bool {
        let bytes = &self.bytes;
        let (start, len) = (range.start(), u64::from(range.byte_len()));
        // A `DeviceRange` start is a 4096-byte multiple and `derive` proved the sector size divides 4096, so byte-domain alignment decides as block-domain alignment does.
        bytes.admits(len)
            && start.is_multiple_of(len)
            && range.end() <= bytes.capacity
            && !bytes.crosses(start, len)
    }

    pub fn kind(&self) -> ProfileKind {
        self.kind
    }

    /// The atomic unit in logical blocks.
    pub fn unit(&self) -> u64 {
        self.unit
    }

    /// The granularity in logical blocks: a qualified length is this times a power of two.
    pub fn granularity(&self) -> u64 {
        self.granularity
    }

    /// The NVM command set boundary, as NABO and NABSPF report it.
    pub fn standard_boundary(&self) -> Option<Boundary> {
        self.standard
    }

    /// The EBS torn-write-prevention boundary, as NTWPB reports it.
    pub fn vendor_boundary(&self) -> Option<Boundary> {
        self.vendor
    }

    pub fn unit_source(&self) -> UnitSource {
        self.unit_source
    }

    /// Bytes in one logical block.
    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }

    /// The driver's split limits the profile was derived with.
    pub fn limits(&self) -> TransferLimits {
        self.limits
    }

    /// The device the profile was derived for.
    pub fn identity(&self) -> &AttachedIdentity {
        &self.identity
    }

    /// NSFEAT bit 6 as decoded, exposed for reporting.
    pub fn atomicity_mode(&self) -> bool {
        self.atomicity_mode
    }
}
