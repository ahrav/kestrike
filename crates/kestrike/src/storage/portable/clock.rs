//! The bounded physical-clock reading a volume's provider returns, and the provider trait.
//!
//! A reading names an interval `[earliest, latest]` of nanoseconds since the Unix epoch on the provider's scale, which holds true time when the provider reports it trusted, and otherwise one typed cause from a closed set.

use super::expiry::NANOS_PER_SECOND;

/// The shortest span between two consecutive UTC month ends, February's 28 days, in nanoseconds.
const MONTH_END_SPACING_NS: u128 = 28 * 86_400 * NANOS_PER_SECOND as u128;

/// A physical time scale with its leap-second profile, in nanoseconds since the Unix epoch, as a clock contract and a provider name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClockScale {
    /// UTC with each leap second smeared linearly over the 24 hours around it.
    UtcSmeared,
    /// UTC with each leap second stepped: an inserted leap second repeats one label and a removed one skips a label.
    UtcStepped,
}

impl ClockScale {
    /// The scale's byte in a root's clock contract.
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::UtcSmeared => 1,
            Self::UtcStepped => 2,
        }
    }

    /// The allowance bounds the leap-second discrepancy between `span_ns` of true time and the difference between its endpoint labels, in nanoseconds.
    ///
    /// A smeared scale spreads each leap second into a rate change, which the contract's rate-error bound covers, so its allowance is zero.
    /// A stepped scale moves by one second at each leap second, and a leap second falls only at the end of a UTC month; consecutive month ends lie at least 28 days apart, so a span holds at most `span_ns / 28 days + 1` of them and the allowance is that many seconds.
    pub(crate) const fn leap_allowance_ns(self, span_ns: u128) -> u128 {
        match self {
            Self::UtcSmeared => 0,
            Self::UtcStepped => (span_ns / MONTH_END_SPACING_NS + 1) * NANOS_PER_SECOND as u128,
        }
    }

    pub(crate) const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::UtcSmeared),
            2 => Some(Self::UtcStepped),
            _ => None,
        }
    }
}

/// Why a provider reports a reading untrusted; the closed set every provider maps its conditions onto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Untrusted {
    /// The provider's source reports its clock status unknown, or a status this build does not name.
    Unknown,
    /// The source reports the clock disrupted, so its accuracy has no bound.
    Disrupted,
    /// The monotonic sample lies past the snapshot's void-after instant.
    Stale,
    /// The source carries a layout version this build does not read.
    Unsupported,
    /// The source holds a field outside its domain: a negative bound, a drift rate of at least one part per one, an invalid time value, a support flag other than 0 or 1, a bound past `u64`, or an instant after the provider's own later monotonic sample.
    Malformed,
    /// The source is absent or shorter than its layout.
    Missing,
    /// The source reports disruption detection disabled, so a disruption would go unseen.
    DisruptionSupportOff,
    /// The hypervisor's disruption marker cannot be read.
    MarkerUnavailable,
    /// The hypervisor's disruption marker differs from the one the source recorded.
    MarkerMismatch,
    /// A boot-time offset bracket showed a suspend after the snapshot was written.
    Suspended,
    /// Every attempt failed and no consistent snapshot was ever read.
    NoSnapshot,
    /// The snapshot was written before the provider's first bracket: no writer update was observed since construction.
    NoWriterUpdate,
    /// Every suspend bracket was wider than the provider's validated limit, or a clock read failed.
    UnboundedBracket,
    /// The source's writer can make its body stores visible to this CPU before the odd generation store that opens an update, so a snapshot read between two equal even generations may mix two updates.
    UnorderedWriter,
}

/// A provider's verdict on one reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Trust {
    Trusted,
    Untrusted(Untrusted),
}

/// One bounded physical-clock reading; the bounds are meaningful only when `trust` is [`Trust::Trusted`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    pub earliest: u64,
    pub latest: u64,
    pub trust: Trust,
}

impl Reading {
    /// An untrusted reading with no bounds.
    pub const fn untrusted(cause: Untrusted) -> Self {
        Self {
            earliest: 0,
            latest: 0,
            trust: Trust::Untrusted(cause),
        }
    }
}

/// The seal that keeps every provider inside this crate: the volume reads exactly one provider kind in production.
pub(crate) mod sealed {
    pub trait Sealed {}
}

/// A bounded physical-clock provider a volume owns on its owner thread; [`SegmentV2`](super::SegmentV2) is its one production implementation.
///
/// [`read`](Self::read) runs on the publication path outside every storage gate; an implementation never blocks, allocates or calls into storage, and does constant work per call.
pub trait PhysicalClock: sealed::Sealed {
    /// The scale every reading of this provider names.
    fn scale(&self) -> ClockScale;

    /// One bounded reading, trusted or untrusted with one cause.
    fn read(&mut self) -> Reading;
}
