//! Portable expiry: a volume's bounded physical-clock provider, the clock contract every root carries, and the portable pair a publication binds beside its key, which carries a binding's expiry across a crash, restart or host replacement in physical time.
//!
//! Invariants owned by this module:
//!
//! - EXPIRY-SHORTENS: a present pair comes only from a reading its provider reported trusted within the contract's maximum uncertainty, taken before the publication's monotonic sample, and names a physical instant at or before the physical instant of the binding's whole-second live deadline, through the writer's upper rate bound; the recovery conversion converts back from the recovering host's latest bound through its lower rate bound and withholds every other case by cause.
//! - Every other reading yields [`PortableExpiry::ABSENT`] with one counted [`Absent`] cause and changes no live outcome: the live deadline, lookups, sweeps and PUT outcomes read only the monotonic deadline.
//! - COLD-START: a cold attach writes RESET roots carrying the clock contract; a warm attach writes no root and converts the checkpoint's pairs under the shard's configured contract (the `volume` module's warm ONE-CONTRACT).
//! - A provider's `read` does constant work, never blocks, allocates or calls into storage, and runs outside every storage gate.

mod clock;
mod contract;
#[cfg(test)]
mod contract_provider_tests;
mod expiry;
#[cfg(test)]
mod expiry_tests;
mod pair;
#[cfg(test)]
pub(crate) mod plant;
pub(crate) mod recovery;
#[cfg(test)]
mod recovery_tests;
#[cfg(test)]
pub(crate) mod scripted;
mod segment_v2;
#[cfg(all(
    test,
    target_arch = "aarch64",
    target_os = "linux",
    not(miri),
    not(loom)
))]
mod segment_v2_barrier_tests;
#[cfg(test)]
mod segment_v2_tests;

#[cfg(test)]
pub(crate) use clock::sealed as clock_seal;
pub use clock::{ClockScale, PhysicalClock, Reading, Trust, Untrusted};
pub(crate) use contract::CONTRACT_LEN;
#[cfg(test)]
pub(crate) use contract::Malformed;
pub use contract::{ClockContract, ContractError};
pub use expiry::Absent;
pub(crate) use pair::PortableExpiry;
pub use pair::{AbsentCounts, ClockReport};
pub use segment_v2::{DEFAULT_MARKER, DEFAULT_SEGMENT, SegmentV2, SegmentV2Error};
