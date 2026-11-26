//! A volume's physical-clock bounds, validated once before any mapping, and the 24 bytes every root carries for them, so a recovering host reads the scale, unit, width, guarantee and provenance under which a portable deadline was written.
//!
//! The encoding, little-endian: scale `u8` at 0, unit `u8` at 1 (1, nanoseconds since the Unix epoch), width `u8` at 2 (64 bits), guarantee kind `u8` at 3 (1, assumption-backed), protocol version `u8` at 4 (2), a zero byte at 5, provider identity `u16` at 6 (1, [`SegmentV2`](super::SegmentV2)), provenance `u32` at 8, the writer's rate-error bound in parts per billion `u32` at 12, and the maximum uncertainty in nanoseconds `u64` at 16.

use super::clock::ClockScale;
use super::expiry::NANOS_PER_SECOND;

pub(crate) const CONTRACT_LEN: usize = 24;

const UNIT_NANOS: u8 = 1;
const WIDTH_BITS: u8 = 64;
const GUARANTEE_ASSUMED: u8 = 1;
const PROTOCOL_VERSION: u8 = 2;
const PROVIDER_SEGMENT_V2: u16 = 1;

/// Physical-clock bounds the caller supplies in full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockContract {
    /// Attach refuses a provider whose readings name another scale.
    pub scale: ClockScale,
    /// The widest reading, latest minus earliest, that converts to a portable deadline; validation requires a positive value.
    pub max_uncertainty_ns: u64,
    /// The upper bound, in parts per billion, on how far the rate of the writer's and a recovering host's `CLOCK_MONOTONIC` departs from true time, clock-discipline slew included; validation requires it below `1e9`.
    pub rate_error_ppb: u32,
    /// A nonzero reference naming where the bounds come from.
    pub provenance: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractError {
    ZeroUncertainty,
    RateErrorTooLarge { rate_error_ppb: u32 },
    ZeroProvenance,
}

impl ClockContract {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.max_uncertainty_ns == 0 {
            return Err(ContractError::ZeroUncertainty);
        }
        if u64::from(self.rate_error_ppb) >= NANOS_PER_SECOND {
            return Err(ContractError::RateErrorTooLarge {
                rate_error_ppb: self.rate_error_ppb,
            });
        }
        if self.provenance == 0 {
            return Err(ContractError::ZeroProvenance);
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> [u8; CONTRACT_LEN] {
        let mut bytes = [0; CONTRACT_LEN];
        bytes[0] = self.scale.code();
        bytes[1] = UNIT_NANOS;
        bytes[2] = WIDTH_BITS;
        bytes[3] = GUARANTEE_ASSUMED;
        bytes[4] = PROTOCOL_VERSION;
        bytes[6..8].copy_from_slice(&PROVIDER_SEGMENT_V2.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.provenance.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.rate_error_ppb.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.max_uncertainty_ns.to_le_bytes());
        bytes
    }

    /// Decodes contract bytes, refusing each malformed field by name in byte order.
    pub(crate) fn decode(bytes: &[u8; CONTRACT_LEN]) -> Result<Self, Malformed> {
        let scale = ClockScale::from_code(bytes[0]).ok_or(Malformed::Scale)?;
        if bytes[1] != UNIT_NANOS {
            return Err(Malformed::Unit);
        }
        if bytes[2] != WIDTH_BITS {
            return Err(Malformed::Width);
        }
        if bytes[3] != GUARANTEE_ASSUMED {
            return Err(Malformed::Guarantee);
        }
        if bytes[4] != PROTOCOL_VERSION {
            return Err(Malformed::Protocol);
        }
        if bytes[5] != 0 {
            return Err(Malformed::Reserved);
        }
        if u16::from_le_bytes([bytes[6], bytes[7]]) != PROVIDER_SEGMENT_V2 {
            return Err(Malformed::Provider);
        }
        let word = |at: usize| {
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        let provenance = word(8);
        if provenance == 0 {
            return Err(Malformed::Provenance);
        }
        let mut uncertainty = [0; 8];
        uncertainty.copy_from_slice(&bytes[16..24]);
        let contract = Self {
            scale,
            max_uncertainty_ns: u64::from_le_bytes(uncertainty),
            rate_error_ppb: word(12),
            provenance,
        };
        contract.validate().map_err(|_| Malformed::Bounds)?;
        Ok(contract)
    }
}

/// The contract field whose bytes lie outside its domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Malformed {
    Scale,
    Unit,
    Width,
    Guarantee,
    Protocol,
    Reserved,
    Provider,
    Provenance,
    /// The bounds fail [`ClockContract::validate`].
    Bounds,
}
