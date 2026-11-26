//! The feed contract: the authority and contract reference whose events a coverage position counts, validated once before any mapping and recorded in every root.

/// The feed whose positions [`Storage::advance_coverage`](super::super::Storage::advance_coverage) takes; both fields are nonzero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeedContract {
    /// The identity of the authority that orders the feed's events.
    pub authority: [u8; 16],
    /// A reference to the contract the feed's delivery, retention and replay follow.
    pub contract: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedError {
    ZeroAuthority,
    ZeroContract,
}

impl FeedContract {
    pub fn validate(&self) -> Result<(), FeedError> {
        if self.authority == [0; 16] {
            return Err(FeedError::ZeroAuthority);
        }
        if self.contract == 0 {
            return Err(FeedError::ZeroContract);
        }
        Ok(())
    }

    /// Each root records the feed as 20 bytes: the authority followed by the little-endian contract reference.
    pub(crate) fn encode(&self) -> [u8; FEED_LEN] {
        let mut bytes = [0; FEED_LEN];
        bytes[..16].copy_from_slice(&self.authority);
        bytes[16..].copy_from_slice(&self.contract.to_le_bytes());
        bytes
    }
}

pub(crate) const FEED_LEN: usize = 20;
