//! Per-peer PUT permission: a fixed grant beside the principal mapping, read only through [`PutPermits::check`].
//!
//! Invariants owned by this module:
//!
//! - Permission comes only from configuration: [`PutPermits::load`] grants exactly the listed principals, each of which must be a peer of the key ring, and nothing grants or revokes permission afterwards. A peer the configuration does not list holds no permission.
//! - [`PutPermits::check`] reads the grant and changes nothing, so an owner that runs it on a PUT BEGIN after session admission and before any fill authority, reservation or credit leaves storage, the request census and every credit unchanged on a refusal.
//! - The grant is one flag per peer, in an array charged once at load; a refusal at load leaves the budget unchanged.

use crate::storage::EngineBudget;

use super::auth::{KeyError, KeyRing};
use super::datagram::PeerId;
use super::frame::Status;

/// Which peers may PUT, one flag per peer in [`PeerId`] order.
#[derive(Debug)]
pub(super) struct PutPermits {
    granted: Box<[bool]>,
}

impl PutPermits {
    /// Bytes the permission of `peers` peers charges.
    pub(super) fn charge(peers: usize) -> usize {
        peers * size_of::<bool>()
    }

    /// Grants PUT to each principal of `granted` among `ring`'s peers, charging [`charge`](Self::charge) bytes against `budget`.
    ///
    /// # Errors
    ///
    /// `Budget`, then for the first offending principal in `granted` order `Unknown` when it is no peer of `ring` or `Duplicate` when it is listed twice; each leaves `budget` unchanged.
    pub(super) fn load(
        ring: &KeyRing,
        granted: &[u32],
        budget: &mut EngineBudget,
    ) -> Result<Self, KeyError> {
        let peers = ring.peers();
        let mut staged = *budget;
        staged
            .charge(Self::charge(peers))
            .map_err(KeyError::Budget)?;
        let mut flags = vec![false; peers].into_boxed_slice();
        for &principal in granted {
            let peer = ring
                .peer_of(principal)
                .ok_or(KeyError::Unknown { principal })?;
            let flag = &mut flags[usize::from(peer.0)];
            if *flag {
                return Err(KeyError::Duplicate { principal });
            }
            *flag = true;
        }
        *budget = staged;
        Ok(Self { granted: flags })
    }

    /// Whether `peer` may PUT: `Ok` for a granted peer, and `Err(PermissionDenied)` for every other peer, including one outside the ring.
    ///
    /// # Errors
    ///
    /// [`Status::PermissionDenied`] when the configuration did not grant `peer` PUT.
    pub(super) fn check(&self, peer: PeerId) -> Result<(), Status> {
        match self.granted.get(usize::from(peer.0)) {
            Some(true) => Ok(()),
            _ => Err(Status::PermissionDenied),
        }
    }
}
