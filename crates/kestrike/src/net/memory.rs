//! One endpoint's fixed memory: its receive packet pool, a view over the
//! arena's `PacketReceive` kind, and its request table, validated together
//! and charged once.
//!
//! Invariants owned by this module:
//!
//! - The arena already maps and charges the packet backing, its alignment
//!   padding, the pool records and the device reference counts; the endpoint
//!   charges only what it allocates itself, its request table. The
//!   transport's constructors charge their own state, the payload
//!   descriptor pool its descriptor memory, so each byte is charged once.
//! - [`EndpointConfig::validate`] refuses an arena without both packet kinds,
//!   a receive data room shorter than one whole frame, and every shape the
//!   endpoint cannot run; it computes every product with checked
//!   arithmetic, and its charge is the request table
//!   [`ValidEndpointConfig::initialize`] allocates.
//! - Initialization charges the whole computed total to a copy of the
//!   caller's [`EngineBudget`] before it allocates, and writes the copy back
//!   only after every allocation, so a refusal leaves the caller's budget,
//!   and its configuration, unchanged; success charges exactly
//!   [`ValidEndpointConfig::charge`] once.
//! - The receive pool's control reserve covers a whole batch, so while no
//!   control lease or posting from an earlier batch holds them, a receive
//!   finds its buffers even when data leases hold every buffer data may take.
//! - Peer shares sum within the request slots, so one peer's requests never
//!   take a slot another peer's share needs; table pressure then means
//!   retired slots.

use std::marker::PhantomData;

use crate::storage::{
    BufferArena, EngineBudget, EngineBudgetExceeded, PacketLayout, Platform, PoolKind,
    ValidatedBufferConfig,
};

use super::datagram::{FRAME_OVERHEAD, MAX_DATAGRAM};
use super::geometry::FRAGMENT_LEN;
use super::packet::{PacketPool, PacketPoolError};
use super::requests::{MAX_REQUEST_SLOTS, RequestTable};
use super::upload::SourceSlot;

/// The fixed memory of one endpoint, of either role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointConfig {
    /// Configured peers; at least one.
    pub peers: u16,
    /// Request slots in total, at most [`MAX_REQUEST_SLOTS`].
    pub request_slots: u32,
    /// Live requests one peer may hold, active and draining together; at most `request_slots`.
    pub peer_requests: u32,
    /// Receive buffers data use can never take; at least `batch`, below the receive pool's count.
    pub receive_reserve: u32,
    /// Datagrams one receive or send call handles.
    pub batch: u32,
}

/// Why a configuration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointConfigError {
    NoPeers,
    /// `request_slots` is zero or above [`MAX_REQUEST_SLOTS`].
    RequestSlots,
    /// `peer_requests` is zero, or `peers * peer_requests` exceeds `request_slots`.
    PeerRequests,
    /// The arena holds no pool of this packet kind.
    MissingKind(PoolKind),
    /// A receive buffer's data room is shorter than one frame of [`MAX_DATAGRAM`] bytes after [`FRAME_OVERHEAD`].
    ReceiveRoom {
        data_room: usize,
    },
    /// The batch is zero or above the receive reserve.
    Batch,
    Receive(PacketPoolError),
    /// The total charge overflows `usize`.
    Overflow,
}

/// A configuration that passed every check for request state `T` against one arena configuration, with the exact bytes its initialization charges.
///
/// Its traits do not depend on `T`, which only names the table it initializes.
pub struct ValidEndpointConfig<T> {
    config: EndpointConfig,
    /// The arena configuration the checks ran against; [`initialize`](Self::initialize) accepts an arena of this configuration alone.
    arena: ValidatedBufferConfig,
    charge: usize,
    state: PhantomData<fn() -> T>,
}

/// One endpoint's receive pool and request table, built together.
///
/// The fields are public so an endpoint can own the table while the pool and
/// the arena outlive it in the caller's frame, which lets packet leases
/// outlive the endpoint's polling and close.
pub struct EndpointMemory<'a, T> {
    /// The configuration these parts were validated for.
    pub config: EndpointConfig,
    pub receive: PacketPool<'a>,
    pub requests: RequestTable<T>,
}

impl EndpointConfig {
    /// Checks the shape against `arena` and computes the charge of a table holding `T` request state.
    ///
    /// # Errors
    ///
    /// The first failing check, in this order: `NoPeers`, `RequestSlots`,
    /// `PeerRequests`, `MissingKind` for each packet kind, `ReceiveRoom`,
    /// `Batch`, `Receive` for a reserve not below the receive count,
    /// then `Overflow`.
    pub fn validate<T>(
        &self,
        arena: &ValidatedBufferConfig,
    ) -> Result<ValidEndpointConfig<T>, EndpointConfigError> {
        if self.peers == 0 {
            return Err(EndpointConfigError::NoPeers);
        }
        if self.request_slots == 0 || self.request_slots > MAX_REQUEST_SLOTS {
            return Err(EndpointConfigError::RequestSlots);
        }
        let shares = u64::from(self.peers) * u64::from(self.peer_requests);
        if self.peer_requests == 0 || shares > u64::from(self.request_slots) {
            return Err(EndpointConfigError::PeerRequests);
        }
        if let Some(kind) = PoolKind::PACKET
            .into_iter()
            .find(|kind| arena.pool(*kind).count == 0)
        {
            return Err(EndpointConfigError::MissingKind(kind));
        }
        let stride = arena.pool(PoolKind::PacketReceive).buffer_len as usize;
        let receive = PacketLayout::of(stride).map_or(0, |layout| layout.data_room);
        if receive < FRAME_OVERHEAD + MAX_DATAGRAM {
            return Err(EndpointConfigError::ReceiveRoom { data_room: receive });
        }
        if self.batch == 0 || self.batch > self.receive_reserve {
            return Err(EndpointConfigError::Batch);
        }
        if self.receive_reserve >= arena.pool(PoolKind::PacketReceive).count {
            return Err(EndpointConfigError::Receive(PacketPoolError::Reserve));
        }
        let charge = RequestTable::<T>::metadata_bytes(self.request_slots, self.peers)
            .ok_or(EndpointConfigError::Overflow)?;
        Ok(ValidEndpointConfig {
            config: *self,
            arena: *arena,
            charge,
            state: PhantomData,
        })
    }
}

impl<T> Clone for ValidEndpointConfig<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for ValidEndpointConfig<T> {}

impl<T> PartialEq for ValidEndpointConfig<T> {
    fn eq(&self, other: &Self) -> bool {
        (self.config, self.arena, self.charge) == (other.config, other.arena, other.charge)
    }
}

impl<T> Eq for ValidEndpointConfig<T> {}

impl<T> std::fmt::Debug for ValidEndpointConfig<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidEndpointConfig")
            .field("config", &self.config)
            .field("charge", &self.charge)
            .finish()
    }
}

impl<T> ValidEndpointConfig<T> {
    /// Bytes [`initialize`](Self::initialize) charges.
    pub fn charge(&self) -> usize {
        self.charge
    }

    /// Builds the receive pool over `arena`, which must be the arena this
    /// configuration was validated against, and allocates the request table
    /// after charging [`charge`](Self::charge) bytes to a copy of `budget`,
    /// then writes the copy back.
    ///
    /// # Errors
    ///
    /// `EngineBudgetExceeded` when the charge does not fit; `budget` is unchanged and nothing is allocated.
    ///
    /// # Panics
    ///
    /// When `arena.config()` differs from the configuration validated against, or [`PacketPool::new`] refuses the receive view.
    pub fn initialize<'a, P: Platform>(
        &self,
        arena: &'a BufferArena<P>,
        budget: &mut EngineBudget,
    ) -> Result<EndpointMemory<'a, T>, EngineBudgetExceeded> {
        assert_eq!(
            *arena.config(),
            self.arena,
            "an endpoint initializes over the arena its configuration was validated against"
        );
        let mut staged = *budget;
        staged.charge(self.charge)?;
        let config = &self.config;
        let receive = PacketPool::new(arena, PoolKind::PacketReceive, config.receive_reserve)
            .expect("the validated arena's receive pool, viewed once");
        let memory = EndpointMemory {
            config: *config,
            receive,
            requests: RequestTable::new(config.request_slots, config.peers, config.peer_requests),
        };
        *budget = staged;
        Ok(memory)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourcesError {
    Count,
    Capacity,
    Exhausted,
    Budget(EngineBudgetExceeded),
}

pub fn sources<'a, P: Platform>(
    arena: &'a BufferArena<P>,
    count: u32,
    budget: &mut EngineBudget,
) -> Result<Box<[SourceSlot<'a>]>, SourcesError> {
    let spec = arena.config().pool(PoolKind::ReadResponse);
    if count > spec.count || count > u32::from(u16::MAX) + 1 {
        return Err(SourcesError::Count);
    }
    if count > 0 && spec.buffer_len < FRAGMENT_LEN {
        return Err(SourcesError::Capacity);
    }
    let mut staged = *budget;
    staged
        .charge(count as usize * size_of::<SourceSlot<'a>>())
        .map_err(SourcesError::Budget)?;
    let slots = (0..count)
        .map(|_| arena.acquire(PoolKind::ReadResponse).map(SourceSlot::new))
        .collect::<Result<Box<[_]>, _>>()
        .map_err(|_| SourcesError::Exhausted)?;
    *budget = staged;
    Ok(slots)
}
