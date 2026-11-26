//! The one datagram seam both endpoint roles drive: a bounded nonblocking
//! receive batch of packet leases and a bounded send batch of a header plus at
//! most two payload pieces.
//!
//! Invariants every implementation upholds:
//!
//! - One call handles at most the batch it is given and never blocks; no
//!   datagram ready is a successful empty batch.
//! - A receive posts buffers from the endpoint's receive pool, lets them be
//!   written, and hands datagram `i` back as a control lease in slot `i`,
//!   its length the bytes kept, with its peer and whether the datagram was
//!   longer than the buffer; a truncated datagram keeps only its first
//!   `capacity` bytes. Only a buffer the transport finished writing becomes
//!   a lease. A receive may keep buffers posted to its device ring between
//!   calls.
//! - A send takes datagrams in order and reports the accepted prefix:
//!   datagrams before the returned count were taken whole, later ones were
//!   not taken and stay with the caller.
//! - A send copies the header and every [`Payload::Inline`] piece before it
//!   returns. For a [`Payload::Retained`] piece it takes a device reference
//!   to the source buffer's incarnation before publishing the datagram, and
//!   returns that reference only once the device read the bytes; a datagram
//!   it did not take holds no reference once the call returns. The caller
//!   may drop its own handle at once: the buffer stays off the free stack
//!   until the last reference returns.
//!
//! Every transport implements this one contract; the in-memory test link is one implementation.

use super::geometry::FRAGMENT_LEN;
use super::packet::{PacketLease, PacketPool};
use crate::storage::SourceRange;

/// The most payload pieces one datagram carries after its header.
pub const MAX_PAYLOAD_SLICES: usize = 2;

/// Bytes of every frame's fixed header.
pub const HEADER_LEN: usize = 192;

/// The longest datagram either endpoint sends: a header and one whole fragment.
pub const MAX_DATAGRAM: usize = HEADER_LEN + FRAGMENT_LEN as usize;

/// The most GET frames one packed datagram carries: 2 to `MAX_PACKED_GETS` canonical GET frames back to back, each a
/// 192-byte header with an empty body under its own session sequence and tag.
///
/// The value is part of the wire contract between builds: an owner accepts at least the largest pack any client
/// build sends. An owner handles a packed datagram of up to this many frames frame by frame and drops a longer one
/// whole, as malformed when it arrives untruncated from a configured peer.
pub const MAX_PACKED_GETS: usize = 8;

const _: () = assert!(MAX_PACKED_GETS >= 2 && MAX_PACKED_GETS * HEADER_LEN <= MAX_DATAGRAM);

/// Bytes of the Ethernet, IPv4 and UDP headers in front of every datagram.
pub const FRAME_OVERHEAD: usize = 14 + 20 + 8;

/// A configured peer, by its index in the endpoint's fixed peer list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(pub u16);

/// The longest peer list an endpoint holds: a [`PeerId`] names each index below it.
pub const MAX_PEERS: usize = u16::MAX as usize;

/// What a receive learned about one datagram besides its bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Received {
    pub peer: Option<PeerId>,
    /// The datagram was longer than the buffer; the buffer keeps its first `capacity` bytes.
    pub truncated: bool,
}

/// One payload piece of a datagram.
#[derive(Debug, Clone, Copy)]
pub enum Payload<'b, 'a> {
    /// Bytes the transport copies before the send returns, such as a control frame's body.
    Inline(&'b [u8]),
    /// A range of a retained arena buffer the device reads in place; the frame encodes the same bytes.
    Retained(SourceRange<'b, 'a>),
}

impl Payload<'_, '_> {
    pub const EMPTY: Self = Self::Inline(&[]);

    pub fn len(&self) -> usize {
        self.bytes().len()
    }

    /// The piece's bytes, as the frame encodes them and the device sends them.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Inline(bytes) => bytes,
            Self::Retained(source) => source.bytes(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One datagram to send: a header and up to [`MAX_PAYLOAD_SLICES`] payload pieces, concatenated on the wire in that order.
#[derive(Debug, Clone, Copy)]
pub struct Outgoing<'b, 'a> {
    pub peer: PeerId,
    pub header: &'b [u8],
    pub payload: [Payload<'b, 'a>; MAX_PAYLOAD_SLICES],
}

impl Outgoing<'_, '_> {
    /// The datagram's length on the wire.
    pub fn len(&self) -> usize {
        self.header.len() + self.payload.iter().map(Payload::len).sum::<usize>()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A call that failed with nothing taken or received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramError {
    /// The transport is closed.
    Closed,
    /// The transport reported an error; `code` is its platform error number when it has one.
    Failed { code: Option<i32> },
}

/// A bounded, nonblocking datagram transport over a fixed peer set, whose
/// retained payload sources and receive buffers live in arena `'a`, so it
/// may keep receive buffers posted across calls.
pub trait Datagrams<'a> {
    /// Receives at most `min(into.len(), meta.len())` datagrams from `pool`'s
    /// buffers without blocking, filling `into` and `meta` in step, and
    /// returns how many arrived. Slots past the count are left as they were.
    /// Every call passes the same pool, which owns the buffers the transport
    /// keeps posted.
    ///
    /// # Errors
    ///
    /// `DatagramError` when the transport fails before any datagram arrived; nothing is filled.
    fn receive<'p>(
        &mut self,
        pool: &'p PacketPool<'a>,
        into: &mut [Option<PacketLease<'p>>],
        meta: &mut [Received],
    ) -> Result<usize, DatagramError>;

    /// Receive buffers the transport keeps posted to its device ring between
    /// calls: the effective descriptor count after the device's own
    /// adjustment, every one of which the device may refill at once.
    fn rx_ring(&self) -> u32;

    /// Returns the device references of transmits the device finished
    /// reading, within a bounded budget and without sending. The endpoint
    /// calls it every turn, sending or not, so a device's returns reach the
    /// pool even while the endpoint is closed or idle.
    fn reclaim(&mut self);

    /// The count of outbound datagrams the host's bandwidth allowance has queued or dropped so far, where the transport's device reports it; the endpoint reads it at a bounded interval to shape its egress below the allowance.
    fn egress_exceeded(&mut self) -> Option<u64> {
        None
    }

    /// Sends `batch` in order without blocking and returns the length of the prefix the transport took whole.
    ///
    /// # Errors
    ///
    /// `DatagramError` when the transport fails before taking the first datagram.
    fn send(&mut self, batch: &[Outgoing<'_, 'a>]) -> Result<usize, DatagramError>;
}
