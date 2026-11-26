//! Where a packet buffer's frame bytes lie inside its arena stride.
//!
//! A packet buffer is one DPDK mempool object: the mempool object header,
//! the mbuf, a private area of [`PRIVATE`] bytes, the mbuf headroom, then the
//! data room the device reads or writes. The header and trailer sizes come
//! from DPDK's own object-size rule for this build, so the layout matches
//! what the native mempool lays out over the same stride.

use spdk_sys as sys;

/// Bytes of each mbuf's private area, which holds a transmit mbuf's
/// device-reference token.
pub const PRIVATE: usize = 16;

/// The parts of a packet buffer of one stride.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketLayout {
    /// Bytes from the buffer's start to its mbuf, the mempool object header's size.
    pub mbuf_offset: usize,
    /// Bytes from the buffer's start to its first data-room byte.
    pub data_offset: usize,
    /// Bytes of data room, the most one frame may hold.
    pub data_room: usize,
}

/// Mempool flags the packet pools use; spreading across memory channels is
/// off, so an object fills its stride with no padding.
pub(crate) const MEMPOOL_FLAGS: u32 = sys::RTE_MEMPOOL_F_NO_SPREAD;

/// The mempool object header and trailer sizes for this build; under Miri,
/// which runs no native code, the 64-byte header and empty trailer this
/// build's object-size rule gives.
#[cfg(miri)]
pub(crate) fn object_overhead() -> (usize, usize) {
    (64, 0)
}

/// The mempool object header and trailer sizes for this build.
#[cfg(not(miri))]
pub(crate) fn object_overhead() -> (usize, usize) {
    let mut sizes = sys::rte_mempool_objsz::default();
    // SAFETY: a pure size computation that only writes `sizes`.
    unsafe { sys::rte_mempool_calc_obj_size(0, MEMPOOL_FLAGS, &mut sizes) };
    (sizes.header_size as usize, sizes.trailer_size as usize)
}

impl PacketLayout {
    /// The layout of a packet buffer of `stride` bytes, or `None` when the
    /// stride cannot hold the object header, the mbuf, its private area, the
    /// headroom and a data room.
    pub fn of(stride: usize) -> Option<Self> {
        let (header, trailer) = object_overhead();
        let element = stride.checked_sub(header + trailer)?;
        let before = size_of::<sys::rte_mbuf>() + PRIVATE + sys::RTE_PKTMBUF_HEADROOM as usize;
        let data_room = element.checked_sub(before)?;
        (data_room > 0).then_some(Self {
            mbuf_offset: header,
            data_offset: header + before,
            data_room,
        })
    }
}
