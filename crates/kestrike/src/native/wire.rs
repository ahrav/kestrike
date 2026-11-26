//! The Ethernet, IPv4 and UDP headers of every datagram on the device path:
//! encoding for transmit and validation before a received frame reaches frame
//! parsing.
//!
//! Invariants owned by this module:
//!
//! - A received frame reaches frame parsing only when it is one complete
//!   IPv4/UDP packet in one buffer: the device's masked packet-type fields
//!   name IPv4 without options and UDP with no tunnel, its masked IP and L4
//!   checksum fields are exactly GOOD, the Ethernet type is IPv4, the
//!   destination MAC and address are this host's and the destination port is
//!   its base port, the IPv4 version and
//!   header length are 4 and 5, the packet is not a fragment, the IPv4 and UDP
//!   lengths match the frame's length exactly, and the source address and
//!   port belong to a configured peer. Validation then exposes exactly the
//!   UDP payload.
//! - Every configured source port of a peer maps to that one peer; any other
//!   address or port carries no peer. [`Wire::new`] refuses peers whose
//!   address and port ranges overlap, an empty or overflowing port range, and
//!   more peers than a [`PeerId`] names.
//! - [`Wire::new`] charges its source table and header templates,
//!   [`Wire::charge`] bytes, to the engine budget before it allocates them
//!   and commits the charge only when it returns the addressing; each
//!   addressing is built once, by its own charged construction.
//! - A source's peer is one probe of an open-addressing table keyed by
//!   address. Peers on one address lie on that address's probe run, and their
//!   ranges are disjoint, so the first entry on the run whose range holds the
//!   port is the one peer that owns it.
//! - An encoded header leaves the IPv4 and UDP checksums to the device's
//!   offload, sets don't-fragment, and states the exact lengths. Each peer's
//!   headers from the local first port to the peer's first port are encoded
//!   once at construction; [`Wire::headers`] copies that template and writes
//!   the two length fields.
//! - The checks over a received frame split into those over its descriptor
//!   fields and length and those over its bytes; their composition keeps the
//!   documented refusal order.

use std::alloc::Layout;
use std::ops::Range;

use spdk_sys as sys;

use crate::net::FRAME_OVERHEAD;
use crate::net::MAX_PEERS;
use crate::net::PeerId;
use crate::net::linear_probe::{find, probe, spread, table_len};
use crate::storage::{EngineBudget, EngineBudgetExceeded};

/// Bytes of the Ethernet, IPv4 and UDP headers, which the transmit offload fields name.
pub(crate) const ETH_LEN: u64 = 14;
pub(crate) const IPV4_LEN: u64 = 20;
pub(crate) const UDP_LEN: u64 = 8;

const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
const UDP: u8 = 17;

/// One end's link and network identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Station {
    pub mac: [u8; 6],
    pub ip: [u8; 4],
    /// The first UDP port of the end's `ports` consecutive ports.
    pub port: u16,
    pub ports: u16,
}

/// A peer's slot in the source table; a zero range word marks a vacant slot.
#[derive(Debug, Clone, Copy, Default)]
struct Source {
    ip: u32,
    /// The first port, at most 65535; a probe compares it as loaded.
    port: u32,
    /// The number of ports in the high half, at least one in an occupied slot, and the [`PeerId`] this slot resolves to in the low half.
    range: u32,
}

impl Source {
    fn ports(self) -> u32 {
        self.range >> 16
    }

    fn peer(self) -> u16 {
        self.range as u16
    }

    fn vacant(self) -> bool {
        self.range == 0
    }

    /// Whether `port` is one of the slot's ports: a port below the first wraps past the length of every range.
    fn owns(self, port: u16) -> bool {
        u32::from(port).wrapping_sub(self.port) < self.ports()
    }

    fn overlaps(self, other: Self) -> bool {
        let end = |s: Self| s.port + s.ports();
        self.ip == other.ip && self.port < end(other) && other.port < end(self)
    }
}

/// The `N` bytes of `headers` from byte `at`, which a caller decodes as one word.
#[inline(always)]
fn field<const N: usize>(headers: &[u8; FRAME_OVERHEAD], at: usize) -> [u8; N] {
    let mut bytes = [0; N];
    bytes.copy_from_slice(&headers[at..at + N]);
    bytes
}

/// This host and its peers, with the MAC of the next hop toward each peer.
#[derive(Debug)]
pub struct Wire<'c> {
    local: Station,
    /// Indexed by [`PeerId`]; each peer's MAC is its next hop's.
    peers: &'c [Station],
    /// Every peer, placed by the [`spread`] of its address.
    sources: Box<[Source]>,
    /// Indexed by [`PeerId`]: the headers of a zero-payload datagram to the peer from the local first port to the peer's first port; a send copies one and writes the two length fields for its payload.
    templates: Box<[[u8; FRAME_OVERHEAD]]>,
}

/// Why an addressing configuration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// A station's port range is empty or runs past port 65535.
    Ports,
    /// Two peers share an address with overlapping port ranges, so a frame could name either.
    Overlap,
    /// More peers than a [`PeerId`] names.
    Peers,
    /// The engine budget cannot hold the source table and header templates.
    Budget(EngineBudgetExceeded),
}

impl<'c> Wire<'c> {
    /// The addressing of `local` and its `peers`, indexed by [`PeerId`],
    /// charging its source table and header templates to `budget`.
    ///
    /// # Errors
    ///
    /// In this order, each with `budget` unchanged:
    ///
    /// - [`WireError::Ports`] if `local` or a peer has an empty port range or one that runs past port 65535.
    /// - [`WireError::Peers`] if `peers` holds more than [`MAX_PEERS`] stations.
    /// - [`WireError::Budget`] if `budget` cannot hold the charge, before anything is allocated.
    /// - [`WireError::Overlap`] if two peers share an address and their port ranges overlap; the table built to find it is freed.
    pub fn new(
        local: Station,
        peers: &'c [Station],
        budget: &mut EngineBudget,
    ) -> Result<Self, WireError> {
        let ranges = |station: &Station| {
            station.ports > 0 && station.port.checked_add(station.ports - 1).is_some()
        };
        if !ranges(&local) || !peers.iter().all(ranges) {
            return Err(WireError::Ports);
        }
        let Some(charge) = Self::charge(peers.len()) else {
            return Err(WireError::Peers);
        };
        let mut staged = *budget;
        staged.charge(charge).map_err(WireError::Budget)?;
        let mut sources = vec![Source::default(); table_len(peers.len())].into_boxed_slice();
        for (peer, station) in (0..=u16::MAX).zip(peers) {
            let source = Source {
                ip: u32::from_be_bytes(station.ip),
                port: u32::from(station.port),
                range: u32::from(station.ports) << 16 | u32::from(peer),
            };
            match probe(&sources, spread(source.ip), Source::vacant, |seen| {
                seen.overlaps(source)
            }) {
                Ok(_) => return Err(WireError::Overlap),
                Err(slot) => sources[slot] = source,
            }
        }
        let templates = peers
            .iter()
            .map(|peer| {
                let mut template = [0; FRAME_OVERHEAD];
                encode(&local, &mut template, peer, local.port, peer.port, 0);
                template
            })
            .collect();
        *budget = staged;
        Ok(Self {
            local,
            peers,
            sources,
            templates,
        })
    }

    /// The heap bytes the source table and header templates of `peers` peers keep, or `None` above
    /// [`MAX_PEERS`].
    pub(crate) fn charge(peers: usize) -> Option<usize> {
        if peers > MAX_PEERS {
            return None;
        }
        let sources = Layout::array::<Source>(table_len(peers)).ok()?;
        let templates = Layout::array::<[u8; FRAME_OVERHEAD]>(peers).ok()?;
        sources.size().checked_add(templates.size())
    }

    pub fn local(&self) -> &Station {
        &self.local
    }

    /// The number of peers, each named by a [`PeerId`] below it.
    pub fn peers(&self) -> usize {
        self.peers.len()
    }

    pub fn peer(&self, id: PeerId) -> Option<&Station> {
        self.peers.get(usize::from(id.0))
    }

    /// `headers` writes headers for `payload_len` UDP payload bytes from the local first port to `peer`'s first port. If `peer` is unknown or `payload_len` exceeds 65,507, `headers` returns `None` and preserves `out`.
    #[inline]
    pub fn headers(
        &self,
        out: &mut [u8; FRAME_OVERHEAD],
        peer: PeerId,
        payload_len: u16,
    ) -> Option<()> {
        let ip_len = (20 + 8u16).checked_add(payload_len)?;
        *out = *self.templates.get(usize::from(peer.0))?;
        out[16..18].copy_from_slice(&ip_len.to_be_bytes());
        out[38..40].copy_from_slice(&(8 + payload_len).to_be_bytes());
        Some(())
    }
}

/// What a received frame's device descriptor reported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RxMeta {
    pub ol_flags: u64,
    pub packet_type: u32,
    pub nb_segs: u16,
    pub pkt_len: u32,
    pub data_len: u16,
}

/// Why a received frame was dropped before frame parsing; `Source` stays the last reason, which [`Refused::COUNT`] counts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refused {
    /// The buffer is not one this receive pool posted to the device.
    Foreign,
    /// The frame's data does not start at the mbuf headroom.
    Headroom,
    /// The frame spans more than one buffer.
    Segments,
    /// The packet type is not IPv4 without options carrying UDP with no tunnel.
    PacketType,
    /// The IP checksum field is not exactly GOOD.
    IpChecksum,
    /// The L4 checksum field is not exactly GOOD.
    L4Checksum,
    /// Shorter than the headers, or a length field disagrees with the frame.
    Length,
    /// Not IPv4, or IPv4 with options, or not UDP.
    Header,
    /// A fragment: more fragments follow, or the offset is nonzero.
    Fragment,
    /// The destination MAC or address is not this host's, or the port is not its base port.
    Destination,
    /// The source address and port are no configured peer's.
    Source,
}

impl Refused {
    /// The number of reasons, for a counter per reason.
    pub const COUNT: usize = Self::Source as usize + 1;
}

impl Wire<'_> {
    /// The peer a received frame came from and the range of its UDP payload, when every check passes.
    ///
    /// # Errors
    ///
    /// The first failing check. Checks run in [`Refused`]'s order from `Segments` on, except that the IPv4 and UDP length fields are checked after `Header`; the short-frame `Length` check runs before `Header`.
    pub fn accept(&self, meta: &RxMeta, frame: &[u8]) -> Result<(PeerId, Range<usize>), Refused> {
        Self::accept_descriptor(meta, frame.len())?;
        self.accept_frame(frame)
    }

    /// The checks over a received frame's descriptor fields alone, for a frame of `frame_len` bytes, which run before the frame's bytes are leased.
    ///
    /// # Errors
    ///
    /// `Segments`, `PacketType`, `IpChecksum`, `L4Checksum`, then `Length` for a frame shorter than its headers, in that order.
    #[inline]
    pub fn accept_descriptor(meta: &RxMeta, frame_len: usize) -> Result<(), Refused> {
        if meta.nb_segs != 1
            || meta.pkt_len != u32::from(meta.data_len)
            || frame_len != usize::from(meta.data_len)
        {
            return Err(Refused::Segments);
        }
        let l3 = meta.packet_type & sys::RTE_PTYPE_L3_MASK;
        let l4 = meta.packet_type & sys::RTE_PTYPE_L4_MASK;
        if l3 != sys::RTE_PTYPE_L3_IPV4
            || l4 != sys::RTE_PTYPE_L4_UDP
            || meta.packet_type & sys::RTE_PTYPE_TUNNEL_MASK != 0
        {
            return Err(Refused::PacketType);
        }
        if meta.ol_flags & u64::from(sys::RTE_MBUF_F_RX_IP_CKSUM_MASK)
            != u64::from(sys::RTE_MBUF_F_RX_IP_CKSUM_GOOD)
        {
            return Err(Refused::IpChecksum);
        }
        if meta.ol_flags & u64::from(sys::RTE_MBUF_F_RX_L4_CKSUM_MASK)
            != u64::from(sys::RTE_MBUF_F_RX_L4_CKSUM_GOOD)
        {
            return Err(Refused::L4Checksum);
        }
        if frame_len < FRAME_OVERHEAD {
            return Err(Refused::Length);
        }
        Ok(())
    }

    /// The checks over a received frame's bytes, after [`accept_descriptor`](Self::accept_descriptor) passed for its length: the peer the frame came from and the range of its UDP payload.
    ///
    /// # Errors
    ///
    /// `Length` for a frame shorter than its headers, then `Header`, `Length` for a length field that disagrees with the frame, `Fragment`, `Destination` and `Source`, in that order.
    #[inline(always)]
    pub fn accept_frame(&self, frame: &[u8]) -> Result<(PeerId, Range<usize>), Refused> {
        let Some(headers) = frame.first_chunk::<FRAME_OVERHEAD>() else {
            return Err(Refused::Length);
        };
        let be = |at: usize| u16::from_be_bytes(field(headers, at));
        if headers[12..14] != ETHERTYPE_IPV4 || headers[14] != 0x45 || headers[23] != UDP {
            return Err(Refused::Header);
        }
        if be(16) as usize != frame.len() - 14 || be(38) as usize != frame.len() - 34 {
            return Err(Refused::Length);
        }
        // More fragments, or a nonzero fragment offset; don't-fragment is allowed.
        if be(20) & 0x3fff != 0 {
            return Err(Refused::Fragment);
        }
        // The destination MAC and port compare as one word: the MAC in the low six bytes and, above it, the port, which is the low half of the big-endian word at byte 34.
        let local = &self.local;
        let [m0, m1, m2, m3, m4, m5] = local.mac;
        let ours =
            u64::from_le_bytes([m0, m1, m2, m3, m4, m5, 0, 0]) | (u64::from(local.port) << 48);
        let dst_port = u32::from_be_bytes(field(headers, 34)) as u16;
        let theirs = (u64::from_le_bytes(field(headers, 0)) & 0xffff_ffff_ffff)
            | (u64::from(dst_port) << 48);
        if theirs != ours || headers[30..34] != local.ip {
            return Err(Refused::Destination);
        }
        let (src_ip, src_port) = (
            u32::from_be_bytes([headers[26], headers[27], headers[28], headers[29]]),
            be(34),
        );
        let slot = find(&self.sources, spread(src_ip), Source::vacant, |seen| {
            seen.ip == src_ip && seen.owns(src_port)
        })
        .ok_or(Refused::Source)?;
        Ok((PeerId(slot.peer()), FRAME_OVERHEAD..frame.len()))
    }

    /// Writes the headers of a datagram of `payload_len` UDP payload bytes to `peer` from source port `src_port` and to the peer's port `dst_port`; tests build inbound frames with it.
    #[cfg(test)]
    pub(crate) fn encode(
        &self,
        out: &mut [u8; FRAME_OVERHEAD],
        peer: &Station,
        src_port: u16,
        dst_port: u16,
        payload_len: u16,
    ) {
        encode(&self.local, out, peer, src_port, dst_port, payload_len);
    }
}

/// Writes the headers of a datagram of `payload_len` UDP payload bytes from `local`'s `src_port` to `peer`'s `dst_port`.
fn encode(
    local: &Station,
    out: &mut [u8; FRAME_OVERHEAD],
    peer: &Station,
    src_port: u16,
    dst_port: u16,
    payload_len: u16,
) {
    let ip_len = (20 + 8 + payload_len).to_be_bytes();
    let udp_len = (8 + payload_len).to_be_bytes();
    out[0..6].copy_from_slice(&peer.mac);
    out[6..12].copy_from_slice(&local.mac);
    out[12..14].copy_from_slice(&ETHERTYPE_IPV4);
    out[14..20].copy_from_slice(&[0x45, 0, ip_len[0], ip_len[1], 0, 0]);
    // Don't fragment, TTL 64, UDP, checksum left to the device.
    out[20..26].copy_from_slice(&[0x40, 0, 64, UDP, 0, 0]);
    out[26..30].copy_from_slice(&local.ip);
    out[30..34].copy_from_slice(&peer.ip);
    out[34..36].copy_from_slice(&src_port.to_be_bytes());
    out[36..38].copy_from_slice(&dst_port.to_be_bytes());
    out[38..40].copy_from_slice(&udp_len);
    out[40..42].copy_from_slice(&[0, 0]);
}
