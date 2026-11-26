//! Principal keys, frame tags and boot entropy: every frame is authenticated by its principal's key before any session or request state reads it.
//!
//! Invariants owned by this module:
//!
//! - A [`KeyRing`] holds exactly one distinct 32-byte key per configured peer, in arrays allocated and charged once at initialization and rewritten in place by a re-key; loading refuses a missing, malformed, unknown or duplicated principal and two principals sharing one key, and changes nothing on refusal.
//! - A tag is HMAC-SHA256 (RFC 2104 with FIPS 180-4 SHA-256) over a frame's MAC input, keyed by the peer's key, truncated to its leftmost 16 bytes; verification compares those bytes in constant time.
//! - A GET DATA frame's tag covers its body through a 16-byte digest that takes the covered body's place in the MAC input. The digest is POLYVAL (RFC 8452) of the body, its two slices read as one stream zero-padded to whole 16-byte blocks, under the session's data key. The data key is the leftmost 16 bytes of HMAC-SHA256 under the peer's key over the owner-to-client domain block and one 176-byte block of a fixed label and the session's owner and client boot nonces. The header carries the body length, which separates bodies that differ only in trailing zeros, and the send sequence; it enters the HMAC beside the digest, so the tag is HMAC applied to a universal hash of the body, and the digest stays inside the tag computation. Each peer key keeps the data key of the last session for which it tagged a DATA frame or authenticated a received one, and derives a new key when a frame names another owner endpoint or session. A received frame's derived key replaces the kept one only after its tag verifies, and a re-key empties the kept key. A received DATA frame whose tag fails costs one POLYVAL pass over its body, plus one derivation when it names an owner endpoint or session other than the kept key's, and leaves the kept key in place. The data key and the digest stay in the peer key's memory and the tag computation; diagnostics and wire bytes carry the tag alone.
//! - [`Authenticated`] is the only way to read a received frame's header for session and request processing, and only the ring's authenticate methods build one, after the tag verified under the frame's principal and the ring's key epoch. [`KeyRing::authenticate_tagged`] verifies a tag the caller computed over the frame's bytes under the peer's key with [`KeyRing::tag`] or [`KeyRing::tag_pair`], and is callable only within `net`.
//!
//!   ```compile_fail,E0624
//!   # use kestrike::net::*;
//!   # fn f(ring: &KeyRing, frame: &Frame<'_>, peer: PeerId) {
//!   let forged = ring.authenticate_tagged(frame, peer, frame.header().tag);
//!   # }
//!   ```
//! - Diagnostics from this module carry no key or tag bytes: `Debug` of a ring prints its principals and epoch, `Debug` of an [`Authenticated`] prints peer, kind, principal, session epoch and sequence, and refusals name principals, epochs and lengths.
//! - Tagging and verification allocate nothing: each peer keeps the SHA-256 states of its key's two pad blocks and memoizes, for each of GET, START, DATA, ACK and COMPLETE, for each PUT kind from BEGIN through RESULT, and in one slot shared by the other kinds, the state after the first block of the last frame it tagged or checked, so a frame whose first block is memoized costs three chained compressions plus one per block of covered body, plus one padding block when the body is empty, ends on a block boundary, or leaves fewer than nine bytes free in its last block. The covered body is hashed in place from at most two borrowed slices, a block that straddles them and the final partial block assembled in a stack buffer, and the final one or two blocks carry the FIPS 180-4 padding; a covered body whose first slice holds 16 bytes and whose second is empty, a DATA frame's digest among them, ends its inner hash on one block copied from the constant [`PAD_DATA`] in [`KeyRing::tag`], [`KeyRing::authenticate`] and the one input [`KeyRing::tags`] hashes alone; the group path, which serves [`KeyRing::tag_pair`], [`KeyRing::authenticate_pair`], [`KeyRing::authenticate_group`] and the groups of four, three and two of [`KeyRing::tags`], and the vector pass assemble the same block in the stack buffer. Verification hints the frame's body, which the body crc check reads right after the tag, [`HINTS`] lines at a time. Verified alone, a frame gets two batches before the header's middle blocks, then, with a covered body, one before each run of up to 16 whole body blocks or before the one block of a 16-byte single-slice body, or, with no covered body, one before each of the last two compressions. Verified in a pair or a group, a frame gets every line before its tag computation starts. A DATA frame gets none, since its digest read its body before the tag. A re-key empties every slot. The memo is interior-mutable, so a ring is not `Sync`.
//! - [`KeyRing::authenticate_group`] verifies frames whose tags cover their bodies through the group path, and [`KeyRing::tag_pair`] and [`KeyRing::authenticate_pair`] compute two frames' tags through it with two chains: after each chain's first block, up to four frames' chains compress every later block together. The header's middle blocks take one pass. When every covered body is shorter than 56 bytes, as for header-only frames and DATA digests, each chain's one last inner block takes one pass; otherwise the whole blocks at the start of each body take one pass per run the live chains share, and every later block, from the straddling block through the padding, takes one pass per block, each pass holding the chains with blocks left. The outer blocks take one pass. On aarch64 with `sha2`, a group of two to four frames whose covered bodies are all empty, the shape of GET, ACK and CANCEL frames, runs as one kernel pass from each chain's middle blocks through its outer block. Each chain compresses its own blocks in order from its own state, so each tag is the same function of its frame as alone, and the processor's pipeline overlaps the chains' compressions.
//! - [`KeyRing::tags`] gives each input the tag [`KeyRing::tag`] gives it. On x86_64 with `avx512f`, `avx512bw` and `vpclmulqdq`, groups of fifteen or sixteen inputs run their inner hash chains in the sixteen 32-bit lanes of AVX-512 registers, one message block per lane per step, while every lane has a block left; each chain then finishes and takes its outer hash alone. The other inputs, on every architecture, hash through the group path [`KeyRing::authenticate_group`] uses: four chains at a time, with a remainder of five as three chains and two, of three as three chains and of two as two chains, and an input alone only when it is the one input left.
//! - Boot nonces come from the operating system's entropy through `getrandom`, and an all-zero nonce is refused, because zero marks an absent nonce on the wire.

use std::cell::{Cell, RefCell};

use sha2::block_api::compress256;
use subtle::ConstantTimeEq;

pub use crate::entropy::EntropyError;
pub(super) use crate::entropy::{nonce_from, os_entropy};
use crate::storage::prefetch::{LINE, hint_read};
use crate::storage::{EngineBudget, EngineBudgetExceeded};

use super::data_hash::DataHash;
use super::datagram::HEADER_LEN;
use super::datagram::PeerId;
use super::frame::{
    AUTHENTICATED_LEN, DATA_DIGEST_LEN, Direction, Frame, Header, KIND_AT, Kind, MacInput,
    data_mac_input, data_session, mac_input_for,
};
use super::linear_probe::{probe, spread, table_len};
use super::sha_lanes::{self, BLOCK_LEN, Block, LANES, Lanes, State};
#[cfg(target_arch = "aarch64")]
use super::sha_lanes::{FixedBlock, Tail};

/// Bytes of every principal key.
pub const KEY_LEN: usize = 32;

/// Bytes of a frame's truncated tag.
pub const TAG_LEN: usize = 16;

/// An empty word of a ring's scratch: an unclaimed peer or a free key-table slot.
const EMPTY: u16 = u16::MAX;

/// Bytes of the domain block, and of the header that follow it in a tag's first block.
const DOMAIN_LEN: usize = 16;
const HEADER_IN_FIRST: usize = BLOCK_LEN - DOMAIN_LEN;

/// `RUN` sets the batch size for in-place body compression and the number of lines hinted per [`Ahead`] step.
const RUN: usize = 16;
const HINTS: usize = RUN;

/// Memo slots per peer: one for each of GET, START, DATA, ACK and COMPLETE and one for each of PUT BEGIN, PUT AUTHORITY, PUT PREPARE, PUT READY, PUT DATA, PUT ACK and PUT RESULT, a transfer's ordinary traffic, and one that every other kind shares. A frame's first block holds the endpoint, the direction and the header's first 48 bytes: the magic, the version, the kind, the principal, the key epoch, the owner boot nonce and the first eight bytes of the client boot nonce. The request ID and every later field lie in later blocks, so the frames of one kind in one session and direction share one block: concurrent uploads of one peer, whose control frames alternate in kind, each find their kind's block memoized. Whole-block comparisons on lookup preserve correctness across slot collisions.
const MIDSTATES: usize = 13;

/// Last blocks with FIPS 180-4 padding in place: for an inner hash with no covered body, the case of every GET kind, and for the outer hash over the inner digest.
const PAD_HEADER: [u8; BLOCK_LEN] = padded(0, DOMAIN_LEN + AUTHENTICATED_LEN);
const PAD_DIGEST: [u8; BLOCK_LEN] = padded(32, 32);

/// [`PAD_HEADER`] with its round words, the block that ends the inner hash of every chain of a header-only group.
#[cfg(target_arch = "aarch64")]
static HEADER_END: FixedBlock = FixedBlock::new(PAD_HEADER);

/// The inner hash's last block for a covered body of one 16-byte slice, a DATA frame's digest among them: [`digest_block`] copies the body into its first 16 bytes, and the padding follows them.
const PAD_DATA: [u8; BLOCK_LEN] = padded(
    DATA_DIGEST_LEN,
    DOMAIN_LEN + AUTHENTICATED_LEN + DATA_DIGEST_LEN,
);

/// Bytes of the inner hash's message before the covered body: the key's pad block, the domain block and the header. It fills whole blocks, so the covered body starts on a block boundary.
const PREFIX_LEN: usize = BLOCK_LEN + DOMAIN_LEN + AUTHENTICATED_LEN;

/// A block whose first `used` bytes the caller fills, followed by the padding of a message of the pad block and `len` bytes.
pub(crate) const fn padded(used: usize, len: usize) -> [u8; BLOCK_LEN] {
    let mut block = [0; BLOCK_LEN];
    block[used] = 0x80;
    let bits = ((BLOCK_LEN + len) * 8) as u64;
    let bytes = bits.to_be_bytes();
    let mut at = 0;
    while at < 8 {
        block[BLOCK_LEN - 8 + at] = bytes[at];
        at += 1;
    }
    block
}

/// SHA-256's initial hash value (FIPS 180-4, section 5.3.3).
pub(crate) const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// `inner` and `outer` hold the SHA-256 states after hashing their respective HMAC pad blocks (RFC 2104). Treat the pair as key material: anyone with both states can generate a valid tag for any message under the key.
#[derive(Clone, Copy)]
pub(crate) struct Keyed {
    pub(crate) inner: [u32; 8],
    pub(crate) outer: [u32; 8],
}

/// The inner hash's state after one message block, kept with that block; `state` always equals the compression of `block` from the key's inner pad state.
#[derive(Clone, Copy)]
struct Midstate {
    block: [u8; BLOCK_LEN],
    state: [u32; 8],
}

impl Midstate {
    fn of(keyed: &Keyed, block: [u8; BLOCK_LEN]) -> Self {
        let mut state = keyed.inner;
        sha_lanes::lone(&mut state, &[block]);
        Self { block, state }
    }

    /// Whether `block` is `input`'s first block, compared as 128-bit words read in place from `block` and the input's header, plus one computed domain word.
    #[inline(always)]
    fn names(&self, input: &MacInput<'_>) -> bool {
        let domain =
            u128::from(input.endpoint) << 96 | u128::from(input.direction as u8) << (96 - 8);
        let (words, _) = self.block.as_chunks::<16>();
        let (lead, _) = input.header[..HEADER_IN_FIRST].as_chunks::<16>();
        let mut same = u128::from_be_bytes(words[0]) == domain;
        for (word, header) in words[1..].iter().zip(lead) {
            same &= u128::from_ne_bytes(*word) == u128::from_ne_bytes(*header);
        }
        same
    }
}

struct PeerKey {
    keyed: Keyed,
    /// Empty until a frame of the slot's kinds is tagged or checked, and emptied by a re-key.
    first: [Cell<Option<Midstate>>; MIDSTATES],
    /// The data key of the last session for which this key tagged or authenticated a DATA frame, as a keyed POLYVAL hash with the owner endpoint and boot nonces that name it; emptied by a re-key.
    ///
    /// A digest borrows the kept key in place, and its borrow ends before [`install`](PeerKey::install) takes the cell's one runtime mutable borrow, so no borrow panics; a re-key empties the cell through `&mut self`.
    data: RefCell<Option<DataKey>>,
}

/// A DATA body's digest, with the data key the digest derived when no key was kept or the kept key named another endpoint or session; [`PeerKey::keep`] installs the derived key, for a received frame only once [`KeyRing::kept`] finds it authenticated.
struct BodyDigest {
    bytes: [u8; DATA_DIGEST_LEN],
    derived: Option<Derived>,
}

/// A data key derived for owner `endpoint`'s session named by `nonces`, held as its 16 bytes so the digests a pair or group verification holds stay small; [`PeerKey::install`] keys a hash from them.
struct Derived {
    endpoint: u32,
    nonces: ([u8; 16], [u8; 16]),
    key: [u8; 16],
}

/// A session's data key: its owner endpoint, its owner and client boot nonces and the POLYVAL hash keyed by the key they derive.
struct DataKey {
    endpoint: u32,
    nonces: ([u8; 16], [u8; 16]),
    hash: DataHash,
}

impl PeerKey {
    #[inline(always)]
    fn new(keyed: Keyed) -> Self {
        Self {
            keyed,
            first: std::array::from_fn(|_| Cell::new(None)),
            data: RefCell::new(None),
        }
    }

    /// Moves to `keyed` and empties every memo slot and the data key, in place.
    #[inline(always)]
    fn rekey(&mut self, keyed: Keyed) {
        self.keyed = keyed;
        for slot in &mut self.first {
            *slot.get_mut() = None;
        }
        *self.data.get_mut() = None;
    }

    /// The POLYVAL of `body`, its two slices read as one stream zero-padded to whole blocks, under the data key of owner `endpoint`'s session named by `nonces`.
    ///
    /// Carries the data key too when this call derived it because no key is kept or the kept key names another endpoint or session; the kept key stays in place until [`keep`](Self::keep) installs the derived one.
    fn digest(&self, endpoint: u32, nonces: ([u8; 16], [u8; 16]), body: [&[u8]; 2]) -> BodyDigest {
        if let Some(data) = self.data.borrow().as_ref()
            && (data.endpoint, data.nonces) == (endpoint, nonces)
        {
            return BodyDigest {
                bytes: data.hash.digest(body),
                derived: None,
            };
        }
        self.derive(endpoint, nonces, body)
    }

    /// [`digest`](Self::digest) under a data key derived for the session, taken when no key is kept or the kept key names another endpoint or session; out of line so the kept-key path stays small.
    #[cold]
    #[inline(never)]
    fn derive(&self, endpoint: u32, nonces: ([u8; 16], [u8; 16]), body: [&[u8]; 2]) -> BodyDigest {
        let key = self.data_key(endpoint, nonces);
        BodyDigest {
            bytes: DataHash::new(key).digest(body),
            derived: Some(Derived {
                endpoint,
                nonces,
                key,
            }),
        }
    }

    /// Installs the data key `digest` derived, when it derived one, in the kept key's place.
    fn keep(&self, digest: &mut BodyDigest) {
        if let Some(derived) = digest.derived.take() {
            self.install(derived);
        }
    }

    /// Replaces the kept data key with `derived`, keyed anew from its 16 bytes; out of line as [`derive`](Self::derive) is.
    #[cold]
    #[inline(never)]
    fn install(&self, derived: Derived) {
        *self.data.borrow_mut() = Some(DataKey {
            endpoint: derived.endpoint,
            nonces: derived.nonces,
            hash: DataHash::new(derived.key),
        });
    }

    /// The data key of the session named by `nonces`: the leftmost 16 bytes of HMAC-SHA256 under this key over the owner-to-client domain block of owner `endpoint` and a 176-byte block of [`DATA_KEY_LABEL`], the owner boot nonce, the client boot nonce and zeros.
    ///
    /// The label's version bytes separate this derivation input from every accepted frame's MAC input. Its kind byte selects the memo slot the unlisted kinds share.
    fn data_key(&self, endpoint: u32, (owner, client): ([u8; 16], [u8; 16])) -> [u8; 16] {
        let mut block = [0; AUTHENTICATED_LEN];
        block[..16].copy_from_slice(DATA_KEY_LABEL);
        block[16..32].copy_from_slice(&owner);
        block[32..48].copy_from_slice(&client);
        let input = MacInput {
            endpoint,
            direction: Direction::OwnerToClient,
            header: &block,
            body: [&[], &[]],
        };
        unhinted(self, &input)
    }
}

/// The label that opens a data key's derivation input: the frame magic, then `DA` at the version offset, which reads as version `0x4441`.
const DATA_KEY_LABEL: &[u8; 16] = b"IMGNET01DATA KEY";

/// One principal's key as the loader receives it.
#[derive(Clone, Copy)]
pub struct KeyEntry<'k> {
    pub principal: u32,
    pub key: &'k [u8],
}

impl std::fmt::Debug for KeyEntry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyEntry")
            .field("principal", &self.principal)
            .field("key_len", &self.key.len())
            .finish()
    }
}

/// Why a key set was refused; it names principals and lengths, never key bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// A configured peer has no key.
    Missing {
        principal: u32,
    },
    /// A key is not [`KEY_LEN`] bytes.
    Malformed {
        principal: u32,
        len: usize,
    },
    /// A key names a principal that is not configured.
    Unknown {
        principal: u32,
    },
    /// A principal has two keys, or is configured as two peers.
    Duplicate {
        principal: u32,
    },
    /// Two principals share one key.
    Shared {
        first: u32,
        second: u32,
    },
    /// A replacement keeps the ring's key epoch, under which frames tagged with the old keys would still name a live epoch.
    SameEpoch {
        epoch: u32,
    },
    /// The peers exceed the 65,535 a session table holds.
    Count {
        entries: usize,
        peers: usize,
    },
    Budget(EngineBudgetExceeded),
}

pub struct KeyRing {
    principals: Box<[u32]>,
    /// An open-addressing table of [`table_len`] peer indices, placed by principal.
    index: Box<[u16]>,
    /// One word per peer and a key table of [`table_len`] words, for checking a replacement without allocating; after a successful check, word `p` is peer `p`'s entry index.
    scratch: Box<[u16]>,
    keyed: Box<[PeerKey]>,
    epoch: u32,
    lanes: Lanes,
}

impl std::fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRing")
            .field("principals", &self.principals)
            .field("epoch", &self.epoch)
            .finish()
    }
}

/// A received frame whose tag verified under its principal's key and the ring's epoch, from peer `peer`; it borrows the frame, so a verified view costs no copy of the header.
#[derive(Clone, Copy)]
pub struct Authenticated<'f, 'b> {
    frame: &'f Frame<'b>,
    peer: PeerId,
}

impl std::fmt::Debug for Authenticated<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let header = self.frame.header();
        f.debug_struct("Authenticated")
            .field("peer", &self.peer)
            .field("kind", &header.kind)
            .field("principal", &header.principal)
            .field("epoch", &header.epoch)
            .field("sequence", &header.sequence)
            .finish()
    }
}

impl<'f, 'b> Authenticated<'f, 'b> {
    #[inline(always)]
    pub fn header(&self) -> Header {
        self.frame.header()
    }

    pub fn peer(&self) -> PeerId {
        self.peer
    }

    pub fn frame(&self) -> &'f Frame<'b> {
        self.frame
    }
}

/// Why a frame was not authenticated; the frame changes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// The principal is not configured, or not the one this peer speaks for.
    Principal { principal: u32 },
    /// The key epoch is not the ring's.
    KeyEpoch { found: u32 },
    /// The tag did not verify.
    Tag,
}

impl KeyRing {
    /// Bytes a ring of `peers` keys charges.
    pub fn charge(peers: usize) -> usize {
        peers * (size_of::<u32>() + size_of::<u16>() + size_of::<PeerKey>())
            + 2 * table_len(peers) * size_of::<u16>()
    }

    /// `KeyRing::load` loads one key per principal of `peers`, in `peers` order, at key `epoch`. It checks [`charge`](Self::charge) bytes against `budget` before allocating its tables and commits the charge on success.
    ///
    /// # Errors
    ///
    /// In order: `Count` for more peers than a session table holds, `Budget`, `Duplicate` for the first principal configured again, then per entry `Malformed`, `Unknown` and `Duplicate`, then `Missing` for the first peer without a key, then `Shared` for the first entry whose key an earlier entry holds; each leaves `budget` unchanged, and `Count` and `Budget` allocate nothing.
    pub fn load(
        peers: &[u32],
        entries: &[KeyEntry<'_>],
        epoch: u32,
        budget: &mut EngineBudget,
    ) -> Result<Self, KeyError> {
        let Ok(count) = u16::try_from(peers.len()) else {
            return Err(KeyError::Count {
                entries: entries.len(),
                peers: peers.len(),
            });
        };
        // Staging the charge preserves `budget` on failure.
        let mut staged = *budget;
        staged
            .charge(Self::charge(peers.len()))
            .map_err(KeyError::Budget)?;
        // Inserting the peers in order, the first one that meets its own principal is the first configured again.
        let mut index = vec![EMPTY; table_len(peers.len())].into_boxed_slice();
        for (peer, &principal) in (0..count).zip(peers) {
            match probe(&index, spread(principal), vacant, |seen| {
                peers[usize::from(seen)] == principal
            }) {
                Ok(_) => return Err(KeyError::Duplicate { principal }),
                Err(slot) => index[slot] = peer,
            }
        }
        let mut scratch = vec![0; peers.len() + table_len(peers.len())].into_boxed_slice();
        assign(peers, &index, entries, &mut scratch)?;
        let keyed = scratch[..peers.len()]
            .iter()
            .map(|&at| PeerKey::new(keyed(entries[usize::from(at)].key)))
            .collect();
        *budget = staged;
        Ok(Self {
            principals: peers.into(),
            index,
            scratch,
            keyed,
            epoch,
            lanes: Lanes::detect(),
        })
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// The configured peers' count.
    pub fn peers(&self) -> usize {
        self.principals.len()
    }

    /// The peer whose principal is `principal`.
    pub fn peer_of(&self, principal: u32) -> Option<PeerId> {
        find(&self.principals, &self.index, principal).map(|at| PeerId(at as u16))
    }

    pub fn principal(&self, peer: PeerId) -> Option<u32> {
        self.principals.get(usize::from(peer.0)).copied()
    }

    /// The 16-byte POLYVAL of `body` under the data key of the session whose boot nonces are `nonces`, owner then client, between owner `endpoint` and `peer`: the covered body of that session's DATA frames. `peer`'s key keeps the data key for the session's next frame. `None` for a peer outside the ring.
    #[inline]
    pub(super) fn data_digest(
        &self,
        peer: PeerId,
        endpoint: u32,
        nonces: ([u8; 16], [u8; 16]),
        body: [&[u8]; 2],
    ) -> Option<[u8; DATA_DIGEST_LEN]> {
        let key = self.keyed.get(usize::from(peer.0))?;
        let mut digest = key.digest(endpoint, nonces, body);
        key.keep(&mut digest);
        Some(digest.bytes)
    }

    /// The MAC input of the encoded header `encoded` sent with `payload` between owner `endpoint` and `peer`: [`mac_input_for`]'s, or for DATA the domain block, `encoded[..176]` and the [`data_digest`](Self::data_digest) of `payload` under the session the header names, written to `digest`. `None` where `mac_input_for` refuses a kind other than DATA, for DATA travelling client to owner, for a DATA payload whose length differs from the header's datagram body length, or for a peer outside the ring.
    #[inline]
    pub(super) fn mac_input<'s>(
        &self,
        peer: PeerId,
        encoded: &'s [u8; HEADER_LEN],
        payload: [&'s [u8]; 2],
        (endpoint, direction): (u32, Direction),
        digest: &'s mut [u8; DATA_DIGEST_LEN],
    ) -> Option<MacInput<'s>> {
        if encoded[KIND_AT] != Kind::Data as u8 {
            return mac_input_for(encoded, payload, endpoint, direction);
        }
        if direction != Direction::OwnerToClient {
            return None;
        }
        let nonces = data_session(encoded, payload[0].len() + payload[1].len())?;
        *digest = self.data_digest(peer, endpoint, nonces, payload)?;
        Some(data_mac_input(
            encoded.first_chunk()?,
            digest,
            endpoint,
            direction,
        ))
    }

    /// Returns the same input as [`mac_input`](Self::mac_input) using the supplied body digest. The caller must compute `digest` with [`data_digest`](Self::data_digest) over the same payload bytes under the session named by the header, which also confirmed the peer is in the ring. Returns `None` when the kind differs from DATA, the direction differs from owner to client, or `payload_len` differs from the header's datagram body length.
    #[inline]
    pub(super) fn mac_input_digested<'s>(
        &self,
        encoded: &'s [u8; HEADER_LEN],
        payload_len: usize,
        (endpoint, direction): (u32, Direction),
        digest: &'s [u8; DATA_DIGEST_LEN],
    ) -> Option<MacInput<'s>> {
        if encoded[KIND_AT] != Kind::Data as u8 || direction != Direction::OwnerToClient {
            return None;
        }
        data_session(encoded, payload_len)?;
        Some(data_mac_input(
            encoded.first_chunk()?,
            digest,
            endpoint,
            direction,
        ))
    }

    /// The covered-body digest of a DATA frame received from `peer` for owner `endpoint` travelling `direction`, computed from its raw body before its tag is checked.
    ///
    /// Zeros for every other kind and for a DATA frame travelling client to owner, whose input carries zeros in the digest's place. [`mac_input`](Self::mac_input) returns `None` for client-to-owner DATA when sending, and the owner drops such a frame at dispatch.
    #[inline]
    fn frame_digest(
        &self,
        frame: &Frame<'_>,
        peer: PeerId,
        endpoint: u32,
        direction: Direction,
    ) -> BodyDigest {
        let header = frame.header();
        if header.kind != Kind::Data || direction != Direction::OwnerToClient {
            return BodyDigest {
                bytes: [0; DATA_DIGEST_LEN],
                derived: None,
            };
        }
        self.keyed[usize::from(peer.0)].digest(
            endpoint,
            (header.owner_nonce, header.client_nonce),
            [frame.raw_body(), &[]],
        )
    }

    /// `result`, after `peer`'s key stores the data key `digest` derived when `result` is `Ok`; a frame that fails authentication leaves the kept key in place.
    #[inline]
    fn kept<'f, 'b>(
        &self,
        result: Result<Authenticated<'f, 'b>, AuthError>,
        peer: PeerId,
        digest: &mut BodyDigest,
    ) -> Result<Authenticated<'f, 'b>, AuthError> {
        if result.is_ok() {
            self.keyed[usize::from(peer.0)].keep(digest);
        }
        result
    }

    /// The truncated tag of `input` under `peer`'s key; `None` for a peer outside the ring.
    #[inline]
    pub fn tag(&self, peer: PeerId, input: &MacInput<'_>) -> Option<[u8; TAG_LEN]> {
        Some(unhinted(self.keyed.get(usize::from(peer.0))?, input))
    }

    /// The truncated tags of two inputs under their peers' keys, each equal to its [`tag`](Self::tag), computed through the group path with two chains; `None` for a peer outside the ring.
    #[inline]
    pub fn tag_pair(
        &self,
        peers: [PeerId; 2],
        inputs: [&MacInput<'_>; 2],
    ) -> Option<[[u8; TAG_LEN]; 2]> {
        let keys = [
            self.keyed.get(usize::from(peers[0].0))?,
            self.keyed.get(usize::from(peers[1].0))?,
        ];
        Some(laned(self.lanes, keys, inputs))
    }

    /// The truncated tag of each of `inputs` under `peer`'s key, written to the same position of `tags`, each equal to its [`tag`](Self::tag); `None`, with `tags` unchanged, for a peer outside the ring or slices of different lengths.
    /// On an x86_64 CPU with `avx512f`, `avx512bw` and `vpclmulqdq` the inputs hash sixteen chains to one vector pass while at least fifteen remain. The rest, consecutive and in order, hash as groups of four chains while six or more remain or exactly four do, then five as three chains and two, three as three chains and two as a pair; an input hashes alone only when it is the one input of the rest. Each group compresses every block after each chain's first through `Lanes`, its live chains together, regrouping as chains finish.
    pub fn tags(
        &self,
        peer: PeerId,
        inputs: &[MacInput<'_>],
        tags: &mut [[u8; TAG_LEN]],
    ) -> Option<()> {
        let key = self.keyed.get(usize::from(peer.0))?;
        if inputs.len() != tags.len() {
            return None;
        }
        #[cfg(target_arch = "x86_64")]
        let done = wide::tags(key, inputs, tags);
        #[cfg(not(target_arch = "x86_64"))]
        let done = 0;
        let (inputs, tags) = (&inputs[done..], &mut tags[done..]);
        if let ([input], [tag]) = (inputs, &mut *tags) {
            *tag = unhinted(key, input);
            return Some(());
        }
        // Five inputs at the end hash as three chains and two, so a group of four leaves no input to hash alone.
        let fours = if inputs.len() % 4 == 1 {
            (inputs.len() / 4).saturating_sub(1)
        } else {
            inputs.len() / 4
        };
        let (quads, rest) = inputs.split_at(4 * fours);
        let (quad_tags, rest_tags) = tags.split_at_mut(4 * fours);
        for (quad, out) in quads
            .as_chunks::<4>()
            .0
            .iter()
            .zip(quad_tags.as_chunks_mut::<4>().0)
        {
            *out = laned(self.lanes, [key; 4], quad.each_ref());
        }
        let threes = usize::from(rest.len() == 3 || rest.len() == 5);
        let (triple, rest) = rest.split_at(3 * threes);
        let (triple_tags, rest_tags) = rest_tags.split_at_mut(3 * threes);
        if let (Ok(triple), Ok(out)) = (
            <&[MacInput<'_>; 3]>::try_from(triple),
            <&mut [[u8; TAG_LEN]; 3]>::try_from(triple_tags),
        ) {
            *out = laned(self.lanes, [key; 3], triple.each_ref());
        }
        if let ([first, second], [out, last]) = (rest, rest_tags) {
            [*out, *last] = laned(self.lanes, [key; 2], [first, second]);
        }
        Some(())
    }

    /// The ring's passes of two to four chains run through [`Lanes::portable`], with the fused tail off. A chain compressed alone and the x86_64 vector pass keep their dispatch.
    #[cfg(test)]
    pub(super) fn with_portable_lanes(mut self) -> Self {
        self.lanes = Lanes::portable();
        self
    }

    /// The boot nonces, owner then client, of the session whose data key `peer`'s key keeps.
    #[cfg(test)]
    pub(super) fn kept_session(&self, peer: PeerId) -> Option<([u8; 16], [u8; 16])> {
        self.keyed[usize::from(peer.0)]
            .data
            .borrow()
            .as_ref()
            .map(|data| data.nonces)
    }

    /// Whether [`tags`](Self::tags) hashes fifteen or sixteen inputs in one vector pass on this CPU: x86_64 with `avx512f`, `avx512bw` and `vpclmulqdq`. A caller that splits a run into calls of sixteen reads it to choose between a last call of one input after a full pass and a last call of two.
    #[inline]
    pub(super) fn vector_pass_detected() -> bool {
        #[cfg(target_arch = "x86_64")]
        return wide::detected();
        #[cfg(not(target_arch = "x86_64"))]
        return false;
    }

    /// How many leading inputs [`tags`](Self::tags) hashes in vector passes on this CPU, writing their tags; zero off x86_64 or without `avx512f`, `avx512bw` and `vpclmulqdq`.
    #[cfg(test)]
    pub(super) fn vector_tags(
        &self,
        peer: PeerId,
        inputs: &[MacInput<'_>],
        tags: &mut [[u8; TAG_LEN]],
    ) -> usize {
        let key = &self.keyed[usize::from(peer.0)];
        #[cfg(target_arch = "x86_64")]
        return wide::tags(key, inputs, tags);
        #[cfg(not(target_arch = "x86_64"))]
        return {
            let _ = (key, inputs, tags);
            0
        };
    }

    /// Tags one to sixteen `inputs` in one vector pass, whatever their count, and returns whether the CPU ran it; [`tags`](Self::tags) takes the pass only for fifteen inputs or more.
    ///
    /// # Panics
    ///
    /// For a peer outside the ring and, on x86_64, for an input count outside one to sixteen or a `tags` slice of another length.
    #[cfg(test)]
    pub(super) fn vector_pass(
        &self,
        peer: PeerId,
        inputs: &[MacInput<'_>],
        tags: &mut [[u8; TAG_LEN]],
    ) -> bool {
        let key = &self.keyed[usize::from(peer.0)];
        #[cfg(target_arch = "x86_64")]
        return wide::vector_pass(key, inputs, tags);
        #[cfg(not(target_arch = "x86_64"))]
        return {
            let _ = (key, inputs, tags);
            false
        };
    }

    /// Authenticates `frame`, received from the transport's `peer`, for `endpoint` and `direction`: the principal must be `peer`'s, the key epoch the ring's, and the tag must verify in constant time.
    ///
    /// # Errors
    ///
    /// `Principal`, `KeyEpoch` or `Tag`, in that order.
    #[inline]
    pub fn authenticate<'f, 'b>(
        &self,
        frame: &'f Frame<'b>,
        peer: PeerId,
        endpoint: u32,
        direction: Direction,
    ) -> Result<Authenticated<'f, 'b>, AuthError> {
        self.admit(frame, peer)?;
        let mut digest = self.frame_digest(frame, peer, endpoint, direction);
        let input = input_of(frame, &digest.bytes, endpoint, direction);
        let tag = truncated(&self.keyed[usize::from(peer.0)], &input, ahead_of(frame));
        self.kept(verified(tag, frame, peer), peer, &mut digest)
    }

    /// [`authenticate`](Self::authenticate) given `tag`, which the caller computed over `frame`'s bytes under `peer`'s key with [`tag`](Self::tag) or [`tag_pair`](Self::tag_pair).
    ///
    /// # Errors
    ///
    /// As [`authenticate`](Self::authenticate).
    #[inline]
    pub(super) fn authenticate_tagged<'f, 'b>(
        &self,
        frame: &'f Frame<'b>,
        peer: PeerId,
        tag: [u8; TAG_LEN],
    ) -> Result<Authenticated<'f, 'b>, AuthError> {
        self.admit(frame, peer)?;
        verified(tag, frame, peer)
    }

    pub(super) fn tag_group<const N: usize>(
        &self,
        inputs: [(PeerId, &MacInput<'_>); N],
    ) -> Option<[[u8; TAG_LEN]; N]> {
        if inputs
            .iter()
            .any(|(peer, _)| usize::from(peer.0) >= self.keyed.len())
        {
            return None;
        }
        let keys = inputs.map(|(peer, _)| &self.keyed[usize::from(peer.0)]);
        Some(laned(self.lanes, keys, inputs.map(|(_, input)| input)))
    }

    /// Authenticates frames whose tags cover their bodies, such as PUT DATA frames, as [`authenticate`](Self::authenticate) does.
    pub fn authenticate_group<'f, 'b, const N: usize>(
        &self,
        frames: [(&'f Frame<'b>, PeerId); N],
        endpoint: u32,
        direction: Direction,
    ) -> [Result<Authenticated<'f, 'b>, AuthError>; N] {
        let admitted = frames.map(|(frame, peer)| self.admit(frame, peer));
        if admitted.iter().any(Result::is_err) {
            return std::array::from_fn(|at| {
                admitted[at].and_then(|()| {
                    self.authenticate(frames[at].0, frames[at].1, endpoint, direction)
                })
            });
        }
        let mut digests: [BodyDigest; N] = std::array::from_fn(|at| {
            self.frame_digest(frames[at].0, frames[at].1, endpoint, direction)
        });
        let inputs: [MacInput<'_>; N] = std::array::from_fn(|at| {
            input_of(frames[at].0, &digests[at].bytes, endpoint, direction)
        });
        let keys: [&PeerKey; N] =
            std::array::from_fn(|at| &self.keyed[usize::from(frames[at].1.0)]);
        for (frame, _) in frames {
            Ahead::new(ahead_of(frame)).rest();
        }
        let tags = laned(self.lanes, keys, inputs.each_ref());
        std::array::from_fn(|at| {
            let (frame, peer) = frames[at];
            self.kept(verified(tags[at], frame, peer), peer, &mut digests[at])
        })
    }

    /// [`authenticate`](Self::authenticate) for two frames, their tags computed through the group path with two chains; each frame's result is the one `authenticate` gives it alone.
    #[inline]
    pub fn authenticate_pair<'f, 'b, 'g, 'c>(
        &self,
        first: (&'f Frame<'b>, PeerId),
        second: (&'g Frame<'c>, PeerId),
        endpoint: u32,
        direction: Direction,
    ) -> (
        Result<Authenticated<'f, 'b>, AuthError>,
        Result<Authenticated<'g, 'c>, AuthError>,
    ) {
        let admitted = (self.admit(first.0, first.1), self.admit(second.0, second.1));
        let (Ok(()), Ok(())) = admitted else {
            return (
                admitted
                    .0
                    .and_then(|()| self.authenticate(first.0, first.1, endpoint, direction)),
                admitted
                    .1
                    .and_then(|()| self.authenticate(second.0, second.1, endpoint, direction)),
            );
        };
        let mut digests = (
            self.frame_digest(first.0, first.1, endpoint, direction),
            self.frame_digest(second.0, second.1, endpoint, direction),
        );
        let inputs = (
            input_of(first.0, &digests.0.bytes, endpoint, direction),
            input_of(second.0, &digests.1.bytes, endpoint, direction),
        );
        Ahead::new(ahead_of(first.0)).rest();
        Ahead::new(ahead_of(second.0)).rest();
        let tags = laned(
            self.lanes,
            [
                &self.keyed[usize::from(first.1.0)],
                &self.keyed[usize::from(second.1.0)],
            ],
            [&inputs.0, &inputs.1],
        );
        (
            self.kept(verified(tags[0], first.0, first.1), first.1, &mut digests.0),
            self.kept(
                verified(tags[1], second.0, second.1),
                second.1,
                &mut digests.1,
            ),
        )
    }

    /// The principal and key-epoch checks of [`authenticate`](Self::authenticate), before the tag.
    #[inline(always)]
    fn admit(&self, frame: &Frame<'_>, peer: PeerId) -> Result<(), AuthError> {
        let header = frame.header();
        self.admit_fields(peer, header.principal, header.key_epoch)
    }

    #[inline(always)]
    pub(super) fn admits(&self, peer: PeerId, principal: u32, key_epoch: u32) -> bool {
        self.admit_fields(peer, principal, key_epoch).is_ok()
    }

    #[inline(always)]
    fn admit_fields(&self, peer: PeerId, principal: u32, key_epoch: u32) -> Result<(), AuthError> {
        if self.principal(peer) != Some(principal) {
            return Err(AuthError::Principal { principal });
        }
        if key_epoch != self.epoch {
            return Err(AuthError::KeyEpoch { found: key_epoch });
        }
        Ok(())
    }

    /// Replaces every key and moves to key `epoch` in place, keeping the ring's charged arrays; the configured principals stay.
    ///
    /// # Errors
    ///
    /// `SameEpoch` when `epoch` is the ring's, then the per-entry, `Missing` and `Shared` refusals of [`load`](Self::load); a refusal leaves the ring unchanged, and success allocates nothing.
    pub(super) fn replace(&mut self, entries: &[KeyEntry<'_>], epoch: u32) -> Result<(), KeyError> {
        if epoch == self.epoch {
            return Err(KeyError::SameEpoch { epoch });
        }
        assign(&self.principals, &self.index, entries, &mut self.scratch)?;
        for (slot, &at) in self.keyed.iter_mut().zip(self.scratch.iter()) {
            slot.rekey(keyed(entries[usize::from(at)].key));
        }
        self.epoch = epoch;
        Ok(())
    }
}

/// The index of the peer whose principal is `principal`, through `index`, the peer table of the distinct `peers`.
fn find(peers: &[u32], index: &[u16], principal: u32) -> Option<usize> {
    probe(index, spread(principal), vacant, |peer| {
        peers[usize::from(peer)] == principal
    })
    .ok()
    .map(|slot| usize::from(index[slot]))
}

fn vacant(word: u16) -> bool {
    word == EMPTY
}

/// Checks that `entries` hold exactly one distinct, well-formed key per peer of the distinct `peers`, and on success leaves `scratch[p]` the index of peer `p`'s entry.
/// `index` is the peer table of `peers` and `scratch` holds one word per peer and a key table; the refusals and their order are [`KeyRing::load`]'s after its peer checks.
fn assign(
    peers: &[u32],
    index: &[u16],
    entries: &[KeyEntry<'_>],
    scratch: &mut [u16],
) -> Result<(), KeyError> {
    let (claims, table) = scratch.split_at_mut(peers.len());
    // An entry index stored in `claims` is below the peers' count: well-formed entries of distinct configured principals number at most the peers, so every refusal comes at or before the entry at that count.
    claims.fill(EMPTY);
    for (at, entry) in entries.iter().enumerate() {
        if entry.key.len() != KEY_LEN {
            return Err(KeyError::Malformed {
                principal: entry.principal,
                len: entry.key.len(),
            });
        }
        let Some(peer) = find(peers, index, entry.principal) else {
            return Err(KeyError::Unknown {
                principal: entry.principal,
            });
        };
        if claims[peer] != EMPTY {
            return Err(KeyError::Duplicate {
                principal: entry.principal,
            });
        }
        claims[peer] = at as u16;
    }
    // The entries name distinct configured principals, so they cover every peer exactly when they number as many as the peers.
    if let Some(peer) = claims.iter().position(|&at| at == EMPTY) {
        return Err(KeyError::Missing {
            principal: peers[peer],
        });
    }
    // Entries now number as many as the peers, so their indices fit a word. Inserting the keys in entry order into an open-addressing table of at least twice their count, the first entry that meets its own key holds an earlier entry's key, and the occupant is that key's earliest holder.
    table.fill(EMPTY);
    for (entry, at) in entries.iter().zip(0..) {
        match probe(table, key_hash(entry.key), vacant, |earlier| {
            entries[usize::from(earlier)].key == entry.key
        }) {
            Ok(slot) => {
                return Err(KeyError::Shared {
                    first: entries[usize::from(table[slot])].principal,
                    second: entry.principal,
                });
            }
            Err(slot) => table[slot] = at,
        }
    }
    Ok(())
}

/// A slot hash of a 32-byte key that mixes all of its bytes.
fn key_hash(key: &[u8]) -> usize {
    let word = |at: usize| {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&key[at * 8..at * 8 + 8]);
        u64::from_le_bytes(bytes)
    };
    let mixed =
        word(0) ^ word(1).rotate_left(16) ^ word(2).rotate_left(32) ^ word(3).rotate_left(48);
    (mixed.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32) as usize
}

/// The bytes a received frame's verification hints ahead of reading them: its raw body, which the body crc check reads next, except for DATA, whose digest already read the body.
#[inline]
fn ahead_of<'b>(frame: &Frame<'b>) -> &'b [u8] {
    if frame.header().kind == Kind::Data {
        &[]
    } else {
        frame.raw_body()
    }
}

/// The MAC input of a received `frame` for `endpoint` and `direction`: [`Frame::mac_input`]'s, or for DATA, which that method leaves to the caller, the domain block and the authenticated header with `digest` as the covered body.
fn input_of<'s>(
    frame: &'s Frame<'_>,
    digest: &'s [u8; DATA_DIGEST_LEN],
    endpoint: u32,
    direction: Direction,
) -> MacInput<'s> {
    match frame.mac_input(endpoint, direction) {
        Some(input) => input,
        None => data_mac_input(frame.authenticated(), digest, endpoint, direction),
    }
}

/// Whether `tag` equals `expected`, compared in constant time. The difference of every tag byte folds into one
/// 64-bit word that passes the optimization barrier before its one comparison; the tag comparison inspection
/// (`verification/tag-compare/expected.json`) checks that each condition in `tag_compare_decision`, a release-build
/// caller that inlines this comparison, depends on every byte of both tags.
#[inline(always)]
pub(crate) fn tags_equal(tag: [u8; TAG_LEN], expected: [u8; TAG_LEN]) -> bool {
    let difference = u128::from_ne_bytes(tag) ^ u128::from_ne_bytes(expected);
    let folded = std::hint::black_box(difference as u64 | (difference >> 64) as u64);
    bool::from(folded.ct_eq(&0))
}

/// `frame` authenticated when `tag` is its header's tag; the comparison runs in constant time.
#[inline(always)]
fn verified<'f, 'b>(
    tag: [u8; TAG_LEN],
    frame: &'f Frame<'b>,
    peer: PeerId,
) -> Result<Authenticated<'f, 'b>, AuthError> {
    if !tags_equal(tag, frame.header().tag) {
        return Err(AuthError::Tag);
    }
    Ok(Authenticated { frame, peer })
}

/// Whole body blocks reach the compression in place, [`RUN`] at a time; the straddling, partial and padding blocks go one at a time.
fn truncated(key: &PeerKey, input: &MacInput<'_>, ahead: &[u8]) -> [u8; TAG_LEN] {
    let mut ahead = Ahead::new(ahead);
    let mut inner = first_state(key, input);
    ahead.step();
    ahead.step();
    sha_lanes::lone(&mut inner, rest_blocks(input));
    if input.body_len() == 0 {
        ahead.step();
        sha_lanes::lone(&mut inner, &[PAD_HEADER]);
        ahead.step();
    } else if let Some(block) = digest_block(input) {
        ahead.step();
        sha_lanes::lone(&mut inner, &[block]);
    } else {
        let mut body = Body::of(input);
        loop {
            let run = body.run(RUN);
            if !run.is_empty() {
                ahead.step();
                sha_lanes::lone(&mut inner, run);
                continue;
            }
            let Some(block) = body.next_block() else {
                break;
            };
            sha_lanes::lone(&mut inner, std::slice::from_ref(block));
        }
    }
    tag_of(&outer_hash(&key.keyed, &inner))
}

/// [`truncated`] with no bytes to hint, each run of whole blocks compressed in one call so the hash keeps its state in registers across the run.
fn unhinted(key: &PeerKey, input: &MacInput<'_>) -> [u8; TAG_LEN] {
    let mut inner = first_state(key, input);
    sha_lanes::lone(&mut inner, rest_blocks(input));
    if input.body_len() == 0 {
        sha_lanes::lone(&mut inner, &[PAD_HEADER]);
    } else if let Some(block) = digest_block(input) {
        sha_lanes::lone(&mut inner, &[block]);
    } else {
        let mut body = Body::of(input);
        sha_lanes::lone(&mut inner, body.run(usize::MAX));
        while let Some(block) = body.next_block() {
            sha_lanes::lone(&mut inner, std::slice::from_ref(block));
        }
    }
    tag_of(&outer_hash(&key.keyed, &inner))
}

impl Lanes {
    /// `states[i]` and `blocks[i]` belong to chain `i`. Each pass compresses blocks for up to four chains into their respective states. Those chains must have equal block counts.
    ///
    /// # Panics
    ///
    /// When two chains of one pass differ in block count.
    #[inline(always)]
    pub(super) fn each(self, states: &mut [State], blocks: &[&[Block]]) {
        debug_assert_eq!(states.len(), blocks.len());
        for (states, blocks) in states.chunks_mut(LANES).zip(blocks.chunks(LANES)) {
            if let (Ok(states), Ok(blocks)) =
                (<&mut [State; 4]>::try_from(&mut *states), blocks.try_into())
            {
                self.quad(states, blocks);
            } else if let (Ok(states), Ok(blocks)) =
                (<&mut [State; 3]>::try_from(&mut *states), blocks.try_into())
            {
                self.triple(states, blocks);
            } else if let (Ok(states), Ok(blocks)) =
                (<&mut [State; 2]>::try_from(&mut *states), blocks.try_into())
            {
                self.pair(states, blocks);
            } else {
                for (state, run) in states.iter_mut().zip(blocks) {
                    sha_lanes::lone(state, run);
                }
            }
        }
    }
}

/// The tags of `inputs` under `keys`, after each chain's memoized or freshly compressed first block: the header's two middle blocks of every chain in one pass, then the covered body, then the outer block of every chain in one pass. When every covered body is shorter than 56 bytes, each chain's body takes one block, the fixed [`PAD_HEADER`] for an empty body and an assembled block otherwise, compressed in one pass. Otherwise `body_passes` compresses the bodies. Each pass compresses its live chains through [`Lanes::each`].
///
/// On aarch64 with `sha2`, `Lanes::tail` handles two to four inputs with empty covered bodies in one kernel pass. For each chain, the kernel preserves the separate passes' compression order: the chain's two middle blocks, [`PAD_HEADER`] using `HEADER_END`'s round words, then the chain's outer block.
#[inline]
fn laned<'b, const N: usize>(
    lanes: Lanes,
    keys: [&PeerKey; N],
    inputs: [&MacInput<'b>; N],
) -> [[u8; TAG_LEN]; N] {
    let mut states: [State; N] = [[0; 8]; N];
    for at in 0..N {
        states[at] = first_state(keys[at], inputs[at]);
    }
    // Header-only groups, the shape of polled control frames, end every chain on the fixed padding block and assemble none.
    let header_only = inputs.iter().all(|input| input.body_len() == 0);
    #[cfg(target_arch = "aarch64")]
    if header_only {
        let tail = Tail {
            middle: inputs.map(rest_blocks),
            last: &HEADER_END,
            outer: keys.map(|key| &key.keyed.outer),
            pad: PAD_DIGEST.last_chunk().expect("a block's second half"),
        };
        if lanes.tail(&mut states, &tail) {
            return states.map(|outer| tag_of(&outer));
        }
    }
    lanes.each(&mut states, &inputs.map(rest_blocks));
    if header_only {
        lanes.each(&mut states, &[std::slice::from_ref(&PAD_HEADER); N]);
    } else if inputs.iter().all(|input| input.body_len() < BLOCK_LEN - 8) {
        let mut assembled = [[0; BLOCK_LEN]; N];
        let mut tails: [&[Block]; N] = [std::slice::from_ref(&PAD_HEADER); N];
        for ((tail, block), input) in tails.iter_mut().zip(&mut assembled).zip(inputs) {
            if input.body_len() > 0 {
                short_tail(input, block);
                *tail = std::slice::from_ref(block);
            }
        }
        lanes.each(&mut states, &tails);
    } else {
        body_passes(lanes, &mut states, inputs);
    }
    let blocks: [Block; N] = std::array::from_fn(|at| outer_block(&states[at]));
    let mut outer = keys.map(|key| key.keyed.outer);
    lanes.each(&mut outer, &blocks.each_ref().map(std::slice::from_ref));
    std::array::from_fn(|at| tag_of(&outer[at]))
}

/// Compresses each covered body of `inputs` into `states`, the chains in lockstep: the whole blocks at the start of each body in place, each pass as long as the shortest live run, then every block `Body::next_block` yields, one block per live chain a pass.
fn body_passes<const N: usize>(lanes: Lanes, states: &mut [State; N], inputs: [&MacInput<'_>; N]) {
    let mut bodies = inputs.map(Body::of);
    let mut runs: [&[Block]; N] = std::array::from_fn(|at| bodies[at].run(usize::MAX));
    let mut live = [0; N];
    loop {
        let mut count = 0;
        for (at, run) in runs.iter().enumerate() {
            if !run.is_empty() {
                live[count] = at;
                count += 1;
            }
        }
        if count == 0 {
            break;
        }
        let common = live[..count]
            .iter()
            .map(|&at| runs[at].len())
            .min()
            .unwrap_or(0);
        let mut pass = [[0; 8]; N];
        let mut slices: [&[Block]; N] = [&[]; N];
        for (slot, &at) in live[..count].iter().enumerate() {
            pass[slot] = states[at];
            (slices[slot], runs[at]) = runs[at].split_at(common);
        }
        lanes.each(&mut pass[..count], &slices[..count]);
        for (slot, &at) in live[..count].iter().enumerate() {
            states[at] = pass[slot];
        }
    }
    loop {
        let mut count = 0;
        let mut pass = [[0; 8]; N];
        let mut slices: [&[Block]; N] = [&[]; N];
        for (at, body) in bodies.iter_mut().enumerate() {
            if let Some(block) = body.next_block() {
                slices[count] = std::slice::from_ref(block);
                pass[count] = states[at];
                live[count] = at;
                count += 1;
            }
        }
        if count == 0 {
            break;
        }
        lanes.each(&mut pass[..count], &slices[..count]);
        for (slot, &at) in live[..count].iter().enumerate() {
            states[at] = pass[slot];
        }
    }
}

/// The inner hash's one block after the header when `input`'s first body slice holds 16 bytes and its second is empty: those bytes and [`PAD_DATA`]'s padding; `None` for every other covered body.
#[inline(always)]
fn digest_block(input: &MacInput<'_>) -> Option<[u8; BLOCK_LEN]> {
    let [body, rest] = input.body;
    let body: &[u8; DATA_DIGEST_LEN] = body.try_into().ok()?;
    if !rest.is_empty() {
        return None;
    }
    let mut block = PAD_DATA;
    block[..DATA_DIGEST_LEN].copy_from_slice(body);
    Some(block)
}

/// `Body` yields whole blocks in place, assembles slice-straddling blocks in `scratch`, and appends FIPS 180-4 padding. Padding requires an additional block when fewer than nine bytes remain.
struct Body<'b> {
    /// The covered body not yet hashed, the first slice consumed before the second.
    body: [&'b [u8]; 2],
    /// The message's length in bits, the padding's last field.
    bits: u64,
    stage: Stage,
    /// `scratch` holds an assembled block until the compression consumes it.
    scratch: [u8; BLOCK_LEN],
}

/// `Stage` tracks padding progress through a [`Body`]'s final blocks.
#[derive(Clone, Copy)]
enum Stage {
    /// Body bytes remain, or the padding has not started.
    Body,
    /// The `0x80` byte filled the last body block, so a block holding only the length remains.
    Length,
    /// The length went out.
    Done,
}

impl<'b> Body<'b> {
    fn of(input: &MacInput<'b>) -> Self {
        Self {
            body: input.body,
            bits: ((PREFIX_LEN + input.body_len()) as u64) * 8,
            stage: Stage::Body,
            scratch: [0; BLOCK_LEN],
        }
    }

    /// Blocks [`next_block`](Self::next_block) still yields.
    #[cfg(target_arch = "x86_64")]
    fn blocks(&self) -> usize {
        match self.stage {
            Stage::Done => 0,
            Stage::Length => 1,
            Stage::Body => (self.body[0].len() + self.body[1].len() + 9).div_ceil(BLOCK_LEN),
        }
    }

    #[inline(always)]
    fn promote(&mut self) {
        if self.body[0].is_empty() {
            self.body[0] = std::mem::take(&mut self.body[1]);
        }
    }

    #[inline(always)]
    fn run(&mut self, max: usize) -> &'b [[u8; BLOCK_LEN]] {
        self.promote();
        let (whole, _) = self.body[0].as_chunks::<BLOCK_LEN>();
        let take = whole.len().min(max);
        self.body[0] = &self.body[0][take * BLOCK_LEN..];
        &whole[..take]
    }

    /// `next_block` returns `None` after yielding the block containing the message length.
    #[inline(always)]
    fn next_block(&mut self) -> Option<&[u8; BLOCK_LEN]> {
        self.promote();
        if let Some((block, rest)) = self.body[0].split_first_chunk::<BLOCK_LEN>() {
            self.body[0] = rest;
            return Some(block);
        }
        self.scratch = [0; BLOCK_LEN];
        match self.stage {
            Stage::Done => return None,
            Stage::Length => {}
            Stage::Body => {
                let mut used = 0;
                for piece in &mut self.body {
                    let take = piece.len().min(BLOCK_LEN - used);
                    self.scratch[used..used + take].copy_from_slice(&piece[..take]);
                    *piece = &piece[take..];
                    used += take;
                }
                if used == BLOCK_LEN {
                    return Some(&self.scratch);
                }
                self.scratch[used] = 0x80;
                if used >= BLOCK_LEN - 8 {
                    self.stage = Stage::Length;
                    return Some(&self.scratch);
                }
            }
        }
        self.scratch[BLOCK_LEN - 8..].copy_from_slice(&self.bits.to_be_bytes());
        self.stage = Stage::Done;
        Some(&self.scratch)
    }
}

/// Writes into the zeroed `block` the inner hash's one block after the header for a covered body of at most 55 bytes in one or two slices: the body's bytes, `0x80` and the message length, the block `Body` assembles for that body.
#[inline(always)]
fn short_tail(input: &MacInput<'_>, block: &mut Block) {
    let len = input.body_len();
    debug_assert!(len < BLOCK_LEN - 8);
    let [first, second] = input.body;
    copy_short(&mut block[..first.len()], first);
    copy_short(&mut block[first.len()..len], second);
    block[len] = 0x80;
    block[BLOCK_LEN - 8..].copy_from_slice(&(((PREFIX_LEN + len) * 8) as u64).to_be_bytes());
}

/// Copies `src` into `dst`, slices of equal length, in fixed-width 16-, 8-, 4-, 2- and 1-byte moves, which compile to inline loads and stores for the at most 55 bytes `short_tail` copies; `len` takes the shorter slice so every move indexes in bounds.
#[inline(always)]
fn copy_short(dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());
    let len = src.len().min(dst.len());
    let mut at = 0;
    while at + 16 <= len {
        dst[at..at + 16].copy_from_slice(&src[at..at + 16]);
        at += 16;
    }
    for width in [8, 4, 2, 1] {
        if at + width <= len {
            dst[at..at + width].copy_from_slice(&src[at..at + width]);
            at += width;
        }
    }
}

/// `Ahead` hints up to [`HINTS`] lines per step for bytes read right after a tag.
struct Ahead<'b>(std::slice::Chunks<'b, u8>);

impl<'b> Ahead<'b> {
    fn new(bytes: &'b [u8]) -> Self {
        Self(bytes.chunks(HINTS * LINE))
    }

    #[inline(always)]
    fn step(&mut self) {
        for line in self.0.next().unwrap_or_default().chunks(LINE) {
            hint_read(line.as_ptr());
        }
    }

    #[inline(always)]
    fn rest(&mut self) {
        for chunk in self.0.by_ref() {
            for line in chunk.chunks(LINE) {
                hint_read(line.as_ptr());
            }
        }
    }
}

#[cfg(test)]
thread_local! {
    /// First blocks this thread compressed because the memo slot of the frame's kind held another block or none.
    pub(super) static FRESH_FIRST_BLOCKS: Cell<usize> = const { Cell::new(0) };
    /// Hash chains this thread started over a GET header that travels from a client to an owner, one for each such input of a tag computation, whether its first block came from the memo or was compressed. Sealing a client's GET counts as well as checking one, so a test that measures an owner resets the count after it seals its frames.
    pub(super) static GET_TAGS: Cell<usize> = const { Cell::new(0) };
}

/// The inner hash's state after `input`'s first block, from the memo slot of its kind when the slot holds that block, and otherwise computed and memoized.
#[inline(always)]
fn first_state(key: &PeerKey, input: &MacInput<'_>) -> [u32; 8] {
    #[cfg(test)]
    if input.direction == Direction::ClientToOwner && input.header[KIND_AT] == Kind::Get as u8 {
        GET_TAGS.with(|count| count.set(count.get() + 1));
    }
    let slot = &key.first[slot_of(input)];
    if let Some(memo) = slot.get().filter(|memo| memo.names(input)) {
        return memo.state;
    }
    #[cfg(test)]
    FRESH_FIRST_BLOCKS.with(|count| count.set(count.get() + 1));
    let mut first = [0; BLOCK_LEN];
    first[..DOMAIN_LEN].copy_from_slice(&input.domain());
    first[DOMAIN_LEN..].copy_from_slice(&input.header[..HEADER_IN_FIRST]);
    let fresh = Midstate::of(&key.keyed, first);
    slot.set(Some(fresh));
    fresh.state
}

/// Blocks of the header after the inner hash's first block.
#[cfg(target_arch = "x86_64")]
const REST_BLOCKS: usize = (AUTHENTICATED_LEN - HEADER_IN_FIRST) / BLOCK_LEN;
const _: () = assert!((AUTHENTICATED_LEN - HEADER_IN_FIRST).is_multiple_of(BLOCK_LEN));

/// The header bytes after the first `HEADER_IN_FIRST` bytes form the inner hash's middle blocks.
#[inline(always)]
fn rest_blocks<'b>(input: &MacInput<'b>) -> &'b [[u8; BLOCK_LEN]] {
    input.header[HEADER_IN_FIRST..].as_chunks::<BLOCK_LEN>().0
}

/// The leftmost [`TAG_LEN`] bytes of the outer digest.
#[inline(always)]
fn tag_of(outer: &[u32; 8]) -> [u8; TAG_LEN] {
    let mut tag = [0; TAG_LEN];
    tag.copy_from_slice(&digest_bytes(outer)[..TAG_LEN]);
    tag
}

/// The memo slots: GET through COMPLETE in kind order from slot 0, then PUT BEGIN through PUT RESULT in kind order from `PUT_SLOT`, then the one every other kind shares.
const PUT_SLOT: usize = (Kind::Complete as u8 - Kind::Get as u8 + 1) as usize;
const SHARED_SLOT: usize = PUT_SLOT + (Kind::PutResult as u8 - Kind::PutBegin as u8 + 1) as usize;
const _: () = assert!(SHARED_SLOT == MIDSTATES - 1);

/// The memo slot of `input`'s first block, from the kind byte.
fn slot_of(input: &MacInput<'_>) -> usize {
    const GET: u8 = Kind::Get as u8;
    const COMPLETE: u8 = Kind::Complete as u8;
    const PUT_BEGIN: u8 = Kind::PutBegin as u8;
    const PUT_RESULT: u8 = Kind::PutResult as u8;
    match input.header[KIND_AT] {
        kind @ GET..=COMPLETE => usize::from(kind - GET),
        kind @ PUT_BEGIN..=PUT_RESULT => PUT_SLOT + usize::from(kind - PUT_BEGIN),
        _ => SHARED_SLOT,
    }
}

fn outer_hash(keyed: &Keyed, inner: &[u32; 8]) -> [u32; 8] {
    let mut outer = keyed.outer;
    sha_lanes::lone(&mut outer, &[outer_block(inner)]);
    outer
}

/// The outer hash's one message block: the inner digest with the padding in place.
#[inline(always)]
pub(crate) fn outer_block(inner: &[u32; 8]) -> [u8; BLOCK_LEN] {
    let mut block = PAD_DIGEST;
    block[..32].copy_from_slice(&digest_bytes(inner));
    block
}

/// `digest_bytes` uses SHA-256 digest byte order.
#[inline(always)]
pub(crate) fn digest_bytes(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (word, out) in words.iter().zip(bytes.as_chunks_mut::<4>().0) {
        *out = word.to_be_bytes();
    }
    bytes
}

/// `keyed` precomputes the RFC 2104 inner and outer pad-block states of a key of at most one block.
///
/// # Panics
///
/// If `key` is longer than one block.
#[inline(always)]
pub(crate) fn keyed(key: &[u8]) -> Keyed {
    let mut block = [0; BLOCK_LEN];
    block[..key.len()].copy_from_slice(key);
    let mut inner = SHA256_IV;
    compress256(&mut inner, &[block.map(|byte| byte ^ 0x36)]);
    let mut outer = SHA256_IV;
    compress256(&mut outer, &[block.map(|byte| byte ^ 0x5c)]);
    Keyed { inner, outer }
}

/// SHA-256 over sixteen independent chains at once, one chain per 32-bit lane of each AVX-512 register.
#[cfg(target_arch = "x86_64")]
mod wide {
    use std::arch::x86_64::{
        __m512i, _mm512_add_epi32, _mm512_loadu_si512, _mm512_ror_epi32, _mm512_set1_epi32,
        _mm512_set4_epi32, _mm512_setzero_si512, _mm512_shuffle_epi8, _mm512_shuffle_i32x4,
        _mm512_srli_epi32, _mm512_storeu_si512, _mm512_ternarylogic_epi32, _mm512_unpackhi_epi32,
        _mm512_unpackhi_epi64, _mm512_unpacklo_epi32, _mm512_unpacklo_epi64,
    };

    use sha2::block_api::compress256;

    use super::super::sha_lanes::K;
    use super::{
        BLOCK_LEN, Body, MacInput, PeerKey, REST_BLOCKS, TAG_LEN, first_state, outer_hash,
        rest_blocks, tag_of,
    };

    const LANES: usize = 16;

    /// A pass costs about as much as fifteen 8 KiB PUT DATA tags hashed two chains at a time through the SHA extensions, regardless of lane count. The threshold serves full-fragment PUT DATA batches.
    const LANES_MIN: usize = 15;

    /// Writes the tags of the leading inputs, in passes of up to [`LANES`] while at least [`LANES_MIN`] remain, and returns how many it wrote; none on a CPU without `avx512f`, `avx512bw` and `vpclmulqdq`.
    ///
    /// Skylake-SP, Cascade Lake and Cooper Lake report `avx512f` and `avx512bw` without `vpclmulqdq` and keep the group path: the Intel 64 and IA-32 Architectures Optimization Reference Manual assigns their 512-bit integer instructions a lower core frequency license, which also slows the poll's other work.
    pub(super) fn tags(
        key: &PeerKey,
        inputs: &[MacInput<'_>],
        tags: &mut [[u8; TAG_LEN]],
    ) -> usize {
        let mut done = 0;
        if detected() {
            while inputs.len() - done >= LANES_MIN {
                let end = inputs.len().min(done + LANES);
                // SAFETY: runtime detection above reported every CPU feature `pass` enables.
                unsafe { pass(key, &inputs[done..end], &mut tags[done..end]) };
                done = end;
            }
        }
        done
    }

    /// Whether the CPU reports every feature [`tags`] requires before it runs a [`pass`]: a superset of `pass`'s `target_feature` list, which the callers of `pass` rely on.
    pub(super) fn detected() -> bool {
        std::arch::is_x86_feature_detected!("avx512f")
            && std::arch::is_x86_feature_detected!("avx512bw")
            && std::arch::is_x86_feature_detected!("vpclmulqdq")
    }

    /// One [`pass`] over one to [`LANES`] inputs whatever their count, when the CPU has it; whether it ran.
    #[cfg(test)]
    pub(super) fn vector_pass(
        key: &PeerKey,
        inputs: &[MacInput<'_>],
        tags: &mut [[u8; TAG_LEN]],
    ) -> bool {
        assert!((1..=LANES).contains(&inputs.len()) && tags.len() == inputs.len());
        if !detected() {
            return false;
        }
        // SAFETY: `detected` reported every CPU feature `pass` enables.
        unsafe { pass(key, inputs, tags) };
        true
    }

    /// The tags of between one and [`LANES`] inputs: their chains run in lockstep while every lane has a block left, a lane past `inputs` repeating the last input, then each finishes alone.
    ///
    /// # Safety
    ///
    /// The CPU implements `avx512f` and `avx512bw`.
    #[target_feature(enable = "avx512f,avx512bw")]
    unsafe fn pass(key: &PeerKey, inputs: &[MacInput<'_>], tags: &mut [[u8; TAG_LEN]]) {
        debug_assert!((1..=LANES).contains(&inputs.len()) && tags.len() == inputs.len());
        #[cfg(test)]
        crate::isa_witness::ran(crate::isa_witness::Kernel::HmacWide);
        let input = |lane: usize| &inputs[lane.min(inputs.len() - 1)];
        let mut states: [[u32; 8]; LANES] =
            std::array::from_fn(|lane| first_state(key, input(lane)));
        let mut parts: [_; LANES] = std::array::from_fn(|lane| {
            let mut tail = Body::of(input(lane));
            (tail.run(usize::MAX), tail)
        });
        // Each lane's message after its first block: the header blocks, the whole body blocks, then the tail with its padding.
        let common = parts
            .iter()
            .map(|(whole, tail)| REST_BLOCKS + whole.len() + tail.blocks())
            .min()
            .unwrap_or(0);
        let mut lanes = [[0u32; LANES]; 8];
        for (lane, state) in states.iter().enumerate() {
            for (word, value) in state.iter().enumerate() {
                lanes[word][lane] = *value;
            }
        }
        let mut vector = [_mm512_setzero_si512(); 8];
        for (value, row) in vector.iter_mut().zip(&lanes) {
            // SAFETY: the load reads one 64-byte row of `lanes`.
            *value = unsafe { _mm512_loadu_si512(row.as_ptr().cast()) };
        }
        let mut owned = [[0u8; BLOCK_LEN]; LANES];
        for step in 0..common {
            for (lane, (whole, tail)) in parts.iter_mut().enumerate() {
                if step >= REST_BLOCKS + whole.len() {
                    owned[lane] = tail.next_block().copied().unwrap_or([0; BLOCK_LEN]);
                }
            }
            let rows: [&[u8; BLOCK_LEN]; LANES] = std::array::from_fn(|lane| {
                let whole = parts[lane].0;
                if step < REST_BLOCKS {
                    &rest_blocks(input(lane))[step]
                } else if step < REST_BLOCKS + whole.len() {
                    &whole[step - REST_BLOCKS]
                } else {
                    &owned[lane]
                }
            });
            compress(&mut vector, rows);
        }
        for (word, value) in vector.iter().enumerate() {
            // SAFETY: each store writes one 64-byte row of `lanes`.
            unsafe { _mm512_storeu_si512(lanes[word].as_mut_ptr().cast(), *value) };
        }
        for (lane, ((state, (whole, tail)), tag)) in states
            .iter_mut()
            .zip(&mut parts)
            .zip(tags.iter_mut())
            .enumerate()
        {
            *state = std::array::from_fn(|word| lanes[word][lane]);
            let mut step = common;
            while let Some(block) = leading(input(lane), whole, step) {
                compress256(state, std::slice::from_ref(block));
                step += 1;
            }
            while let Some(block) = tail.next_block() {
                compress256(state, std::slice::from_ref(block));
            }
            *tag = tag_of(&outer_hash(&key.keyed, state));
        }
    }

    /// Block `step` of an input's message after its first block, among its header blocks and then its whole body blocks; `None` once the tail begins.
    fn leading<'b>(
        input: &MacInput<'b>,
        whole: &'b [[u8; BLOCK_LEN]],
        step: usize,
    ) -> Option<&'b [u8; BLOCK_LEN]> {
        match step.checked_sub(REST_BLOCKS) {
            None => Some(&rest_blocks(input)[step]),
            Some(at) => whole.get(at),
        }
    }

    /// One compression of each lane's state in `state`, word `w` of every lane in `state[w]`, by that lane's block in `rows`.
    #[inline]
    #[target_feature(enable = "avx512f,avx512bw")]
    fn compress(state: &mut [__m512i; 8], rows: [&[u8; BLOCK_LEN]; LANES]) {
        let swap = _mm512_set4_epi32(0x0c0d_0e0f, 0x0809_0a0b, 0x0405_0607, 0x0001_0203);
        // The loop keeps the row loads inline in this function's target-feature context.
        let mut words = [_mm512_setzero_si512(); LANES];
        for (word, row) in words.iter_mut().zip(rows) {
            // SAFETY: the load reads one 64-byte block.
            *word = _mm512_shuffle_epi8(unsafe { _mm512_loadu_si512(row.as_ptr().cast()) }, swap);
        }
        let mut w = transpose(words);
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        macro_rules! round {
            ($scheduled:expr, $base:expr, $j:expr, $a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident) => {
                if $scheduled {
                    let (w15, w2) = (w[($j + 1) % 16], w[($j + 14) % 16]);
                    let s0 = _mm512_ternarylogic_epi32::<0x96>(
                        _mm512_ror_epi32::<7>(w15),
                        _mm512_ror_epi32::<18>(w15),
                        _mm512_srli_epi32::<3>(w15),
                    );
                    let s1 = _mm512_ternarylogic_epi32::<0x96>(
                        _mm512_ror_epi32::<17>(w2),
                        _mm512_ror_epi32::<19>(w2),
                        _mm512_srli_epi32::<10>(w2),
                    );
                    w[$j] = _mm512_add_epi32(
                        _mm512_add_epi32(w[$j], s0),
                        _mm512_add_epi32(w[($j + 9) % 16], s1),
                    );
                }
                let kw = _mm512_add_epi32(w[$j], _mm512_set1_epi32(K[$base + $j] as i32));
                let s1 = _mm512_ternarylogic_epi32::<0x96>(
                    _mm512_ror_epi32::<6>($e),
                    _mm512_ror_epi32::<11>($e),
                    _mm512_ror_epi32::<25>($e),
                );
                let ch = _mm512_ternarylogic_epi32::<0xCA>($e, $f, $g);
                let t1 = _mm512_add_epi32(_mm512_add_epi32($h, s1), _mm512_add_epi32(ch, kw));
                let s0 = _mm512_ternarylogic_epi32::<0x96>(
                    _mm512_ror_epi32::<2>($a),
                    _mm512_ror_epi32::<13>($a),
                    _mm512_ror_epi32::<22>($a),
                );
                let maj = _mm512_ternarylogic_epi32::<0xE8>($a, $b, $c);
                $d = _mm512_add_epi32($d, t1);
                $h = _mm512_add_epi32(t1, _mm512_add_epi32(s0, maj));
            };
        }
        macro_rules! sixteen {
            ($scheduled:expr, $base:expr) => {
                round!($scheduled, $base, 0, a, b, c, d, e, f, g, h);
                round!($scheduled, $base, 1, h, a, b, c, d, e, f, g);
                round!($scheduled, $base, 2, g, h, a, b, c, d, e, f);
                round!($scheduled, $base, 3, f, g, h, a, b, c, d, e);
                round!($scheduled, $base, 4, e, f, g, h, a, b, c, d);
                round!($scheduled, $base, 5, d, e, f, g, h, a, b, c);
                round!($scheduled, $base, 6, c, d, e, f, g, h, a, b);
                round!($scheduled, $base, 7, b, c, d, e, f, g, h, a);
                round!($scheduled, $base, 8, a, b, c, d, e, f, g, h);
                round!($scheduled, $base, 9, h, a, b, c, d, e, f, g);
                round!($scheduled, $base, 10, g, h, a, b, c, d, e, f);
                round!($scheduled, $base, 11, f, g, h, a, b, c, d, e);
                round!($scheduled, $base, 12, e, f, g, h, a, b, c, d);
                round!($scheduled, $base, 13, d, e, f, g, h, a, b, c);
                round!($scheduled, $base, 14, c, d, e, f, g, h, a, b);
                round!($scheduled, $base, 15, b, c, d, e, f, g, h, a);
            };
        }
        sixteen!(false, 0);
        for base in [16, 32, 48] {
            sixteen!(true, base);
        }
        for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *word = _mm512_add_epi32(*word, value);
        }
    }

    /// The 16x16 transpose of 32-bit words: row `r` of `rows` is lane `r`'s block, and word `w` of the result holds word `w` of every lane.
    #[inline]
    #[target_feature(enable = "avx512f")]
    fn transpose(rows: [__m512i; LANES]) -> [__m512i; LANES] {
        let mut pairs = rows;
        for at in 0..8 {
            pairs[2 * at] = _mm512_unpacklo_epi32(rows[2 * at], rows[2 * at + 1]);
            pairs[2 * at + 1] = _mm512_unpackhi_epi32(rows[2 * at], rows[2 * at + 1]);
        }
        let mut quads = pairs;
        for at in 0..4 {
            let (x, y, z, v) = (
                pairs[4 * at],
                pairs[4 * at + 1],
                pairs[4 * at + 2],
                pairs[4 * at + 3],
            );
            quads[4 * at] = _mm512_unpacklo_epi64(x, z);
            quads[4 * at + 1] = _mm512_unpackhi_epi64(x, z);
            quads[4 * at + 2] = _mm512_unpacklo_epi64(y, v);
            quads[4 * at + 3] = _mm512_unpackhi_epi64(y, v);
        }
        let mut halves = quads;
        for at in 0..2 {
            for j in 0..4 {
                let (x, y) = (quads[8 * at + j], quads[8 * at + 4 + j]);
                halves[8 * at + j] = _mm512_shuffle_i32x4::<0x88>(x, y);
                halves[8 * at + 4 + j] = _mm512_shuffle_i32x4::<0xDD>(x, y);
            }
        }
        let mut words = halves;
        for j in 0..8 {
            words[j] = _mm512_shuffle_i32x4::<0x88>(halves[j], halves[8 + j]);
            words[8 + j] = _mm512_shuffle_i32x4::<0xDD>(halves[j], halves[8 + j]);
        }
        words
    }
}

/// A fresh 128-bit boot nonce from the operating system's entropy.
///
/// # Errors
///
/// `Unavailable` when `getrandom` fails or returns fewer than 16 bytes,
/// or `Zero` when its complete result is all zeros.
pub fn boot_nonce() -> Result<[u8; 16], EntropyError> {
    nonce_from(os_entropy)
}
