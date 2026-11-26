//! The canonical frame: a 192-byte big-endian header, the body at offset 192, and the checks that accept exactly the canonical encodings.
//!
//! Header layout, big-endian at fixed offsets: magic `IMGNET01` at 0; version `u16` at 8, holding 3; kind `u8` at 10; flags `u8` at 11, holding 0; header length `u16` at 12, holding 192, and a zero `u16` at 14; principal `u32` at 16 and key epoch `u32` at 20; owner boot nonce at 24 and client boot nonce at 40, 16 bytes each; request ID at 56, packet sequence at 64, verified allocation ID, PUT fill serial or INVALIDATE interval low end at 72 and total logical bytes at 80, `u64` each; metadata length `u32` at 88 and body length `u32` at 92; fragment index or ACK base `u32` at 96 and fragment count `u32` at 100; logical stream offset, PUT BEGIN's cache version, INVALIDATE interval high end or an ACK's receipt mask, `u64` at 104; datagram body length `u32` at 112 and receive-slot grant `u32` at 116; status `u16` at 120 and a zero `u16` at 122; GET's wait, PUT BEGIN's authority duration or PUT PREPARE's time to live, in milliseconds, `u32` at 124; the full key at 128 (32 bytes); header crc32c `u32` at 160 and body crc32c `u32` at 164; peer session epoch `u64` at 168; truncated HMAC tag at 176 (16 bytes).
//!
//! Invariants owned by this module:
//!
//! - [`parse`] reads only the received bytes, at fixed offsets, with no alignment or layout assumption, and allocates nothing. It checks, in order: the receive's truncation flag and the 192-byte minimum; magic and header length; version, kind, flags and reserved fields; the datagram body length against the bytes received; every field constraint of the kind, with arithmetic widened to `u64` so no sum or product overflows; then the header crc over `[0, 176)` with its own field read as zero. It returns the first failure. A header that passes every check also passes on a branch-light path that tests the same constraints in one combined pass, and that path accepts only headers the ordered checks accept.
//! - A parsed [`Frame`] leaves the body crc to [`Frame::check_body`], and callers check it only after the frame's tag verifies under [`KeyRing::authenticate`](super::KeyRing::authenticate), so they trust no unauthenticated body byte.
//! - [`encode`] writes the header for at most two borrowed payload slices, folding the body crc over the slices and the header crc over the header, without concatenating payload; it refuses a header that [`parse`] would refuse, so every encoded frame is canonical.
//! - The MAC input is a 16-byte domain block (the owner endpoint identifier, the direction, eleven zero bytes), the canonical header bytes `[0, 176)`, then the covered body: the whole declared body of every kind except DATA, and for DATA the 16-byte digest of its body (see [`KeyRing::mac_input`](super::KeyRing::mac_input)). Parsing bounds every length before the tag, so the MAC reads only bytes the header declares.
//! - Zero is reserved: the client boot nonce is nonzero on every frame, and the owner boot nonce and the peer session epoch are zero exactly on HELLO, which precedes both, so every session epoch an endpoint issues is at least 1.
//! - The version field holds [`VERSION`]: a frame with any other value, version 2 included, fails with `FrameError::Version` after the magic and header-length checks. [`Kind`] and [`Status`] are closed sets: an unlisted value rejects the frame. The eleven bootstrap and GET kinds are 1 to 11, the nine PUT kinds 12 to 20, the six ownership kinds 21 to 26, and INVALIDATE and INVALIDATED 27 and 28. The 23 GET statuses are 1 to 23 and the five PUT statuses 24 to 28.
//! - HELLO, CHALLENGE and CONFIRM carry the 8-byte control body, and READY the body [`ReadyBody`](super::ownership::ReadyBody) decodes. Each ownership kind's body is the envelope [`OwnershipBody`](super::ownership::OwnershipBody) decodes, and its header follows the bootstrap kinds' field rules with the request field free.
//! - INVALIDATE and INVALIDATED carry the request, the key and the inclusive version interval, its low end in the allocation field and its high end in the offset field, with every other object, length, fragment, grant, status and duration field zero; an interval whose low end exceeds its high end refuses the frame. INVALIDATED echoes the INVALIDATE it acknowledges.
//! - A wire slot's operation is decidable from the kind alone: GET's ERROR and CANCEL carry only the 23 GET statuses, and PUT has its own error and cancel kinds.
//! - PUT fields: PUT BEGIN carries the request, the key and the authority duration in `remaining_ms`, nonzero, with the allocation, manifest, fragment and grant fields zero, and the FILL's cache version, the per-key version of its source read, in the offset field; any value, 0 included, is canonical, and the owner's coverage check judges version 0 by its key. PUT AUTHORITY carries the request, the key and the nonzero fill serial in the allocation field, and every later PUT kind names its fill attempt by that serial; PUT ERROR and PUT CANCEL leave the allocation field free, zero before any serial exists and the serial afterward. PUT PREPARE carries the manifest (the two lengths, their sum as the total and its fragment count) and the time to live in `remaining_ms`, nonzero. PUT READY carries the manifest and the initial cumulative grant, at most the count and at most [`MAX_WINDOW`]. PUT DATA carries one canonical fragment exactly as DATA does. PUT ACK carries the manifest, the cumulative receipt base, a receipt mask naming only fragments below the grant, and the cumulative grant, from the base to the count and at most [`MAX_WINDOW`] above the base. A cumulative grant never decreases, so every fragment the owner holds stays below it. PUT RESULT carries the request, the key, the serial and the manifest of the published object, with `remaining_ms` zero.
//! - The owner keeps a PUT's retained outcome only for its configured linger after the request's deadline or end, as it keeps a GET's cached terminal; no field carries that horizon, so a PUT RESULT's `remaining_ms` is zero. A deployment keeps the linger at least the longest gap between a client's retries, so a retry inside the client's deadline finds the outcome.
//! - An ACK's offset field is its receipt mask: bit `i` set means the ACK's sender holds fragment `base + 1 + i`, so every set bit names a fragment below the count, or below the grant for PUT ACK, and an ACK whose base is that bound or one below it carries a zero mask.

use crate::storage::Crc32c;

use super::datagram::{HEADER_LEN, MAX_PAYLOAD_SLICES};
use super::geometry::{FRAGMENT_LEN, FragmentGeometry};

/// `IMGNET01`: the first eight bytes of every frame.
pub const MAGIC: [u8; 8] = *b"IMGNET01";

/// The wire version every frame carries.
pub const VERSION: u16 = 3;

/// Header bytes the header crc and the MAC cover: everything before the tag.
pub const AUTHENTICATED_LEN: usize = 176;

/// The body of HELLO, CHALLENGE and CONFIRM, and the first bytes of a READY body: the request-slot cap and the window cap.
pub const BOOTSTRAP_BODY_LEN: usize = 8;

/// The largest negotiable receive window, in fragments.
pub const MAX_WINDOW: u32 = 4096;

/// Doublings of a request's retry wait on either end after consecutive retries without progress. A congested path that drops a window's fragments loses its retransmissions too, so each unanswered retry spaces the next one further, and progress restores the configured wait. Both ends double alike: a client and an owner with equal `retry_us` and `attempts` run the same schedule of waits, so the owner's backed-off silence stays within the client's total retry time. A client also restarts its clock on any DATA and pauses it while every granted fragment awaits release, so the two schedules match within those restarts.
pub const RETRY_DOUBLINGS: u32 = 3;

pub(super) fn retry_wait(retry_us: u64, attempts: u32) -> u64 {
    retry_us.saturating_mul(1 << attempts.min(RETRY_DOUBLINGS))
}

/// The largest negotiable request-slot cap.
pub const MAX_SLOT_CAP: u32 = 1 << 16;

const VERSION_AT: usize = 8;
pub(super) const KIND_AT: usize = 10;
const FLAGS_AT: usize = 11;
const HEADER_LEN_AT: usize = 12;
const RESERVED_AT: usize = 14;
const PRINCIPAL_AT: usize = 16;
const KEY_EPOCH_AT: usize = 20;
const OWNER_NONCE_AT: usize = 24;
const CLIENT_NONCE_AT: usize = 40;
const REQUEST_AT: usize = 56;
const SEQUENCE_AT: usize = 64;
const ALLOCATION_AT: usize = 72;
const TOTAL_AT: usize = 80;
const METADATA_AT: usize = 88;
const BODY_AT: usize = 92;
const INDEX_AT: usize = 96;
const COUNT_AT: usize = 100;
const OFFSET_AT: usize = 104;
const DATAGRAM_AT: usize = 112;
const GRANT_AT: usize = 116;
const STATUS_AT: usize = 120;
const STATUS_RESERVED_AT: usize = 122;
const REMAINING_AT: usize = 124;
pub(super) const KEY_AT: usize = 128;
const HEADER_CRC_AT: usize = 160;
const BODY_CRC_AT: usize = 164;
const EPOCH_AT: usize = 168;
const TAG_AT: usize = 176;

/// What a frame does; a kind byte outside this set rejects the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Kind {
    Hello = 1,
    Challenge = 2,
    Confirm = 3,
    Ready = 4,
    Get = 5,
    Start = 6,
    Data = 7,
    Ack = 8,
    Complete = 9,
    Error = 10,
    Cancel = 11,
    /// Client to owner: asks for fill authority over the key before the client acquires any source byte.
    PutBegin = 12,
    /// Owner to client: the fill attempt the owner holds for the request, named by its serial.
    PutAuthority = 13,
    /// Client to owner: the object's lengths and time to live under the granted serial.
    PutPrepare = 14,
    /// Owner to client: storage is reserved and primed; carries the first cumulative grant.
    PutReady = 15,
    /// Client to owner: one fragment of the object's metadata-then-body bytes.
    PutData = 16,
    /// Owner to client: the cumulative receipt base, receipt mask and grant.
    PutAck = 17,
    /// Owner to client: the attempt published the object.
    PutResult = 18,
    /// Owner to client: the PUT ended, or its BEGIN was refused, with a status.
    PutError = 19,
    /// Client to owner: the client ends the PUT.
    PutCancel = 20,
    /// Client to owner: which tenure holds a shard.
    WhoHolds = 21,
    /// Owner to client: the responder's view of a shard's tenure.
    Holder = 22,
    /// Owner to client: the request reached a host that is not the shard's current owner.
    WrongOwner = 23,
    /// Owner to client: a liveness beat naming the sender's tenure.
    Heartbeat = 24,
    /// Client to owner: a request to check a shard's owner on the sender's behalf.
    Probe = 25,
    /// Owner to client: the outcome of a probe.
    ProbeReply = 26,
    /// Client to owner: INVALIDATE of the key's versions from the allocation field through the offset field.
    Invalidate = 27,
    /// Owner to client: the INVALIDATE of the same request, key and interval is acknowledged.
    Invalidated = 28,
}

impl Kind {
    /// Every kind, in wire order from 1.
    #[cfg(test)]
    pub(super) const ALL: [Self; 28] = [
        Self::Hello,
        Self::Challenge,
        Self::Confirm,
        Self::Ready,
        Self::Get,
        Self::Start,
        Self::Data,
        Self::Ack,
        Self::Complete,
        Self::Error,
        Self::Cancel,
        Self::PutBegin,
        Self::PutAuthority,
        Self::PutPrepare,
        Self::PutReady,
        Self::PutData,
        Self::PutAck,
        Self::PutResult,
        Self::PutError,
        Self::PutCancel,
        Self::WhoHolds,
        Self::Holder,
        Self::WrongOwner,
        Self::Heartbeat,
        Self::Probe,
        Self::ProbeReply,
        Self::Invalidate,
        Self::Invalidated,
    ];

    pub(super) fn from_wire(byte: u8) -> Option<Self> {
        Some(match byte {
            1 => Self::Hello,
            2 => Self::Challenge,
            3 => Self::Confirm,
            4 => Self::Ready,
            5 => Self::Get,
            6 => Self::Start,
            7 => Self::Data,
            8 => Self::Ack,
            9 => Self::Complete,
            10 => Self::Error,
            11 => Self::Cancel,
            12 => Self::PutBegin,
            13 => Self::PutAuthority,
            14 => Self::PutPrepare,
            15 => Self::PutReady,
            16 => Self::PutData,
            17 => Self::PutAck,
            18 => Self::PutResult,
            19 => Self::PutError,
            20 => Self::PutCancel,
            21 => Self::WhoHolds,
            22 => Self::Holder,
            23 => Self::WrongOwner,
            24 => Self::Heartbeat,
            25 => Self::Probe,
            26 => Self::ProbeReply,
            27 => Self::Invalidate,
            28 => Self::Invalidated,
            _ => return None,
        })
    }

    /// HELLO, CHALLENGE, CONFIRM and READY. Each carries the 8-byte control body, except READY, whose longer body starts with it.
    pub fn is_bootstrap(self) -> bool {
        matches!(
            self,
            Self::Hello | Self::Challenge | Self::Confirm | Self::Ready
        )
    }

    /// The nine PUT kinds, numbered 12 to 20.
    pub fn is_put(self) -> bool {
        (Self::PutBegin as u8..=Self::PutCancel as u8).contains(&(self as u8))
    }

    /// The six ownership kinds, numbered 21 to 26.
    #[inline]
    pub fn is_ownership(self) -> bool {
        (Self::WhoHolds as u8..=Self::ProbeReply as u8).contains(&(self as u8))
    }

    /// The one way a frame of this kind travels.
    pub fn direction(self) -> Direction {
        match self {
            Self::WhoHolds
            | Self::Probe
            | Self::Hello
            | Self::Confirm
            | Self::Get
            | Self::Ack
            | Self::Cancel
            | Self::PutBegin
            | Self::PutPrepare
            | Self::PutData
            | Self::PutCancel
            | Self::Invalidate => Direction::ClientToOwner,
            Self::Holder
            | Self::WrongOwner
            | Self::Heartbeat
            | Self::ProbeReply
            | Self::Challenge
            | Self::Ready
            | Self::Start
            | Self::Data
            | Self::Complete
            | Self::Error
            | Self::PutAuthority
            | Self::PutReady
            | Self::PutAck
            | Self::PutResult
            | Self::PutError
            | Self::Invalidated => Direction::OwnerToClient,
        }
    }
}

/// An ERROR, CANCEL, PUT ERROR or PUT CANCEL status; a status outside this set rejects the frame, and every other kind carries status 0.
///
/// Statuses 1 to 23 are GET's; 24 to 28 belong to PUT alone, so GET's ERROR refuses them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Status {
    Missing = 1,
    Expired = 2,
    Contended = 3,
    LeasePressure = 4,
    ObjectPressure = 5,
    ReceivePressure = 6,
    RequestPressure = 7,
    RetransmissionPressure = 8,
    StoragePressure = 9,
    ReadOpsPressure = 10,
    TooLarge = 11,
    ClockUnavailable = 12,
    Closed = 13,
    DeviceError = 14,
    Short = 15,
    IntegrityError = 16,
    TimedOut = 17,
    Cancelled = 18,
    OwnerUnavailable = 19,
    SessionMismatch = 20,
    /// A duplicate's fingerprint differs from the live or retained request of its wire identity.
    ConflictingRequest = 21,
    CounterExhausted = 22,
    InvalidRequest = 23,
    /// The owner holds no evidence of the request's outcome: its retained outcome expired or its session retired, so the PUT may or may not have published. The owner sends it best effort and starts no work.
    UnknownOutcome = 24,
    /// Another request holds fill authority over the key; the BEGIN acquired nothing.
    InProgress = 25,
    /// The peer holds no PUT permission; the BEGIN acquired nothing.
    PermissionDenied = 26,
    /// The key's fill serials are spent: no new attempt can start on it, unlike transient pressure.
    AttemptExhausted = 27,
    /// A resent fragment's body differs from the bytes the owner holds for its index or, after the owner consumed that fragment, from the body the original frame's tag covers; the upload ends.
    ConflictingData = 28,
}

impl Status {
    pub fn from_wire(value: u16) -> Option<Self> {
        Some(match value {
            1 => Self::Missing,
            2 => Self::Expired,
            3 => Self::Contended,
            4 => Self::LeasePressure,
            5 => Self::ObjectPressure,
            6 => Self::ReceivePressure,
            7 => Self::RequestPressure,
            8 => Self::RetransmissionPressure,
            9 => Self::StoragePressure,
            10 => Self::ReadOpsPressure,
            11 => Self::TooLarge,
            12 => Self::ClockUnavailable,
            13 => Self::Closed,
            14 => Self::DeviceError,
            15 => Self::Short,
            16 => Self::IntegrityError,
            17 => Self::TimedOut,
            18 => Self::Cancelled,
            19 => Self::OwnerUnavailable,
            20 => Self::SessionMismatch,
            21 => Self::ConflictingRequest,
            22 => Self::CounterExhausted,
            23 => Self::InvalidRequest,
            24 => Self::UnknownOutcome,
            25 => Self::InProgress,
            26 => Self::PermissionDenied,
            27 => Self::AttemptExhausted,
            28 => Self::ConflictingData,
            _ => return None,
        })
    }

    /// Statuses 1 to 23, the ones a GET's ERROR carries.
    pub fn is_get(self) -> bool {
        self as u16 <= Self::InvalidRequest as u16
    }
}

/// Which way a frame travels, the direction byte of the MAC domain block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Direction {
    ClientToOwner = 1,
    OwnerToClient = 2,
}

/// Every variable header field; [`encode`] writes the fixed fields and computes both crcs, and [`parse`] checks them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kind: Kind,
    pub principal: u32,
    pub key_epoch: u32,
    pub owner_nonce: [u8; 16],
    pub client_nonce: [u8; 16],
    pub request: u64,
    pub sequence: u64,
    /// GET's verified allocation ID, a PUT's fill serial, or an INVALIDATE's or INVALIDATED's interval low end.
    pub allocation: u64,
    pub total: u64,
    pub metadata_len: u32,
    pub body_len: u32,
    /// The fragment index, or an ACK's cumulative receipt base.
    pub index: u32,
    pub count: u32,
    /// A DATA fragment's payload offset, PUT BEGIN's cache version, an INVALIDATE's or INVALIDATED's interval high end, or an ACK's receipt mask: bit `i` set means the ACK's sender holds fragment `index + 1 + i`.
    pub offset: u64,
    /// Body bytes this datagram carries after the header.
    pub datagram_len: u32,
    /// GET's initial receive-slot grant, or an ACK's, PUT READY's or PUT ACK's cumulative grant: a PUT's fragments below it may be sent.
    pub grant: u32,
    pub status: u16,
    /// GET's wait in milliseconds, PUT BEGIN's authority duration, or PUT PREPARE's time to live.
    pub remaining_ms: u32,
    pub key: [u8; 32],
    pub epoch: u64,
    pub tag: [u8; 16],
}

/// A frame constraint a kind places on a header field or on its body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// A READY or ownership body broke the grammar, for the reason it carries.
    Body(super::ownership::OwnershipError),
    OwnerNonce,
    ClientNonce,
    Request,
    Allocation,
    Total,
    MetadataLen,
    BodyLen,
    Index,
    Count,
    Offset,
    DatagramLen,
    Grant,
    Status,
    Remaining,
    Key,
    Epoch,
    /// A HELLO, CHALLENGE or CONFIRM body's request-slot cap; a READY body reports its caps through `Body`.
    SlotCap,
    /// A HELLO, CHALLENGE or CONFIRM body's window cap; a READY body reports its caps through `Body`.
    WindowCap,
}

/// The first check a datagram failed, in the processing order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The datagram was longer than the receive box.
    Truncated,
    /// Fewer than 192 bytes arrived.
    Short {
        len: usize,
    },
    Magic,
    HeaderLen {
        found: u16,
    },
    Version {
        found: u16,
    },
    Kind {
        found: u8,
    },
    Flags {
        found: u8,
    },
    /// A reserved field is nonzero.
    Reserved,
    /// The datagram body length field differs from the body bytes present after the header.
    DatagramLen {
        declared: u32,
        received: usize,
    },
    /// A field breaks its kind's canonical constraint.
    Field {
        kind: Kind,
        field: Field,
    },
    HeaderCrc {
        stored: u32,
        computed: u32,
    },
    BodyCrc {
        stored: u32,
        computed: u32,
    },
}

/// A datagram whose header passed every check through the header crc, and its body, whose crc is still unchecked.
///
/// It holds the kind and borrows the datagram's header and body, and [`header`](Self::header) decodes the fields from the header bytes on each call, so parsing writes no decoded header and a frame is 32 bytes to move.
#[derive(Debug, Clone, Copy)]
pub struct Frame<'b> {
    kind: Kind,
    head: &'b [u8; HEADER_LEN],
    body: &'b [u8],
}

fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

#[inline]
pub(super) fn be32(bytes: &[u8], at: usize) -> u32 {
    let mut word = [0; 4];
    word.copy_from_slice(&bytes[at..at + 4]);
    u32::from_be_bytes(word)
}

#[inline]
pub(super) fn be64(bytes: &[u8], at: usize) -> u64 {
    let mut word = [0; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    u64::from_be_bytes(word)
}

#[inline]
pub(super) fn array<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    let mut out = [0; N];
    out.copy_from_slice(&bytes[at..at + N]);
    out
}

/// Folds the header crc over `[0, 176)` with the crc field read as zero.
fn header_crc(crc: Crc32c, header: &[u8; HEADER_LEN]) -> u32 {
    // The crc field is the low half of its little-endian word.
    let mut running = crc.start();
    running.update_words_masked::<{ AUTHENTICATED_LEN / 8 }, { HEADER_CRC_AT / 8 }>(
        words(&header[..AUTHENTICATED_LEN]),
        !0xFFFF_FFFF,
    );
    running.finish()
}

/// The header crc of `head` for [`parse`] to compare: on aarch64 the fold runs now, so the kind checks after it run beside its latency; elsewhere it runs when called, after the kind checks, so a header they refuse skips it.
#[inline(always)]
fn header_fold(crc: Crc32c, head: &[u8; HEADER_LEN]) -> impl Fn() -> u32 {
    #[cfg(target_arch = "aarch64")]
    {
        let computed = header_crc(crc, head);
        move || computed
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        move || header_crc(crc, head)
    }
}

/// `words` panics if `bytes` holds fewer than `N` eight-byte words; debug builds also require `bytes.len()` to be a multiple of eight.
#[inline(always)]
fn words<const N: usize>(bytes: &[u8]) -> &[[u8; 8]; N] {
    let (words, rest) = bytes.as_chunks::<8>();
    debug_assert!(rest.is_empty());
    words
        .first_chunk::<N>()
        .expect("a word count the caller sized the slice for")
}

fn body_crc<'s>(crc: Crc32c, pieces: impl IntoIterator<Item = &'s [u8]>) -> u32 {
    let mut running = crc.start();
    for piece in pieces {
        if !piece.is_empty() {
            running.update(piece);
        }
    }
    running.finish()
}

/// Checks one datagram of `bytes`, received with the transport's `truncated` flag, through its header crc.
///
/// The branch-light path accepts only headers the ordered checks accept; [`checked`] reports the first failing check in the processing order.
///
/// # Errors
///
/// The first failing check, in the module's processing order.
pub fn parse(crc: Crc32c, bytes: &[u8], truncated: bool) -> Result<Frame<'_>, FrameError> {
    if !truncated && let Some((head, body)) = bytes.split_first_chunk::<HEADER_LEN>() {
        let fold = header_fold(crc, head);
        if let Some(kind) = canonical(head, body)
            && fold() == be32(head, HEADER_CRC_AT)
        {
            return Ok(Frame { kind, head, body });
        }
    }
    checked(crc, bytes, truncated)
}

#[inline(always)]
pub(super) fn principal_and_key_epoch(header: &[u8; AUTHENTICATED_LEN]) -> (u32, u32) {
    (be32(header, PRINCIPAL_AT), be32(header, KEY_EPOCH_AT))
}

/// The sequence field of one unparsed frame header, trusted only after [`parse`] and authentication pass. `bytes` starts at the header: a lone datagram or one frame of a packed datagram.
#[inline]
pub(super) fn raw_sequence(bytes: &[u8]) -> Option<u64> {
    bytes
        .get(SEQUENCE_AT..SEQUENCE_AT + 8)
        .map(|field| be64(field, 0))
}

/// The body crc field of a datagram that holds a whole header: the crc32c of the datagram's body once [`Frame::check_body`] passed on the frame [`parse`] made of the same bytes.
///
/// # Panics
///
/// - If `bytes` ends before the field does.
pub(super) fn raw_body_crc(bytes: &[u8]) -> u32 {
    be32(bytes, BODY_CRC_AT)
}

/// The kind of a whole 192-byte header that passes every check [`checked`] makes from the magic through the field constraints, else `None`; [`parse`] applies the truncation flag and the 192-byte minimum before it.
///
/// It tests the constraints of the fixed-field checks and of [`check_kind`] in one combined pass, combining each kind's zero fields into one value, so a canonical header costs few branches. It accepts only what those checks accept; `None` sends the datagram to [`checked`], which names the failure.
#[inline(always)]
pub(super) fn canonical(head: &[u8; HEADER_LEN], body: &[u8]) -> Option<Kind> {
    // Read little-endian, each word keeps its fields' bytes in place: a 4-byte field at word offset 0 is the low half, and a word is zero exactly when every field in it is.
    let word = |at: usize| u64::from_le_bytes(array(head, at));
    // The word at 8 holds the version in bytes 0 and 1, the kind in byte 2, the flags in byte 3, the header length in bytes 4 and 5 and the reserved field in bytes 6 and 7.
    let kind = Kind::from_wire(head[KIND_AT])?;
    let [high, low] = VERSION.to_be_bytes();
    let fixed = u64::from_le_bytes([high, low, 0, 0, 0, HEADER_LEN as u8, 0, 0]);
    let hello = kind == Kind::Hello;
    let datagram = be32(head, DATAGRAM_AT);
    let common = word(0) == u64::from_le_bytes(MAGIC)
        && word(VERSION_AT) & !(0xFF << 16) == fixed
        && usize::try_from(datagram).is_ok_and(|len| len == body.len())
        && word(CLIENT_NONCE_AT) | word(CLIENT_NONCE_AT + 8) != 0
        // HELLO has both the owner nonce and the epoch zero; every other kind has both nonzero.
        && u8::from(word(OWNER_NONCE_AT) | word(OWNER_NONCE_AT + 8) == 0)
            + u8::from(word(EPOCH_AT) == 0)
            == if hello { 2 } else { 0 }
        // The status word's bytes 2 and 3 are the reserved field after the status.
        && word(STATUS_AT) & 0xFFFF_0000 == 0;
    if !common {
        return None;
    }
    // Each field is read where an arm tests it, so the match carries the kind alone across its arms.
    let status = || be16(head, STATUS_AT);
    let grant = || be32(head, GRANT_AT);
    let index = || be32(head, INDEX_AT);
    let count = || be32(head, COUNT_AT);
    let total = || be64(head, TOTAL_AT);
    let offset = || be64(head, OFFSET_AT);
    let serial = || word(ALLOCATION_AT) != 0;
    // The status word is the status, the reserved field checked above and the remaining duration; the datagram word is the datagram length then the grant; the index word is the index then the count.
    let status_word = || word(STATUS_AT);
    let status_only = || word(STATUS_AT) & 0xFFFF;
    let remaining_set = || word(STATUS_AT) >> 32 != 0;
    let datagram_only = || word(DATAGRAM_AT) & 0xFFFF_FFFF;
    let grant_only = || word(DATAGRAM_AT) >> 32;
    let index_only = || word(INDEX_AT) & 0xFFFF_FFFF;
    // The total, both lengths, the index, the count and the offset, then with the allocation.
    let shape = || word(TOTAL_AT) | word(METADATA_AT) | word(INDEX_AT) | word(OFFSET_AT);
    let object = || word(ALLOCATION_AT) | shape();
    let manifest = || manifest_at(head);
    let holds = match kind {
        Kind::WhoHolds
        | Kind::Holder
        | Kind::WrongOwner
        | Kind::Heartbeat
        | Kind::Probe
        | Kind::ProbeReply => {
            let key = word(KEY_AT) | word(KEY_AT + 8) | word(KEY_AT + 16) | word(KEY_AT + 24);
            key | object() | grant_only() | status_word() == 0
                && super::ownership::OwnershipBody::admits(kind, body)
        }
        Kind::Hello | Kind::Challenge | Kind::Confirm | Kind::Ready => {
            let key = word(KEY_AT) | word(KEY_AT + 8) | word(KEY_AT + 16) | word(KEY_AT + 24);
            let control = if kind == Kind::Ready {
                super::ownership::ReadyBody::admits(body)
            } else {
                body.len() == BOOTSTRAP_BODY_LEN
                    && (1..=MAX_SLOT_CAP).contains(&be32(body, 0))
                    && (1..=MAX_WINDOW).contains(&be32(body, 4))
            };
            word(REQUEST_AT) | key | object() | grant_only() | status_word() == 0 && control
        }
        Kind::Get => {
            word(ALLOCATION_AT)
                | word(TOTAL_AT)
                | word(INDEX_AT)
                | word(OFFSET_AT)
                | datagram_only()
                | status_only()
                == 0
                && (1..=MAX_WINDOW).contains(&grant())
                && remaining_set()
        }
        Kind::Start | Kind::Complete => {
            let index_at = if kind == Kind::Start { 0 } else { count() };
            status_word() | word(DATAGRAM_AT) | word(OFFSET_AT) == 0
                && index() == index_at
                && manifest()
        }
        Kind::Ack => {
            status_word() | datagram_only() == 0
                && index() <= count()
                && mask_within(offset(), index(), count())
                && manifest()
        }
        Kind::PutData if !serial() => false,
        Kind::Data | Kind::PutData => {
            status_word() | grant_only() == 0
                && index() < count()
                && manifest()
                && offset() == u64::from(index()) * u64::from(FRAGMENT_LEN)
                && u64::from(datagram) == (total() - offset()).min(u64::from(FRAGMENT_LEN))
        }
        // PUT BEGIN carries the FILL's version in the offset field.
        Kind::PutBegin => {
            let object = word(ALLOCATION_AT) | word(TOTAL_AT) | word(METADATA_AT) | word(INDEX_AT);
            object | word(DATAGRAM_AT) | status_only() == 0 && remaining_set()
        }
        Kind::Invalidate | Kind::Invalidated => {
            word(TOTAL_AT) | word(METADATA_AT) | word(INDEX_AT) | word(DATAGRAM_AT) | status_word()
                == 0
                && be64(head, ALLOCATION_AT) <= offset()
        }
        Kind::PutAuthority => serial() && shape() | word(DATAGRAM_AT) | status_word() == 0,
        Kind::PutPrepare => {
            serial()
                && index_only() | word(OFFSET_AT) | word(DATAGRAM_AT) | status_only() == 0
                && remaining_set()
                && manifest()
        }
        Kind::PutReady => {
            serial()
                && index_only() | word(OFFSET_AT) | datagram_only() | status_word() == 0
                && put_grant(grant(), 0, count())
                && manifest()
        }
        Kind::PutAck => {
            serial()
                && status_word() | datagram_only() == 0
                && index() <= count()
                && put_grant(grant(), index(), count())
                && mask_within(offset(), index(), grant())
                && manifest()
        }
        Kind::PutResult => {
            serial()
                && index_only() | word(OFFSET_AT) | word(DATAGRAM_AT) | status_word() == 0
                && manifest()
        }
        Kind::Error | Kind::Cancel | Kind::PutError | Kind::PutCancel => {
            let zeroed = if kind.is_put() { shape() } else { object() };
            zeroed | word(DATAGRAM_AT) == 0 && !remaining_set() && status_listed(kind, status())
        }
    };
    holds.then_some(kind)
}

/// The header fields of `head`, read at their offsets.
#[inline(always)]
fn decode(kind: Kind, head: &[u8; HEADER_LEN]) -> Header {
    Header {
        kind,
        principal: be32(head, PRINCIPAL_AT),
        key_epoch: be32(head, KEY_EPOCH_AT),
        owner_nonce: array(head, OWNER_NONCE_AT),
        client_nonce: array(head, CLIENT_NONCE_AT),
        request: be64(head, REQUEST_AT),
        sequence: be64(head, SEQUENCE_AT),
        allocation: be64(head, ALLOCATION_AT),
        total: be64(head, TOTAL_AT),
        metadata_len: be32(head, METADATA_AT),
        body_len: be32(head, BODY_AT),
        index: be32(head, INDEX_AT),
        count: be32(head, COUNT_AT),
        offset: be64(head, OFFSET_AT),
        datagram_len: be32(head, DATAGRAM_AT),
        grant: be32(head, GRANT_AT),
        status: be16(head, STATUS_AT),
        remaining_ms: be32(head, REMAINING_AT),
        key: array(head, KEY_AT),
        epoch: be64(head, EPOCH_AT),
        tag: array(head, TAG_AT),
    }
}

/// Applies every check of the processing order to `bytes` and returns the first failure, or the frame when none fails.
#[cold]
#[inline(never)]
pub(super) fn checked(crc: Crc32c, bytes: &[u8], truncated: bool) -> Result<Frame<'_>, FrameError> {
    if truncated {
        return Err(FrameError::Truncated);
    }
    let Some((head, body)) = bytes.split_first_chunk::<HEADER_LEN>() else {
        return Err(FrameError::Short { len: bytes.len() });
    };
    if bytes[..8] != MAGIC {
        return Err(FrameError::Magic);
    }
    let header_len = be16(bytes, HEADER_LEN_AT);
    if usize::from(header_len) != HEADER_LEN {
        return Err(FrameError::HeaderLen { found: header_len });
    }
    let found = be16(bytes, VERSION_AT);
    if found != VERSION {
        return Err(FrameError::Version { found });
    }
    let kind = Kind::from_wire(bytes[KIND_AT]).ok_or(FrameError::Kind {
        found: bytes[KIND_AT],
    })?;
    if bytes[FLAGS_AT] != 0 {
        return Err(FrameError::Flags {
            found: bytes[FLAGS_AT],
        });
    }
    if be16(bytes, RESERVED_AT) != 0 || be16(bytes, STATUS_RESERVED_AT) != 0 {
        return Err(FrameError::Reserved);
    }
    let datagram_len = be32(bytes, DATAGRAM_AT);
    if datagram_len as usize != body.len() {
        return Err(FrameError::DatagramLen {
            declared: datagram_len,
            received: body.len(),
        });
    }
    check_kind(&decode(kind, head), body).map_err(|field| bad(kind, field))?;
    let stored = be32(bytes, HEADER_CRC_AT);
    let computed = header_crc(crc, head);
    if stored != computed {
        return Err(FrameError::HeaderCrc { stored, computed });
    }
    Ok(Frame { kind, head, body })
}

#[inline(always)]
fn bad(kind: Kind, field: Field) -> FrameError {
    FrameError::Field { kind, field }
}

/// The first of `fields` whose value is nonzero.
#[inline(always)]
fn zeros(fields: &[(Field, u64)]) -> Result<(), Field> {
    match fields.iter().find(|(_, value)| *value != 0) {
        Some(&(field, _)) => Err(field),
        None => Ok(()),
    }
}

#[inline(always)]
fn require(holds: bool, field: Field) -> Result<(), Field> {
    if holds { Ok(()) } else { Err(field) }
}

/// Checks every field constraint of `header`'s kind, in a fixed order per kind, and names the first field that breaks one; for a bootstrap or ownership kind, `body` is the whole datagram body, and its length matches `datagram_len`. The result fits a register, which the caller widens to a [`FrameError`].
///
/// It and its field helpers carry `#[inline(always)]`, so each caller, the encoder included, runs the checks beside its own loads of the header.
#[inline(always)]
fn check_kind(header: &Header, body: &[u8]) -> Result<(), Field> {
    let kind = header.kind;
    require(header.client_nonce != [0; 16], Field::ClientNonce)?;
    let hello = kind == Kind::Hello;
    require(hello == (header.owner_nonce == [0; 16]), Field::OwnerNonce)?;
    require(hello == (header.epoch == 0), Field::Epoch)?;
    require(status_listed(kind, header.status), Field::Status)?;
    let datagram = u64::from(header.datagram_len);
    let (grant, remaining) = (u64::from(header.grant), u64::from(header.remaining_ms));
    // The offset field carries a PUT BEGIN's version and an INVALIDATE's high end.
    let unversioned = Header {
        offset: 0,
        ..*header
    };
    match kind {
        Kind::WhoHolds
        | Kind::Holder
        | Kind::WrongOwner
        | Kind::Heartbeat
        | Kind::Probe
        | Kind::ProbeReply => {
            no_object(header)?;
            require(header.key == [0; 32], Field::Key)?;
            zeros(&[(Field::Grant, grant), (Field::Remaining, remaining)])?;
            super::ownership::OwnershipBody::decode(kind, body)
                .map(|_| ())
                .map_err(Field::Body)
        }
        Kind::Hello | Kind::Challenge | Kind::Confirm | Kind::Ready => {
            zeros(&[(Field::Request, header.request)])?;
            require(header.key == [0; 32], Field::Key)?;
            no_object(header)?;
            zeros(&[(Field::Grant, grant), (Field::Remaining, remaining)])?;
            if kind == Kind::Ready {
                return super::ownership::ReadyBody::decode(body)
                    .map(|_| ())
                    .map_err(Field::Body);
            }
            require(body.len() == BOOTSTRAP_BODY_LEN, Field::DatagramLen)?;
            let (slots, window) = (be32(body, 0), be32(body, 4));
            require((1..=MAX_SLOT_CAP).contains(&slots), Field::SlotCap)?;
            require((1..=MAX_WINDOW).contains(&window), Field::WindowCap)
        }
        Kind::Get => {
            zeros(&[
                (Field::DatagramLen, datagram),
                (Field::Allocation, header.allocation),
                (Field::Total, header.total),
                (Field::Index, u64::from(header.index)),
                (Field::Count, u64::from(header.count)),
                (Field::Offset, header.offset),
            ])?;
            require((1..=MAX_WINDOW).contains(&header.grant), Field::Grant)?;
            require(header.remaining_ms != 0, Field::Remaining)
        }
        Kind::Start | Kind::Complete => {
            manifest(header)?;
            zeros(&[
                (Field::Remaining, remaining),
                (Field::Grant, grant),
                (Field::DatagramLen, datagram),
                (Field::Offset, header.offset),
            ])?;
            let index = if kind == Kind::Start { 0 } else { header.count };
            require(header.index == index, Field::Index)
        }
        Kind::Ack => {
            manifest(header)?;
            zeros(&[
                (Field::Remaining, remaining),
                (Field::DatagramLen, datagram),
            ])?;
            require(
                mask_within(header.offset, header.index, header.count),
                Field::Offset,
            )?;
            require(header.index <= header.count, Field::Index)
        }
        Kind::Data | Kind::PutData => {
            if kind == Kind::PutData {
                serial(header)?;
            }
            manifest(header)?;
            zeros(&[(Field::Remaining, remaining), (Field::Grant, grant)])?;
            fragment(header)
        }
        Kind::Error | Kind::Cancel | Kind::PutError | Kind::PutCancel => {
            zeros(&[(Field::DatagramLen, datagram)])?;
            // A PUT's error or cancel may precede its serial, so its allocation field is free.
            if kind.is_put() {
                no_shape(header)?;
            } else {
                no_object(header)?;
            }
            zeros(&[(Field::Grant, grant), (Field::Remaining, remaining)])
        }
        Kind::PutBegin => {
            zeros(&[(Field::DatagramLen, datagram)])?;
            no_object(&unversioned)?;
            zeros(&[(Field::Grant, grant)])?;
            require(header.remaining_ms != 0, Field::Remaining)
        }
        Kind::Invalidate | Kind::Invalidated => {
            no_shape(&unversioned)?;
            zeros(&[
                (Field::DatagramLen, datagram),
                (Field::Grant, grant),
                (Field::Remaining, remaining),
            ])?;
            require(header.allocation <= header.offset, Field::Offset)
        }
        Kind::PutAuthority => {
            serial(header)?;
            zeros(&[(Field::DatagramLen, datagram)])?;
            no_shape(header)?;
            zeros(&[(Field::Grant, grant), (Field::Remaining, remaining)])
        }
        Kind::PutPrepare => {
            serial(header)?;
            manifest(header)?;
            zeros(&[
                (Field::DatagramLen, datagram),
                (Field::Index, u64::from(header.index)),
                (Field::Offset, header.offset),
                (Field::Grant, grant),
            ])?;
            require(header.remaining_ms != 0, Field::Remaining)
        }
        Kind::PutReady => {
            serial(header)?;
            manifest(header)?;
            zeros(&[
                (Field::DatagramLen, datagram),
                (Field::Index, u64::from(header.index)),
                (Field::Offset, header.offset),
                (Field::Remaining, remaining),
            ])?;
            require(put_grant(header.grant, 0, header.count), Field::Grant)
        }
        Kind::PutAck => {
            serial(header)?;
            manifest(header)?;
            zeros(&[
                (Field::Remaining, remaining),
                (Field::DatagramLen, datagram),
            ])?;
            require(header.index <= header.count, Field::Index)?;
            require(
                put_grant(header.grant, header.index, header.count),
                Field::Grant,
            )?;
            require(
                mask_within(header.offset, header.index, header.grant),
                Field::Offset,
            )
        }
        Kind::PutResult => {
            serial(header)?;
            manifest(header)?;
            zeros(&[
                (Field::DatagramLen, datagram),
                (Field::Index, u64::from(header.index)),
                (Field::Offset, header.offset),
                (Field::Grant, grant),
                (Field::Remaining, remaining),
            ])
        }
    }
}

#[inline(never)]
fn ordered(header: &Header, body: &[u8]) -> Result<(), FrameError> {
    check_kind(header, body).map_err(|field| bad(header.kind, field))
}

/// A `true` result satisfies every [`check_kind`] check for `header` and `body`; on `false` the encoder calls [`ordered`], which accepts the header or names the failure.
#[inline(always)]
fn encodable(header: &Header, body: &[u8]) -> bool {
    let h = header;
    let session =
        h.client_nonce != [0; 16] && h.owner_nonce != [0; 16] && h.epoch != 0 && h.status == 0;
    let manifest = || {
        h.total == u64::from(h.metadata_len) + u64::from(h.body_len)
            && u64::from(h.count) == FragmentGeometry::fragments(h.total)
    };
    let control = || {
        h.allocation | h.total | h.offset == 0
            && h.metadata_len | h.body_len | h.index | h.count | h.grant | h.remaining_ms == 0
            && h.key == [0; 32]
    };
    session
        && match h.kind {
            Kind::WhoHolds
            | Kind::Holder
            | Kind::WrongOwner
            | Kind::Heartbeat
            | Kind::Probe
            | Kind::ProbeReply => {
                control() && super::ownership::OwnershipBody::admits(h.kind, body)
            }
            Kind::Ready => h.request == 0 && control() && super::ownership::ReadyBody::admits(body),
            Kind::Data | Kind::PutData => {
                (h.kind == Kind::Data || h.allocation != 0)
                    && h.remaining_ms | h.grant == 0
                    && h.index < h.count
                    && manifest()
                    && h.offset == u64::from(h.index) * u64::from(FRAGMENT_LEN)
                    && u64::from(h.datagram_len)
                        == (h.total - h.offset).min(u64::from(FRAGMENT_LEN))
            }
            Kind::Ack => {
                h.remaining_ms | h.datagram_len == 0
                    && h.index <= h.count
                    && mask_within(h.offset, h.index, h.count)
                    && manifest()
            }
            Kind::PutAck => {
                h.allocation != 0
                    && h.remaining_ms | h.datagram_len == 0
                    && h.index <= h.count
                    && put_grant(h.grant, h.index, h.count)
                    && mask_within(h.offset, h.index, h.grant)
                    && manifest()
            }
            Kind::Get => {
                h.allocation | h.total | h.offset == 0
                    && h.index | h.count | h.datagram_len == 0
                    && (1..=MAX_WINDOW).contains(&h.grant)
                    && h.remaining_ms != 0
            }
            Kind::Start | Kind::Complete => {
                let index = if h.kind == Kind::Start { 0 } else { h.count };
                h.remaining_ms | h.grant | h.datagram_len == 0
                    && h.offset == 0
                    && h.index == index
                    && manifest()
            }
            // PUT BEGIN carries the FILL's version in the offset field.
            Kind::PutBegin => {
                h.allocation | h.total == 0
                    && h.metadata_len | h.body_len | h.index | h.count == 0
                    && h.datagram_len | h.grant == 0
                    && h.remaining_ms != 0
            }
            Kind::PutAuthority => {
                h.allocation != 0
                    && h.total | h.offset == 0
                    && h.metadata_len | h.body_len | h.index | h.count == 0
                    && h.datagram_len | h.grant | h.remaining_ms == 0
            }
            // PREPARE carries a deadline and no grant, READY a grant within its count and no deadline, RESULT neither.
            Kind::PutPrepare | Kind::PutReady | Kind::PutResult => {
                let granted = if h.kind == Kind::PutReady {
                    put_grant(h.grant, 0, h.count)
                } else {
                    h.grant == 0
                };
                h.allocation != 0
                    && h.offset == 0
                    && h.index | h.datagram_len == 0
                    && (h.remaining_ms != 0) == (h.kind == Kind::PutPrepare)
                    && granted
                    && manifest()
            }
            _ => false,
        }
}

/// Whether `status` is canonical for `kind`: GET's ERROR carries a GET status, PUT ERROR any status, both CANCEL kinds `Cancelled` or `TimedOut`, and every other kind zero.
#[inline(always)]
fn status_listed(kind: Kind, status: u16) -> bool {
    match kind {
        Kind::Cancel | Kind::PutCancel => {
            matches!(
                Status::from_wire(status),
                Some(Status::Cancelled | Status::TimedOut)
            )
        }
        Kind::Error => Status::from_wire(status).is_some_and(Status::is_get),
        Kind::PutError => Status::from_wire(status).is_some(),
        _ => status == 0,
    }
}

/// Whether the header at `head` carries a manifest: the total is the sum of the two lengths, and the count is the total's fragment count.
#[inline(always)]
fn manifest_at(head: &[u8; HEADER_LEN]) -> bool {
    let total = be64(head, TOTAL_AT);
    total == u64::from(be32(head, METADATA_AT)) + u64::from(be32(head, BODY_AT))
        && u64::from(be32(head, COUNT_AT)) == FragmentGeometry::fragments(total)
}

/// Whether a PUT's cumulative `grant` lies between the receipt `base` and the `count`, at most [`MAX_WINDOW`] fragments above the base.
#[inline(always)]
fn put_grant(grant: u32, base: u32, count: u32) -> bool {
    base <= grant && grant <= count && grant - base <= MAX_WINDOW
}

/// A PUT kind after BEGIN names its fill attempt by a nonzero serial in the allocation field.
#[inline(always)]
fn serial(header: &Header) -> Result<(), Field> {
    require(header.allocation != 0, Field::Allocation)
}

/// Whether every set bit of an ACK's receipt `mask` names a fragment below `bound`, the count for GET and the grant for PUT: bit `i` names fragment `base + 1 + i`.
#[inline(always)]
fn mask_within(mask: u64, base: u32, bound: u32) -> bool {
    let room = u64::from(bound).saturating_sub(u64::from(base) + 1);
    room >= u64::BITS as u64 || mask >> room == 0
}

/// The object, length, fragment and offset fields all zero.
#[inline(always)]
fn no_object(header: &Header) -> Result<(), Field> {
    zeros(&[(Field::Allocation, header.allocation)])?;
    no_shape(header)
}

/// The length, fragment and offset fields all zero; the allocation field is free.
#[inline(always)]
fn no_shape(header: &Header) -> Result<(), Field> {
    zeros(&[
        (Field::Total, header.total),
        (Field::MetadataLen, u64::from(header.metadata_len)),
        (Field::BodyLen, u64::from(header.body_len)),
        (Field::Index, u64::from(header.index)),
        (Field::Count, u64::from(header.count)),
        (Field::Offset, header.offset),
    ])
}

/// The total is the two lengths' sum and the count is its fragment count.
#[inline(always)]
fn manifest(header: &Header) -> Result<(), Field> {
    let total = u64::from(header.metadata_len) + u64::from(header.body_len);
    require(header.total == total, Field::Total)?;
    let count = FragmentGeometry::fragments(header.total);
    require(u64::from(header.count) == count, Field::Count)
}

/// A DATA fragment's index, offset and length match the manifest: offset `index * 8192`, 8192 bytes except the last, which carries the exact remainder.
#[inline(always)]
fn fragment(header: &Header) -> Result<(), Field> {
    require(header.index < header.count, Field::Index)?;
    let range = FragmentGeometry::fragment(header.index, header.total);
    require(header.offset == range.start, Field::Offset)?;
    let len = range.end - range.start;
    require(u64::from(header.datagram_len) == len, Field::DatagramLen)
}

impl<'b> Frame<'b> {
    #[inline(always)]
    pub fn header(&self) -> Header {
        decode(self.kind, self.head)
    }

    /// The datagram's body; its crc is unchecked until [`check_body`](Self::check_body) passes.
    #[inline]
    pub fn raw_body(&self) -> &'b [u8] {
        self.body
    }

    /// [`parse`] admits HELLO, CHALLENGE and CONFIRM only with exactly [`BOOTSTRAP_BODY_LEN`] body bytes, and READY only with its longer body, which starts with the same caps.
    ///
    /// # Panics
    ///
    /// - If the body holds fewer than [`BOOTSTRAP_BODY_LEN`] bytes, which [`parse`] rules out for every bootstrap kind.
    #[inline]
    pub(super) fn bootstrap_body(&self) -> [u8; BOOTSTRAP_BODY_LEN] {
        *self
            .body
            .first_chunk()
            .expect("a bootstrap kind's body holds its caps")
    }

    /// The bytes the tag covers, for `endpoint` and `direction`: the domain block, the header's first 176 bytes and the whole body. `None` for DATA, whose covered body is the universal hash of its body under its session's data key; [`KeyRing::authenticate`](super::KeyRing::authenticate) builds that input.
    pub fn mac_input(&self, endpoint: u32, direction: Direction) -> Option<MacInput<'b>> {
        if self.kind == Kind::Data {
            return None;
        }
        Some(MacInput {
            endpoint,
            direction,
            header: self.authenticated(),
            body: [self.body, &[]],
        })
    }

    /// The header's first 176 bytes, the part every tag covers.
    #[inline]
    pub fn authenticated(&self) -> &'b [u8; AUTHENTICATED_LEN] {
        let (authenticated, _) = self.head.split_first_chunk().expect("176 of 192 bytes");
        authenticated
    }

    /// The body crc the datagram carries, which [`check_body`](Self::check_body) verifies against the body.
    #[inline]
    pub fn body_crc(&self) -> u32 {
        be32(self.head, BODY_CRC_AT)
    }

    /// Checks the body crc over exactly the declared body bytes and returns them.
    ///
    /// # Errors
    ///
    /// `BodyCrc` when the stored crc differs.
    #[inline]
    pub fn check_body(&self, crc: Crc32c) -> Result<&'b [u8], FrameError> {
        let stored = self.body_crc();
        let computed = body_crc(crc, [self.body]);
        if computed != stored {
            return Err(FrameError::BodyCrc { stored, computed });
        }
        Ok(self.body)
    }
}

/// The bytes a frame's tag covers, in order: the 16-byte domain block, the header's first 176 bytes and the covered body, the concatenation of `body`'s slices.
#[derive(Debug, Clone, Copy)]
pub struct MacInput<'b> {
    /// The owner endpoint identifier, the first four bytes of the domain block big-endian.
    pub endpoint: u32,
    pub direction: Direction,
    pub header: &'b [u8; AUTHENTICATED_LEN],
    /// The covered body in at most two borrowed slices: the whole body of a frame other than DATA, and a DATA frame's 16-byte body digest.
    pub body: [&'b [u8]; MAX_PAYLOAD_SLICES],
}

impl MacInput<'_> {
    /// Bytes of the covered body.
    pub fn body_len(&self) -> usize {
        self.body[0].len() + self.body[1].len()
    }

    /// The MAC domain block: the owner endpoint identifier big-endian, the direction byte, then eleven zero bytes.
    pub fn domain(&self) -> [u8; 16] {
        let mut block = [0; 16];
        block[..4].copy_from_slice(&self.endpoint.to_be_bytes());
        block[4] = self.direction as u8;
        block
    }
}

fn pair(first: [u8; 4], second: [u8; 4]) -> [u8; 8] {
    let mut word = [0; 8];
    word[..4].copy_from_slice(&first);
    word[4..].copy_from_slice(&second);
    word
}

fn pair16(first: [u8; 2], second: [u8; 2]) -> [u8; 4] {
    [first[0], first[1], second[0], second[1]]
}

fn half(bytes: [u8; 16], at: usize) -> [u8; 8] {
    let mut word = [0; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    word
}

/// Encodes `header` with body `payload` into `out`, folding the body crc over the slices as they lie and the header crc over the encoded header.
/// `header.datagram_len` must equal the slices' total length, and a bootstrap or ownership kind's body must be the first slice; the tag is written as `header.tag`.
///
/// # Errors
///
/// Before any byte of `out` is written: a `DatagramLen` mismatch with the slices, a `Field { field: DatagramLen }` error when a bootstrap or ownership frame's second slice is nonempty, or the field constraint of the kind that [`parse`] would report.
///
/// It stays out of line and leaves by a tail call on every path, so it saves no register and its caller holds no state of the dispatch across the call.
#[inline(never)]
pub fn encode(
    crc: Crc32c,
    header: &Header,
    payload: [&[u8]; MAX_PAYLOAD_SLICES],
    out: &mut [u8; HEADER_LEN],
) -> Result<(), FrameError> {
    #[cfg(target_arch = "aarch64")]
    if crc.folds_lanes() {
        if header.datagram_len == 0 && payload[0].is_empty() && payload[1].is_empty() {
            // A frame that declares no body byte and carries none has the empty message's body crc and no slice to fold. The declared length is tested first, so a frame with a body leaves on that one test.
            carried(header, payload)?;
            // SAFETY: the mechanism folds lanes only after detection confirmed the CRC and AES extensions on this CPU.
            return unsafe { encode_bare(header, out, crc.start().finish()) };
        }
        // SAFETY: the mechanism folds lanes only after detection confirmed the CRC and AES extensions on this CPU.
        return unsafe { encode_walked(header, payload, out, (crc,)) };
    }
    encode_slices(header, payload, out, (crc,))
}

/// [`encode`] for a frame that declares or carries a body byte, under a mechanism that folds lanes: the body crc over the slices, then the lane encoder by a tail call.
///
/// Like [`encode_slices`], it is out of line, so `encode` needs no frame for it. Both take the crc last and in a one-field tuple, for the aarch64 release code of `encode` and of its callers.
///
/// `encode` receives its return slot in `x8` and its arguments in `x0` to `x3`; each of the two receives its return slot in `x0` and its arguments from `x1`. With the crc last, `encode` prepares either tail call with `mov x4, x0` and `mov x0, x8`: the crc's address moves to the last argument register, the return slot to the first, and `header`, `payload` and `out` stay in `x1` to `x3`.
///
/// `encode` copies its crc argument into the tuple and otherwise only reads it. A caller that holds the crc in a field or a local then passes the address of that field or local, and `encode` reads the crc there.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
#[target_feature(enable = "crc,aes")]
fn encode_walked(
    header: &Header,
    payload: [&[u8]; MAX_PAYLOAD_SLICES],
    out: &mut [u8; HEADER_LEN],
    (crc,): (Crc32c,),
) -> Result<(), FrameError> {
    // Each slice is read from `payload` when its turn comes, so the second is not held across the first's fold.
    let [first, second] = &payload;
    let mut body = crc.start();
    if !first.is_empty() {
        body.update(first);
    }
    if !second.is_empty() {
        body.update(second);
    }
    encode_folded(header, payload, body.finish(), out)
}

/// [`encode`] under a mechanism that does not fold lanes: the body crc over the slices, then the checks of [`admitted`], and the stores and the mechanism's fold of [`encode_header`].
#[inline(never)]
fn encode_slices(
    header: &Header,
    payload: [&[u8]; MAX_PAYLOAD_SLICES],
    out: &mut [u8; HEADER_LEN],
    (crc,): (Crc32c,),
) -> Result<(), FrameError> {
    let body_crc = body_crc(crc, payload);
    match admitted(header, payload) {
        Ok(()) => {
            encode_header(header, body_crc, out, |words| crc.checksum_words(words));
            Ok(())
        }
        Err(refusal) => Err(refusal),
    }
}

/// The header crc folded as lanes over the words [`encode_header`] wrote. The lane encoders pass this one closure, so they instantiate `encode_header` for one fold.
#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "crc,aes")]
fn lane_fold() -> impl FnOnce(&[[u8; 8]; AUTHENTICATED_LEN / 8]) -> u32 {
    |words| {
        Crc32c::checksum_written::<{ AUTHENTICATED_LEN / 8 }, { AUTHENTICATED_LEN / 8 }>(words, 0)
    }
}

/// The lane encoder for a frame that declares no body byte and carries none, whose empty payload [`carried`] accepted. A header [`encodable`] accepts leaves by a tail call to [`write_folded`] and any other header by one to [`fold_ordered`], so this function makes no call it returns from and saves no register.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
#[target_feature(enable = "crc,aes")]
fn encode_bare(
    header: &Header,
    out: &mut [u8; HEADER_LEN],
    body_crc: u32,
) -> Result<(), FrameError> {
    if encodable(header, &[]) {
        return write_folded(header, out, body_crc);
    }
    fold_ordered(header, out, body_crc)
}

/// The lane encoder for a frame with no body byte whose header [`encode_bare`] did not accept: [`ordered`] accepts it or names the failure before any byte of `out` is written.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
#[target_feature(enable = "crc,aes")]
fn fold_ordered(
    header: &Header,
    out: &mut [u8; HEADER_LEN],
    body_crc: u32,
) -> Result<(), FrameError> {
    ordered(header, &[])?;
    write_folded(header, out, body_crc)
}

/// The stores and the lane fold of [`encode_header`] for a frame with no body byte that the checks accepted. It makes no call, and both paths of [`encode_bare`] end in this one copy.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
#[target_feature(enable = "crc,aes")]
fn write_folded(
    header: &Header,
    out: &mut [u8; HEADER_LEN],
    body_crc: u32,
) -> Result<(), FrameError> {
    encode_header(header, body_crc, out, lane_fold());
    Ok(())
}

/// Accepts `payload` as the body `header` declares: the slices' total length is `header.datagram_len`, and a bootstrap or ownership kind's body is the first slice alone. Otherwise the first of [`encode`]'s two payload errors.
#[inline(always)]
fn carried(header: &Header, payload: [&[u8]; MAX_PAYLOAD_SLICES]) -> Result<(), FrameError> {
    let received: usize = payload.iter().map(|slice| slice.len()).sum();
    if header.datagram_len as usize != received {
        return Err(FrameError::DatagramLen {
            declared: header.datagram_len,
            received,
        });
    }
    // A control body travels as one slice, the one the MAC input covers.
    if (header.kind.is_bootstrap() || header.kind.is_ownership()) && !payload[1].is_empty() {
        return Err(bad(header.kind, Field::DatagramLen));
    }
    Ok(())
}

/// [`encode`] with the body crc `body_crc` the caller computed over the slices' bytes, which a sender holding its payload's verified checksums supplies without folding the payload again.
#[inline]
pub fn encode_with_body_crc(
    crc: Crc32c,
    header: &Header,
    payload: [&[u8]; MAX_PAYLOAD_SLICES],
    body_crc: u32,
    out: &mut [u8; HEADER_LEN],
) -> Result<(), FrameError> {
    #[cfg(target_arch = "aarch64")]
    if crc.folds_lanes() {
        // SAFETY: the mechanism folds lanes only after detection confirmed the CRC and AES extensions on this CPU.
        return unsafe { encode_folded(header, payload, body_crc, out) };
    }
    match admitted(header, payload) {
        Ok(()) => {
            encode_header(header, body_crc, out, |words| crc.checksum_words(words));
            Ok(())
        }
        Err(refusal) => Err(refusal),
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "crc,aes")]
fn encode_folded(
    header: &Header,
    payload: [&[u8]; MAX_PAYLOAD_SLICES],
    body_crc: u32,
    out: &mut [u8; HEADER_LEN],
) -> Result<(), FrameError> {
    match admitted(header, payload) {
        Ok(()) => {
            encode_header(header, body_crc, out, lane_fold());
            Ok(())
        }
        Err(refusal) => Err(refusal),
    }
}

/// Accepts `header` with the body `payload` for [`encode_header`]: `payload` by [`carried`], then the header by [`encodable`] or [`ordered`]. The caller asks it before any byte of its output is written.
///
/// [`carried`]'s refusal here and this function's refusal in each caller return as they are, by a `match`: `?` in those places passes the refusal through `From`, which adds instructions to the encoders' path for an accepted frame with a body. [`ordered`]'s refusal returns by `?`, the shorter form on that path.
#[inline(always)]
fn admitted(header: &Header, payload: [&[u8]; MAX_PAYLOAD_SLICES]) -> Result<(), FrameError> {
    match carried(header, payload) {
        Ok(()) => {}
        Err(refusal) => return Err(refusal),
    }
    if !encodable(header, payload[0]) {
        ordered(header, payload[0])?;
    }
    Ok(())
}

/// Writes `header` into `out`, with `body_crc` in its field and the header crc `fold` computes over the authenticated bytes. The caller has accepted the header and its body, by [`admitted`] or by [`encode_bare`]'s checks.
#[inline(always)]
fn encode_header(
    header: &Header,
    body_crc: u32,
    out: &mut [u8; HEADER_LEN],
    fold: impl FnOnce(&[[u8; 8]; AUTHENTICATED_LEN / 8]) -> u32,
) {
    // Every header word is written whole: each eight-byte load of the checksum then reads one store.
    let mut put = |at: usize, word: [u8; 8]| out[at..at + 8].copy_from_slice(&word);
    put(0, MAGIC);
    put(
        VERSION_AT,
        pair(
            pair16(VERSION.to_be_bytes(), [header.kind as u8, 0]),
            pair16((HEADER_LEN as u16).to_be_bytes(), [0; 2]),
        ),
    );
    put(
        PRINCIPAL_AT,
        pair(
            header.principal.to_be_bytes(),
            header.key_epoch.to_be_bytes(),
        ),
    );
    put(OWNER_NONCE_AT, half(header.owner_nonce, 0));
    put(OWNER_NONCE_AT + 8, half(header.owner_nonce, 8));
    put(CLIENT_NONCE_AT, half(header.client_nonce, 0));
    put(CLIENT_NONCE_AT + 8, half(header.client_nonce, 8));
    put(REQUEST_AT, header.request.to_be_bytes());
    put(SEQUENCE_AT, header.sequence.to_be_bytes());
    put(ALLOCATION_AT, header.allocation.to_be_bytes());
    put(TOTAL_AT, header.total.to_be_bytes());
    put(
        METADATA_AT,
        pair(
            header.metadata_len.to_be_bytes(),
            header.body_len.to_be_bytes(),
        ),
    );
    put(
        INDEX_AT,
        pair(header.index.to_be_bytes(), header.count.to_be_bytes()),
    );
    put(OFFSET_AT, header.offset.to_be_bytes());
    put(
        DATAGRAM_AT,
        pair(
            header.datagram_len.to_be_bytes(),
            header.grant.to_be_bytes(),
        ),
    );
    put(
        STATUS_AT,
        pair(
            pair16(header.status.to_be_bytes(), [0; 2]),
            header.remaining_ms.to_be_bytes(),
        ),
    );
    for (at, word) in header.key.as_chunks::<8>().0.iter().enumerate() {
        put(KEY_AT + 8 * at, *word);
    }
    // The header crc field holds zeros until the fold over the authenticated bytes fills it.
    put(HEADER_CRC_AT, pair([0; 4], body_crc.to_be_bytes()));
    put(EPOCH_AT, header.epoch.to_be_bytes());
    put(TAG_AT, half(header.tag, 0));
    put(TAG_AT + 8, half(header.tag, 8));
    let crc = fold(words(&out[..AUTHENTICATED_LEN]));
    out[HEADER_CRC_AT..HEADER_CRC_AT + 4].copy_from_slice(&crc.to_be_bytes());
}

/// The MAC input of an encoded header sent with `payload`, the slices [`encode`] took: the domain block, `encoded[..176]` and `payload`, the covered body.
///
/// `None` when the version is not [`VERSION`], the kind is unlisted or is DATA, whose covered body is the universal hash of its body under its session's data key and whose input [`KeyRing`](super::KeyRing) builds, or when the payload's length differs from the header's datagram body length.
#[inline]
pub fn mac_input_for<'b>(
    encoded: &'b [u8; HEADER_LEN],
    payload: [&'b [u8]; MAX_PAYLOAD_SLICES],
    endpoint: u32,
    direction: Direction,
) -> Option<MacInput<'b>> {
    Kind::from_wire(encoded[KIND_AT]).filter(|&kind| kind != Kind::Data)?;
    let declared = usize::try_from(be32(encoded, DATAGRAM_AT)).ok()?;
    if be16(encoded, VERSION_AT) != VERSION || payload[0].len() + payload[1].len() != declared {
        return None;
    }
    Some(MacInput {
        endpoint,
        direction,
        header: encoded.first_chunk()?,
        body: payload,
    })
}

/// The owner and client boot nonces of an encoded DATA header whose datagram body length is `payload_len`, naming the session whose data key digests its body; `None` for any other length.
#[inline]
pub(super) fn data_session(
    encoded: &[u8; HEADER_LEN],
    payload_len: usize,
) -> Option<([u8; 16], [u8; 16])> {
    if usize::try_from(be32(encoded, DATAGRAM_AT)).ok()? != payload_len {
        return None;
    }
    let nonce = |at: usize| {
        let mut nonce = [0; 16];
        nonce.copy_from_slice(&encoded[at..at + 16]);
        nonce
    };
    Some((nonce(OWNER_NONCE_AT), nonce(CLIENT_NONCE_AT)))
}

/// The MAC input of a DATA frame whose first 176 header bytes are `header`: the domain block, `header` and, as the covered body, `digest`, the 16-byte universal hash of the frame's body under its session's data key.
pub(super) fn data_mac_input<'b>(
    header: &'b [u8; AUTHENTICATED_LEN],
    digest: &'b [u8; DATA_DIGEST_LEN],
    endpoint: u32,
    direction: Direction,
) -> MacInput<'b> {
    MacInput {
        endpoint,
        direction,
        header,
        body: [digest, &[]],
    }
}

/// Bytes of a DATA frame's body digest, the covered body of its MAC input.
pub const DATA_DIGEST_LEN: usize = 16;

/// Writes `tag` into an encoded header; the header crc excludes the tag, so the header stays canonical.
#[inline]
pub fn seal(encoded: &mut [u8; HEADER_LEN], tag: [u8; 16]) {
    encoded[TAG_AT..].copy_from_slice(&tag);
}

const _: () = assert!(FRAGMENT_LEN == 8192 && TAG_AT + 16 == HEADER_LEN);

// A frame is its kind, a header pointer and a body slice.
const _: () = assert!(size_of::<Frame<'_>>() == 32);

// The fields [`encode`] packs into shared words sit side by side.
const _: () = assert!(
    KIND_AT == VERSION_AT + 2
        && FLAGS_AT == KIND_AT + 1
        && HEADER_LEN_AT == FLAGS_AT + 1
        && RESERVED_AT == HEADER_LEN_AT + 2
        && KEY_EPOCH_AT == PRINCIPAL_AT + 4
        && BODY_AT == METADATA_AT + 4
        && COUNT_AT == INDEX_AT + 4
        && GRANT_AT == DATAGRAM_AT + 4
        && STATUS_RESERVED_AT == STATUS_AT + 2
        && REMAINING_AT == STATUS_RESERVED_AT + 2
        && BODY_CRC_AT == HEADER_CRC_AT + 4
);

#[cfg(test)]
pub(super) mod tests;
