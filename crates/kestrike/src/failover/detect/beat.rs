//! The host heartbeat codec. Hosts send authenticated, bounded heartbeats to their peers, each sealed for one
//! receiving host. The caller supplies the transport; this codec is host to host, and its [`VERSION`] numbers the
//! heartbeat layout on its own, so a layout or tag-input change takes a new value.
//!
//! Layout, big-endian at fixed offsets: the protocol version `u16` at 0, the entry count `u8` at 2 and the sender's
//! self-health `u8` at 3 (1 healthy, 0 unhealthy); the sender host `u64` at 4; the sender's boot nonce at 12, 16
//! bytes; the sender's wall-clock boot stamp in microseconds since the Unix epoch at 28; the sequence at 36, the peer
//! acknowledgment at 44, the device-I/O progress at 52, the request-completion progress at 60 and the outstanding
//! work at 68, `u64` each; the boot nonce of the receiving host's boot that the acknowledgment names at 76, 16 bytes.
//! [`HEADER_LEN`] bytes of header precede one [`ENTRY_LEN`]-byte entry per shard the sender
//! owns: the shard `u32` at 0, the generation `g` `u64` at 4, the activated epoch `a` `u32` at 12, the volume state
//! `u8` at 16 (1 active, 2 retired), the read-age presence `u8` at 17, the Report age in microseconds `u64` at 18
//! and the freshness-clock age in microseconds `u64` at 26. A 32-byte tag follows the entries.
//!
//! Invariants:
//!
//! - BEAT-AUTHENTICATED: the tag is HMAC-SHA256 under the sender's [`BeatKey`] over a 16-byte domain label, the
//!   receiving host and every byte before the tag, so the read ages and every other field are under the tag and a
//!   heartbeat sealed for one receiver fails at every other. A valid tag proves possession of the sender's key; a
//!   key holder can forge that sender's heartbeats, which disturbs detection and grants no ownership, because the
//!   takeover compare-and-swap decides. [`decode`] reads only the version, the count and the sender before the tag
//!   verifies in constant time.
//! - BEAT-BOUNDED: a heartbeat holds at most [`MAX_ENTRIES`] entries and is exactly
//!   `HEADER_LEN + ENTRY_LEN·n + 32` bytes. Encoding and decoding allocate nothing.
//! - ONE-ENCODING: an absent read age is presence 0 with a zero age, and [`decode`] accepts exactly the encodings
//!   [`encode`] writes, so a decoded heartbeat re-encodes to the bytes it came from.

use subtle::ConstantTimeEq;

use crate::failover::assignment::hmac;
use crate::failover::records::Host;
use crate::failover::report::{field_at, put, u32_at, u64_at};
use crate::net::ownership::{ActivatedEpoch, Shard, ShardGeneration, VolumeState};

/// The protocol version this codec writes and accepts.
pub const VERSION: u16 = 3;
/// The largest entry count: one entry per shard a host can own, the largest instance attachment limit.
pub const MAX_ENTRIES: usize = 128;
pub const HEADER_LEN: usize = 92;
pub const ENTRY_LEN: usize = 34;
const TAG_LEN: usize = 32;
const DOMAIN: &[u8; 16] = b"ebs-heartbeat-03";
const KEY_DOMAIN: &[u8; 16] = b"ebs-beat-key--01";

const COUNT_AT: usize = 2;
const HEALTH_AT: usize = 3;
const HOST_AT: usize = 4;
const BOOT_AT: usize = 12;
const BOOTED_AT: usize = 28;
const SEQUENCE_AT: usize = 36;
const ACK_AT: usize = 44;
const IO_AT: usize = 52;
const COMPLETIONS_AT: usize = 60;
const PENDING_AT: usize = 68;
const ACK_BOOT_AT: usize = 76;

const SHARD_AT: usize = 0;
const GENERATION_AT: usize = 4;
const EPOCH_AT: usize = 12;
const VOLUME_AT: usize = 16;
const PRESENCE_AT: usize = 17;
const REPORT_AGE_AT: usize = 18;
pub const READ_AGE_AT: usize = 26;

/// The largest heartbeat encoding, 4,476 bytes.
pub const MAX_LEN: usize = HEADER_LEN + ENTRY_LEN * MAX_ENTRIES + TAG_LEN;

const _: () = assert!(MAX_ENTRIES <= u8::MAX as usize);
const _: () = assert!(ACK_BOOT_AT + 16 == HEADER_LEN);
const _: () = assert!(PENDING_AT + 8 == ACK_BOOT_AT);
const _: () = assert!(BOOT_AT + 16 == BOOTED_AT);
const _: () = assert!(READ_AGE_AT + 8 == ENTRY_LEN);
const _: () = assert!(MAX_LEN == 4_476);

/// The key that authenticates one host's heartbeats. It derives no `Debug`.
#[derive(Clone, Copy)]
pub struct BeatKey(pub [u8; 32]);

impl BeatKey {
    /// The heartbeat key of `host_key` authenticates heartbeats in an HMAC domain of its own.
    pub fn derive(host_key: &[u8; 32]) -> Self {
        Self(hmac(host_key, &[KEY_DOMAIN]))
    }
}

/// The heartbeat's per-host fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub host: Host,
    /// The nonzero nonce the sender drew at boot.
    pub boot: [u8; 16],
    /// The sender's wall-clock reading at boot, in microseconds since the Unix epoch. A stamp can repeat or move
    /// backward across boots after a clock step; a receiver admits at once a boot whose stamp is above every stamp it
    /// admitted from the sender, and any other boot once the current one is suspected and the heartbeat acknowledges
    /// one of the receiver's recent heartbeats.
    pub booted_at_us: u64,
    pub sequence: u64,
    /// The highest heartbeat sequence the sender received from the receiving host, in the receiving host's boot
    /// `ack_boot`.
    pub ack: u64,
    /// Device commands the sender completed since boot.
    pub io: u64,
    /// Requests the sender answered since boot.
    pub completions: u64,
    /// Device commands and requests in flight at the sender when it built the heartbeat.
    pub pending: u64,
    /// The receiving host's boot nonce from the heartbeat `ack` names; all zero when the sender received none.
    pub ack_boot: [u8; 16],
    /// The sender serves or recovers its tenures. The producer's caller sets `false` while the sender's restart holds
    /// (DEVICE-FAILURE-HOLD in `failover::restart`), so its observers read a declared failure once the detector's
    /// onset count of windows admitted heartbeats that carry it, with no healthy one between.
    pub healthy: bool,
}

/// One shard the sender owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub shard: Shard,
    pub generation: ShardGeneration,
    pub epoch: ActivatedEpoch,
    pub volume: VolumeState,
    /// Microseconds since the submission of the sender's latest certified Report.
    pub report_age_us: u64,
    /// Microseconds since the last refresh of the sender's freshness clock for this tenure: a shard-record read or
    /// own compare-and-swap showing its own `(g, owner, E)`, counted at the read's send time. The sender samples it
    /// when it builds the heartbeat, after it received the heartbeat `ack` names, so the receiver's acknowledged send
    /// time minus this age is no later than the read. Absent before the first refresh.
    pub read_age_us: Option<u64>,
}

/// The first check that refused a heartbeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeatError {
    /// Fewer bytes than a header and a tag, bytes other than the length the count fixes, or a destination shorter
    /// than the encoding.
    Length,
    /// The protocol version is not [`VERSION`].
    Version,
    /// More than [`MAX_ENTRIES`] entries.
    Count,
    /// The sender is zero or its key lookup found no key.
    Sender,
    Tag,
    /// A field outside its encoding: health, boot nonce, shard, generation, epoch, volume state or read age.
    Field,
}

fn entry_of(b: &[u8; ENTRY_LEN]) -> Option<Entry> {
    let read_age = u64_at(b, READ_AGE_AT);
    Some(Entry {
        shard: Shard::new(u32_at(b, SHARD_AT))?,
        generation: ShardGeneration::new(u64_at(b, GENERATION_AT))?,
        epoch: ActivatedEpoch::new(u32_at(b, EPOCH_AT)).filter(|a| a.is_activated())?,
        volume: match b[VOLUME_AT] {
            1 => VolumeState::Active,
            2 => VolumeState::Retired,
            _ => return None,
        },
        report_age_us: u64_at(b, REPORT_AGE_AT),
        read_age_us: match b[PRESENCE_AT] {
            0 if read_age == 0 => None,
            1 => Some(read_age),
            _ => return None,
        },
    })
}

fn tag(key: &BeatKey, receiver: Host, body: &[u8]) -> [u8; 32] {
    hmac(&key.0, &[DOMAIN, &receiver.get().to_be_bytes(), body])
}

/// Writes the tag of `bytes`, every byte before its last 32, for `receiver` into those last 32 bytes.
pub(super) fn seal(bytes: &mut [u8], key: &BeatKey, receiver: Host) {
    let (body, out) = bytes.split_at_mut(bytes.len() - TAG_LEN);
    out.copy_from_slice(&tag(key, receiver, body));
}

/// Writes the heartbeat of `header` and `entries`, sealed for `receiver` under `key`, to the front of `out` and
/// returns its length.
///
/// # Errors
///
/// `Count` above [`MAX_ENTRIES`] entries, `Length` when `out` is shorter than the encoding, then `Field` for a zero
/// boot nonce or an entry whose epoch has not activated, each before any write.
pub fn encode(
    header: &Header,
    entries: &[Entry],
    receiver: Host,
    key: &BeatKey,
    out: &mut [u8],
) -> Result<usize, BeatError> {
    if entries.len() > MAX_ENTRIES {
        return Err(BeatError::Count);
    }
    let len = HEADER_LEN + ENTRY_LEN * entries.len() + TAG_LEN;
    let out = out.get_mut(..len).ok_or(BeatError::Length)?;
    if header.boot == [0; 16] || entries.iter().any(|e| !e.epoch.is_activated()) {
        return Err(BeatError::Field);
    }
    put(out, 0, &VERSION.to_be_bytes());
    out[COUNT_AT] = entries.len() as u8;
    out[HEALTH_AT] = u8::from(header.healthy);
    put(out, HOST_AT, &header.host.get().to_be_bytes());
    put(out, BOOT_AT, &header.boot);
    put(out, BOOTED_AT, &header.booted_at_us.to_be_bytes());
    put(out, SEQUENCE_AT, &header.sequence.to_be_bytes());
    put(out, ACK_AT, &header.ack.to_be_bytes());
    put(out, IO_AT, &header.io.to_be_bytes());
    put(out, COMPLETIONS_AT, &header.completions.to_be_bytes());
    put(out, PENDING_AT, &header.pending.to_be_bytes());
    put(out, ACK_BOOT_AT, &header.ack_boot);
    for (e, b) in entries
        .iter()
        .zip(out[HEADER_LEN..].as_chunks_mut::<ENTRY_LEN>().0)
    {
        put(b, SHARD_AT, &e.shard.get().to_be_bytes());
        put(b, GENERATION_AT, &e.generation.get().to_be_bytes());
        put(b, EPOCH_AT, &e.epoch.get().to_be_bytes());
        b[VOLUME_AT] = e.volume as u8;
        b[PRESENCE_AT] = u8::from(e.read_age_us.is_some());
        put(b, REPORT_AGE_AT, &e.report_age_us.to_be_bytes());
        put(b, READ_AGE_AT, &e.read_age_us.unwrap_or(0).to_be_bytes());
    }
    seal(out, key, receiver);
    Ok(len)
}

/// Decodes and authenticates one heartbeat sealed for `receiver`. `key` receives the sender before the tag verifies
/// and returns its key, or `None` for a host the receiver does not admit.
///
/// # Errors
///
/// The first failing check in this order: `Length` for fewer bytes than a header and a tag, `Version`, `Count`,
/// `Length` for a length other than the count fixes, `Sender`, `Tag`, then `Field`.
pub fn decode(
    bytes: &[u8],
    receiver: Host,
    key: impl FnOnce(Host) -> Option<BeatKey>,
) -> Result<(Header, impl Iterator<Item = Entry> + '_), BeatError> {
    if bytes.len() < HEADER_LEN + TAG_LEN {
        return Err(BeatError::Length);
    }
    if u16::from_be_bytes([bytes[0], bytes[1]]) != VERSION {
        return Err(BeatError::Version);
    }
    let count = usize::from(bytes[COUNT_AT]);
    if count > MAX_ENTRIES {
        return Err(BeatError::Count);
    }
    if bytes.len() != HEADER_LEN + ENTRY_LEN * count + TAG_LEN {
        return Err(BeatError::Length);
    }
    let host = Host::new(u64_at(bytes, HOST_AT)).ok_or(BeatError::Sender)?;
    let key = key(host).ok_or(BeatError::Sender)?;
    let (body, received) = bytes.split_at(bytes.len() - TAG_LEN);
    if !bool::from(tag(&key, receiver, body).ct_eq(received)) {
        return Err(BeatError::Tag);
    }
    let boot: [u8; 16] = field_at(body, BOOT_AT);
    let ack_boot: [u8; 16] = field_at(body, ACK_BOOT_AT);
    let entries = body[HEADER_LEN..].as_chunks::<ENTRY_LEN>().0;
    if body[HEALTH_AT] > 1 || boot == [0; 16] || !entries.iter().all(|e| entry_of(e).is_some()) {
        return Err(BeatError::Field);
    }
    let header = Header {
        host,
        boot,
        booted_at_us: u64_at(body, BOOTED_AT),
        sequence: u64_at(body, SEQUENCE_AT),
        ack: u64_at(body, ACK_AT),
        io: u64_at(body, IO_AT),
        completions: u64_at(body, COMPLETIONS_AT),
        pending: u64_at(body, PENDING_AT),
        ack_boot,
        healthy: body[HEALTH_AT] == 1,
    };
    Ok((header, entries.iter().filter_map(entry_of)))
}
