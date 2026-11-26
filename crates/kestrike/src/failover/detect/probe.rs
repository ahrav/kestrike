//! Indirect probe messages between hosts. An observer asks probers outside a suspect's placement partition for
//! their reading of the suspect, and each prober answers the observer that asked. [`VERSION`] numbers this layout
//! apart from the heartbeat's, so a layout or tag-input change takes a new value. The reading table grows by
//! appended codes within one version while no release carries the codec; a decoder refuses a code past its table
//! as `Field`.
//!
//! Layout, [`LEN`] bytes, big-endian at fixed offsets: the protocol version `u16` at 0, the kind `u8` at 2 (1
//! request, 2 reply), the reading `u8` at 3 (0 in a request; in a reply 1 ALIVE, 2 DEAD silent, 3 DEAD gray, 4
//! UNKNOWN, 5 DEAD declared), the sender host `u64` at 4, the requester's boot nonce at 12, 16 bytes, then the request fields: the
//! suspect host `u64` at 28, its partition `u32` at 36, the observation generation `u64` at 40, the probe cycle
//! `u64` at 48, the round `u32` at 56 and the issuing window close `u64` at 60. A 32-byte tag follows at 68.
//!
//! Invariants:
//!
//! - PROBE-AUTHENTICATED: the tag is HMAC-SHA256 under the sender's [`ProbeKey`] over a 16-byte domain label, the
//!   receiving host and every byte before the tag, so a message sealed for one receiver fails at every other.
//!   The tagged input is 92 bytes at every message, so the tag is three SHA-256 compressions from a [`Keyed`]
//!   key's two pad-block states (RFC 2104): two over the input and its padding, one over the inner digest.
//!   [`ProbeKey::derive`] computes the key from the host key under a label of its own, apart from the heartbeat and
//!   report keys. [`decode`] reads only the version, the kind and the sender before the tag verifies in constant
//!   time. The keys are symmetric and every host agent's directory projection holds every host's probe key, so a
//!   valid tag shows the message comes from a holder of the sender's key: a listed host can seal another host's
//!   probe messages, as it can its heartbeats, which moves detection evidence and grants no ownership, because the
//!   takeover compare-and-swap decides.
//! - REPLY-NAMES-ITS-REQUEST: a reply carries every field of the request it answers and echoes the boot nonce the
//!   request carried, so the observer that receives it matches the reply to a request it sent to that sender in its
//!   current boot, whose detector counters can repeat a request of an earlier boot. The codec authenticates the sender; the binding to a
//!   sent request is the receiver's check.
//! - ONE-ENCODING: [`decode`] accepts exactly the encodings [`encode`] writes, so a decoded message re-encodes to the
//!   bytes it came from. Encoding and decoding allocate nothing.

use sha2::block_api::compress256;
use subtle::ConstantTimeEq;

use super::host::{ProbeRequest, Reading};
use super::{Failure, ObservationGeneration};
use crate::failover::arbiter::Partition;
use crate::failover::assignment::hmac;
use crate::failover::records::Host;
use crate::failover::report::{put, u32_at, u64_at};
use crate::net::SHA256_IV;

/// The protocol version this codec writes and accepts.
pub const VERSION: u16 = 1;
/// The length of every probe message, request or reply.
pub const LEN: usize = 100;
const TAG_LEN: usize = 32;
const DOMAIN: &[u8; 16] = b"ebs-probe-msg-01";
const KEY_DOMAIN: &[u8; 16] = b"ebs-probe-key-01";

const KIND_AT: usize = 2;
const READING_AT: usize = 3;
const SENDER_AT: usize = 4;
const BOOT_AT: usize = 12;
const SUSPECT_AT: usize = 28;
const PARTITION_AT: usize = 36;
const GENERATION_AT: usize = 40;
const CYCLE_AT: usize = 48;
const ROUND_AT: usize = 56;
const ISSUED_AT: usize = 60;
const TAG_AT: usize = 68;

const REQUEST: u8 = 1;
const REPLY: u8 = 2;
/// The readings of a reply in code order; code `i + 1` names `READINGS[i]`. A declared hold has a code of its own,
/// so the observer's arbiter tells it from silence and from an observed stall.
const READINGS: [Reading; 5] = [
    Reading::Alive,
    Reading::Dead(Failure::Silent),
    Reading::Dead(Failure::Gray),
    Reading::Unknown,
    Reading::Dead(Failure::Declared),
];

const _: () = assert!(TAG_AT + TAG_LEN == LEN);
const _: () = assert!(ISSUED_AT + 8 == TAG_AT);
const _: () = assert!(BOOT_AT + 16 == SUSPECT_AT);

/// The SHA-256 block length.
const BLOCK: usize = 64;
/// The bytes a tag covers: the domain label, the receiving host and every byte before the tag.
const INPUT: usize = DOMAIN.len() + 8 + TAG_AT;
// The tagged input, its 0x80 byte and its 8-byte bit length end in the inner hash's third block.
const _: () = assert!(INPUT > BLOCK && INPUT + 9 <= 2 * BLOCK);

/// The key that authenticates one host's probe messages.
#[derive(Clone, Copy)]
pub struct ProbeKey(pub [u8; 32]);

impl ProbeKey {
    /// The probe-specific HMAC label separates probe keys from the other keys derived from `host_key`.
    pub fn derive(host_key: &[u8; 32]) -> Self {
        Self(hmac(host_key, &[KEY_DOMAIN]))
    }

    /// The key's two pad-block states, which every tag under the key starts from.
    pub fn keyed(&self) -> Keyed {
        let mut pad = [0; BLOCK];
        pad[..self.0.len()].copy_from_slice(&self.0);
        let (mut inner, mut outer) = (SHA256_IV, SHA256_IV);
        compress256(&mut inner, &[pad.map(|byte| byte ^ 0x36)]);
        compress256(&mut outer, &[pad.map(|byte| byte ^ 0x5c)]);
        Keyed { inner, outer }
    }
}

/// A probe key prepared for tagging: the SHA-256 states after the key's inner and outer pad blocks (RFC 2104). A
/// holder of these states seals and verifies as a holder of the key does.
#[derive(Clone, Copy)]
pub struct Keyed {
    inner: [u32; 8],
    outer: [u32; 8],
}

/// A probe message: an observer's request, or a prober's reading of the suspect a request names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message {
    Request(ProbeRequest),
    Reply {
        request: ProbeRequest,
        reading: Reading,
    },
}

/// The first check that refused a probe message, or the receiving agent's refusal of a decoded one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeError {
    Length,
    Version,
    Kind,
    Sender,
    Tag,
    /// A reading byte outside its kind's table, or a zero suspect.
    Field,
    /// The receiver requires the reply's request fields and sender to match an outstanding request to that sender.
    Unrequested,
    /// The receiver requires its detector to track the suspect before answering.
    Untracked,
}

fn reading_code(message: &Message) -> u8 {
    match message {
        Message::Request(_) => 0,
        Message::Reply { reading, .. } => {
            let at = READINGS.iter().position(|r| r == reading);
            at.map_or(0, |at| at as u8 + 1)
        }
    }
}

/// The SHA-256 digest bytes of `state`.
fn digest(state: &[u32; 8]) -> [u8; 32] {
    let mut digest = [0; 32];
    for (word, out) in state.iter().zip(digest.as_chunks_mut().0) {
        *out = word.to_be_bytes();
    }
    digest
}

/// HMAC-SHA256 under `key` over [`DOMAIN`], `receiver` and `body`, every byte of a message before its tag. The
/// label, the receiver and the body's first 40 bytes fill the inner hash's second block. The rest of the body and
/// the hash's padding fill its third, and the inner digest with its padding fills the outer hash's second.
fn tag(key: &Keyed, receiver: Host, body: &[u8; TAG_AT]) -> [u8; 32] {
    let mut blocks = [[0; BLOCK]; 2];
    let input = blocks.as_flattened_mut();
    input[..DOMAIN.len()].copy_from_slice(DOMAIN);
    input[DOMAIN.len()..INPUT - TAG_AT].copy_from_slice(&receiver.get().to_be_bytes());
    input[INPUT - TAG_AT..INPUT].copy_from_slice(body);
    input[INPUT] = 0x80;
    input[2 * BLOCK - 8..].copy_from_slice(&(8 * (BLOCK + INPUT) as u64).to_be_bytes());
    let mut inner = key.inner;
    compress256(&mut inner, &blocks);
    let mut last = [0; BLOCK];
    last[..32].copy_from_slice(&digest(&inner));
    last[32] = 0x80;
    last[BLOCK - 8..].copy_from_slice(&(8 * (BLOCK + 32) as u64).to_be_bytes());
    let mut outer = key.outer;
    compress256(&mut outer, &[last]);
    digest(&outer)
}

/// The encoding of `message` from `sender`, sealed for `receiver` under `key`, the sender's probe key. `boot` is the
/// requester's boot nonce: the sender's own in a request, and the one the answered request carried in a reply.
pub fn encode(
    message: &Message,
    boot: [u8; 16],
    sender: Host,
    receiver: Host,
    key: &ProbeKey,
) -> [u8; LEN] {
    seal(message, boot, sender, receiver, &key.keyed())
}

/// [`encode`] under a prepared key.
pub fn seal(
    message: &Message,
    boot: [u8; 16],
    sender: Host,
    receiver: Host,
    key: &Keyed,
) -> [u8; LEN] {
    let (kind, request) = match message {
        Message::Request(request) => (REQUEST, request),
        Message::Reply { request, .. } => (REPLY, request),
    };
    let mut out = [0; LEN];
    put(&mut out, 0, &VERSION.to_be_bytes());
    out[KIND_AT] = kind;
    out[READING_AT] = reading_code(message);
    put(&mut out, SENDER_AT, &sender.get().to_be_bytes());
    put(&mut out, BOOT_AT, &boot);
    put(&mut out, SUSPECT_AT, &request.suspect.get().to_be_bytes());
    put(&mut out, PARTITION_AT, &request.partition.0.to_be_bytes());
    put(&mut out, GENERATION_AT, &request.generation.0.to_be_bytes());
    put(&mut out, CYCLE_AT, &request.cycle.to_be_bytes());
    put(&mut out, ROUND_AT, &request.round.to_be_bytes());
    put(&mut out, ISSUED_AT, &request.issued.to_be_bytes());
    let (body, sealed) = out
        .split_first_chunk_mut()
        .expect("a message holds its body");
    sealed.copy_from_slice(&tag(key, receiver, body));
    out
}

/// Decodes and authenticates one probe message sealed for `receiver`, returning its sender, the requester's boot
/// nonce and the message. `key`
/// receives the sender before the tag verifies and returns its probe key, or `None` for a host the receiver does
/// not admit.
///
/// # Errors
///
/// [`decode`] returns the first error in check order: `Length` requires exactly [`LEN`] bytes, `Version` requires
/// [`VERSION`], `Kind` a request or reply, `Sender` a nonzero sender with a key, then `Tag`, then `Field`.
pub fn decode(
    bytes: &[u8],
    receiver: Host,
    key: impl FnOnce(Host) -> Option<ProbeKey>,
) -> Result<(Host, [u8; 16], Message), ProbeError> {
    open(bytes, receiver, |sender| key(sender).map(|key| key.keyed()))
}

/// [`decode`] under the sender's prepared key.
///
/// # Errors
///
/// The errors of [`decode`], in its order.
pub fn open(
    bytes: &[u8],
    receiver: Host,
    key: impl FnOnce(Host) -> Option<Keyed>,
) -> Result<(Host, [u8; 16], Message), ProbeError> {
    let Ok(bytes) = <&[u8; LEN]>::try_from(bytes) else {
        return Err(ProbeError::Length);
    };
    if u16::from_be_bytes([bytes[0], bytes[1]]) != VERSION {
        return Err(ProbeError::Version);
    }
    let kind = bytes[KIND_AT];
    if kind != REQUEST && kind != REPLY {
        return Err(ProbeError::Kind);
    }
    let sender = Host::new(u64_at(bytes, SENDER_AT)).ok_or(ProbeError::Sender)?;
    let key = key(sender).ok_or(ProbeError::Sender)?;
    let (body, received) = bytes.split_first_chunk().expect("a message holds its body");
    if !bool::from(tag(&key, receiver, body).ct_eq(received)) {
        return Err(ProbeError::Tag);
    }
    let request = ProbeRequest {
        suspect: Host::new(u64_at(body, SUSPECT_AT)).ok_or(ProbeError::Field)?,
        partition: Partition(u32_at(body, PARTITION_AT)),
        generation: ObservationGeneration(u64_at(body, GENERATION_AT)),
        cycle: u64_at(body, CYCLE_AT),
        round: u32_at(body, ROUND_AT),
        issued: u64_at(body, ISSUED_AT),
    };
    let message = match (kind, body[READING_AT]) {
        (REQUEST, 0) => Message::Request(request),
        (REPLY, code) => Message::Reply {
            request,
            reading: *(code.checked_sub(1))
                .and_then(|at| READINGS.get(usize::from(at)))
                .ok_or(ProbeError::Field)?,
        },
        _ => return Err(ProbeError::Field),
    };
    let mut boot = [0; 16];
    boot.copy_from_slice(&body[BOOT_AT..SUSPECT_AT]);
    Ok((sender, boot, message))
}

#[cfg(test)]
#[path = "probe_tests.rs"]
mod tests;
