//! HMAC-SHA256 (RFC 2104) of a sealed record's body under its domain label: the tag [`super::Writer::seal`] and the
//! reconciler status writer append and [`super::Reader::accept`] and the status reader verify.
//!
//! Invariants owned by this module:
//!
//! - TAG-FUNCTION: [`tag`] returns HMAC-SHA256 under the key over the 16-byte label and the body, the value
//!   `failover::assignment::hmac` returns for the key and those two parts, on every CPU. It compresses the body's
//!   whole blocks where they lie and allocates nothing.
//! - On little-endian aarch64 with the `sha2` and `sha3` features, the tag's two hashes compress through
//!   `net::sha_one::compress`, one chain of FIPS 180-4 compressions in the `sha2` instructions, which leaves the
//!   states `sha2::block_api::compress256` leaves. A tag is one chain: each compression takes the state the
//!   previous one produced, so the chain's latency sets the tag's time.
//! - On every other CPU, and under Miri, `failover::assignment::hmac` computes the tag.

use super::TAG_LEN;
use crate::failover::assignment::hmac;

/// The tag of `body` under `key` and the 16-byte `domain` label.
pub(super) fn tag(key: &[u8; 32], domain: &[u8; 16], body: &[u8]) -> [u8; TAG_LEN] {
    #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
    if crate::net::sha_one::detected() {
        // SAFETY: `sha_one::detected` reported every CPU feature `sha_one::with_features` gives `chain::hmac`.
        return unsafe { chain::hmac(key, domain, body) };
    }
    hmac(key, &[domain, body])
}

/// SHA-256 padding and the tag's HMAC over one chain of compressions in the aarch64 `sha2` instructions, through
/// `net::sha_one::compress`.
#[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
pub(super) mod chain {
    use crate::net::SHA256_IV;
    use crate::net::sha_one::{compress, with_features};

    pub(in super::super) const BLOCK: usize = 64;

    pub(in super::super) type State = [u32; 8];

    with_features! {
        /// HMAC-SHA256 under `key` over `label` followed by `body`.
        pub(super) fn hmac(key: &[u8; 32], label: &[u8; 16], body: &[u8]) -> [u8; 32] {
            let mut pad = [0; BLOCK];
            pad[..key.len()].copy_from_slice(key);
            let (mut inner, mut outer) = (SHA256_IV, SHA256_IV);
            compress(&mut inner, &[pad.map(|byte| byte ^ 0x36)]);
            compress(&mut outer, &[pad.map(|byte| byte ^ 0x5c)]);
            // The label and the body's first 48 bytes fill the inner hash's second block, so the rest of the body
            // compresses in place from a block boundary.
            let mut head = [0; BLOCK];
            head[..label.len()].copy_from_slice(label);
            let (first, rest) = body.split_at(body.len().min(BLOCK - label.len()));
            let held = label.len() + first.len();
            head[label.len()..held].copy_from_slice(first);
            let (blocks, tail) = match held {
                BLOCK => {
                    compress(&mut inner, &[head]);
                    rest.as_chunks()
                }
                _ => (&[][..], &head[..held]),
            };
            compress(&mut inner, blocks);
            let inner = finish(inner, tail, BLOCK + label.len() + body.len());
            finish(outer, &inner, BLOCK + inner.len())
        }
    }

    with_features! {
        /// The SHA-256 digest of a message of `len` bytes that ends in `tail`, shorter than a block, and whose blocks
        /// before `tail` are compressed into `state`: the tail, the byte 0x80, zeros and the bit length fill one more
        /// block, or two when the tail leaves fewer than nine bytes of its block.
        pub(in super::super) fn finish(mut state: State, tail: &[u8], len: usize) -> [u8; 32] {
            let mut last = [[0; BLOCK]; 2];
            let count = if tail.len() < BLOCK - 8 { 1 } else { 2 };
            let bytes = last.as_flattened_mut();
            bytes[..tail.len()].copy_from_slice(tail);
            bytes[tail.len()] = 0x80;
            last[count - 1][BLOCK - 8..].copy_from_slice(&(len as u64 * 8).to_be_bytes());
            compress(&mut state, &last[..count]);
            let mut digest = [0; 32];
            for (word, out) in state.iter().zip(digest.as_chunks_mut().0) {
                *out = word.to_be_bytes();
            }
            digest
        }
    }
}
