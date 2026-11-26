//! The reference decoder implements the fixed-field contract from `net/frame.rs` with independent offsets, constants, and bitwise crc32c.
//!
//! [`decode`] follows the first invariant's check order and returns the [`Refusal`] for the first failure:
//!
//! 1. The truncation flag is clear (first invariant).
//! 2. At least 192 bytes arrived (first invariant).
//! 3. The magic at bytes `[0, 8)` is `IMGNET01` (layout paragraph).
//! 4. The header length, the `u16` at 12, is 192 (layout paragraph).
//! 5. The version, the `u16` at 8, is 3 (layout paragraph).
//! 6. The kind, the byte at 10, is 1 to 28 (sixth invariant's kind ranges).
//! 7. The flags, the byte at 11, are 0 (layout paragraph).
//! 8. The reserved `u16` fields at 14 and 122 are 0 (layout paragraph).
//! 9. The datagram body length, the `u32` at 112, equals the byte count from offset 192 on (first invariant and layout paragraph).
//! 10. The header crc, the `u32` at 160, equals the crc32c of `[0, 176)` with `[160, 164)` read as zero (first invariant).
//!
//! A successful [`decode`] establishes fixed-field validity. The frame contract has the production decoder check every field constraint of the kind, the client boot nonce's nonzero rule among them, after the datagram length and before the header crc; [`decode`]'s checks end at the ten above.
//!
//! The crc is crc32c, the Castagnoli crc: reflected polynomial `0x82F63B78`, with the initial value and the final xor all ones.
//!
//! A source-text test rejects both the parent-module path keyword and the library-root path keyword, even in comments. In code, the test also rejects macro definitions, inclusion macros, `path` attributes, and out-of-line module declarations.

/// The offset of the body: a datagram's bytes from here on are its body, and the datagram body length counts them.
pub const BODY_START: usize = 192;

/// The fields [`decode`] returns for a datagram that passes the fixed-field checks: the kind byte, the variable header fields and the stored body crc. The body stays in the caller's slice. Multibyte integers are read big-endian, and `body_crc` is the stored value at offset 164, returned unchecked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fields {
    pub kind: u8,
    pub principal: u32,
    pub key_epoch: u32,
    pub owner_nonce: [u8; 16],
    pub client_nonce: [u8; 16],
    pub request: u64,
    pub sequence: u64,
    pub allocation: u64,
    pub total: u64,
    pub metadata_len: u32,
    pub body_len: u32,
    pub index: u32,
    pub count: u32,
    pub offset: u64,
    pub datagram_len: u32,
    pub grant: u32,
    pub status: u16,
    pub remaining_ms: u32,
    pub key: [u8; 32],
    pub epoch: u64,
    pub tag: [u8; 16],
    pub body_crc: u32,
}

/// The fixed-field check a datagram failed first. The variants follow the order in which [`decode`] applies the checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Truncated,
    Short,
    Magic,
    HeaderLen,
    Version,
    Kind,
    Flags,
    Reserved,
    DatagramLen,
    HeaderCrc,
}

/// [`decode`] handles inputs of any length and reads at most the first 192 bytes. The caller supplies the transport's truncation flag as `truncated`.
///
/// # Errors
///
/// [`decode`] returns the [`Refusal`] for the first failing check.
pub fn decode(bytes: &[u8], truncated: bool) -> Result<Fields, Refusal> {
    if truncated {
        return Err(Refusal::Truncated);
    }
    if bytes.len() < BODY_START {
        return Err(Refusal::Short);
    }
    if bytes[..8] != *b"IMGNET01" {
        return Err(Refusal::Magic);
    }
    if be(bytes, 12, 2) != 192 {
        return Err(Refusal::HeaderLen);
    }
    if be(bytes, 8, 2) != 3 {
        return Err(Refusal::Version);
    }
    if bytes[10] < 1 || bytes[10] > 28 {
        return Err(Refusal::Kind);
    }
    if bytes[11] != 0 {
        return Err(Refusal::Flags);
    }
    if be(bytes, 14, 2) != 0 || be(bytes, 122, 2) != 0 {
        return Err(Refusal::Reserved);
    }
    if be(bytes, 112, 4) != (bytes.len() - BODY_START) as u64 {
        return Err(Refusal::DatagramLen);
    }
    if be(bytes, 160, 4) != header_crc(bytes) as u64 {
        return Err(Refusal::HeaderCrc);
    }
    Ok(Fields {
        kind: bytes[10],
        principal: be(bytes, 16, 4) as u32,
        key_epoch: be(bytes, 20, 4) as u32,
        owner_nonce: array(bytes, 24),
        client_nonce: array(bytes, 40),
        request: be(bytes, 56, 8),
        sequence: be(bytes, 64, 8),
        allocation: be(bytes, 72, 8),
        total: be(bytes, 80, 8),
        metadata_len: be(bytes, 88, 4) as u32,
        body_len: be(bytes, 92, 4) as u32,
        index: be(bytes, 96, 4) as u32,
        count: be(bytes, 100, 4) as u32,
        offset: be(bytes, 104, 8),
        datagram_len: be(bytes, 112, 4) as u32,
        grant: be(bytes, 116, 4) as u32,
        status: be(bytes, 120, 2) as u16,
        remaining_ms: be(bytes, 124, 4) as u32,
        key: array(bytes, 128),
        epoch: be(bytes, 168, 8),
        tag: array(bytes, 176),
        body_crc: be(bytes, 164, 4) as u32,
    })
}

fn be(bytes: &[u8], at: usize, width: usize) -> u64 {
    let mut value = 0u64;
    for i in 0..width {
        value = (value << 8) | bytes[at + i] as u64;
    }
    value
}

fn array<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[at..at + N]);
    out
}

fn header_crc(bytes: &[u8]) -> u32 {
    let mut header = [0u8; 176];
    header.copy_from_slice(&bytes[..176]);
    header[160..164].fill(0);
    bitwise_crc32c(&header)
}

/// Returns the crc32c of `bytes`, one bit at a time: reflected Castagnoli polynomial `0x82F63B78`, initial value and final xor all ones.
pub fn bitwise_crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    let mut at = 0;
    while at < bytes.len() {
        crc ^= bytes[at] as u32;
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
        at += 1;
    }
    !crc
}
