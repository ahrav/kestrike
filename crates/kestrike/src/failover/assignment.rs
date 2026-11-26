//! Bounded assignment decoding with a domain-separated HMAC before field access.
//! The tag covers the 16-byte domain label followed by the entire body.
//!
//! Format 3 is 658 bytes: a little-endian `u32` version; nine 64-byte zero-padded identifier fields in issuer,
//! instance, volume, AZ, shard, owner, partition, color and attachment order; a 16-byte assignment ID; three
//! little-endian `u64` values for generation, rollout and content incarnation; a little-endian `u32` attachment
//! incarnation; one byte each for the content and deletion tags; and a 32-byte HMAC.

use super::identity::{Generation, Incarnation, is_volume};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const DOMAIN: &[u8; 16] = b"ebs-assignment01";
const TEXT: usize = 64;
pub const ASSIGNMENT_BYTES: usize = 4 + 9 * TEXT + 16 + 8 * 3 + 4 + 2 + 32;
const VERSION: u32 = 3;

/// Expected root content, or explicit permission to format empty media.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Content {
    Incarnation(u64),
    Format,
}
/// MAC-covered issuer fields. Text uses at most 63 ASCII identifier bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    pub id: [u8; 16],
    pub generation: Generation,
    pub issuer: String,
    pub instance: String,
    pub volume: String,
    pub az: String,
    pub shard: String,
    pub owner: String,
    pub partition: String,
    pub color: String,
    pub attachment: String,
    pub incarnation: Incarnation,
    pub content: Content,
    pub delete_on_termination: Option<bool>,
    pub rollout: Generation,
}
/// The first codec check that refused the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignmentError {
    Length,
    Version,
    Tag,
    Field,
}
/// Fields whose full assignment tag verified under the host key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedAssignment(Assignment);
impl AuthenticatedAssignment {
    pub fn fields(&self) -> &Assignment {
        &self.0
    }
}

/// `hmac` computes HMAC-SHA256 (RFC 2104) over the concatenation of `parts`.
pub(crate) fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut inner_pad = [0x36; 64];
    let mut outer_pad = [0x5c; 64];
    for i in 0..32 {
        inner_pad[i] ^= key[i];
        outer_pad[i] ^= key[i];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    for part in parts {
        inner.update(part);
    }
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner.finalize());
    outer.finalize().into()
}

fn is_identifier(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.len() < TEXT
        && bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b"-_:./".contains(&b))
}

pub(crate) fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

pub(crate) fn text(out: &mut Vec<u8>, value: &str) -> Result<(), AssignmentError> {
    if !is_identifier(value.as_bytes()) {
        return Err(AssignmentError::Field);
    }
    out.extend_from_slice(value.as_bytes());
    out.resize(out.len() + TEXT - value.len(), 0);
    Ok(())
}
/// Bounds-checked field reader for assignment and local record bytes.
pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);
impl Reader<'_> {
    pub(crate) fn take<const N: usize>(&mut self) -> Result<[u8; N], AssignmentError> {
        let head = self.0.get(..N).ok_or(AssignmentError::Length)?;
        let value = head.try_into().expect("fixed-width slice");
        self.0 = &self.0[N..];
        Ok(value)
    }
    pub(crate) fn u64(&mut self) -> Result<u64, AssignmentError> {
        Ok(u64::from_le_bytes(self.take()?))
    }
    pub(crate) fn u32(&mut self) -> Result<u32, AssignmentError> {
        Ok(u32::from_le_bytes(self.take()?))
    }
    pub(crate) fn text(&mut self) -> Result<String, AssignmentError> {
        let bytes = self.0.get(..TEXT).ok_or(AssignmentError::Length)?;
        self.0 = &self.0[TEXT..];
        let end = memchr::memchr(0, bytes).ok_or(AssignmentError::Field)?;
        if !is_identifier(&bytes[..end]) || !is_zero(&bytes[end..]) {
            return Err(AssignmentError::Field);
        }
        let value = std::str::from_utf8(&bytes[..end]).map_err(|_| AssignmentError::Field)?;
        Ok(value.to_owned())
    }
}

#[cfg(test)]
impl Assignment {
    /// Signs the closed schema, validating fields through the receiving decoder.
    ///
    /// # Errors
    ///
    /// [`AssignmentError::Field`] covers malformed padding, identifiers, flags, counters and reserved identity fields.
    pub fn sign(&self, key: &[u8; 32]) -> Result<Vec<u8>, AssignmentError> {
        let mut out = Vec::with_capacity(ASSIGNMENT_BYTES);
        out.extend_from_slice(&VERSION.to_le_bytes());
        for value in [
            &self.issuer,
            &self.instance,
            &self.volume,
            &self.az,
            &self.shard,
            &self.owner,
            &self.partition,
            &self.color,
            &self.attachment,
        ] {
            text(&mut out, value)?;
        }
        out.extend_from_slice(&self.id);
        for value in [
            self.generation.0,
            self.rollout.0,
            match self.content {
                Content::Incarnation(g) => g,
                Content::Format => 0,
            },
        ] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out.extend_from_slice(&self.incarnation.get().to_le_bytes());
        out.extend_from_slice(&[
            match self.content {
                Content::Incarnation(_) => 0,
                Content::Format => 1,
            },
            match self.delete_on_termination {
                None => 0,
                Some(false) => 1,
                Some(true) => 2,
            },
        ]);
        out.extend_from_slice(&hmac(key, &[DOMAIN, &out]));
        verify(&out, key)?;
        Ok(out)
    }
}
/// Length and version precede authentication. Decoding follows a constant-time
/// comparison of the full domain-separated HMAC-SHA256 tag.
///
/// # Errors
///
/// `Length`, `Version` and `Tag` precede `Field`, which covers malformed
/// padding, identifiers, flags, counters and reserved identity fields.
pub fn verify(bytes: &[u8], key: &[u8; 32]) -> Result<AuthenticatedAssignment, AssignmentError> {
    if bytes.len() != ASSIGNMENT_BYTES {
        return Err(AssignmentError::Length);
    }
    if bytes[..4] != VERSION.to_le_bytes() {
        return Err(AssignmentError::Version);
    }
    let (body, tag) = bytes.split_at(bytes.len() - 32);
    if !bool::from(hmac(key, &[DOMAIN, body]).ct_eq(tag)) {
        return Err(AssignmentError::Tag);
    }
    let mut r = Reader(&body[4..]);
    let issuer = r.text()?;
    let instance = r.text()?;
    let volume = r.text()?;
    let az = r.text()?;
    let shard = r.text()?;
    let owner = r.text()?;
    let partition = r.text()?;
    let color = r.text()?;
    let attachment = r.text()?;
    let id = r.take()?;
    let generation = Generation(r.u64()?);
    let rollout = Generation(r.u64()?);
    let content = r.u64()?;
    let incarnation = Incarnation::new(r.u32()?).map_err(|_| AssignmentError::Field)?;
    let content = match (r.take::<1>()?[0], content) {
        (0, g) if g > 0 => Content::Incarnation(g),
        (1, 0) => Content::Format,
        _ => return Err(AssignmentError::Field),
    };
    let delete_on_termination = match r.take::<1>()?[0] {
        0 => None,
        1 => Some(false),
        2 => Some(true),
        _ => return Err(AssignmentError::Field),
    };
    if id == [0; 16] || generation.0 == 0 || rollout.0 == 0 || !is_volume(&volume) {
        return Err(AssignmentError::Field);
    }
    Ok(AuthenticatedAssignment(Assignment {
        id,
        generation,
        issuer,
        instance,
        volume,
        az,
        shard,
        owner,
        partition,
        color,
        attachment,
        incarnation,
        content,
        delete_on_termination,
        rollout,
    }))
}
