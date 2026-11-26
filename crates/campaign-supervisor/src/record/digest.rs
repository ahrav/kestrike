//! SHA-256 digests in records, encoded as 64 lowercase hexadecimal
//! digits.

use std::fmt;
use std::io;

use serde::de::{self, Deserialize, Deserializer, Unexpected};
use serde::{Serialize, Serializer};
use sha2::{Digest as _, Sha256};

/// A SHA-256 digest: a record checksum, a job identity's hash or a
/// manifest digest. Its text and its encoding are its 64 lowercase
/// hexadecimal digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    /// The SHA-256 of `bytes`.
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// The digest whose text is `text`; `None` unless `text` is exactly 64
    /// lowercase hexadecimal digits.
    pub fn parse(text: &str) -> Option<Self> {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        let (pairs, []) = text.as_bytes().as_chunks::<2>() else {
            return None;
        };
        if pairs.len() != 32 {
            return None;
        }
        let mut bytes = [0; 32];
        for (byte, &[high, low]) in bytes.iter_mut().zip(pairs) {
            *byte = (digit(high)? << 4) | digit(low)?;
        }
        Some(Self(bytes))
    }

    /// The SHA-256 of every byte `source` yields.
    ///
    /// # Errors
    ///
    /// The first failed read of `source`.
    pub fn read(source: impl io::Read) -> io::Result<Self> {
        let mut hashing = Hashing::new(source);
        io::copy(&mut hashing, &mut io::sink())?;
        Ok(hashing.finish())
    }

    pub(crate) fn finish(hasher: Sha256) -> Self {
        Self(hasher.finalize().into())
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(super) fn hex(&self) -> [u8; 64] {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut text = [0; 64];
        for (pair, byte) in text.as_chunks_mut::<2>().0.iter_mut().zip(self.0) {
            *pair = [
                DIGITS[usize::from(byte >> 4)],
                DIGITS[usize::from(byte & 0x0f)],
            ];
        }
        text
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = self.hex();
        f.write_str(std::str::from_utf8(&text).expect("hexadecimal digits are ASCII"))
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = self.hex();
        serializer.serialize_str(std::str::from_utf8(&text).expect("hexadecimal digits are ASCII"))
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(Hex)
    }
}

/// The visitor that reads a digest from its text.
struct Hex;

impl de::Visitor<'_> for Hex {
    type Value = Digest;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("64 lowercase hex digits")
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<Digest, E> {
        Digest::parse(text).ok_or_else(|| E::invalid_value(Unexpected::Str(text), &self))
    }
}

/// A reader that hashes every byte it passes on from `source`, so a copy
/// knows the digest of exactly the bytes it wrote.
pub struct Hashing<R> {
    source: R,
    hasher: Sha256,
}

impl<R: io::Read> Hashing<R> {
    pub fn new(source: R) -> Self {
        Self {
            source,
            hasher: Sha256::new(),
        }
    }

    /// The digest of the bytes read so far.
    pub fn finish(self) -> Digest {
        Digest::finish(self.hasher)
    }
}

impl<R: io::Read> io::Read for Hashing<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let filled = self.source.read(buffer)?;
        self.hasher.update(&buffer[..filled]);
        Ok(filled)
    }
}
