//! The hasher behind the search's memo tables: an unkeyed word-mixing hash
//! of the bits `Hash` feeds it, equal for equal values, so a memo lookup
//! finds the pair an earlier expansion recorded. The tables hold states the
//! search derives from one history; `Eq` decides every membership test, so a
//! hash collision costs one extra probe and leaves the verdict unchanged.

use std::hash::{BuildHasherDefault, Hasher};

pub(crate) type MemoBuild = BuildHasherDefault<MemoHasher>;

const MULTIPLIER: u64 = 0x517c_c1b7_2722_0a95;

#[derive(Default)]
pub(crate) struct MemoHasher(u64);

impl MemoHasher {
    fn mix(&mut self, word: u64) {
        self.0 = (self.0.rotate_left(5) ^ word).wrapping_mul(MULTIPLIER);
    }
}

impl Hasher for MemoHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(8) {
            let mut word = [0u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            self.mix(u64::from_le_bytes(word));
        }
    }

    fn write_u8(&mut self, value: u8) {
        self.mix(u64::from(value));
    }

    fn write_u16(&mut self, value: u16) {
        self.mix(u64::from(value));
    }

    fn write_u32(&mut self, value: u32) {
        self.mix(u64::from(value));
    }

    fn write_u64(&mut self, value: u64) {
        self.mix(value);
    }

    fn write_u128(&mut self, value: u128) {
        self.mix(value as u64);
        self.mix((value >> 64) as u64);
    }

    fn write_usize(&mut self, value: usize) {
        self.mix(value as u64);
    }
}
