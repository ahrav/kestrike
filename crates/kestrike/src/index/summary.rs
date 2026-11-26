//! The chain summary: one 64-bit word per base bucket that holds, for every
//! occupied pair of the bucket's chain, two bits selected by the pair's tag.
//! A reader whose tag selects a bit the word lacks has proved, under the
//! sequence it reads the word under, that no pair of the chain carries the
//! tag, and copies nothing without loading a bucket; a tag whose bits are
//! both present scans the chain as before and the pairs decide. The word
//! never excludes a present tag: an insert stores the exact union over the
//! chain's occupied pairs, inside the same bracket as the pair, and a
//! removal leaves the word unchanged, a superset of the remaining tags until
//! the next insert into the chain stores the exact union again.
//!
//! The summaries of a shard form one dense array beside its buckets, eight
//! bytes per base bucket, so the words of a shard's most recently touched
//! chains stay in a reader's private cache while its buckets do not: a
//! lookup of an absent key then costs the summary line and no bucket line.
//! The two bits come from the tag's bits 3..9 and 9..15, above the three the
//! control lane holds and below the tag's top bit, so the lane filter and
//! the summary filter test different bits of the same tag. With two
//! six-bit selectors over 64 bits, a chain of `n` distinct tags admits an
//! absent tag with probability about `(1 - (1 - 2/64)^n)^2`, under 0.09 for
//! a chain of eleven tags.

/// Bits of a summary word.
pub const SUMMARY_BITS: u32 = 64;

/// The bits a pair carrying `tag` sets in its chain's summary: bit `tag`'s
/// bits 3..9 and bit `tag`'s bits 9..15.
#[inline(always)]
pub(crate) const fn summary_bits(tag: u16) -> u64 {
    (1 << ((tag >> 3) & 0b11_1111)) | (1 << ((tag >> 9) & 0b11_1111))
}

/// Whether `summary` proves that no occupied pair of its chain carries
/// `tag`: a tag's bit is absent.
#[inline(always)]
pub(crate) const fn excludes(summary: u64, tag: u16) -> bool {
    let bits = summary_bits(tag);
    summary & bits != bits
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tag's bits are two of the sixty-four, drawn from bits 3..15 of the
    /// tag only; a word with both set includes the tag and a word lacking
    /// either excludes it.
    #[test]
    fn a_tag_selects_two_bits_from_its_middle_twelve_and_a_word_lacking_one_excludes_it() {
        for tag in [
            0u16, 1, 7, 8, 0xFF, 0x100, 0x200, 0x1FF8, 0x7E07, 0x8007, 0xFFFF,
        ] {
            let bits = summary_bits(tag);
            assert!(bits.count_ones() == 1 || bits.count_ones() == 2, "{tag:#x}");
            assert!(!excludes(bits, tag));
            assert!(!excludes(u64::MAX, tag));
            assert!(excludes(0, tag));
            // The lane's three bits and the top bit never change the bits.
            for other in [tag ^ 0b111, tag ^ 0x8000, tag ^ 0x8007] {
                assert_eq!(summary_bits(other), bits, "{tag:#x} {other:#x}");
            }
            // A change inside bits 3..15 changes the bits.
            assert_ne!(summary_bits(tag ^ 0b1000), bits);
            assert_ne!(summary_bits(tag ^ 0x100), bits);
            assert_ne!(summary_bits(tag ^ 0x4000), bits);
        }
        assert_eq!(summary_bits(0), 1);
        assert_eq!(summary_bits(0b0000_1000), 0b10 | 1);
        assert_eq!(summary_bits(0b10_0000_0000), 1 | 0b10);
        assert_eq!(summary_bits(0b10_0000_1000), 0b10);
        assert_eq!(summary_bits(0x1F8), 1 << 63 | 1);
        // A word summarizing several tags includes each and excludes a tag
        // whose bits are both absent.
        let word = summary_bits(0x0010) | summary_bits(0x1E00);
        assert!(!excludes(word, 0x0010));
        assert!(!excludes(word, 0x1E00));
        assert!(excludes(word, 0x0020));
    }

    /// A chain's union admits every member tag whatever the other members
    /// are.
    #[test]
    fn a_union_admits_every_member_tag() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u16
        };
        let mut admitted_absent = 0u32;
        let mut absent = 0u32;
        for _ in 0..2_000 {
            let members: Vec<u16> = (0..11).map(|_| next()).collect();
            let word = members
                .iter()
                .fold(0, |word, &tag| word | summary_bits(tag));
            for &tag in &members {
                assert!(!excludes(word, tag), "{word:#x} {tag:#x}");
            }
            let other = next();
            if !members
                .iter()
                .any(|&tag| summary_bits(tag) == summary_bits(other))
            {
                absent += 1;
                admitted_absent += u32::from(!excludes(word, other));
            }
        }
        let rate = f64::from(admitted_absent) / f64::from(absent);
        assert!((0.03..0.20).contains(&rate), "{rate}");
    }
}
