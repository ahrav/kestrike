//! Kani proof of the slot locator codec in `held`: over every 64-bit locator
//! word, [`Held::decode`](super::held::Held::decode) returns the direct
//! extent unchanged, the one sequence handle the word spells, or nothing, and
//! [`Held::locator`](super::held::Held::locator) spells every sequence handle
//! of a count from 2 through `EXTENT_LIMIT` back to that handle.
//!
//! Bounds: the proof is loop-free and runs at Kani's default unwinding. The
//! word is a symbolic `u64`, which covers the whole 37-bit start, 3-bit tail
//! and 24-bit length; the handle is a symbolic `u32` block and a symbolic
//! count of 2 through `EXTENT_LIMIT`.

#[cfg(kani)]
mod verification {
    use super::super::blocks::Block;
    use super::super::extent::ExtentLocator;
    use super::super::geometry::EXTENT_LIMIT;
    use super::super::held::{DIRECT_UNITS, Held};

    /// Bits of the locator's start field, below its 3-bit tail.
    const START_BITS: u32 = 37;

    /// Over one symbolic locator word: a length of at most `DIRECT_UNITS` decodes to that locator as a direct
    /// extent; a longer one, of count `len - DIRECT_UNITS`, decodes to a sequence handle exactly when that count lies in `2..=EXTENT_LIMIT`, its
    /// start lies below `2^32` and its tail is zero, the handle carries that start and count, and its locator is the
    /// word; every other word decodes to nothing. Over one symbolic handle of a count in that range: its locator
    /// decodes back to it.
    #[kani::proof]
    fn the_locator_codec_decodes_each_form_alone_and_refuses_every_other_word() {
        let locator = ExtentLocator::from_bits(kani::any());
        let len = locator.len_units();
        let start = locator.start_unit();
        let tail = (locator.bits() >> START_BITS) & 7;
        let count = u64::from(len).wrapping_sub(u64::from(DIRECT_UNITS));
        let spelled = len > DIRECT_UNITS
            && (2..=EXTENT_LIMIT).contains(&count)
            && start <= u64::from(u32::MAX)
            && tail == 0;
        let decoded = Held::decode(locator);
        kani::cover!(matches!(decoded, Some(Held::Direct(_))) && tail != 0);
        kani::cover!(matches!(decoded, Some(Held::Sequence { .. })));
        kani::cover!(decoded.is_none() && len > DIRECT_UNITS && count == 1);
        kani::cover!(decoded.is_none() && count == EXTENT_LIMIT + 1);
        kani::cover!(decoded.is_none() && (2..=EXTENT_LIMIT).contains(&count) && tail != 0);
        kani::cover!(decoded.is_none() && (2..=EXTENT_LIMIT).contains(&count) && tail == 0);
        match decoded {
            Some(Held::Direct(direct)) => {
                assert!(len <= DIRECT_UNITS);
                assert_eq!(direct, locator);
            }
            Some(
                held @ Held::Sequence {
                    block,
                    count: held_count,
                },
            ) => {
                assert!(spelled);
                assert_eq!(u64::from(block.0), start);
                assert_eq!(u64::from(held_count), count);
                assert_eq!(held.locator(), locator);
            }
            None => {
                assert!(len > DIRECT_UNITS && !spelled);
            }
        }

        let handle = Held::Sequence {
            block: Block(kani::any()),
            count: kani::any(),
        };
        if let Held::Sequence { count, .. } = handle {
            kani::assume((2..=EXTENT_LIMIT).contains(&u64::from(count)));
            kani::cover!(count == 2);
            kani::cover!(u64::from(count) == EXTENT_LIMIT);
        }
        assert_eq!(Held::decode(handle.locator()), Some(handle));
    }
}
