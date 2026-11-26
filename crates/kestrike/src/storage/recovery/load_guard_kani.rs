//! Kani proof of the extent bounds rule in `load_guard`: over every 64-bit
//! locator word and every [`LoadLimits`](super::load_guard::LoadLimits),
//! `extent_range` admits an extent exactly when its length is positive and
//! at most `DIRECT_UNITS` and its units lie inside
//! `[payload_start, payload_end)`, and returns those units.
//!
//! Bounds: the proof is loop-free and runs at Kani's default unwinding. The
//! word is a symbolic `u64`, which covers the whole 37-bit start, 3-bit tail
//! and 24-bit length, and every field of the limits is symbolic.

#[cfg(kani)]
mod verification {
    use super::super::super::geometry::DIRECT_UNITS;
    use super::super::load_guard::{LoadLimits, LoadRefusal, extent_range};

    /// Bits of a locator's start field.
    const START_BITS: u32 = 37;
    /// Bits below a locator's length field.
    const LEN_SHIFT: u32 = 40;

    /// Over one symbolic locator word and symbolic limits: the rule returns the word's `[start, start + len)` exactly
    /// when `1 <= len <= DIRECT_UNITS`, `payload_start <= start` and `start + len <= payload_end`, and `Bounds` for
    /// every other word.
    #[kani::proof]
    fn the_extent_bounds_rule_admits_exactly_the_short_nonempty_extents_inside_the_payload() {
        let bits: u64 = kani::any();
        let limits = LoadLimits {
            payload_start: kani::any(),
            payload_end: kani::any(),
            reserve_units: kani::any(),
            slot_count: kani::any(),
            n_max: kani::any(),
            record_chunk_len: kani::any(),
        };
        let start = bits & ((1 << START_BITS) - 1);
        let len = bits >> LEN_SHIFT;
        let end = start + len;
        let inside = (1..=u64::from(DIRECT_UNITS)).contains(&len)
            && limits.payload_start <= start
            && end <= limits.payload_end;
        let range = extent_range(bits, &limits);
        kani::cover!(range.is_ok());
        kani::cover!(range.is_ok() && len == u64::from(DIRECT_UNITS));
        kani::cover!(range == Ok((limits.payload_start, limits.payload_end)));
        kani::cover!(range.is_err() && len == 0);
        kani::cover!(range.is_err() && len == u64::from(DIRECT_UNITS) + 1);
        kani::cover!(range.is_err() && len == 1 && start + 1 == limits.payload_start);
        kani::cover!(range.is_err() && len == 1 && end - 1 == limits.payload_end);
        match range {
            Ok(units) => {
                assert!(inside);
                assert_eq!(units, (start, end));
            }
            Err(refusal) => {
                assert!(!inside);
                assert_eq!(refusal, LoadRefusal::Bounds);
            }
        }
    }
}
