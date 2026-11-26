//! A seeded SplitMix64 generator for replayable tests (Steele, Lea and Flood, *Fast Splittable Pseudorandom Number Generators*, OOPSLA 2014).

/// SplitMix64: every seed yields one fixed sequence, so a failing run replays from its seed.
#[derive(Debug, Clone)]
pub(crate) struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub(crate) fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..bound`. The modulo bias is irrelevant at test bounds.
    ///
    /// # Panics
    ///
    /// If `bound` is zero.
    pub(crate) fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }
}

#[cfg(test)]
mod tests {
    use super::SplitMix64;

    /// The generator's first outputs for seed 0, computed from the reference `splitmix64.c` constants.
    #[test]
    fn seed_zero_produces_the_reference_sequence() {
        let mut rng = SplitMix64::new(0);
        assert_eq!(rng.next_u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(rng.next_u64(), 0x6E78_9E6A_A1B9_65F4);
        assert_eq!(rng.next_u64(), 0x06C4_5D18_8009_454F);
    }
}
