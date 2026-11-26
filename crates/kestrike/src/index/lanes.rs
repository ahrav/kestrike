//! Up to eight keys' SipHash-1-3 passes at once, each lane the same word
//! [`siphash13`] gives for its key.
//!
//! [`Lanes::detect`] picks one mechanism when the hasher is drawn: on x86_64
//! the AVX-512 foundation instructions when runtime detection reports both
//! `avx512f` and `vpclmulqdq`, one key per 64-bit lane of four 512-bit state
//! vectors, and otherwise one scalar pass per key. Under Miri every target
//! takes the scalar passes. A message word enters lane `i` as key `i`'s
//! word, so the vector rounds compute the scalar rounds lane by lane and
//! both mechanisms return the same words.
//!
//! On aarch64 every key takes one scalar SipHash-1-3 pass. On Neoverse V1
//! (Graviton3) that pass costs about 12.4 ns per key. On the same core,
//! POLYVAL digests an 8 KiB GET body in about 417 ns, and crc32c over that
//! body takes about 172 ns. The x86_64 AVX-512 pass saves about 9 ns per key
//! on Sapphire Rapids. Against the Graviton3 body work, that is about 1.5%
//! for a GET that hashes one key. The fastest measured multi-key aarch64
//! pass runs at 7.8 ns per key. It saves about 4.6 ns, under 1% of the same
//! body work.
//! Either of two findings calls for evaluating a multi-key aarch64 pass. One
//! is a profile of the owner endpoint on Graviton that attributes 5% or more
//! of a core to the index hash. The other is a production size mix whose GET
//! bodies average under 1 KiB.
//!
//! A pass hashes exactly the keys it is given. The vector kernel runs on a
//! full group of eight keys; an empty group hashes nothing, and a group of
//! one to seven keys runs one scalar pass per key on every mechanism, so
//! every key in a pass is a caller's key and each word past the group stays
//! as the caller left it.
//!
//! The mechanism's width is the group the lookup preparation hashes ahead
//! at once: eight keys per AVX-512 pass, and one key per scalar pass,
//! hashed as its element's lookahead reaches it so its rounds overlap the lookups of the
//! elements before it.

use super::hash::{Key, State, siphash13};

/// Keys one multi-key pass hashes at most.
pub(crate) const LANES: usize = 8;

#[cfg(test)]
thread_local! {
    /// Runs of the AVX-512 kernel on this thread, one per full group.
    pub(crate) static VECTOR_PASSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };

    /// Scalar passes [`Lanes::siphash13`] has run on this thread, one per
    /// key of a group it hashed scalarly.
    pub(crate) static SCALAR_PASSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How a multi-key pass runs on this CPU. Its mechanism is private to this
/// module, so code outside it obtains a `Lanes` only from
/// [`detect`](Self::detect) or a copy of one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lanes(Mechanism);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mechanism {
    /// One scalar pass per key.
    Scalar,
    /// Eight 64-bit lanes of AVX-512 vectors.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    Avx512,
}

impl Lanes {
    /// The widest mechanism this CPU runs.
    pub(crate) fn detect() -> Self {
        #[cfg(all(target_arch = "x86_64", not(miri)))]
        if wide(
            std::arch::is_x86_feature_detected!("avx512f"),
            std::arch::is_x86_feature_detected!("vpclmulqdq"),
        ) {
            return Self(Mechanism::Avx512);
        }
        Self(Mechanism::Scalar)
    }

    /// Every mechanism this CPU runs, the scalar one first, for tests that
    /// hold each to the scalar words.
    #[cfg(test)]
    pub(crate) fn available() -> Vec<Self> {
        let scalar = Self(Mechanism::Scalar);
        let mut all = vec![scalar];
        let widest = Self::detect();
        if widest != scalar {
            all.push(widest);
        }
        all
    }

    /// Keys one pass of this mechanism hashes together: a batch derives its
    /// fingerprints in aligned groups of this many keys.
    pub(crate) fn width(self) -> usize {
        match self.0 {
            Mechanism::Scalar => 1,
            #[cfg(all(target_arch = "x86_64", not(miri)))]
            Mechanism::Avx512 => LANES,
        }
    }

    /// The pass of every key of `keys`, at most [`LANES`] of them, from
    /// `initial` into the leading words of `out`. A full group of [`LANES`]
    /// keys runs this mechanism's multi-key pass; a shorter group runs one
    /// scalar pass per key and leaves the words past `keys.len()` as they
    /// were.
    #[inline]
    pub(crate) fn siphash13(self, initial: &State, keys: &[Key], out: &mut [u64; LANES]) {
        debug_assert!(keys.len() <= LANES);
        #[cfg(all(target_arch = "x86_64", not(miri)))]
        if let (Mechanism::Avx512, Ok(block)) = (self.0, <&[Key; LANES]>::try_from(keys)) {
            // SAFETY: only this module names `Mechanism`, and only `detect`
            // builds `Mechanism::Avx512`, after runtime detection reported
            // `avx512f`; `available` returns what `detect` returned. The CPU
            // therefore implements every instruction the kernel uses.
            *out = unsafe { avx512::siphash13(initial, block) };
            return;
        }
        #[cfg(test)]
        SCALAR_PASSES.with(|count| count.set(count.get() + keys.len()));
        for (word, key) in out.iter_mut().zip(keys) {
            *word = siphash13(*initial, key);
        }
    }
}

/// Skylake-SP, Cascade Lake and Cooper Lake report `avx512f` without
/// `vpclmulqdq` and keep the scalar pass: the Intel 64 and IA-32
/// Architectures Optimization Reference Manual assigns their 512-bit
/// integer instructions a lower core frequency license, which also slows
/// the scalar work beside the batch.
#[cfg(all(target_arch = "x86_64", not(miri)))]
fn wide(avx512f: bool, vpclmulqdq: bool) -> bool {
    avx512f && vpclmulqdq
}

#[cfg(all(target_arch = "x86_64", not(miri)))]
mod avx512 {
    use std::arch::x86_64::{
        __m512i, _mm512_add_epi64, _mm512_loadu_si512, _mm512_permutex2var_epi64, _mm512_rol_epi64,
        _mm512_set_epi64, _mm512_set1_epi64, _mm512_storeu_si512, _mm512_ternarylogic_epi64,
        _mm512_xor_si512,
    };

    use super::{Key, LANES, State};

    /// One SipRound on eight lanes.
    #[inline(always)]
    fn round(v: &mut [__m512i; 4]) {
        // SAFETY: only `siphash13` calls `round`, and it enables `avx512f`.
        unsafe {
            v[0] = _mm512_add_epi64(v[0], v[1]);
            v[1] = _mm512_rol_epi64::<13>(v[1]);
            v[1] = _mm512_xor_si512(v[1], v[0]);
            v[0] = _mm512_rol_epi64::<32>(v[0]);
            v[2] = _mm512_add_epi64(v[2], v[3]);
            v[3] = _mm512_rol_epi64::<16>(v[3]);
            v[3] = _mm512_xor_si512(v[3], v[2]);
            v[0] = _mm512_add_epi64(v[0], v[3]);
            v[3] = _mm512_rol_epi64::<21>(v[3]);
            v[3] = _mm512_xor_si512(v[3], v[0]);
            v[2] = _mm512_add_epi64(v[2], v[1]);
            v[1] = _mm512_rol_epi64::<17>(v[1]);
            v[1] = _mm512_xor_si512(v[1], v[2]);
            v[2] = _mm512_rol_epi64::<32>(v[2]);
        }
    }

    /// The block's 256 bytes load as four vectors of two keys each; two
    /// rounds of two-source permutes transpose them so vector `j` holds
    /// word `j` of keys 0 through 7 in lanes 0 through 7.
    #[target_feature(enable = "avx512f")]
    pub(super) unsafe fn siphash13(initial: &State, block: &[Key; LANES]) -> [u64; LANES] {
        #[cfg(test)]
        super::VECTOR_PASSES.with(|count| count.set(count.get() + 1));
        let base = block.as_ptr().cast::<u8>();
        // SAFETY: `block` is 256 contiguous readable bytes, four 64-byte
        // loads at offsets 0, 64, 128 and 192, and `_mm512_loadu_si512` has
        // no alignment requirement.
        let [a, b, c, d] =
            [0, 64, 128, 192].map(|at| unsafe { _mm512_loadu_si512(base.add(at).cast()) });
        let even = _mm512_set_epi64(14, 12, 10, 8, 6, 4, 2, 0);
        let odd = _mm512_set_epi64(15, 13, 11, 9, 7, 5, 3, 1);
        let (ab_even, ab_odd) = (
            _mm512_permutex2var_epi64(a, even, b),
            _mm512_permutex2var_epi64(a, odd, b),
        );
        let (cd_even, cd_odd) = (
            _mm512_permutex2var_epi64(c, even, d),
            _mm512_permutex2var_epi64(c, odd, d),
        );
        let words = [
            _mm512_permutex2var_epi64(ab_even, even, cd_even),
            _mm512_permutex2var_epi64(ab_odd, even, cd_odd),
            _mm512_permutex2var_epi64(ab_even, odd, cd_even),
            _mm512_permutex2var_epi64(ab_odd, odd, cd_odd),
        ];
        let mut v = initial.map(|word| _mm512_set1_epi64(word as i64));
        let length = _mm512_set1_epi64(((super::super::hash::MESSAGE_BYTES as u64) << 56) as i64);
        for block in words.into_iter().chain([length]) {
            v[3] = _mm512_xor_si512(v[3], block);
            round(&mut v);
            v[0] = _mm512_xor_si512(v[0], block);
        }
        v[2] = _mm512_xor_si512(v[2], _mm512_set1_epi64(0xff));
        round(&mut v);
        round(&mut v);
        round(&mut v);
        // 0x96 is the three-way exclusive or.
        let folded = _mm512_xor_si512(_mm512_ternarylogic_epi64::<0x96>(v[0], v[1], v[2]), v[3]);
        let mut out = [0u64; LANES];
        // SAFETY: `out` is 64 writable bytes and the store has no alignment
        // requirement.
        unsafe { _mm512_storeu_si512(out.as_mut_ptr().cast(), folded) };
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::seeded::SplitMix64;

    fn state(k0: u64, k1: u64) -> State {
        [
            k0 ^ 0x736f6d6570736575,
            k1 ^ 0x646f72616e646f6d,
            k0 ^ 0x6c7967656e657261,
            k1 ^ 0x7465646279746573,
        ]
    }

    /// Every mechanism this CPU runs gives each lane the scalar pass of its
    /// own key: under several states, for random blocks, for blocks whose
    /// keys differ in one byte at every position and lane, and for blocks of
    /// one repeated key, so a lane that read another lane's word or a
    /// transposition that swapped two words fails.
    #[test]
    fn every_mechanism_gives_each_lane_its_own_scalar_pass() {
        let mut rng = SplitMix64::new(0x5EED_1A9E);
        let states = [
            state(0, 0),
            state(0x0706050403020100, 0x0f0e0d0c0b0a0908),
            state(u64::MAX, u64::MAX),
            state(rng.next_u64(), rng.next_u64()),
        ];
        let mut blocks: Vec<[Key; LANES]> = (0..64)
            .map(|_| {
                std::array::from_fn(|_| {
                    let mut key = [0u8; 32];
                    for chunk in key.chunks_mut(8) {
                        chunk.copy_from_slice(&rng.next_u64().to_le_bytes());
                    }
                    key
                })
            })
            .collect();
        for byte in 0..32 {
            blocks.push(std::array::from_fn(|lane| {
                let mut key = [0u8; 32];
                key[byte] = 1 + lane as u8;
                key
            }));
        }
        blocks.push([[0xA5; 32]; LANES]);
        blocks.push([[0; 32]; LANES]);
        let mechanisms = Lanes::available();
        eprintln!("multi-key mechanisms on this CPU: {mechanisms:?}");
        for lanes in mechanisms {
            for initial in &states {
                for block in &blocks {
                    let expected = block.map(|key| siphash13(*initial, &key));
                    for len in 0..=LANES {
                        let mut out = [u64::MAX; LANES];
                        lanes.siphash13(initial, &block[..len], &mut out);
                        assert_eq!(out[..len], expected[..len], "{lanes:?} {len}");
                    }
                }
            }
        }
    }

    /// The pass runs on the keys it is given and no others: on every
    /// mechanism an empty group hashes nothing and a group of one to seven
    /// keys runs one scalar pass per key, leaving every word past the group
    /// as it was; only a full group of eight on the AVX-512 mechanism runs
    /// the vector kernel. The keys are asymmetric, each nonzero in a
    /// different byte, and lanes 2 and 5 repeat one key, so a padding key, a
    /// lane swapped with another lane holding a different key or a word
    /// written past the group fails. The full groups' vector passes form the
    /// AVX-512 kernel's witness, which runs on a host with `avx512f` and
    /// `vpclmulqdq` outside Miri.
    #[test]
    fn only_a_full_group_runs_the_vector_pass() {
        use std::cell::Cell;
        let initial = state(0x0706050403020100, 0x0f0e0d0c0b0a0908);
        let mut block: [Key; LANES] = std::array::from_fn(|lane| {
            let mut key = [0u8; 32];
            key[lane * 3] = 1 + lane as u8;
            key[31 - lane] ^= 0x80;
            key
        });
        block[5] = block[2];
        let expected = block.map(|key| siphash13(initial, &key));
        let passes = || (VECTOR_PASSES.with(Cell::get), SCALAR_PASSES.with(Cell::get));
        let mechanisms = Lanes::available();
        let mut detected = crate::isa_witness::detected!(x86_64: "avx512f", "vpclmulqdq");
        detected.present &= !cfg!(miri);
        crate::isa_witness::witness(
            "index-vector",
            detected,
            || passes().0,
            || {
                for lanes in &mechanisms {
                    for len in 0..=LANES {
                        let mut out = [u64::MAX; LANES];
                        let (vector_before, scalar_before) = passes();
                        lanes.siphash13(&initial, &block[..len], &mut out);
                        let (vector_after, scalar_after) = passes();
                        let full = lanes.width() == LANES && len == LANES;
                        assert_eq!(
                            vector_after - vector_before,
                            usize::from(full),
                            "{lanes:?} {len}"
                        );
                        assert_eq!(
                            scalar_after - scalar_before,
                            if full { 0 } else { len },
                            "{lanes:?} {len}"
                        );
                        assert_eq!(out[..len], expected[..len], "{lanes:?} {len}");
                        assert!(
                            out[len..].iter().all(|word| *word == u64::MAX),
                            "{lanes:?} {len}"
                        );
                    }
                }
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn only_cpus_with_vpclmulqdq_take_the_avx512_pass() {
        assert!(wide(true, true));
        assert!(!wide(true, false));
        assert!(!wide(false, true));
        assert!(!wide(false, false));
    }
}
