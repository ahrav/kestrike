//! POLYVAL (RFC 8452) of a GET DATA body under its session's data key: the digest a DATA frame's tag covers in the body's place.
//!
//! Invariants owned by this module:
//!
//! - [`DataHash::digest`] reads a body's two slices as one stream zero-padded to whole 16-byte blocks and returns the stream's POLYVAL under the hash's key, the same value on every CPU, and allocates nothing.
//! - On x86_64 with `avx512f`, `avx512bw`, `avx512vbmi2` and `vpclmulqdq`, a hash keeps its key's powers H^1 to H^32 under POLYVAL's product and absorbs the stream in one pass, 32 blocks per step, reading each 64-byte register of the stream from the slice that holds it and assembling a register that straddles the slices from both: the accumulator joins the step's first block, each block takes the carry-less product with the power equal to its distance from the step's end, the products sum unreduced in the four 128-bit lanes of AVX-512 registers, and one reduction per step, a multiplication by x^-128 modulo x^128 + x^127 + x^126 + x^121 + 1, runs on all four lanes' sums before they add to the next accumulator. Each block's product is Karatsuba's three 64-bit carry-less products, of the low halves, the high halves and the halves' sums; registers go two at a time with both registers' halves' sums packed into one register, so a pair of registers takes six multiplications, and an odd last register of the last step takes its three alone. The stream's last step of n blocks, n from 1 to 32 with the last block partial when its bytes end inside one, takes the powers H^n to H^1, and its masked loads read no byte past either slice or the powers. On aarch64 with `neon`, `aes` and `sha3`, whose carry-less multiply is `pmull` and whose `eor3` adds three registers, a hash keeps the powers H^1 to H^64 two to a table entry, as the three vectors a pair of blocks multiplies by: the two powers' low halves, their high halves and each power's halves summed. It absorbs each run of the stream in steps of at most 64 blocks in 128-bit registers: each block's product is Karatsuba's three 64-bit carry-less products, so a pair of blocks takes six and a block that goes alone takes three, the products sum unreduced, and one reduction per step, two carry-less multiplies by x^63 + x^62 + x^57, yields the next accumulator. A step of n blocks, n from 1 to 64, takes the powers H^n to H^1. A run of fewer than 64 blocks, the last one zero-padded when partial, is one step; a longer run is a first step of the blocks it holds beyond a multiple of 64, when it holds any, and then steps of 64 that end with the run. A partial last block comes from the run's last 16 bytes moved down by a table lookup, or from loads inside its own bytes when the run is shorter than a block or the second slice completes it, so no load reads past either slice. The steps of 64 go through an assembly loop written out over a step's 32 pairs: it reads the last step's last two blocks through a pointer of their own, at a copy with the partial block zero-padded when the run ends inside one, adds each kind's two products to their sum in a single `eor3` and reduces each step's sums among the first pairs of the next step. On every other CPU the `polyval` crate computes the same function.
//! - A hash's key, powers and accumulator stay in the hash and the computation; the type has no `Debug`, so diagnostics carry none of them.

use polyval::Polyval;
use polyval::universal_hash::UniversalHash;

use super::frame::DATA_DIGEST_LEN;

/// Bytes of a POLYVAL block and key.
const BLOCK: usize = 16;

/// A session's data key as a keyed POLYVAL hash.
pub(super) struct DataHash {
    engine: Engine,
}

/// The implementation computing a hash's POLYVAL, chosen once when the hash is built.
#[cfg_attr(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    expect(
        clippy::large_enum_variant,
        reason = "a peer key keeps its data key inline, so deriving one allocates nothing"
    )
)]
enum Engine {
    /// The `polyval` crate's state keyed by the data key, cloned for each body.
    Portable(Polyval),
    /// The key's powers H^32 to H^1, which each 32-block step loads into AVX-512 registers.
    #[cfg(target_arch = "x86_64")]
    Wide(wide::Powers),
    /// The key's powers H^64 to H^1 as the vectors pairs of blocks multiply by with `pmull`, which each step of up to 64 blocks loads.
    #[cfg(target_arch = "aarch64")]
    Pmull(pmull::Powers),
}

impl DataHash {
    /// The hash keyed by `key`, on the vector engine where the CPU has its features.
    pub(super) fn new(key: [u8; BLOCK]) -> Self {
        #[cfg(target_arch = "x86_64")]
        if let Some(powers) = wide::Powers::new(key) {
            return Self {
                engine: Engine::Wide(powers),
            };
        }
        #[cfg(target_arch = "aarch64")]
        if let Some(powers) = pmull::Powers::new(key) {
            return Self {
                engine: Engine::Pmull(powers),
            };
        }
        Self::portable(key)
    }

    /// The hash keyed by `key` on the `polyval` crate, whatever the CPU.
    pub(super) fn portable(key: [u8; BLOCK]) -> Self {
        Self {
            engine: Engine::Portable(Polyval::new(&key.into())),
        }
    }

    /// The POLYVAL of `body`, its two slices read as one stream zero-padded to whole blocks.
    pub(super) fn digest(&self, body: [&[u8]; 2]) -> [u8; DATA_DIGEST_LEN] {
        match &self.engine {
            Engine::Portable(keyed) => {
                let mut hash = keyed.clone();
                stream(body, |run| hash.update_padded(run));
                hash.finalize().into()
            }
            #[cfg(target_arch = "x86_64")]
            Engine::Wide(powers) => powers.digest(body),
            #[cfg(target_arch = "aarch64")]
            Engine::Pmull(powers) => powers.digest(body),
        }
    }

    /// Whether the hash runs on the vector engine.
    #[cfg(test)]
    pub(super) fn is_wide(&self) -> bool {
        !matches!(self.engine, Engine::Portable(_))
    }
}

/// Hands `absorb` the stream of `body`'s two slices in up to three nonempty runs, each but the last a whole number of blocks: the first slice's whole blocks, then the block that straddles the slices, assembled in a stack buffer when the first slice ends inside a block, then the rest of the second slice.
#[inline(always)]
fn stream(body: [&[u8]; 2], mut absorb: impl FnMut(&[u8])) {
    let [first, second] = body;
    let (whole, tail) = first.split_at(first.len() / BLOCK * BLOCK);
    if !whole.is_empty() {
        absorb(whole);
    }
    let mut rest = second;
    if !tail.is_empty() {
        let mut block = [0; BLOCK];
        block[..tail.len()].copy_from_slice(tail);
        let take = (BLOCK - tail.len()).min(second.len());
        block[tail.len()..tail.len() + take].copy_from_slice(&second[..take]);
        absorb(&block);
        rest = &second[take..];
    }
    if !rest.is_empty() {
        absorb(rest);
    }
}

/// POLYVAL with 64-block aggregation in NEON registers and the `pmull` carry-less multiply.
#[cfg(target_arch = "aarch64")]
mod pmull {
    use std::arch::aarch64::{
        uint8x16_t, vdupq_n_u8, veorq_u8, vextq_u8, vgetq_lane_p64, vld1q_u8, vmull_p64,
        vqtbl1q_u8, vreinterpretq_p64_u8, vreinterpretq_u8_p128, vreinterpretq_u8_u64,
        vreinterpretq_u64_u8, vst1q_u8, vuzp1q_u64, vuzp2q_u64,
    };

    use super::{BLOCK, DATA_DIGEST_LEN};

    /// Blocks per step, and powers a hash keeps.
    const STEP: usize = 64;

    /// Bytes of one step.
    const STEP_LEN: usize = STEP * BLOCK;

    /// Bytes of a pair of blocks.
    const PAIR_LEN: usize = 2 * BLOCK;

    /// Pairs of blocks per step, and entries of a hash's table.
    const PAIRS: usize = STEP / 2;

    /// x^63 + x^62 + x^57: modulo x^128 + x^127 + x^126 + x^121 + 1, x^-64 equals x^64 plus this polynomial.
    const P1: u64 = 0xC200_0000_0000_0000;

    /// The [`pair_keys`] of two consecutive powers, the higher power first, on a 64-byte boundary: an entry fills one cache line, so no load of a pair's keys crosses two.
    #[derive(Clone, Copy)]
    #[repr(C, align(64))]
    struct Entry([[u8; BLOCK]; 3]);

    /// A key's powers in descending order, two to an entry: entry `j` holds H^(64 - 2j) and H^(63 - 2j), so blocks `2j` and `2j + 1` of a whole step take entry `j`, and block `k` of a step of `n` blocks takes the power at position `64 - n + k`.
    ///
    /// Only [`Powers::new`] builds one, after runtime detection reported `neon`, `aes` and `sha3`, every CPU feature this module's functions enable.
    pub(super) struct Powers {
        entries: [Entry; PAIRS],
    }

    impl Powers {
        /// The powers of `key` on a CPU that reports `neon`, `aes` and `sha3`; `None` on every other CPU.
        pub(super) fn new(key: [u8; BLOCK]) -> Option<Self> {
            let detected = std::arch::is_aarch64_feature_detected!("neon")
                && std::arch::is_aarch64_feature_detected!("aes")
                && std::arch::is_aarch64_feature_detected!("sha3");
            // SAFETY: runtime detection above reported every CPU feature `expand` enables.
            detected.then(|| Self {
                entries: unsafe { expand(key) },
            })
        }

        /// The POLYVAL of `body`, its two slices read as one stream zero-padded to whole blocks.
        pub(super) fn digest(&self, body: [&[u8]; 2]) -> [u8; DATA_DIGEST_LEN] {
            // SAFETY: only `new` builds a `Powers`, after runtime detection reported every CPU feature `digest` enables.
            unsafe { digest(self, body) }
        }
    }

    /// The powers H^1 to H^64 of `key` under POLYVAL's product, packed two to an entry. Each power above H is the product of two lower ones, H^n for the highest power of two n below its exponent and the power that completes it, so a power is at most six multiplications behind the key and the products of one n do not wait on each other.
    #[target_feature(enable = "neon,aes")]
    fn expand(key: [u8; BLOCK]) -> [Entry; PAIRS] {
        // H^k at index k - 1, once written.
        let mut powers = [block(&key); STEP];
        let (mut known, mut n) = (1, 1);
        while known < STEP {
            if known == 2 * n {
                n = known;
            }
            let by = pair_keys(powers[n - 1], powers[n - 1]);
            powers[known] = Sums::lone(powers[known - n], by).reduce();
            known += 1;
        }
        let mut entries = [Entry([[0; BLOCK]; 3]); PAIRS];
        // `known` is 64 here and counts down by pairs: the powers at indexes `known + 1` and `known`, H^(known + 2) and H^(known + 1), fill entry `31 - known / 2`. An entry is built as a value and assigned whole, so nothing borrows the table and it can be built in the return place.
        while known > 0 {
            known -= 2;
            let mut entry = Entry([[0; BLOCK]; 3]);
            for (at, key) in pair_keys(powers[known + 1], powers[known])
                .into_iter()
                .enumerate()
            {
                // SAFETY: the store writes the 16 bytes of one vector of `entry`.
                unsafe { vst1q_u8(entry.0[at].as_mut_ptr(), key) };
            }
            entries[PAIRS - 1 - known / 2] = entry;
        }
        entries
    }

    /// The three vectors a pair of blocks multiplies by, for the powers `first` and `second` its first and second block take: the powers' low 64-bit halves, their high halves, and each power's halves summed. The same three vectors of a pair of blocks are its factors.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    fn pair_keys(first: uint8x16_t, second: uint8x16_t) -> [uint8x16_t; 3] {
        let (first, second) = (vreinterpretq_u64_u8(first), vreinterpretq_u64_u8(second));
        let low = vreinterpretq_u8_u64(vuzp1q_u64(first, second));
        let high = vreinterpretq_u8_u64(vuzp2q_u64(first, second));
        [low, high, veorq_u8(low, high)]
    }

    /// The digest of `first` then `second`: the first slice as one run, completed to a whole block by the second slice's first bytes when it ends inside one, then the rest of the second slice as another. A body of one run is that run's [`absorb`] from a zero accumulator, in return position; a body of two runs goes through [`two_runs`].
    #[target_feature(enable = "neon,aes")]
    fn digest(powers: &Powers, [first, second]: [&[u8]; 2]) -> [u8; DATA_DIGEST_LEN] {
        #[cfg(test)]
        crate::isa_witness::ran(crate::isa_witness::Kernel::PolyvalPmull);
        let (straddle, rest) =
            second.split_at((first.len().wrapping_neg() % BLOCK).min(second.len()));
        if rest.is_empty() {
            absorb(powers, 0, first, straddle)
        } else {
            two_runs(powers, first, straddle, rest)
        }
    }

    /// The accumulator's bytes after `first` then `straddle` as one run and `rest` as another, from a zero accumulator. Out of line, so that [`digest`] keeps nothing across a call.
    #[inline(never)]
    #[target_feature(enable = "neon,aes")]
    fn two_runs(powers: &Powers, first: &[u8], straddle: &[u8], rest: &[u8]) -> [u8; BLOCK] {
        let sum = u128::from_le_bytes(absorb(powers, 0, first, straddle));
        absorb(powers, sum, rest, &[])
    }

    /// The accumulator's bytes after `run` then `more`, whose blocks follow `sum`'s stream and whose last block, when partial, is zero-padded; `more` is at most the bytes that complete `run`'s last block. A run of at least 64 blocks, a partial last one counted, goes through [`whole_steps`], which takes its steps of 64 through an assembly loop; a shorter run is a [`fold`].
    #[inline]
    #[target_feature(enable = "neon,aes")]
    fn absorb(powers: &Powers, sum: u128, run: &[u8], more: &[u8]) -> [u8; BLOCK] {
        if run.len() <= STEP_LEN - BLOCK {
            fold(&powers.entries, sum, run, more)
        } else {
            whole_steps(powers, sum, run, more)
        }
    }

    /// The accumulator bytes that [`absorb`] defines for `run` followed by `more`. A partial last block counts toward the block count `n` of `run`, and the function panics if `n < 64`. When `n % 64` is nonzero, [`fold`] takes that many leading whole blocks. The assembly loop of [`steps_eor3`] takes the remaining `n / 64` steps of 64 blocks, so it performs the run's last reduction.
    ///
    /// The loop loads blocks 62 and 63 of the last step through a pointer of their own: to the run's last 32 bytes, or, when the run ends inside block 63, to a stack copy of block 62 followed by that block's bytes, `more` and zeros. So the loop reads no byte past the run.
    #[inline(never)]
    #[target_feature(enable = "neon,aes")]
    fn whole_steps(powers: &Powers, sum: u128, run: &[u8], more: &[u8]) -> [u8; BLOCK] {
        let entries = &powers.entries;
        let blocks = run.len().div_ceil(BLOCK);
        debug_assert!(blocks >= STEP && more.len() <= run.len().wrapping_neg() % BLOCK);
        // The first `blocks % 64` blocks are whole and inside a run of at least 64 blocks.
        let (head, steps) = run.split_at(blocks % STEP * BLOCK);
        let (whole, tail) = steps.split_at(steps.len() / BLOCK * BLOCK);
        let (Some(before), Some(end)) = (whole.last_chunk::<BLOCK>(), steps.last_chunk()) else {
            // A run of at least 64 blocks leaves `steps` one step or more: 63 whole blocks, then the block that ends the run.
            unreachable!("whole_steps took a run of fewer than 64 blocks");
        };
        let mut assembled = [0; PAIR_LEN];
        let last = if tail.is_empty() {
            let (_, pair) = steps.split_at(steps.len() - PAIR_LEN);
            pair.as_ptr()
        } else {
            let padded = if more.is_empty() {
                ending(end, tail.len().wrapping_neg())
            } else {
                vreinterpretq_u8_p128(short(tail) | short(more) << (8 * tail.len()))
            };
            // SAFETY: the load reads the 16 bytes of `before`, and the two stores write the 32 bytes of `assembled`.
            unsafe {
                vst1q_u8(assembled.as_mut_ptr(), vld1q_u8(before.as_ptr()));
                vst1q_u8(assembled.as_mut_ptr().add(BLOCK), padded);
            }
            assembled.as_ptr()
        };
        let sum = if head.is_empty() {
            sum
        } else {
            u128::from_le_bytes(fold(entries, sum, head, &[]))
        };
        let count = blocks / STEP;
        // SAFETY: `steps` spans the run's final `count = blocks / 64` steps of 64 blocks each. It contains the whole block `before`, so `count >= 1`. Only the final block can be partial. Each preceding step has 1,024 readable bytes; the final step has at least 992. `last` points to 32 readable bytes that hold the last step's last two blocks: the end of `steps`, or `assembled`, which outlives the call. `Powers::new` built `powers` only after runtime detection reported `neon`, `aes` and `sha3`, every CPU feature the loop enables.
        let sum = unsafe { steps_eor3(entries, sum, steps.as_ptr(), count, last) };
        sum.to_le_bytes()
    }

    // `$x`, `$a` and `$b` added into `$to` by one `eor3`.
    macro_rules! xor_eor3 {
        ($to:literal, $x:literal, $a:literal, $b:literal) => {
            concat!(
                "eor3 ", $to, ".16b, ", $x, ".16b, ", $a, ".16b, ", $b, ".16b\n"
            )
        };
    }
    // Loads the pair of blocks at `$data` into v22 and v23 and the low and high halves of its pair keys at `$keys` into `$kl` and `$kh`, runs `$join` on the blocks, and gathers their low halves, their high halves and the sums of the two into `$tl`, `$th` and `$ts`.
    macro_rules! gather {
        ($data:literal, $keys:literal, $join:literal, $kl:literal, $kh:literal, $tl:literal, $th:literal, $ts:literal) => {
            concat!(
                "ldp q22, q23, ",
                $data,
                "\n",
                "ldp q",
                $kl,
                ", q",
                $kh,
                ", ",
                $keys,
                "\n",
                $join,
                "uzp1 v",
                $tl,
                ".2d, v22.2d, v23.2d\n",
                "uzp2 v",
                $th,
                ".2d, v22.2d, v23.2d\n",
                "eor v",
                $ts,
                ".16b, v",
                $tl,
                ".16b, v",
                $th,
                ".16b\n",
            )
        };
    }
    // The six products of a gathered pair with its pair keys, the half sums' key loaded from `$sums` into v6, into v22 to v27; one `eor3` adds each kind's two to the pair's set of sums `$l`, `$h` and `$m`.
    macro_rules! multiply {
        ($sums:literal, $kl:literal, $kh:literal, $tl:literal, $th:literal, $ts:literal, $l:literal, $h:literal, $m:literal) => {
            concat!(
                "ldr q6, ",
                $sums,
                "\n",
                "pmull v22.1q, v",
                $tl,
                ".1d, v",
                $kl,
                ".1d\n",
                "pmull2 v23.1q, v",
                $tl,
                ".2d, v",
                $kl,
                ".2d\n",
                "pmull v24.1q, v",
                $th,
                ".1d, v",
                $kh,
                ".1d\n",
                "pmull2 v25.1q, v",
                $th,
                ".2d, v",
                $kh,
                ".2d\n",
                "pmull v26.1q, v",
                $ts,
                ".1d, v6.1d\n",
                "pmull2 v27.1q, v",
                $ts,
                ".2d, v6.2d\n",
                xor_eor3!($l, $l, "v22", "v23"),
                xor_eor3!($h, $h, "v24", "v25"),
                xor_eor3!($m, $m, "v26", "v27"),
            )
        };
    }
    // A step's pairs alternate between two sets of registers, so one pair gathers while the pair before it multiplies: an odd pair keeps its keys in v4 and v5, its halves in v28 to v30 and its sums in v16 to v18.
    macro_rules! gather_a {
        ($data:literal, $keys:literal, $join:literal) => {
            gather!($data, $keys, $join, "4", "5", "28", "29", "30")
        };
    }
    macro_rules! multiply_a {
        ($sums:literal) => {
            multiply!($sums, "4", "5", "28", "29", "30", "v16", "v17", "v18")
        };
    }
    // An even pair keeps its keys in v0 and v1, its halves in v2, v7 and v31 and its sums in v19 to v21.
    macro_rules! gather_b {
        ($data:literal, $keys:literal, $join:literal) => {
            gather!($data, $keys, $join, "0", "1", "2", "7", "31")
        };
    }
    macro_rules! multiply_b {
        ($sums:literal) => {
            multiply!($sums, "0", "1", "2", "7", "31", "v19", "v20", "v21")
        };
    }
    // `reduce!` computes [`Sums::reduce`] with the low, high and middle sums in v8, v9 and v10 and [`P1`] in v11, and writes the accumulator to v3. Parts 1 to 6 run in order, one after each of the next step's first six pairs, so the reduction overlaps that step's independent products. After the last step, all six parts run in a row.
    macro_rules! reduce {
        (1) => {
            concat!(
                "eor v12.16b, v8.16b, v9.16b\n",
                "pmull v13.1q, v8.1d, v11.1d\n",
                "ext v8.16b, v8.16b, v8.16b, #8\n",
            )
        };
        (2) => {
            "eor v10.16b, v10.16b, v12.16b\n"
        };
        (3) => {
            xor_eor3!("v8", "v10", "v8", "v13")
        };
        (4) => {
            concat!(
                "ext v10.16b, v10.16b, v10.16b, #8\n",
                "ext v13.16b, v13.16b, v13.16b, #8\n",
                "pmull v8.1q, v8.1d, v11.1d\n",
            )
        };
        (5) => {
            xor_eor3!("v12", "v10", "v12", "v13")
        };
        (6) => {
            "eor v3.16b, v12.16b, v8.16b\n"
        };
        () => {
            concat!(
                reduce!(1),
                reduce!(2),
                reduce!(3),
                reduce!(4),
                reduce!(5),
                reduce!(6),
            )
        };
    }
    /// The accumulator after `count` steps of 64 blocks that start at `steps` and follow `sum`'s stream. The reduction of each step's sums runs among the first pairs of the next step, and the last step's after it. The accumulator arrives and leaves as an integer, in general registers, because a vector crosses into a function with other CPU features through memory.
    ///
    /// A step takes its blocks in pairs, blocks 2 and 3 first and on to 62 and 63, and blocks 0 and 1 last. `uzp1` and `uzp2` gather a pair's low halves and its high halves, one `eor` sums them, and six carry-less products with the pair's [`pair_keys`] follow: the low halves', the high halves' and the half sums', a block in each lane. Each kind's two products join one of two alternating sets of unreduced sums in a single `eor3` (see [`Sums`]). A pair's loads and gathering stand ahead of the products of the pair before it, in registers of their own. The step ends by joining the two sets into three registers, and the next pass reduces them (see [`Sums::reduce`]), one part of `reduce!` behind each of its first six pairs, into the accumulator that joins block 0, whose pair goes last; so the reduction's chain overlaps that step's independent products. After the last step the same parts run in a row. A pair costs 17 micro-operations, five of them loads.
    ///
    /// Blocks 62 and 63 of a step load through a pointer of their own, which in the last step is `last`.
    ///
    /// # Safety
    ///
    /// `count` is at least 1; `steps` points to `count - 1` steps of 1,024 readable bytes followed by 992 readable bytes, and `last` to 32 readable bytes, the last step's last two blocks; the CPU has `neon`, `aes` and `sha3`.
    #[inline(never)]
    #[target_feature(enable = "neon,aes,sha3")]
    unsafe fn steps_eor3(
        entries: &[Entry; PAIRS],
        sum: u128,
        steps: *const u8,
        count: usize,
        last: *const u8,
    ) -> u128 {
        let (low, high): (u64, u64);
        // SAFETY: the caller gives `count` steps at `steps` and 32 readable bytes at `last`. The loop runs once for each step: a pass reads the first 992 bytes of one step from `data`, which then advances by 1024, the step's last 32 bytes from `data + 992`, or from `last` in the last pass, and the three vectors of each of the 32 `entries`, those of entry 16 on through `keys_hi`. So every load is inside the steps, the 32 bytes at `last` or `entries`. Every register the instructions write is an output or a clobber, and they touch no stack.
        unsafe {
            std::arch::asm!(
                "fmov d3, {low}",
                "mov v3.d[1], {high}",
                // The sums 0, `sum` and `sum` reduce to `sum`, so the first step takes the incoming accumulator as later steps take the sums before them.
                "movi v8.2d, #0",
                "mov v9.16b, v3.16b",
                "mov v10.16b, v3.16b",
                "fmov d11, {p1}",
                "2:",
                "add {pair}, {data}, #992",
                "cmp {count}, #1",
                "csel {pair}, {last}, {pair}, eq",
                "movi v16.2d, #0",
                "movi v17.2d, #0",
                "movi v18.2d, #0",
                "movi v19.2d, #0",
                "movi v20.2d, #0",
                "movi v21.2d, #0",
                gather_a!("[{data}, #32]", "[{keys}, #64]", ""),
                gather_b!("[{data}, #64]", "[{keys}, #128]", ""),
                multiply_a!("[{keys}, #96]"),
                reduce!(1),
                gather_a!("[{data}, #96]", "[{keys}, #192]", ""),
                multiply_b!("[{keys}, #160]"),
                reduce!(2),
                gather_b!("[{data}, #128]", "[{keys}, #256]", ""),
                multiply_a!("[{keys}, #224]"),
                reduce!(3),
                gather_a!("[{data}, #160]", "[{keys}, #320]", ""),
                multiply_b!("[{keys}, #288]"),
                reduce!(4),
                gather_b!("[{data}, #192]", "[{keys}, #384]", ""),
                multiply_a!("[{keys}, #352]"),
                reduce!(5),
                gather_a!("[{data}, #224]", "[{keys}, #448]", ""),
                multiply_b!("[{keys}, #416]"),
                reduce!(6),
                gather_b!("[{data}, #256]", "[{keys}, #512]", ""),
                multiply_a!("[{keys}, #480]"),
                gather_a!("[{data}, #288]", "[{keys}, #576]", ""),
                multiply_b!("[{keys}, #544]"),
                gather_b!("[{data}, #320]", "[{keys}, #640]", ""),
                multiply_a!("[{keys}, #608]"),
                gather_a!("[{data}, #352]", "[{keys}, #704]", ""),
                multiply_b!("[{keys}, #672]"),
                gather_b!("[{data}, #384]", "[{keys}, #768]", ""),
                multiply_a!("[{keys}, #736]"),
                gather_a!("[{data}, #416]", "[{keys}, #832]", ""),
                multiply_b!("[{keys}, #800]"),
                gather_b!("[{data}, #448]", "[{keys}, #896]", ""),
                multiply_a!("[{keys}, #864]"),
                gather_a!("[{data}, #480]", "[{keys}, #960]", ""),
                multiply_b!("[{keys}, #928]"),
                gather_b!("[{data}, #512]", "[{keys_hi}]", ""),
                multiply_a!("[{keys}, #992]"),
                gather_a!("[{data}, #544]", "[{keys_hi}, #64]", ""),
                multiply_b!("[{keys_hi}, #32]"),
                gather_b!("[{data}, #576]", "[{keys_hi}, #128]", ""),
                multiply_a!("[{keys_hi}, #96]"),
                gather_a!("[{data}, #608]", "[{keys_hi}, #192]", ""),
                multiply_b!("[{keys_hi}, #160]"),
                gather_b!("[{data}, #640]", "[{keys_hi}, #256]", ""),
                multiply_a!("[{keys_hi}, #224]"),
                gather_a!("[{data}, #672]", "[{keys_hi}, #320]", ""),
                multiply_b!("[{keys_hi}, #288]"),
                gather_b!("[{data}, #704]", "[{keys_hi}, #384]", ""),
                multiply_a!("[{keys_hi}, #352]"),
                gather_a!("[{data}, #736]", "[{keys_hi}, #448]", ""),
                multiply_b!("[{keys_hi}, #416]"),
                gather_b!("[{data}, #768]", "[{keys_hi}, #512]", ""),
                multiply_a!("[{keys_hi}, #480]"),
                gather_a!("[{data}, #800]", "[{keys_hi}, #576]", ""),
                multiply_b!("[{keys_hi}, #544]"),
                gather_b!("[{data}, #832]", "[{keys_hi}, #640]", ""),
                multiply_a!("[{keys_hi}, #608]"),
                gather_a!("[{data}, #864]", "[{keys_hi}, #704]", ""),
                multiply_b!("[{keys_hi}, #672]"),
                gather_b!("[{data}, #896]", "[{keys_hi}, #768]", ""),
                multiply_a!("[{keys_hi}, #736]"),
                gather_a!("[{data}, #928]", "[{keys_hi}, #832]", ""),
                multiply_b!("[{keys_hi}, #800]"),
                gather_b!("[{data}, #960]", "[{keys_hi}, #896]", ""),
                multiply_a!("[{keys_hi}, #864]"),
                gather_a!("[{pair}]", "[{keys_hi}, #960]", ""),
                multiply_b!("[{keys_hi}, #928]"),
                gather_b!("[{data}]", "[{keys}]", "eor v22.16b, v22.16b, v3.16b\n"),
                multiply_a!("[{keys_hi}, #992]"),
                multiply_b!("[{keys}, #32]"),
                // The step's sums, the two sets joined, wait for the next pass or the end.
                "eor v8.16b, v16.16b, v19.16b",
                "eor v9.16b, v17.16b, v20.16b",
                "eor v10.16b, v18.16b, v21.16b",
                "add {data}, {data}, #1024",
                "subs {count}, {count}, #1",
                "b.ne 2b",
                // The last step's sums reduce to the accumulator.
                reduce!(),
                "fmov {low}, d3",
                "mov {high}, v3.d[1]",
                low = inout(reg) sum as u64 => low,
                high = inout(reg) (sum >> 64) as u64 => high,
                data = inout(reg) steps => _,
                pair = out(reg) _,
                last = in(reg) last,
                keys = in(reg) entries.as_ptr(),
                keys_hi = in(reg) entries.as_ptr().wrapping_add(PAIRS / 2),
                count = inout(reg) count => _,
                p1 = in(reg) P1,
                out("v3") _,
                out("v0") _, out("v1") _, out("v2") _, out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                out("v8") _, out("v9") _, out("v10") _, out("v11") _, out("v12") _, out("v13") _,
                out("v16") _, out("v17") _, out("v18") _, out("v19") _,
                out("v20") _, out("v21") _, out("v22") _, out("v23") _,
                out("v24") _, out("v25") _, out("v26") _, out("v27") _,
                out("v28") _, out("v29") _, out("v30") _, out("v31") _,
                options(readonly, nostack),
            );
        }
        u128::from(low) | u128::from(high) << 64
    }

    /// The accumulator's bytes after `run` then `more`, as [`absorb`] defines them, or `sum`'s when both are empty, for a run of at most a step. The run is one step of `n` blocks, the last one zero-padded when partial: the accumulator joins the first block, block `k` takes H^(n - k), and the products reduce once. The blocks go pair by pair from the table entry that holds the first block's power; when that power is its entry's second, which an odd `n` makes it, the first block goes alone through [`Sums::lone`].
    ///
    /// A run of at least a block that has no `more` loads its last block, when partial, without a copy: the run's last 16 bytes less those of the block before, moved down by [`ending`]. A shorter run, and one that `more` completes, goes to [`fold_assembled`] instead, so the path through the pairs makes no call.
    #[inline(never)]
    #[target_feature(enable = "neon,aes")]
    fn fold(entries: &[Entry; PAIRS], sum: u128, run: &[u8], more: &[u8]) -> [u8; BLOCK] {
        debug_assert!(run.len() <= STEP_LEN && more.len() <= run.len().wrapping_neg() % BLOCK);
        if let Some(end) = run.last_chunk::<BLOCK>() {
            if !more.is_empty() {
                return fold_assembled(entries, sum, run, more);
            }
            let sum = vreinterpretq_u8_p128(sum);
            let (mut blocks, tail) = run.as_chunks::<BLOCK>();
            let count = run.len().div_ceil(BLOCK);
            // The entries from the first block's power on: each pair takes the next one.
            let mut table = &entries[(PAIRS - count.div_ceil(2)) % PAIRS..];
            // The accumulator joins the first block, which starts the sums alone or with its pair; in a run of one partial pair it joins that pair.
            let mut joins = vdupq_n_u8(0);
            let mut sums = if count % 2 == 1
                && let ([head, rest @ ..], [entry, after @ ..]) = (blocks, table)
            {
                (blocks, table) = (rest, after);
                Sums::lone(veorq_u8(block(head), sum), keys(entry))
            } else if let ([x, y, rest @ ..], [entry, after @ ..]) = (blocks, table) {
                (blocks, table) = (rest, after);
                Sums::pair(veorq_u8(block(x), sum), block(y), keys(entry))
            } else {
                joins = sum;
                Sums::zero()
            };
            while let ([x, y, rest @ ..], [entry, after @ ..]) = (blocks, table) {
                (blocks, table) = (rest, after);
                sums.add(block(x), block(y), keys(entry));
            }
            // One whole block is left exactly when the run ends inside a block, and then that block and the partial one are the run's last pair, whose entry is the table's last. In a run of 17 to 31 bytes it is the only pair, and the accumulator joins it.
            for first in blocks.iter() {
                let y = ending(end, tail.len().wrapping_neg());
                sums.add(veorq_u8(block(first), joins), y, keys(&entries[PAIRS - 1]));
            }
            let mut bytes = [0; BLOCK];
            // SAFETY: the store writes the 16 bytes of `bytes`.
            unsafe { vst1q_u8(bytes.as_mut_ptr(), sums.reduce()) };
            return bytes;
        }
        if run.is_empty() && more.is_empty() {
            sum.to_le_bytes()
        } else {
            fold_assembled(entries, sum, run, more)
        }
    }

    /// [`fold`] of a run that is shorter than a block or that `more` completes: the run's whole blocks through [`fold`], then its last block, the run's bytes after them with `more` and zeros behind, built in general registers by [`short`] and multiplied by H alone. Out of line, so that [`fold`] keeps nothing across a call.
    #[inline(never)]
    #[target_feature(enable = "neon,aes")]
    fn fold_assembled(entries: &[Entry; PAIRS], sum: u128, run: &[u8], more: &[u8]) -> [u8; BLOCK] {
        let (whole, tail) = run.split_at(run.len() / BLOCK * BLOCK);
        let sum = if whole.is_empty() {
            sum
        } else {
            u128::from_le_bytes(fold(entries, sum, whole, &[]))
        };
        let last = short(tail) | short(more) << (8 * tail.len());
        // The last entry's second power is H.
        let sums = Sums::lone(vreinterpretq_u8_p128(sum ^ last), keys(&entries[PAIRS - 1]));
        let mut bytes = [0; BLOCK];
        // SAFETY: the store writes the 16 bytes of `bytes`.
        unsafe { vst1q_u8(bytes.as_mut_ptr(), sums.reduce()) };
        bytes
    }

    /// `bytes`, shorter than a block, followed by zeros, as a little-endian integer; of a longer slice, its first `len % 16` bytes. Two loads that may overlap cover a length of 8 to 15 and one of 4 to 7, and three bytes cover a shorter one, so nothing is copied through memory and no load waits on a store.
    #[inline]
    fn short(bytes: &[u8]) -> u128 {
        let len = bytes.len() % BLOCK;
        let bytes = &bytes[..len];
        if let (Some(first), Some(last)) = (bytes.first_chunk::<8>(), bytes.last_chunk::<8>()) {
            u128::from(u64::from_le_bytes(*first))
                | u128::from(u64::from_le_bytes(*last)) << (8 * (len - 8))
        } else if let (Some(first), Some(last)) =
            (bytes.first_chunk::<4>(), bytes.last_chunk::<4>())
        {
            let low = u64::from(u32::from_le_bytes(*first))
                | u64::from(u32::from_le_bytes(*last)) << (8 * (len - 4));
            low.into()
        } else if let (Some(&first), Some(&last)) = (bytes.first(), bytes.last()) {
            let low = u32::from(first)
                | u32::from(bytes[len / 2]) << (8 * (len / 2))
                | u32::from(last) << (8 * (len - 1));
            low.into()
        } else {
            0
        }
    }

    /// Index rows for [`ending`]: the 16 bytes from byte `skip`, for `skip` from 0 to 15, name a block's bytes from `skip` on in its first places and no byte in the others.
    static ENDINGS: [u8; 2 * BLOCK] = {
        let mut rows = [0xFF; 2 * BLOCK];
        let mut at = 0;
        while at < BLOCK {
            rows[at] = at as u8;
            at += 1;
        }
        rows
    };

    /// The bytes of `end` from byte `skip % 16` on, followed by zeros: a table lookup moves them down, and an index outside the block reads as zero.
    #[inline]
    #[target_feature(enable = "neon")]
    fn ending(end: &[u8; BLOCK], skip: usize) -> uint8x16_t {
        // SAFETY: the offset is at most 15, so the load reads 16 of the 32 bytes of `ENDINGS`.
        let row = unsafe { vld1q_u8(ENDINGS.as_ptr().wrapping_add(skip % BLOCK)) };
        vqtbl1q_u8(block(end), row)
    }

    /// `bytes` loaded as one block.
    #[inline]
    #[target_feature(enable = "neon")]
    fn block(bytes: &[u8; BLOCK]) -> uint8x16_t {
        // SAFETY: the load reads the 16 bytes of `bytes`.
        unsafe { vld1q_u8(bytes.as_ptr()) }
    }

    /// The three vectors of `entry`, loaded.
    #[inline]
    #[target_feature(enable = "neon")]
    fn keys(entry: &Entry) -> [uint8x16_t; 3] {
        // SAFETY: each load reads the 16 bytes of one vector.
        entry.0.map(|bytes| unsafe { vld1q_u8(bytes.as_ptr()) })
    }

    /// The carry-less product of the low 64-bit half of `value` with [`P1`].
    #[inline]
    #[target_feature(enable = "neon,aes")]
    fn low_by_p1(value: uint8x16_t) -> uint8x16_t {
        vreinterpretq_u8_p128(vmull_p64(
            vgetq_lane_p64::<0>(vreinterpretq_p64_u8(value)),
            P1,
        ))
    }

    /// Unreduced sums over blocks M with halves M0 and M1, each times a power H with halves H0 and H1: `low` sums M0·H0, `high` sums M1·H1 and `middle` sums (M0 + M1)·(H0 + H1), so that the sum of the products M·H is low + (middle + low + high)·x^64 + high·x^128.
    struct Sums {
        low: uint8x16_t,
        high: uint8x16_t,
        middle: uint8x16_t,
    }

    impl Sums {
        #[inline]
        #[target_feature(enable = "neon")]
        fn zero() -> Self {
            Self {
                low: vdupq_n_u8(0),
                high: vdupq_n_u8(0),
                middle: vdupq_n_u8(0),
            }
        }

        /// The products of the block `x` with the second of the two powers whose [`pair_keys`] are `by`, three carry-less multiplications: `ext` swaps the block's halves so each `pmull2` meets the power's half in the upper lane.
        #[inline]
        #[target_feature(enable = "neon,aes")]
        fn lone(x: uint8x16_t, [low, high, both]: [uint8x16_t; 3]) -> Self {
            let (l, h, m): (uint8x16_t, uint8x16_t, uint8x16_t);
            // SAFETY: the instructions read and write only the named registers.
            unsafe {
                std::arch::asm!(
                    "ext {l:v}.16b, {x:v}.16b, {x:v}.16b, #8",
                    "eor {m:v}.16b, {x:v}.16b, {l:v}.16b",
                    "pmull2 {l:v}.1q, {l:v}.2d, {low:v}.2d",
                    "pmull2 {h:v}.1q, {x:v}.2d, {high:v}.2d",
                    "pmull2 {m:v}.1q, {m:v}.2d, {both:v}.2d",
                    x = in(vreg) x,
                    low = in(vreg) low,
                    high = in(vreg) high,
                    both = in(vreg) both,
                    l = out(vreg) l,
                    h = out(vreg) h,
                    m = out(vreg) m,
                    options(pure, nomem, nostack, preserves_flags),
                );
            }
            Self {
                low: l,
                high: h,
                middle: m,
            }
        }

        /// The products of the blocks `x` and `y` with the two powers whose [`pair_keys`] are `by`, six carry-less multiplications: one assembly block, so the pair runs as the 12 vector instructions written here, each kind's two products added to each other.
        #[inline]
        #[target_feature(enable = "neon,aes")]
        fn pair(x: uint8x16_t, y: uint8x16_t, [low, high, both]: [uint8x16_t; 3]) -> Self {
            let (l, h, m): (uint8x16_t, uint8x16_t, uint8x16_t);
            // SAFETY: the instructions read and write only the named registers.
            unsafe {
                std::arch::asm!(
                    "uzp1 {lows:v}.2d, {x:v}.2d, {y:v}.2d",
                    "uzp2 {highs:v}.2d, {x:v}.2d, {y:v}.2d",
                    "eor {sums:v}.16b, {lows:v}.16b, {highs:v}.16b",
                    "pmull {l:v}.1q, {lows:v}.1d, {low:v}.1d",
                    "pmull2 {lows:v}.1q, {lows:v}.2d, {low:v}.2d",
                    "pmull {h:v}.1q, {highs:v}.1d, {high:v}.1d",
                    "pmull2 {highs:v}.1q, {highs:v}.2d, {high:v}.2d",
                    "pmull {m:v}.1q, {sums:v}.1d, {both:v}.1d",
                    "pmull2 {sums:v}.1q, {sums:v}.2d, {both:v}.2d",
                    "eor {l:v}.16b, {l:v}.16b, {lows:v}.16b",
                    "eor {h:v}.16b, {h:v}.16b, {highs:v}.16b",
                    "eor {m:v}.16b, {m:v}.16b, {sums:v}.16b",
                    x = in(vreg) x,
                    y = in(vreg) y,
                    low = in(vreg) low,
                    high = in(vreg) high,
                    both = in(vreg) both,
                    l = out(vreg) l,
                    h = out(vreg) h,
                    m = out(vreg) m,
                    lows = out(vreg) _,
                    highs = out(vreg) _,
                    sums = out(vreg) _,
                    options(pure, nomem, nostack, preserves_flags),
                );
            }
            Self {
                low: l,
                high: h,
                middle: m,
            }
        }

        /// Adds the [`pair`](Self::pair) of the blocks `x` and `y` with `by` to the sums.
        #[inline]
        #[target_feature(enable = "neon,aes")]
        fn add(&mut self, x: uint8x16_t, y: uint8x16_t, by: [uint8x16_t; 3]) {
            let pair = Self::pair(x, y, by);
            self.low = veorq_u8(self.low, pair.low);
            self.high = veorq_u8(self.high, pair.high);
            self.middle = veorq_u8(self.middle, pair.middle);
        }

        /// POLYVAL's reduction of the sums, the next accumulator: with S the 256-bit sum of products and its 128-bit halves S0 and S1, S·x^-128 = S1 + (S0·x^-64)·x^-64, which is below x^128.
        ///
        /// A multiplication by x^-64 swaps a value's 64-bit halves and adds its low half's product with [`P1`]. Written out over the sums, with X = low + high and each product T by `P1`: the first multiplication's low half is that of Q + swap(low) + T1 for Q = middle + X and T1 from `low`, and the result is swap(Q) + X + swap(T1) + T2, T2 from that low half. The first product starts from `low` alone, so the result is five instructions deep behind the last sum.
        #[inline]
        #[target_feature(enable = "neon,aes")]
        fn reduce(self) -> uint8x16_t {
            let swap = |value| vextq_u8::<8>(value, value);
            let x = veorq_u8(self.low, self.high);
            let q = veorq_u8(self.middle, x);
            let first = low_by_p1(self.low);
            let once = veorq_u8(q, veorq_u8(swap(self.low), first));
            let rest = veorq_u8(swap(q), veorq_u8(x, swap(first)));
            veorq_u8(rest, low_by_p1(once))
        }
    }
}

/// POLYVAL with 32-block aggregation in AVX-512 registers.
#[cfg(target_arch = "x86_64")]
mod wide {
    use std::arch::x86_64::{
        __m128i, __m512i, _mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128, _mm256_castsi256_si128,
        _mm256_extracti128_si256, _mm256_xor_si256, _mm512_bslli_epi128, _mm512_bsrli_epi128,
        _mm512_castsi512_si128, _mm512_castsi512_si256, _mm512_clmulepi64_epi128,
        _mm512_extracti64x4_epi64, _mm512_inserti32x4, _mm512_loadu_si512,
        _mm512_maskz_expand_epi8, _mm512_maskz_loadu_epi8, _mm512_or_si512, _mm512_set_epi64,
        _mm512_setzero_si512, _mm512_shuffle_epi32, _mm512_shuffle_i64x2, _mm512_storeu_si512,
        _mm512_ternarylogic_epi64, _mm512_unpackhi_epi64, _mm512_unpacklo_epi64, _mm512_xor_si512,
        _mm512_zextsi128_si512,
    };

    use super::{BLOCK, DATA_DIGEST_LEN};

    /// Blocks per step, and powers a hash keeps.
    const STEP: usize = 32;

    /// Bytes of one step.
    const STEP_LEN: usize = STEP * BLOCK;

    /// Bytes of an AVX-512 register: four blocks.
    const LANE_LEN: usize = 64;

    /// Registers of one step.
    const REGISTERS: usize = STEP_LEN / LANE_LEN;

    /// A key's powers in descending order: entry `k` is H^(32 - k), so block `k` of a step of `n` blocks takes entry `32 - n + k`.
    ///
    /// Only [`Powers::new`] builds one, after runtime detection reported every CPU feature this module's functions enable.
    pub(super) struct Powers([[u8; BLOCK]; STEP]);

    impl Powers {
        /// The powers of `key`; `None` on a CPU without `avx512f`, `avx512bw`, `avx512vbmi2` and `vpclmulqdq`.
        pub(super) fn new(key: [u8; BLOCK]) -> Option<Self> {
            let detected = std::arch::is_x86_feature_detected!("avx512f")
                && std::arch::is_x86_feature_detected!("avx512bw")
                && std::arch::is_x86_feature_detected!("avx512vbmi2")
                && std::arch::is_x86_feature_detected!("vpclmulqdq");
            // SAFETY: runtime detection above reported every CPU feature `expand` enables.
            detected.then(|| unsafe { expand(key) })
        }

        /// The POLYVAL of `body`, its two slices read as one stream zero-padded to whole blocks.
        pub(super) fn digest(&self, body: [&[u8]; 2]) -> [u8; DATA_DIGEST_LEN] {
            // SAFETY: only `new` builds a `Powers`, after runtime detection reported every CPU feature `digest` enables.
            unsafe { digest(self, body) }
        }
    }

    /// The powers H^1 to H^32 of `key` under POLYVAL's product, in five rounds of lane-wise products: H^2, then H^3 and H^4, then H^5 to H^8 as H^1 to H^4 times H^4, then H^9 to H^16 by H^8, then H^17 to H^32 by H^16.
    #[target_feature(enable = "avx512f,avx512bw,vpclmulqdq")]
    fn expand(key: [u8; BLOCK]) -> Powers {
        // Lane 0 holds H and the other lanes zero, whose products stay zero.
        // SAFETY: the load reads the 16 bytes of `key`.
        let h = _mm512_zextsi128_si512(unsafe { _mm_loadu_si128(key.as_ptr().cast()) });
        let two = product(h, h);
        // Lanes 0 and 1 of `low` hold H and H^2, which times H^2 give H^3 and H^4.
        let low = _mm512_inserti32x4::<1>(h, _mm512_castsi512_si128(two));
        let high = product(_mm512_shuffle_i64x2::<0x00>(two, two), low);
        // Lane `j` of register `r` holds H^(4r + j + 1).
        let mut ascending = [_mm512_setzero_si512(); REGISTERS];
        ascending[0] = _mm512_shuffle_i64x2::<0x44>(low, high);
        ascending[1] = product(
            ascending[0],
            _mm512_shuffle_i64x2::<0xFF>(ascending[0], ascending[0]),
        );
        let eight = _mm512_shuffle_i64x2::<0xFF>(ascending[1], ascending[1]);
        ascending[2] = product(ascending[0], eight);
        ascending[3] = product(ascending[1], eight);
        let sixteen = _mm512_shuffle_i64x2::<0xFF>(ascending[3], ascending[3]);
        for at in REGISTERS / 2..REGISTERS {
            ascending[at] = product(ascending[at - REGISTERS / 2], sixteen);
        }
        let mut powers = [[0; BLOCK]; STEP];
        let (entries, _) = powers.as_chunks_mut::<4>();
        for (entries, power) in entries.iter_mut().zip(ascending.iter().rev()) {
            // Reversing the lanes puts the highest power first, as the descending table keeps it.
            let descending = _mm512_shuffle_i64x2::<0x1B>(*power, *power);
            // SAFETY: the store writes the 64 bytes of `entries`.
            unsafe { _mm512_storeu_si512(entries.as_mut_ptr().cast(), descending) };
        }
        Powers(powers)
    }

    /// The stream of a body's two slices, `first` then `second`, as 64-byte registers.
    #[derive(Clone, Copy)]
    struct Slices<'b> {
        first: &'b [u8],
        second: &'b [u8],
    }

    impl Slices<'_> {
        /// The stream's bytes `[at, at + len)` in a register's first `len` bytes and zeros after them.
        ///
        /// # Safety
        ///
        /// `len` is from 1 to 64 and `at + len` is at most the stream's length, so every byte the masks enable lies inside a slice.
        #[inline]
        #[target_feature(enable = "avx512f,avx512bw,avx512vbmi2")]
        unsafe fn register(self, at: usize, len: usize) -> __m512i {
            let split = self.first.len();
            if at + len <= split {
                // SAFETY: the mask enables the `len` bytes `first` holds from `at`; the masked-off bytes are not read.
                return unsafe {
                    _mm512_maskz_loadu_epi8(mask(len), self.first[at..].as_ptr().cast())
                };
            }
            if at >= split {
                // SAFETY: the caller's bound leaves `len` readable bytes in `second` from `at - split`, and the mask enables those; the masked-off bytes are not read.
                return unsafe {
                    _mm512_maskz_loadu_epi8(mask(len), self.second[at - split..].as_ptr().cast())
                };
            }
            // The register straddles the slices: `first`'s last `head` bytes, then `second`'s first `len - head` bytes moved up behind them.
            let head = split - at;
            // SAFETY: the mask enables the `head` bytes `first` holds from `at`; the masked-off bytes are not read.
            let low =
                unsafe { _mm512_maskz_loadu_epi8(mask(head), self.first[at..].as_ptr().cast()) };
            // SAFETY: the caller's bound leaves `len - head` readable bytes at the start of `second`, and the mask enables those; the masked-off bytes are not read.
            let rest =
                unsafe { _mm512_maskz_loadu_epi8(mask(len - head), self.second.as_ptr().cast()) };
            _mm512_or_si512(low, _mm512_maskz_expand_epi8(mask(len) & !mask(head), rest))
        }
    }

    #[target_feature(enable = "avx512f,avx512bw,avx512vbmi2,vpclmulqdq")]
    fn digest(powers: &Powers, [first, second]: [&[u8]; 2]) -> [u8; DATA_DIGEST_LEN] {
        let slices = Slices { first, second };
        let table = powers.0.as_flattened();
        let len = first.len() + second.len();
        let (steps, last) = (len / STEP_LEN, len % STEP_LEN);
        let mut sum = _mm512_setzero_si512();
        if steps > 0 {
            let keys: [__m512i; REGISTERS] = std::array::from_fn(|at| {
                // SAFETY: the load reads 64 of the table's 512 bytes.
                unsafe { _mm512_loadu_si512(table[at * LANE_LEN..].as_ptr().cast()) }
            });
            let sums: [__m512i; REGISTERS / 2] =
                std::array::from_fn(|pair| halves_sums(keys[2 * pair], keys[2 * pair + 1]));
            for step in 0..steps {
                let start = step * STEP_LEN;
                // A step inside one slice loads its registers in place; the step holding the split reads each through `Slices::register`, which assembles the straddling one.
                let inside = if start + STEP_LEN <= first.len() {
                    Some(&first[start..start + STEP_LEN])
                } else if start >= first.len() {
                    Some(&second[start - first.len()..][..STEP_LEN])
                } else {
                    None
                };
                let register = |at: usize| match inside {
                    // SAFETY: the load reads 64 of the step's 512 bytes.
                    Some(bytes) => unsafe {
                        _mm512_loadu_si512(bytes[at * LANE_LEN..].as_ptr().cast())
                    },
                    // SAFETY: the register ends at `start + 512`, and `start + 512 <= steps * 512 <= len`, the stream's length.
                    None => unsafe { slices.register(start + at * LANE_LEN, LANE_LEN) },
                };
                let mut products = Products::zero();
                // The pair holding the accumulator's block goes last, so the other pairs' products overlap the previous step's reduction.
                for pair in (0..REGISTERS / 2).rev() {
                    let joined = joined(register(2 * pair), pair, sum);
                    products.add(
                        [joined, register(2 * pair + 1)],
                        [keys[2 * pair], keys[2 * pair + 1]],
                        sums[pair],
                    );
                }
                sum = products.sum();
            }
        }
        if last > 0 {
            let start = steps * STEP_LEN;
            let skip = (STEP - last.div_ceil(BLOCK)) * BLOCK;
            let registers = last.div_ceil(LANE_LEN);
            // Register `at` of the last step and its powers.
            let load = |at: usize| {
                let offset = at * LANE_LEN;
                let len = (last - offset).min(LANE_LEN);
                // SAFETY: the mask enables the powers of this register's blocks, `skip + offset` to `skip + offset + ceil16(len)`; `offset` is a multiple of 16, so that end is at most `skip + ceil16(last) = 512`, the table's length; the masked-off bytes are not read.
                let key = unsafe {
                    _mm512_maskz_loadu_epi8(
                        mask(len.div_ceil(BLOCK) * BLOCK),
                        table[skip + offset..].as_ptr().cast(),
                    )
                };
                // SAFETY: `len` is from 1 to 64, and the register ends at `start + offset + len <= start + last`, the stream's length.
                (unsafe { slices.register(start + offset, len) }, key)
            };
            let mut products = Products::zero();
            // An odd last register takes its three products alone, so every multiplication of the last step reads stream bytes.
            if registers % 2 == 1 {
                let (block, key) = load(registers - 1);
                products.add_one(joined(block, registers / 2, sum), key);
            }
            for pair in (0..registers / 2).rev() {
                let ((low, low_key), (high, high_key)) = (load(2 * pair), load(2 * pair + 1));
                products.add(
                    [joined(low, pair, sum), high],
                    [low_key, high_key],
                    halves_sums(low_key, high_key),
                );
            }
            sum = products.sum();
        }
        let mut out = [0; DATA_DIGEST_LEN];
        // SAFETY: the store writes the 16 bytes of `out`.
        unsafe { _mm_storeu_si128(out.as_mut_ptr().cast(), _mm512_castsi512_si128(sum)) };
        out
    }

    /// The first register of a step's pair `pair`, with the accumulator `sum` added to the step's first block when `pair` is 0; `sum` holds the accumulator in lane 0 and zeros in the other lanes, as [`Products::sum`] leaves it.
    #[inline]
    #[target_feature(enable = "avx512f")]
    fn joined(register: __m512i, pair: usize, sum: __m512i) -> __m512i {
        if pair == 0 {
            _mm512_xor_si512(register, sum)
        } else {
            register
        }
    }

    /// A byte mask enabling the first `len` of a register's 64 bytes, for `len` from 1 to 64.
    #[inline(always)]
    fn mask(len: usize) -> u64 {
        debug_assert!((1..=LANE_LEN).contains(&len), "mask of {len} bytes");
        u64::MAX >> (LANE_LEN - len)
    }

    /// In each 128-bit lane, the sum of the two 64-bit halves of `low`'s lane, then of `high`'s: the middle factor Karatsuba's product of a pair of registers takes from each.
    #[inline]
    #[target_feature(enable = "avx512f")]
    fn halves_sums(low: __m512i, high: __m512i) -> __m512i {
        _mm512_xor_si512(
            _mm512_unpacklo_epi64(low, high),
            _mm512_unpackhi_epi64(low, high),
        )
    }

    /// Unreduced sums of carry-less products in each 128-bit lane: the low and high 128-bit terms of the 256-bit products and the product of the halves' sums, which Karatsuba's middle term reaches after the low and high terms are added to it.
    struct Products {
        low: __m512i,
        middle: __m512i,
        high: __m512i,
    }

    impl Products {
        #[inline]
        #[target_feature(enable = "avx512f")]
        fn zero() -> Self {
            Self {
                low: _mm512_setzero_si512(),
                middle: _mm512_setzero_si512(),
                high: _mm512_setzero_si512(),
            }
        }

        /// Adds each lane's products of `low` with `low_key` and of `high` with `high_key`, six carry-less multiplications in all, where `key_sums` is [`halves_sums`] of the two keys.
        #[inline]
        #[target_feature(enable = "avx512f,vpclmulqdq")]
        fn add(
            &mut self,
            [low, high]: [__m512i; 2],
            [low_key, high_key]: [__m512i; 2],
            key_sums: __m512i,
        ) {
            let sums = halves_sums(low, high);
            self.low = _mm512_ternarylogic_epi64::<0x96>(
                self.low,
                _mm512_clmulepi64_epi128::<0x00>(low, low_key),
                _mm512_clmulepi64_epi128::<0x00>(high, high_key),
            );
            self.high = _mm512_ternarylogic_epi64::<0x96>(
                self.high,
                _mm512_clmulepi64_epi128::<0x11>(low, low_key),
                _mm512_clmulepi64_epi128::<0x11>(high, high_key),
            );
            self.middle = _mm512_ternarylogic_epi64::<0x96>(
                self.middle,
                _mm512_clmulepi64_epi128::<0x00>(sums, key_sums),
                _mm512_clmulepi64_epi128::<0x11>(sums, key_sums),
            );
        }

        /// Adds each lane's product of `block` with `key`, three carry-less multiplications.
        #[inline]
        #[target_feature(enable = "avx512f,vpclmulqdq")]
        fn add_one(&mut self, block: __m512i, key: __m512i) {
            let sums =
                |value: __m512i| _mm512_xor_si512(value, _mm512_shuffle_epi32::<0x4E>(value));
            self.low = _mm512_xor_si512(self.low, _mm512_clmulepi64_epi128::<0x00>(block, key));
            self.high = _mm512_xor_si512(self.high, _mm512_clmulepi64_epi128::<0x11>(block, key));
            self.middle = _mm512_xor_si512(
                self.middle,
                _mm512_clmulepi64_epi128::<0x00>(sums(block), sums(key)),
            );
        }

        /// The next accumulator in lane 0, the other lanes zero: POLYVAL's reduction of each lane's sum, the four results added together.
        #[inline]
        #[target_feature(enable = "avx512f,avx512bw,vpclmulqdq")]
        fn sum(self) -> __m512i {
            let middle = _mm512_ternarylogic_epi64::<0x96>(self.middle, self.low, self.high);
            let low = _mm512_xor_si512(self.low, _mm512_bslli_epi128::<8>(middle));
            let high = _mm512_xor_si512(self.high, _mm512_bsrli_epi128::<8>(middle));
            _mm512_zextsi128_si512(lanes(reduce(low, high)))
        }
    }

    /// The sum of the four 128-bit lanes of `value`.
    #[inline]
    #[target_feature(enable = "avx512f")]
    fn lanes(value: __m512i) -> __m128i {
        let half = _mm256_xor_si256(
            _mm512_castsi512_si256(value),
            _mm512_extracti64x4_epi64::<1>(value),
        );
        _mm_xor_si128(
            _mm256_castsi256_si128(half),
            _mm256_extracti128_si256::<1>(half),
        )
    }

    /// POLYVAL's product of each 128-bit lane of `a` and `b`: their carry-less product times x^-128, modulo the field polynomial.
    #[inline]
    #[target_feature(enable = "avx512f,avx512bw,vpclmulqdq")]
    fn product(a: __m512i, b: __m512i) -> __m512i {
        let middle = _mm512_xor_si512(
            _mm512_clmulepi64_epi128::<0x01>(a, b),
            _mm512_clmulepi64_epi128::<0x10>(a, b),
        );
        let low = _mm512_xor_si512(
            _mm512_clmulepi64_epi128::<0x00>(a, b),
            _mm512_bslli_epi128::<8>(middle),
        );
        let high = _mm512_xor_si512(
            _mm512_clmulepi64_epi128::<0x11>(a, b),
            _mm512_bsrli_epi128::<8>(middle),
        );
        reduce(low, high)
    }

    /// In each 128-bit lane, `high` times x^128 plus `low`, times x^-128 modulo x^128 + x^127 + x^126 + x^121 + 1.
    ///
    /// Modulo that polynomial, x^-64 equals x^64 + x^63 + x^62 + x^57, so each of two folds multiplies `low` by x^-64: it swaps the 64-bit halves and adds the low half's carry-less product with x^63 + x^62 + x^57.
    #[inline]
    #[target_feature(enable = "avx512f,avx512bw,vpclmulqdq")]
    fn reduce(low: __m512i, high: __m512i) -> __m512i {
        const FOLD: i64 = 0xC200_0000_0000_0000_u64 as i64;
        let constant = _mm512_set_epi64(FOLD, 0, FOLD, 0, FOLD, 0, FOLD, 0);
        let mut low = low;
        for _ in 0..2 {
            let carried = _mm512_clmulepi64_epi128::<0x10>(low, constant);
            low = _mm512_xor_si512(_mm512_shuffle_epi32::<0x4E>(low), carried);
        }
        _mm512_xor_si512(low, high)
    }
}
