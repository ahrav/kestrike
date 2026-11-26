//! SHA-256 compression of several independent chains in one pass, for the tag chains of frames tagged or authenticated together: PUT DATA groups and frame pairs. [`lone`] compresses one chain by itself, through the one-chain kernel of `sha_one` on a CPU that has it: the chain of a frame tagged or authenticated alone, a chain left by itself in a group, the chain of a session's data key, and a chain's first block when its key holds no memo of it.
//!
//! Each chain independently applies FIPS 180-4 compression to its blocks in order, matching `sha2::block_api::compress256`. Each four-round step of a chain consumes the state its previous step produced, so a lone chain waits on every step's result, and interleaving independent chains overlaps those waits. Over runs of 128 blocks per chain, a Graviton4 core (Neoverse V2) compresses one chain through `compress256` at 1.5 GB/s and two, three and four interleaved chains at 3.1, 3.4 and 3.5 GB/s together. With 128 blocks per chain, a Graviton3 core (Neoverse V1) compresses one chain through `compress256` at 1.4 GB/s and two, three and four interleaved chains at 2.9, 3.1 and 3.0 GB/s together. Instantiated at eight chains, the generic aarch64 kernel compresses 3.1 GB/s on Graviton4 and 2.8 GB/s on Graviton3, below its four-chain rate.
//!
//! A compile-time constant SHA-256 block determines all 64 message schedule words, so chains that compress the same block can share its schedule. `FixedBlock` holds those words with the round constants added. On an aarch64 CPU with `sha2`, `Lanes::tail` ends two to four HMAC chains in one kernel pass: each chain's middle blocks, then the fixed last block of its inner hash as sixteen `sha256h` and `sha256h2` pairs over the held words, then its outer block, whose first eight schedule words the pass takes from the state registers.
//!
//! With the x86_64 SHA extensions and chains of four blocks, an AMD EPYC 9R14 core compresses two chains in one pass in 1.2 times the time of one chain through `compress256`, and four chains in 2.3 times, against 2.0 and 4.0 times for separate `compress256` calls. Over runs of 128 blocks per chain, a Xeon Platinum 8488C core (Sapphire Rapids) compresses one chain through `compress256` at 1.6 GB/s and two, three or four interleaved chains at 1.9 GB/s together.

use sha2::block_api::compress256;

pub(super) const BLOCK_LEN: usize = 64;

pub(super) const LANES: usize = 4;
const _: () = assert!(LANES == 4, "Lanes holds kernels for two to four chains");

pub(super) type Block = [u8; BLOCK_LEN];

pub(super) type State = [u32; 8];

#[derive(Clone, Copy)]
pub(super) struct Lanes {
    two: fn(&mut [State; 2], [&[Block]; 2]),
    three: fn(&mut [State; 3], [&[Block]; 3]),
    four: fn(&mut [State; 4], [&[Block]; 4]),
    /// The CPU has the aarch64 `sha2` instructions, so [`tail`](Self::tail) runs two to four chains in one kernel pass.
    #[cfg(target_arch = "aarch64")]
    fused: bool,
}

/// The end of `G` HMAC chains whose inner hashes all end on one fixed block. Chain `g` compresses the run `middle[g]` and then `last` from its state, which ends its inner hash, and then compresses the block holding that digest and `pad` from `outer[g]`, the state after its key's outer pad block. The runs of `middle` are equally long.
#[cfg(target_arch = "aarch64")]
pub(super) struct Tail<'a, const G: usize> {
    pub(super) middle: [&'a [Block]; G],
    pub(super) last: &'a FixedBlock,
    pub(super) outer: [&'a State; G],
    /// The second half of every chain's outer block: the padding of a message of one block and a 32-byte digest.
    pub(super) pad: &'a [u8; BLOCK_LEN / 2],
}

/// A block whose bytes are known at compile time, with its 64 round words: the message schedule of FIPS 180-4 section 6.2.2 with each round's constant added, four words to each of the sixteen steps. The words are a function of the block's bytes alone, so a kernel that compresses from them, with the round instructions and no schedule instruction, leaves the state that compressing the block leaves.
#[cfg(target_arch = "aarch64")]
pub(super) struct FixedBlock {
    steps: [[u32; 4]; 16],
}

#[cfg(target_arch = "aarch64")]
impl FixedBlock {
    pub(super) const fn new(block: Block) -> Self {
        Self {
            steps: round_words(&block),
        }
    }
}

/// `W[t] + K[t]` for the 64 rounds of `block`, four rounds to a step: the block's sixteen big-endian words, extended by the schedule recurrence, each with its round constant added modulo 2^32.
#[cfg(target_arch = "aarch64")]
pub(super) const fn round_words(block: &Block) -> [[u32; 4]; 16] {
    let mut words = [0u32; 64];
    let mut t = 0;
    while t < 16 {
        words[t] = u32::from_be_bytes([
            block[4 * t],
            block[4 * t + 1],
            block[4 * t + 2],
            block[4 * t + 3],
        ]);
        t += 1;
    }
    while t < 64 {
        let (near, far) = (words[t - 2], words[t - 15]);
        let small1 = near.rotate_right(17) ^ near.rotate_right(19) ^ (near >> 10);
        let small0 = far.rotate_right(7) ^ far.rotate_right(18) ^ (far >> 3);
        words[t] = words[t - 16]
            .wrapping_add(small0)
            .wrapping_add(words[t - 7])
            .wrapping_add(small1);
        t += 1;
    }
    let mut steps = [[0u32; 4]; 16];
    t = 0;
    while t < 64 {
        steps[t / 4][t % 4] = words[t].wrapping_add(K[t]);
        t += 1;
    }
    steps
}

impl Lanes {
    /// The compressions this CPU runs: the aarch64 `sha2` instructions, the x86_64 SHA extensions with `ssse3` and `sse4.1`, or [`Lanes::portable`] on every other CPU.
    pub(super) fn detect() -> Self {
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("sha2") {
            return Self {
                two: two_sha2,
                three: three_sha2,
                four: four_sha2,
                fused: true,
            };
        }
        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("sha")
            && std::arch::is_x86_feature_detected!("ssse3")
            && std::arch::is_x86_feature_detected!("sse4.1")
        {
            return Self {
                two: two_sha,
                three: three_sha,
                four: four_sha,
            };
        }
        Self::portable()
    }

    pub(super) fn portable() -> Self {
        Self {
            two: portable::<2>,
            three: portable::<3>,
            four: portable::<4>,
            #[cfg(target_arch = "aarch64")]
            fused: false,
        }
    }

    /// Compresses `blocks[i]` into `states[i]` for two chains in one interleaved pass; the two block runs are equally long.
    #[inline]
    pub(super) fn pair(self, states: &mut [State; 2], blocks: [&[Block]; 2]) {
        assert_eq!(blocks[0].len(), blocks[1].len(), "chains of unequal length");
        (self.two)(states, blocks);
    }

    /// Compresses `blocks[i]` into `states[i]` for three chains in one interleaved pass; the three block runs are equally long.
    #[inline]
    pub(super) fn triple(self, states: &mut [State; 3], blocks: [&[Block]; 3]) {
        assert!(
            blocks.iter().all(|run| run.len() == blocks[0].len()),
            "chains of unequal length"
        );
        (self.three)(states, blocks);
    }

    /// Compresses `blocks[i]` into `states[i]` for four chains in one interleaved pass; the four block runs are equally long.
    #[inline]
    pub(super) fn quad(self, states: &mut [State; 4], blocks: [&[Block]; 4]) {
        assert!(
            blocks.iter().all(|run| run.len() == blocks[0].len()),
            "chains of unequal length"
        );
        (self.four)(states, blocks);
    }

    /// Ends the `G` HMAC chains of `tail` in one kernel pass where the CPU has the aarch64 `sha2` instructions and `G` is two to four, and returns whether it did. `states[g]` enters as chain `g`'s inner state before its middle blocks and leaves as its outer digest state. The pass compresses each chain's middle blocks, the fixed block from its round words, then the outer block, whose first eight schedule words it takes from the state registers. A call that returns false changes nothing.
    ///
    /// # Panics
    ///
    /// Before any kernel step, when the pass would run and the runs of `tail.middle` differ in length.
    #[cfg(target_arch = "aarch64")]
    #[inline]
    pub(super) fn tail<const G: usize>(self, states: &mut [State; G], tail: &Tail<'_, G>) -> bool {
        if !self.fused || !(2..=LANES).contains(&G) {
            return false;
        }
        assert!(
            tail.middle
                .iter()
                .all(|run| run.len() == tail.middle[0].len()),
            "chains of unequal length"
        );
        // SAFETY: `Lanes::detect` sets `fused` only after `is_aarch64_feature_detected!("sha2")` returned true, and the field is private, so the CPU implements every instruction `tail_rounds` uses.
        unsafe { tail_rounds(states, tail) };
        true
    }
}

/// Compresses one chain with the result `compress256` gives: through `sha_one::compress` on a little-endian aarch64 CPU with the `sha2` and `sha3` instructions, and through `compress256` on every other CPU and under Miri. It stays out of line, so its callers share one copy of the detection and of the two calls.
#[inline(never)]
pub(super) fn lone(state: &mut State, blocks: &[Block]) {
    #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
    if super::sha_one::detected() {
        // SAFETY: the detection reported every CPU feature `sha_one::compress` enables.
        unsafe { super::sha_one::compress(state, blocks) };
        return;
    }
    compress256(state, blocks);
}

fn portable<const G: usize>(states: &mut [State; G], blocks: [&[Block]; G]) {
    for at in 0..blocks[0].len() {
        for (state, stream) in states.iter_mut().zip(blocks) {
            compress256(state, std::slice::from_ref(&stream[at]));
        }
    }
}

#[cfg(target_arch = "aarch64")]
fn two_sha2(states: &mut [State; 2], blocks: [&[Block]; 2]) {
    // SAFETY: `Lanes::detect` installs this function only after `is_aarch64_feature_detected!("sha2")` returned true, and the fields are private, so the CPU implements every instruction `rounds` uses.
    unsafe { rounds(states, blocks) }
}

#[cfg(target_arch = "aarch64")]
fn three_sha2(states: &mut [State; 3], blocks: [&[Block]; 3]) {
    // SAFETY: as for `two_sha2`, which `Lanes::detect` installs alongside this function.
    unsafe { rounds(states, blocks) }
}

#[cfg(target_arch = "aarch64")]
fn four_sha2(states: &mut [State; 4], blocks: [&[Block]; 4]) {
    // SAFETY: as for `two_sha2`, which `Lanes::detect` installs alongside this function.
    unsafe { rounds(states, blocks) }
}

#[cfg(target_arch = "x86_64")]
fn two_sha(states: &mut [State; 2], blocks: [&[Block]; 2]) {
    // SAFETY: `Lanes::detect` installs this function only after `is_x86_feature_detected!` reported `sha`, `ssse3` and `sse4.1`, and the fields are private, so the CPU implements every instruction `x86_rounds` uses.
    unsafe { x86_rounds(states, blocks) }
}

#[cfg(target_arch = "x86_64")]
fn three_sha(states: &mut [State; 3], blocks: [&[Block]; 3]) {
    // SAFETY: as for `two_sha`, which `Lanes::detect` installs alongside this function.
    unsafe { x86_rounds(states, blocks) }
}

#[cfg(target_arch = "x86_64")]
fn four_sha(states: &mut [State; 4], blocks: [&[Block]; 4]) {
    // SAFETY: as for `two_sha`, which `Lanes::detect` installs alongside this function.
    unsafe { x86_rounds(states, blocks) }
}

/// FIPS 180-4 SHA-256 round constants (section 4.2.2), shared with the one-chain kernel of `sha_one` and the sixteen-lane pass of `auth`.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub(super) const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn next_blocks<'b, const G: usize>(
    streams: &mut [std::slice::Iter<'b, Block>; G],
) -> Option<[&'b Block; G]> {
    let mut current = [&[0; BLOCK_LEN]; G];
    for (slot, stream) in current.iter_mut().zip(streams) {
        *slot = stream.next()?;
    }
    Some(current)
}

/// One block of every chain of a kernel for `G` chains: the sixty-four rounds over `$schedule`, each chain's sixteen message words as four quadruples, from the states in `$abcd` and `$efgh`, then the addition of the states before the block. Three and four chains take the steps [`rounds`] describes for them, and every other count the two-chain form. Each kernel expands the block in place, so it compiles the rounds within its own `sha2` target feature and register allocation.
#[cfg(target_arch = "aarch64")]
macro_rules! block_rounds {
    ($abcd:ident, $efgh:ident, $schedule:ident, $quad:ident) => {
        let (start_abcd, start_efgh) = ($abcd, $efgh);
        // For three or four chains: whether the step before `step` adds the `sigma0` terms of `step`'s quadruple with shifts and exclusive-ors. That holds for the even steps among 4 to 15, the steps that update the schedule. For the odd ones the step before adds the terms with `sha256su0`.
        let shifted = |step: usize| (4..16).contains(&step) && step.is_multiple_of(2);
        if G == 3 || G == 4 {
            // Step `4 * round + q` of the block, expanded for each literal `q` so that every quadruple an expansion names is one register. Quadruple `q` holds the words the step's rounds consume, and quadruple `(q + 1) % 4` those of the next step.
            macro_rules! step {
                ($round:expr, $q:literal) => {{
                    let q: usize = $q;
                    let step: usize = 4 * $round + q;
                    let k = $quad(&K[4 * step..]);
                    if (4..16).contains(&(step + 1)) && !shifted(step + 1) {
                        for w in &mut $schedule {
                            // SAFETY: the block reads and writes only the vector registers it names, and this function's `sha2` feature covers `sha256su0`.
                            unsafe {
                                std::arch::asm!(
                                    "sha256su0 {w1:v}.4s, {w2:v}.4s",
                                    w1 = inout(vreg) w[(q + 1) % 4],
                                    w2 = in(vreg) w[(q + 2) % 4],
                                    options(nomem, nostack, preserves_flags),
                                );
                            }
                        }
                    }
                    if step >= 4 {
                        for w in &mut $schedule {
                            // The step before added the `sigma0` terms to `w[q]`.
                            // SAFETY: the block reads and writes only the vector registers it names, and this function's `sha2` feature covers `sha256su1`.
                            unsafe {
                                std::arch::asm!(
                                    "sha256su1 {w0:v}.4s, {w2:v}.4s, {w3:v}.4s",
                                    w0 = inout(vreg) w[q],
                                    w2 = in(vreg) w[(q + 2) % 4],
                                    w3 = in(vreg) w[(q + 3) % 4],
                                    options(nomem, nostack, preserves_flags),
                                );
                            }
                        }
                    }
                    for g in 0..G {
                        let w = &mut $schedule[g];
                        // `sha256h` and `sha256h2` each overwrite the state half they update and read the other half as it was before the step, so one half needs a copy. The copy of ABCD goes to `sha256h2`: `sha256h` then updates ABCD in place, and the register move lies between ABCD and the next EFGH, off the ABCD-to-ABCD chain that every step of the block waits on.
                        if shifted(step + 1) {
                            // `x` holds the word after each word of `w1`: the last three words of `w1`, then the first of `w2`. `r7` and `r18` hold `x` rotated right by 7 and by 18 bits, `ushr` leaves `x` shifted right by 3, and the two `eor` and the last `add` add `sigma0` of those words to `w1`, as `sha256su0` does.
                            // SAFETY: the block reads and writes only the vector registers it names, this function's `sha2` feature covers `sha256h` and `sha256h2`, and the other instructions are NEON, which the `sha2` feature implies.
                            unsafe {
                                std::arch::asm!(
                                    "ext {x:v}.16b, {w1:v}.16b, {w2:v}.16b, #4",
                                    "shl {r7:v}.4s, {x:v}.4s, #25",
                                    "sri {r7:v}.4s, {x:v}.4s, #7",
                                    "add {wk:v}.4s, {w0:v}.4s, {k:v}.4s",
                                    "mov {prev:v}.16b, {abcd:v}.16b",
                                    "sha256h {abcd:q}, {efgh:q}, {wk:v}.4s",
                                    "shl {r18:v}.4s, {x:v}.4s, #14",
                                    "sri {r18:v}.4s, {x:v}.4s, #18",
                                    "ushr {x:v}.4s, {x:v}.4s, #3",
                                    "sha256h2 {efgh:q}, {prev:q}, {wk:v}.4s",
                                    "eor {r7:v}.16b, {r7:v}.16b, {r18:v}.16b",
                                    "eor {x:v}.16b, {x:v}.16b, {r7:v}.16b",
                                    "add {w1:v}.4s, {w1:v}.4s, {x:v}.4s",
                                    w0 = in(vreg) w[q],
                                    w1 = inout(vreg) w[(q + 1) % 4],
                                    w2 = in(vreg) w[(q + 2) % 4],
                                    k = in(vreg) k,
                                    abcd = inout(vreg) $abcd[g],
                                    efgh = inout(vreg) $efgh[g],
                                    prev = out(vreg) _,
                                    wk = out(vreg) _,
                                    x = out(vreg) _,
                                    r7 = out(vreg) _,
                                    r18 = out(vreg) _,
                                    options(nomem, nostack, preserves_flags),
                                );
                            }
                        } else {
                            // SAFETY: the block reads and writes only the vector registers it names, this function's `sha2` feature covers `sha256h` and `sha256h2`, and `add` and `mov` are NEON, which the `sha2` feature implies.
                            unsafe {
                                std::arch::asm!(
                                    "add {wk:v}.4s, {w0:v}.4s, {k:v}.4s",
                                    "mov {prev:v}.16b, {abcd:v}.16b",
                                    "sha256h {abcd:q}, {efgh:q}, {wk:v}.4s",
                                    "sha256h2 {efgh:q}, {prev:q}, {wk:v}.4s",
                                    w0 = in(vreg) w[q],
                                    k = in(vreg) k,
                                    abcd = inout(vreg) $abcd[g],
                                    efgh = inout(vreg) $efgh[g],
                                    prev = out(vreg) _,
                                    wk = out(vreg) _,
                                    options(nomem, nostack, preserves_flags),
                                );
                            }
                        }
                    }
                }};
            }
            for round in 0..4 {
                step!(round, 0);
                step!(round, 1);
                step!(round, 2);
                step!(round, 3);
            }
        } else {
            for round in 0..4 {
                for q in 0..4 {
                    let k = $quad(&K[16 * round + 4 * q..]);
                    for w in &mut $schedule {
                        if round > 0 {
                            w[q] = vsha256su1q_u32(
                                vsha256su0q_u32(w[q], w[(q + 1) % 4]),
                                w[(q + 2) % 4],
                                w[(q + 3) % 4],
                            );
                        }
                    }
                    for g in 0..G {
                        let wk = vaddq_u32($schedule[g][q], k);
                        // `sha256h` and `sha256h2` each overwrite the state half they update and read the other half as it was before the step, so one half needs a copy. The copy of ABCD goes to `sha256h2`: `sha256h` then updates ABCD in place, and the register move lies between ABCD and the next EFGH, off the ABCD-to-ABCD chain that every step of the block waits on.
                        // SAFETY: the instructions read and write only the named registers, and this function's `sha2` feature covers `sha256h` and `sha256h2`.
                        unsafe {
                            std::arch::asm!(
                                "mov {prev:v}.16b, {abcd:v}.16b",
                                "sha256h {abcd:q}, {efgh:q}, {wk:v}.4s",
                                "sha256h2 {efgh:q}, {prev:q}, {wk:v}.4s",
                                abcd = inout(vreg) $abcd[g],
                                efgh = inout(vreg) $efgh[g],
                                wk = in(vreg) wk,
                                prev = out(vreg) _,
                                options(pure, nomem, nostack, preserves_flags),
                            );
                        }
                    }
                }
            }
        }
        for g in 0..G {
            $abcd[g] = vaddq_u32($abcd[g], start_abcd[g]);
            $efgh[g] = vaddq_u32($efgh[g], start_efgh[g]);
        }
    };
}

/// Compresses `blocks[i]` into `states[i]` for `G` chains with the `sha2` instructions: each chain keeps its state and its four schedule quadruples in registers, and each four-round step of a block is issued for every chain before the next step.
///
/// A Neoverse V2 core runs every SHA-256 instruction on one vector port. With three or four chains that port sets the time, so their steps spend fewer SHA-256 instructions: steps 3 to 14 each add the `sigma0` terms of the next step's schedule quadruple (FIPS 180-4, sections 4.1.2 and 6.2.2), and steps 4 to 15 each update the schedule with one `sha256su1`. Odd steps add the terms with shifts and exclusive-ors, which other vector ports run. Even steps add them with `sha256su0`. A block takes 50 SHA-256 instructions per chain: 32 for the rounds, 12 `sha256su1` and 6 `sha256su0`. Each `asm!` block of these steps counts as having side effects, so the compiler keeps the blocks in the order written: at even steps 4 to 14 every chain's `sha256su0` for the next step, from step 4 every chain's `sha256su1`, then each chain's round instructions, at odd steps 3 to 13 with the `sigma0` arithmetic before, between and after the two SHA-256 instructions.
///
/// With two chains the time is set by each chain's own steps, each of which waits for the step before it, and a caller that waits for one digest before it starts the next waits on that sequence alone. Two chains run `sha256su0` and `sha256su1` at each of steps 4 to 15, 56 SHA-256 instructions per chain and block, in the order the compiler chooses. Over runs of 128 blocks per chain a Neoverse V1 core compresses two chains at 2.9 GB/s in that form and at 2.8 GB/s with the steps of three and four chains, which take 2.5 to 2.6 percent longer there and 2.8 percent longer over single blocks. Every chain count other than three and four takes the two-chain form.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "sha2")]
fn rounds<const G: usize>(states: &mut [State; G], blocks: [&[Block]; G]) {
    use std::arch::aarch64::{
        uint32x4_t, vaddq_u32, vld1q_u8, vld1q_u32, vreinterpretq_u32_u8, vrev32q_u8,
        vsha256su0q_u32, vsha256su1q_u32, vst1q_u32,
    };
    let quad = |words: &[u32]| -> uint32x4_t {
        assert!(words.len() >= 4);
        // SAFETY: the assertion leaves four readable words, and `vld1q_u32` has no alignment requirement.
        unsafe { vld1q_u32(words.as_ptr()) }
    };
    let mut abcd: [uint32x4_t; G] = std::array::from_fn(|g| quad(&states[g][..4]));
    let mut efgh: [uint32x4_t; G] = std::array::from_fn(|g| quad(&states[g][4..]));
    let mut streams = blocks.map(<[Block]>::iter);
    while let Some(current) = next_blocks(&mut streams) {
        block_step_ran::<G>();
        let mut schedule: [[uint32x4_t; 4]; G] = std::array::from_fn(|g| {
            let block = current[g];
            std::array::from_fn(|q| {
                // SAFETY: `block` holds 64 readable bytes, so the 16 at `16 * q` for `q < 4` are in bounds, and `vld1q_u8` has no alignment requirement.
                let bytes = unsafe { vld1q_u8(block.as_ptr().add(16 * q)) };
                vreinterpretq_u32_u8(vrev32q_u8(bytes))
            })
        });
        block_rounds!(abcd, efgh, schedule, quad);
    }
    for (g, state) in states.iter_mut().enumerate() {
        let (low, high) = state.split_at_mut(4);
        // SAFETY: each half holds four writable words, and `vst1q_u32` has no alignment requirement.
        unsafe {
            vst1q_u32(low.as_mut_ptr(), abcd[g]);
            vst1q_u32(high.as_mut_ptr(), efgh[g]);
        }
    }
}

/// Ends the `G` HMAC chains of `tail` in one pass. The source issues each block step for every chain before the next step; three and four chains keep that order, since their `asm!` blocks count as having side effects, and the compiler orders the two-chain form's schedule and round steps. In every form chain `g` compresses its middle blocks from `states[g]`, then the fixed block from its round words with the round instructions alone, which ends its inner hash, then the outer block from `tail.outer[g]`. The inner digest's big-endian bytes are the outer block's first eight message words, so its two state quadruples go from the registers to the outer block's schedule, and the pad's two quadruples follow them. `states[g]` receives the outer digest state.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "sha2")]
fn tail_rounds<const G: usize>(states: &mut [State; G], tail: &Tail<'_, G>) {
    use std::arch::aarch64::{
        uint32x4_t, vaddq_u32, vld1q_u8, vld1q_u32, vreinterpretq_u32_u8, vrev32q_u8,
        vsha256su0q_u32, vsha256su1q_u32, vst1q_u32,
    };
    let quad = |words: &[u32]| -> uint32x4_t {
        assert!(words.len() >= 4);
        // SAFETY: the assertion leaves four readable words, and `vld1q_u32` has no alignment requirement.
        unsafe { vld1q_u32(words.as_ptr()) }
    };
    let big_endian = |bytes: &[u8; 16]| -> uint32x4_t {
        // SAFETY: `bytes` holds 16 readable bytes, and `vld1q_u8` has no alignment requirement.
        vreinterpretq_u32_u8(vrev32q_u8(unsafe { vld1q_u8(bytes.as_ptr()) }))
    };
    #[cfg(test)]
    crate::isa_witness::ran(crate::isa_witness::Kernel::Sha2Tail);
    let (pad, _) = tail.pad.as_chunks::<16>();
    let pad = [big_endian(&pad[0]), big_endian(&pad[1])];
    let mut abcd: [uint32x4_t; G] = std::array::from_fn(|g| quad(&states[g][..4]));
    let mut efgh: [uint32x4_t; G] = std::array::from_fn(|g| quad(&states[g][4..]));
    let mut streams = tail.middle.map(<[Block]>::iter);
    let mut inner = true;
    // Each turn compresses one block of every chain: the middle blocks in order, then the outer block, whose turn first compresses the fixed block. One loop body serves both, so the kernel holds one expansion of `block_rounds`.
    while inner {
        let mut schedule: [[uint32x4_t; 4]; G] = if let Some(current) = next_blocks(&mut streams) {
            std::array::from_fn(|g| {
                let (quads, _) = current[g].as_chunks::<16>();
                std::array::from_fn(|q| big_endian(&quads[q]))
            })
        } else {
            block_step_ran::<G>();
            let (start_abcd, start_efgh) = (abcd, efgh);
            for words in &tail.last.steps {
                let wk = quad(words);
                for g in 0..G {
                    // The copy of ABCD goes to `sha256h2`, as in the steps of `block_rounds`. The block counts as having side effects, so the chains' instructions stay in the order written.
                    // SAFETY: the block reads and writes only the vector registers it names, this function's `sha2` feature covers `sha256h` and `sha256h2`, and `mov` is NEON, which the `sha2` feature implies.
                    unsafe {
                        std::arch::asm!(
                            "mov {prev:v}.16b, {abcd:v}.16b",
                            "sha256h {abcd:q}, {efgh:q}, {wk:v}.4s",
                            "sha256h2 {efgh:q}, {prev:q}, {wk:v}.4s",
                            abcd = inout(vreg) abcd[g],
                            efgh = inout(vreg) efgh[g],
                            wk = in(vreg) wk,
                            prev = out(vreg) _,
                            options(nomem, nostack, preserves_flags),
                        );
                    }
                }
            }
            let digest = std::array::from_fn(|g| {
                [
                    vaddq_u32(abcd[g], start_abcd[g]),
                    vaddq_u32(efgh[g], start_efgh[g]),
                    pad[0],
                    pad[1],
                ]
            });
            abcd = std::array::from_fn(|g| quad(&tail.outer[g][..4]));
            efgh = std::array::from_fn(|g| quad(&tail.outer[g][4..]));
            inner = false;
            digest
        };
        block_step_ran::<G>();
        block_rounds!(abcd, efgh, schedule, quad);
    }
    for (g, state) in states.iter_mut().enumerate() {
        let (low, high) = state.split_at_mut(4);
        // SAFETY: each half holds four writable words, and `vst1q_u32` has no alignment requirement.
        unsafe {
            vst1q_u32(low.as_mut_ptr(), abcd[g]);
            vst1q_u32(high.as_mut_ptr(), efgh[g]);
        }
    }
}

/// Counts one block step of `G` chains for the architecture qualification tests.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn block_step_ran<const G: usize>() {
    #[cfg(test)]
    crate::isa_witness::ran(match G {
        2 => crate::isa_witness::Kernel::Sha2Two,
        3 => crate::isa_witness::Kernel::Sha2Three,
        4 => crate::isa_witness::Kernel::Sha2Four,
        _ => unreachable!("Lanes holds kernels for two to four chains"),
    });
}

/// Compresses `blocks[i]` into `states[i]` for `G` chains with the SHA extensions: each chain keeps its state as the ABEF and CDGH word quadruples `sha256rnds2` takes, and each four-round step of a block issues that step for every chain before the next step.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sha,ssse3,sse4.1")]
fn x86_rounds<const G: usize>(states: &mut [State; G], blocks: [&[Block]; G]) {
    use std::arch::x86_64::{
        __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_blend_epi16, _mm_loadu_si128, _mm_set_epi64x,
        _mm_setzero_si128, _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32,
        _mm_shuffle_epi8, _mm_shuffle_epi32, _mm_storeu_si128,
    };
    let quad = |words: &[u32]| -> __m128i {
        assert!(words.len() >= 4);
        // SAFETY: the assertion leaves four readable words, and `_mm_loadu_si128` has no alignment requirement.
        unsafe { _mm_loadu_si128(words.as_ptr().cast()) }
    };
    // Reverses the bytes of each 32-bit word: the message words are big-endian.
    let big_endian = _mm_set_epi64x(0x0c0d_0e0f_0809_0a0b, 0x0405_0607_0001_0203);
    let mut abef = [_mm_setzero_si128(); G];
    let mut cdgh = [_mm_setzero_si128(); G];
    for g in 0..G {
        let cdab = _mm_shuffle_epi32::<0xB1>(quad(&states[g][..4]));
        let efgh = _mm_shuffle_epi32::<0x1B>(quad(&states[g][4..]));
        abef[g] = _mm_alignr_epi8::<8>(cdab, efgh);
        cdgh[g] = _mm_blend_epi16::<0xF0>(efgh, cdab);
    }
    let mut streams = blocks.map(<[Block]>::iter);
    while let Some(current) = next_blocks(&mut streams) {
        let (start_abef, start_cdgh) = (abef, cdgh);
        let mut schedule: [[__m128i; 4]; G] = std::array::from_fn(|g| {
            let block = current[g];
            std::array::from_fn(|q| {
                // SAFETY: `block` holds 64 readable bytes, so the 16 at `16 * q` for `q < 4` are in bounds, and `_mm_loadu_si128` has no alignment requirement.
                let bytes = unsafe { _mm_loadu_si128(block.as_ptr().add(16 * q).cast()) };
                _mm_shuffle_epi8(bytes, big_endian)
            })
        });
        // Step `t` runs rounds 4t to 4t + 3; from step 4 on, its four message words replace those of step t - 4 in the schedule. Each step takes its index as a literal, so every schedule index is a constant and the schedule stays in registers.
        macro_rules! step {
            ($t:literal) => {
                if $t >= 4 {
                    for w in &mut schedule {
                        let sum = _mm_add_epi32(
                            _mm_sha256msg1_epu32(w[$t % 4], w[($t + 1) % 4]),
                            _mm_alignr_epi8::<4>(w[($t + 3) % 4], w[($t + 2) % 4]),
                        );
                        w[$t % 4] = _mm_sha256msg2_epu32(sum, w[($t + 3) % 4]);
                    }
                }
                let k = quad(&K[4 * $t..]);
                for g in 0..G {
                    let wk = _mm_add_epi32(schedule[g][$t % 4], k);
                    cdgh[g] = _mm_sha256rnds2_epu32(cdgh[g], abef[g], wk);
                    abef[g] =
                        _mm_sha256rnds2_epu32(abef[g], cdgh[g], _mm_shuffle_epi32::<0x0E>(wk));
                }
            };
        }
        step!(0);
        step!(1);
        step!(2);
        step!(3);
        step!(4);
        step!(5);
        step!(6);
        step!(7);
        step!(8);
        step!(9);
        step!(10);
        step!(11);
        step!(12);
        step!(13);
        step!(14);
        step!(15);
        for g in 0..G {
            abef[g] = _mm_add_epi32(abef[g], start_abef[g]);
            cdgh[g] = _mm_add_epi32(cdgh[g], start_cdgh[g]);
        }
    }
    for (g, state) in states.iter_mut().enumerate() {
        let feba = _mm_shuffle_epi32::<0x1B>(abef[g]);
        let dchg = _mm_shuffle_epi32::<0xB1>(cdgh[g]);
        let (low, high) = state.split_at_mut(4);
        // SAFETY: each half holds four writable words, and `_mm_storeu_si128` has no alignment requirement.
        unsafe {
            _mm_storeu_si128(low.as_mut_ptr().cast(), _mm_blend_epi16::<0xF0>(feba, dchg));
            _mm_storeu_si128(high.as_mut_ptr().cast(), _mm_alignr_epi8::<8>(dchg, feba));
        }
    }
}
