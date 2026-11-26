use sha2::block_api::compress256;

use crate::storage::seeded::SplitMix64;

#[cfg(target_arch = "aarch64")]
use super::sha_lanes::K;
use super::sha_lanes::{BLOCK_LEN, Block, Lanes, State, lone};

fn states(rng: &mut SplitMix64) -> State {
    std::array::from_fn(|_| rng.next_u64() as u32)
}

fn blocks(rng: &mut SplitMix64, count: usize) -> Vec<Block> {
    (0..count)
        .map(|_| std::array::from_fn(|_| rng.next_u64() as u8))
        .collect()
}

fn expected(mut state: State, blocks: &[Block]) -> State {
    compress256(&mut state, blocks);
    state
}

#[test]
fn every_chain_matches_compression_alone() {
    let mut rng = SplitMix64::new(0x5A11);
    for lanes in [Lanes::detect(), Lanes::portable()] {
        for count in [0, 1, 2, 3, 7, 129] {
            let streams: [Vec<Block>; 4] = std::array::from_fn(|_| blocks(&mut rng, count));
            let start: [State; 4] = std::array::from_fn(|_| states(&mut rng));
            let mut pair = [start[0], start[1]];
            lanes.pair(&mut pair, [&streams[0], &streams[1]]);
            assert_eq!(
                pair,
                [
                    expected(start[0], &streams[0]),
                    expected(start[1], &streams[1])
                ],
                "{count} blocks in two chains"
            );
            let mut triple = [start[0], start[1], start[2]];
            lanes.triple(&mut triple, [&streams[0], &streams[1], &streams[2]]);
            assert_eq!(
                triple,
                [
                    expected(start[0], &streams[0]),
                    expected(start[1], &streams[1]),
                    expected(start[2], &streams[2])
                ],
                "{count} blocks in three chains"
            );
            let mut quad = start;
            lanes.quad(
                &mut quad,
                [&streams[0], &streams[1], &streams[2], &streams[3]],
            );
            assert_eq!(
                quad,
                std::array::from_fn(|at| expected(start[at], &streams[at])),
                "{count} blocks in four chains"
            );
        }
    }
}

#[test]
fn equal_starts_over_equal_blocks_stay_equal_and_match_the_digest_of_a_block() {
    use sha2::{Digest, Sha256};
    let iv = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let mut message = [0u8; BLOCK_LEN];
    message[..3].copy_from_slice(b"abc");
    message[3] = 0x80;
    message[BLOCK_LEN - 1] = 24;
    let mut quad = [iv; 4];
    Lanes::detect().quad(&mut quad, [&[message][..]; 4]);
    let digest: Vec<u8> = quad[0].iter().flat_map(|word| word.to_be_bytes()).collect();
    assert!(quad.iter().all(|state| *state == quad[0]));
    assert_eq!(digest[..], Sha256::digest(b"abc")[..]);
}

/// Runs `G` chains through `lanes` at 0, 1, 2, 3, 7 and 129 blocks, each chain's blocks read at every alignment within a 16-byte line and from a distinct start state, then the two published FIPS 180-4 messages in each chain position beside seeded chains; every chain must end at its own expected state, so a lane that took another lane's state, block or position fails.
fn chains_match_the_reference<const G: usize>(
    lanes: Lanes,
    run: impl Fn(Lanes, &mut [State; G], [&[Block]; G]),
) {
    const IV: State = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let mut rng = SplitMix64::new(0x15A0 + G as u64);
    for count in [0, 1, 2, 3, 7, 129] {
        for offset in 0..16 {
            let bytes: [Vec<u8>; G] = std::array::from_fn(|_| {
                (0..offset + count * BLOCK_LEN)
                    .map(|_| rng.next_u64() as u8)
                    .collect()
            });
            let streams: [&[Block]; G] = std::array::from_fn(|g| bytes[g][offset..].as_chunks().0);
            let start: [State; G] = std::array::from_fn(|_| states(&mut rng));
            let mut out = start;
            run(lanes, &mut out, streams);
            let want: [State; G] = std::array::from_fn(|g| expected(start[g], streams[g]));
            assert_eq!(out, want, "{G} chains, {count} blocks at offset {offset}");
        }
    }
    let padded = |message: &[u8]| -> Vec<Block> {
        let mut bytes = message.to_vec();
        bytes.push(0x80);
        while bytes.len() % BLOCK_LEN != BLOCK_LEN - 8 {
            bytes.push(0);
        }
        bytes.extend_from_slice(&(message.len() as u64 * 8).to_be_bytes());
        bytes.as_chunks().0.to_vec()
    };
    let vectors: [(&[u8], State); 2] = [
        (
            b"abc",
            [
                0xba78_16bf,
                0x8f01_cfea,
                0x4141_40de,
                0x5dae_2223,
                0xb003_61a3,
                0x9617_7a9c,
                0xb410_ff61,
                0xf200_15ad,
            ],
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            [
                0x248d_6a61,
                0xd206_38b8,
                0xe5c0_2693,
                0x0c3e_6039,
                0xa33c_e459,
                0x64ff_2167,
                0xf6ec_edd4,
                0x19db_06c1,
            ],
        ),
    ];
    for (message, digest) in vectors {
        let published = padded(message);
        for at in 0..G {
            let seeded: [Vec<Block>; G] =
                std::array::from_fn(|_| blocks(&mut rng, published.len()));
            let streams: [&[Block]; G] = std::array::from_fn(|g| {
                if g == at {
                    &published[..]
                } else {
                    &seeded[g][..]
                }
            });
            let start: [State; G] =
                std::array::from_fn(|g| if g == at { IV } else { states(&mut rng) });
            let mut out = start;
            run(lanes, &mut out, streams);
            for g in 0..G {
                let want = if g == at {
                    digest
                } else {
                    expected(start[g], streams[g])
                };
                assert_eq!(out[g], want, "{G} chains, published message in chain {at}");
            }
        }
    }
}

/// The aarch64 `sha2` kernels for two, three and four chains each run inside its own witness and match compression alone and the published digests; on a host without `sha2` each reports itself unreached.
#[test]
fn the_sha2_kernels_run_every_chain_count_and_match_the_reference() {
    use crate::isa_witness::{Kernel, detected, runs, witness};
    let lanes = Lanes::detect();
    witness(
        "sha2-two",
        detected!(aarch64: "sha2"),
        || runs(Kernel::Sha2Two),
        || chains_match_the_reference::<2>(lanes, |lanes, s, b| lanes.pair(s, b)),
    );
    witness(
        "sha2-three",
        detected!(aarch64: "sha2"),
        || runs(Kernel::Sha2Three),
        || chains_match_the_reference::<3>(lanes, |lanes, s, b| lanes.triple(s, b)),
    );
    witness(
        "sha2-four",
        detected!(aarch64: "sha2"),
        || runs(Kernel::Sha2Four),
        || chains_match_the_reference::<4>(lanes, |lanes, s, b| lanes.quad(s, b)),
    );
}

/// [`lone`] compresses one chain through the one-chain `sha2` kernel inside its witness and matches compression alone at every block count and alignment `chains_match_the_reference` runs and the two published digests; on a host without `sha2` and `sha3` the kernel reports itself unreached and `lone` still matches. The kernel counts one run for each nonempty run of blocks: the five nonzero block counts at sixteen alignments and the two published messages, 5 × 16 + 2 = 82 runs, so a `lone` that compressed any of them another way lowers the count.
#[test]
fn the_lone_chain_runs_the_one_chain_kernel_and_matches_the_reference() {
    use crate::isa_witness::{Kernel, detected, runs, witness};
    let one = detected!(aarch64: "sha2", "sha3");
    let present = one.present;
    let before = runs(Kernel::Sha2One);
    witness(
        "sha2-lone",
        one,
        || runs(Kernel::Sha2One),
        || chains_match_the_reference::<1>(Lanes::detect(), |_, s, b| lone(&mut s[0], b[0])),
    );
    assert_eq!(
        runs(Kernel::Sha2One) - before,
        if present { 82 } else { 0 },
        "every nonempty run of a lone chain goes through the one-chain kernel"
    );
}

/// The runtime-count entry `Lanes::each` compresses one to four chains through the detected kernels and the portable compression alike, and each chain matches compression alone at every block count `chains_match_the_reference` runs and the published digests at every chain position.
#[test]
fn the_runtime_count_entry_matches_the_reference_for_one_to_four_chains() {
    for lanes in [Lanes::detect(), Lanes::portable()] {
        chains_match_the_reference::<1>(lanes, |lanes, s, b| lanes.each(s, &b));
        chains_match_the_reference::<2>(lanes, |lanes, s, b| lanes.each(s, &b));
        chains_match_the_reference::<3>(lanes, |lanes, s, b| lanes.each(s, &b));
        chains_match_the_reference::<4>(lanes, |lanes, s, b| lanes.each(s, &b));
    }
}

/// `pair`, `triple` and `quad` refuse chains of unequal length with a panic before any kernel step, leaving every state as it was.
#[test]
fn every_chain_count_refuses_unequal_lengths_before_compressing() {
    use crate::isa_witness::{Kernel, runs};
    let mut rng = SplitMix64::new(0x0E0A);
    let (long, short) = (blocks(&mut rng, 2), blocks(&mut rng, 1));
    let kernels = [Kernel::Sha2Two, Kernel::Sha2Three, Kernel::Sha2Four];
    let lanes = Lanes::detect();
    let refused = |call: &mut dyn FnMut()| {
        let before = kernels.map(runs);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(call))
            .expect_err("unequal chains panic");
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied());
        assert!(
            message.is_some_and(|text| text.contains("chains of unequal length")),
            "{message:?}"
        );
        assert_eq!(kernels.map(runs), before, "no kernel step ran");
    };
    let start: [State; 4] = std::array::from_fn(|_| states(&mut rng));
    let mut pair = [start[0], start[1]];
    refused(&mut || lanes.pair(&mut pair, [&long, &short]));
    assert_eq!(pair, [start[0], start[1]]);
    let mut triple = [start[0], start[1], start[2]];
    refused(&mut || lanes.triple(&mut triple, [&long, &long, &short]));
    assert_eq!(triple, [start[0], start[1], start[2]]);
    let mut quad = start;
    refused(&mut || lanes.quad(&mut quad, [&short, &long, &long, &long]));
    assert_eq!(quad, start);
}

/// `composed` uses `compress256` as the reference for one chain's HMAC tail.
#[cfg(target_arch = "aarch64")]
fn composed(
    start: State,
    middle: &[Block],
    last: &Block,
    outer: State,
    pad: &[u8; BLOCK_LEN / 2],
) -> State {
    let digest = expected(expected(start, middle), std::slice::from_ref(last));
    let mut block = [0; BLOCK_LEN];
    for (word, out) in digest.iter().zip(block.as_chunks_mut::<4>().0) {
        *out = word.to_be_bytes();
    }
    block[BLOCK_LEN / 2..].copy_from_slice(pad);
    expected(outer, &[block])
}

/// Per-chain draws for `start`, `middle` and `outer` help expose lane mix-ups in the comparison with [`composed`].
#[cfg(target_arch = "aarch64")]
fn tails_match_the_composition<const G: usize>(lanes: Lanes, fused: bool) {
    use super::sha_lanes::{FixedBlock, Tail};
    let mut rng = SplitMix64::new(0x7A11 + G as u64);
    for count in [0, 1, 2, 5] {
        let last = blocks(&mut rng, 1)[0];
        let pad: [u8; BLOCK_LEN / 2] = std::array::from_fn(|_| rng.next_u64() as u8);
        let middle: [Vec<Block>; G] = std::array::from_fn(|_| blocks(&mut rng, count));
        let start: [State; G] = std::array::from_fn(|_| states(&mut rng));
        let outer: [State; G] = std::array::from_fn(|_| states(&mut rng));
        let mut out = start;
        let ran = lanes.tail(
            &mut out,
            &Tail {
                middle: middle.each_ref().map(Vec::as_slice),
                last: &FixedBlock::new(last),
                outer: outer.each_ref(),
                pad: &pad,
            },
        );
        assert_eq!(ran, fused, "{G} chains");
        if !ran {
            assert_eq!(out, start, "{G} chains");
            continue;
        }
        for g in 0..G {
            assert_eq!(
                out[g],
                composed(start[g], &middle[g], &last, outer[g], &pad),
                "chain {g} of {G}, {count} middle blocks"
            );
        }
    }
}

/// On aarch64 with `sha2`, `Sha2Tail` counts one pass per group: 3 chain counts × 4 lengths = 12 passes. Each chain count's step counter includes the middle blocks plus one fixed block and one outer block per tail: 0 + 1 + 2 + 5 + 2 × 4 = 16 steps.
#[cfg(target_arch = "aarch64")]
#[test]
fn the_tail_kernel_runs_one_pass_per_group_and_matches_its_three_compressions() {
    use crate::isa_witness::{Kernel, detected, runs, witness};
    let kernels = [
        Kernel::Sha2Two,
        Kernel::Sha2Three,
        Kernel::Sha2Four,
        Kernel::Sha2Tail,
    ];
    let sha2 = detected!(aarch64: "sha2");
    let present = sha2.present;
    let before = kernels.map(runs);
    witness(
        "sha2-tail",
        sha2,
        || runs(Kernel::Sha2Tail),
        || {
            tails_match_the_composition::<2>(Lanes::detect(), present);
            tails_match_the_composition::<3>(Lanes::detect(), present);
            tails_match_the_composition::<4>(Lanes::detect(), present);
        },
    );
    let ran: [usize; 4] = std::array::from_fn(|at| runs(kernels[at]) - before[at]);
    assert_eq!(ran, if present { [16, 16, 16, 12] } else { [0; 4] });
    let before = kernels.map(runs);
    tails_match_the_composition::<2>(Lanes::portable(), false);
    tails_match_the_composition::<3>(Lanes::portable(), false);
    tails_match_the_composition::<4>(Lanes::portable(), false);
    assert_eq!(kernels.map(runs), before, "the portable lanes run no tail");
}

/// `keyed_state` returns the SHA-256 chaining state after the RFC 2104 inner or outer key block.
#[cfg(target_arch = "aarch64")]
fn keyed_state(key: &[u8], pad: u8) -> State {
    use sha2::{Digest, Sha256};
    let mut block = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    expected(super::auth::SHA256_IV, &[block.map(|byte| byte ^ pad)])
}

/// For RFC 4231 cases 1 to 7, `middle` holds complete data blocks and `fixed` holds the final padded inner block. `pad` encodes the outer message length: a 64-byte outer key block plus a 32-byte inner digest.
#[cfg(target_arch = "aarch64")]
#[test]
fn the_tail_computes_the_rfc_4231_vectors_in_every_chain_position() {
    let mut pad = [0u8; BLOCK_LEN / 2];
    pad[0] = 0x80;
    pad[BLOCK_LEN / 2 - 8..].copy_from_slice(&(96u64 * 8).to_be_bytes());
    let mut rng = SplitMix64::new(0x4231);
    for (key, data, mac) in &super::auth_tests::rfc_4231_cases() {
        let mut message = data.clone();
        message.push(0x80);
        while message.len() % BLOCK_LEN != BLOCK_LEN - 8 {
            message.push(0);
        }
        message.extend_from_slice(&((BLOCK_LEN + data.len()) as u64 * 8).to_be_bytes());
        let (padded, _) = message.as_chunks::<BLOCK_LEN>();
        let (last, middle) = padded.split_last().unwrap();
        let keyed = [keyed_state(key, 0x36), keyed_state(key, 0x5C)];
        published_tail_in_every_position::<2>(&mut rng, keyed, middle, last, &pad, mac);
        published_tail_in_every_position::<3>(&mut rng, keyed, middle, last, &pad, mac);
        published_tail_in_every_position::<4>(&mut rng, keyed, middle, last, &pad, mac);
    }
}

#[cfg(target_arch = "aarch64")]
fn published_tail_in_every_position<const G: usize>(
    rng: &mut SplitMix64,
    keyed: [State; 2],
    middle: &[Block],
    last: &Block,
    pad: &[u8; BLOCK_LEN / 2],
    mac: &[u8],
) {
    use super::sha_lanes::{FixedBlock, Tail};
    let fixed = FixedBlock::new(*last);
    for at in 0..G {
        let seeded: [Vec<Block>; G] = std::array::from_fn(|_| blocks(rng, middle.len()));
        let runs: [&[Block]; G] =
            std::array::from_fn(|g| if g == at { middle } else { &seeded[g][..] });
        let start: [State; G] =
            std::array::from_fn(|g| if g == at { keyed[0] } else { states(rng) });
        let outer: [State; G] =
            std::array::from_fn(|g| if g == at { keyed[1] } else { states(rng) });
        let mut out = start;
        let tail = Tail {
            middle: runs,
            last: &fixed,
            outer: outer.each_ref(),
            pad,
        };
        let ran = Lanes::detect().tail(&mut out, &tail);
        assert_eq!(
            ran,
            std::arch::is_aarch64_feature_detected!("sha2"),
            "chain {at} of {G}: the tail runs exactly where the CPU has `sha2`"
        );
        if !ran {
            assert_eq!(out, start);
            return;
        }
        for g in 0..G {
            if g == at {
                let digest: Vec<u8> = out[g].iter().flat_map(|word| word.to_be_bytes()).collect();
                assert_eq!(digest[..mac.len()], mac[..], "chain {at} of {G}");
            } else {
                assert_eq!(
                    out[g],
                    composed(start[g], runs[g], last, outer[g], pad),
                    "chain {g} beside chain {at} of {G}"
                );
            }
        }
    }
}

/// Each output lane holds the sum modulo 2^32 of a SHA-256 schedule word of `block` and its corresponding `K` constant.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "sha2")]
fn instruction_round_words(block: &Block) -> [[u32; 4]; 16] {
    use std::arch::aarch64::{
        vaddq_u32, vld1q_u8, vld1q_u32, vreinterpretq_u32_u8, vrev32q_u8, vsha256su0q_u32,
        vsha256su1q_u32, vst1q_u32,
    };
    // SAFETY: `block` holds 64 readable bytes, so the 16 at `16 * q` for `q < 4` are in bounds, and `vld1q_u8` has no alignment requirement.
    let mut w: [_; 4] = std::array::from_fn(|q| {
        vreinterpretq_u32_u8(vrev32q_u8(unsafe { vld1q_u8(block.as_ptr().add(16 * q)) }))
    });
    let mut steps = [[0u32; 4]; 16];
    for (step, out) in steps.iter_mut().enumerate() {
        let q = step % 4;
        if step >= 4 {
            w[q] = vsha256su1q_u32(
                vsha256su0q_u32(w[q], w[(q + 1) % 4]),
                w[(q + 2) % 4],
                w[(q + 3) % 4],
            );
        }
        // SAFETY: `K` holds four words from `4 * step` for `step < 16`, `out` holds four writable words, and neither intrinsic has an alignment requirement.
        unsafe {
            vst1q_u32(
                out.as_mut_ptr(),
                vaddq_u32(w[q], vld1q_u32(K[4 * step..].as_ptr())),
            )
        };
    }
    steps
}

/// Big-endian packing gives padded `abc` the first word `0x61626380`. Words 1 to 3 are zero, so those lanes equal their `K` constants.
#[cfg(target_arch = "aarch64")]
#[test]
fn compile_time_round_words_equal_the_schedule_expanded_at_run_time() {
    use super::sha_lanes::round_words;
    const ABC: Block = {
        let mut block = [0u8; BLOCK_LEN];
        (block[0], block[1], block[2], block[3]) = (b'a', b'b', b'c', 0x80);
        block[BLOCK_LEN - 1] = 24;
        block
    };
    const AT_COMPILE_TIME: [[u32; 4]; 16] = round_words(&ABC);
    assert_eq!(
        AT_COMPILE_TIME[0],
        [
            0x6162_6380 + 0x428a_2f98,
            0x7137_4491,
            0xb5c0_fbcf,
            0xe9b5_dba5
        ]
    );
    let recurrence = |block: &Block| -> [[u32; 4]; 16] {
        let mut w = [0u32; 64];
        for (word, bytes) in w.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_be_bytes(*bytes);
        }
        for t in 16..64 {
            let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
            let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
            w[t] = s1
                .wrapping_add(w[t - 7])
                .wrapping_add(s0)
                .wrapping_add(w[t - 16]);
        }
        std::array::from_fn(|step| {
            std::array::from_fn(|at| w[4 * step + at].wrapping_add(K[4 * step + at]))
        })
    };
    assert_eq!(AT_COMPILE_TIME, recurrence(&ABC));
    let mut rng = SplitMix64::new(0x5C4E);
    let mut seeded = blocks(&mut rng, 64);
    seeded.push(ABC);
    let sha2 = std::arch::is_aarch64_feature_detected!("sha2");
    for block in &seeded {
        let words = round_words(std::hint::black_box(block));
        assert_eq!(words, recurrence(block));
        if sha2 {
            // SAFETY: the detection reported the `sha2` feature the function enables.
            assert_eq!(words, unsafe { instruction_round_words(block) });
        }
    }
}

/// `Lanes::tail` returns `false` for one or five chains. For two chains with unequal middle-run lengths, `Lanes::portable().tail` returns `false`, while `Lanes::detect().tail` panics when the CPU supports `sha2`. Each path exits before any kernel step and preserves the chain states.
#[cfg(target_arch = "aarch64")]
#[test]
fn a_tail_outside_two_to_four_equal_chains_changes_nothing() {
    use super::sha_lanes::{FixedBlock, Tail};
    use crate::isa_witness::{Kernel, runs};
    let kernels = [
        Kernel::Sha2Two,
        Kernel::Sha2Three,
        Kernel::Sha2Four,
        Kernel::Sha2Tail,
    ];
    let mut rng = SplitMix64::new(0x7A13);
    let fixed = FixedBlock::new(blocks(&mut rng, 1)[0]);
    let pad = [0x5C; BLOCK_LEN / 2];
    let start: [State; 5] = std::array::from_fn(|_| states(&mut rng));
    let outer: [State; 5] = std::array::from_fn(|_| states(&mut rng));
    let outer = outer.each_ref();
    let (long, short) = (blocks(&mut rng, 2), blocks(&mut rng, 1));
    let before = kernels.map(runs);
    for lanes in [Lanes::detect(), Lanes::portable()] {
        let mut one = [start[0]];
        let tail = Tail {
            middle: [&long[..]],
            last: &fixed,
            outer: [outer[0]],
            pad: &pad,
        };
        assert!(!lanes.tail(&mut one, &tail));
        assert_eq!(one, [start[0]]);
        let mut five = start;
        let tail = Tail {
            middle: [&long[..]; 5],
            last: &fixed,
            outer,
            pad: &pad,
        };
        assert!(!lanes.tail(&mut five, &tail));
        assert_eq!(five, start);
    }
    let mut pair = [start[0], start[1]];
    let tail = Tail {
        middle: [&long[..], &short[..]],
        last: &fixed,
        outer: [outer[0], outer[1]],
        pad: &pad,
    };
    assert!(!Lanes::portable().tail(&mut pair, &tail));
    if std::arch::is_aarch64_feature_detected!("sha2") {
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Lanes::detect().tail(&mut pair, &tail)
        }))
        .expect_err("unequal chains panic");
        let message = panic.downcast_ref::<&str>().copied();
        assert!(
            message.is_some_and(|text| text.contains("chains of unequal length")),
            "{message:?}"
        );
    }
    assert_eq!(pair, [start[0], start[1]]);
    assert_eq!(kernels.map(runs), before, "no kernel step ran");
}
