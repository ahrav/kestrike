//! At each tested length and split, both data-key hash engines must match the `polyval` crate's POLYVAL of the joined, zero-padded body, whether the slices share a buffer or occupy separate buffers.

use std::ops::Range;

use polyval::universal_hash::UniversalHash;

use crate::storage::seeded::SplitMix64;

use super::data_hash::DataHash;

/// The `polyval` crate's POLYVAL of `body`, zero-padded to whole blocks, under `key`.
fn reference(key: [u8; 16], body: &[u8]) -> [u8; 16] {
    let mut hash = polyval::Polyval::new(&key.into());
    hash.update_padded(body);
    hash.finalize().into()
}

fn bytes<const N: usize>(rng: &mut SplitMix64) -> [u8; N] {
    std::array::from_fn(|_| rng.next_u64() as u8)
}

/// Guard bytes on each side of a slice in [`apart`]: one 64-byte AVX-512 register.
const GUARD: usize = 64;

/// A copy of `body[range]` in its own buffer with [`GUARD`] bytes on each side. Each guard byte differs from the corresponding `body` byte or, beyond `body`, from zero padding. Hashing a guard byte in place of either changes the digest input.
fn apart(body: &[u8], range: Range<usize>) -> Vec<u8> {
    let guard = |at: Option<usize>| at.and_then(|at| body.get(at)).map_or(0xA5, |byte| !byte);
    let before = (0..GUARD).map(|ahead| guard((range.start + ahead).checked_sub(GUARD)));
    let after = (0..GUARD).map(|past| guard(Some(range.end + past)));
    before
        .chain(body[range.clone()].iter().copied())
        .chain(after)
        .collect()
}

/// The x86_64 vector engine absorbs 512-byte steps and the aarch64 one 1024-byte steps, so lengths 0 to 1600 give empty bodies, a partial last block, every block count of a step shorter than a whole one, and whole steps; 2047 to 2049, 3071 to 3073, 4095 to 4097 and 8191 to 8193 give bodies a byte short of, at, and a byte past 2, 3, 4 and 8 aarch64 steps and twice as many x86_64 steps, and 3056 gives a 63-block step ahead of two whole aarch64 steps. Splits land on and off block boundaries, at both ends and at random, so a straddling block and an empty first or second slice each occur, and the middle splits of bodies of 2048 bytes or more leave whole steps in both slices. Each split is digested as the two halves of one buffer and again with each slice [`apart`] in a buffer of its own. In one buffer the bytes after the first slice are the second slice's, so only the separate buffers detect an engine that completes a straddling block from memory past the first slice.
#[test]
fn both_engines_match_the_reference_polyval_at_every_length_and_split() {
    let mut rng = SplitMix64::new(0x00DA_7A00);
    #[cfg(target_arch = "x86_64")]
    let wide = std::arch::is_x86_feature_detected!("avx512f")
        && std::arch::is_x86_feature_detected!("avx512bw")
        && std::arch::is_x86_feature_detected!("avx512vbmi2")
        && std::arch::is_x86_feature_detected!("vpclmulqdq");
    #[cfg(target_arch = "aarch64")]
    let wide = std::arch::is_aarch64_feature_detected!("neon")
        && std::arch::is_aarch64_feature_detected!("aes")
        && std::arch::is_aarch64_feature_detected!("sha3");
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let wide = false;
    let lengths = (0..=1600usize).chain([
        2047, 2048, 2049, 3056, 3071, 3072, 3073, 4095, 4096, 4097, 8191, 8192, 8193,
    ]);
    for len in lengths {
        let key: [u8; 16] = if len == 3056 {
            // The identity of POLYVAL's product, x^128 modulo the field polynomial: 1 in the low byte and 0xC2 in the high byte.
            let mut one = [0; 16];
            one[0] = 1;
            one[15] = 0xC2;
            one
        } else {
            bytes(&mut rng)
        };
        let body: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
        let expected = reference(key, &body);
        let hashes = [DataHash::new(key), DataHash::portable(key)];
        assert_eq!(
            hashes[0].is_wide(),
            wide,
            "the vector engine runs where the CPU has it"
        );
        assert!(!hashes[1].is_wide());
        let splits = [0, 1, 15, 16, 17, len / 2, len.saturating_sub(1), len]
            .into_iter()
            .chain((0..len).step_by(97))
            .chain([(rng.next_u64() as usize) % (len + 1)])
            .filter(|&split| split <= len);
        for split in splits {
            let (first, second) = body.split_at(split);
            let (first_apart, second_apart) = (apart(&body, 0..split), apart(&body, split..len));
            let separate = [
                &first_apart[GUARD..GUARD + split],
                &second_apart[GUARD..GUARD + len - split],
            ];
            for hash in &hashes {
                assert_eq!(
                    hash.digest([first, second]),
                    expected,
                    "length {len} split {split} wide {}",
                    hash.is_wide()
                );
                assert_eq!(
                    hash.digest(separate),
                    expected,
                    "length {len} split {split} in separate buffers wide {}",
                    hash.is_wide()
                );
            }
        }
    }
}

/// A digest depends on the key and on every body byte: changing one key bit or one body bit changes the digest on both engines.
#[test]
fn a_changed_key_or_body_bit_changes_the_digest() {
    let mut rng = SplitMix64::new(0x00DA_7A01);
    let key: [u8; 16] = bytes(&mut rng);
    let body: [u8; 1025] = bytes(&mut rng);
    for hash in [DataHash::new(key), DataHash::portable(key)] {
        let digest = hash.digest([&body[..300], &body[300..]]);
        for at in [0, 15, 16, 511, 512, 1024] {
            let mut changed = body;
            changed[at] ^= 1 << (at % 8);
            assert_ne!(
                hash.digest([&changed[..300], &changed[300..]]),
                digest,
                "byte {at}"
            );
        }
        let mut other = key;
        other[7] ^= 0x10;
        let rekeyed = if hash.is_wide() {
            DataHash::new(other)
        } else {
            DataHash::portable(other)
        };
        assert_ne!(rekeyed.digest([&body[..300], &body[300..]]), digest);
    }
}

/// On aarch64 hosts with `neon`, `aes` and `sha3`, `DataHash::new` selects the `pmull` engine.
#[test]
fn the_pmull_engine_runs_and_matches_the_reference() {
    use crate::isa_witness::{Kernel, detected, runs, witness};
    witness(
        "polyval-pmull",
        detected!(aarch64: "neon", "aes", "sha3"),
        || runs(Kernel::PolyvalPmull),
        both_engines_match_the_reference_polyval_at_every_length_and_split,
    );
}
