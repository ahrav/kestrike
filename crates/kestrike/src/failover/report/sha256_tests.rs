use super::sha256::tag;
use super::{DOMAIN, MAX_LEN, TAG_LEN};
use crate::failover::assignment::hmac;
use crate::isa_witness::{Kernel, detected, runs, witness};
use crate::storage::seeded::SplitMix64;

fn bytes(rng: &mut SplitMix64, len: usize) -> Vec<u8> {
    (0..len).map(|_| rng.next_u64() as u8).collect()
}

/// The body lengths the tag tests cover: every length through four blocks past the label, which crosses each
/// padding boundary, the lengths around later block boundaries, and a report's lengths at 0, 1 and 128 entries.
fn lengths() -> Vec<usize> {
    let around = [1_024, 4_096, 65_408].map(|block| block - 16);
    (0..=4 * 64 + 16)
        .chain(around.into_iter().flat_map(|at| at - 9..=at + 1))
        .chain([274, 783, MAX_LEN - TAG_LEN])
        .collect()
}

/// TAG-FUNCTION: the tag equals the HMAC `failover::assignment::hmac` computes over the label and the body, at
/// every length of [`lengths`] and under a fresh key at each. On aarch64 with `sha2` and `sha3` the one-chain
/// kernel computes every tag inside its witness, and on a host without them the witness reports it unreached. A
/// tag runs the kernel once for each key pad block and once to finish each of its two hashes, once more for the
/// label's block when the body fills it, from 48 bytes, and once more for the whole blocks after it, from 112
/// bytes. The 309 lengths hold 48 below 48 bytes, 64 below 112 and 197 from 112, so the kernel runs
/// 48 x 4 + 64 x 5 + 197 x 6 = 1,694 times, and a tag that took the other path would lower the count.
#[test]
fn the_tag_equals_the_reference_hmac_at_every_length() {
    witness(
        "sha2-one",
        detected!(aarch64: "sha2", "sha3"),
        || runs(Kernel::Sha2One),
        || {
            let mut rng = SplitMix64::new(0x1801);
            for len in lengths() {
                let key: [u8; 32] = std::array::from_fn(|_| rng.next_u64() as u8);
                let body = bytes(&mut rng, len);
                assert_eq!(
                    tag(&key, DOMAIN, &body),
                    hmac(&key, &[DOMAIN, &body]),
                    "a body of {len} bytes"
                );
            }
        },
    );
}

/// A tag changes with each input: one flipped bit of the key, of the body's first, middle or last byte, or one byte
/// more or fewer gives another tag, so no input byte is skipped or read twice in place of another.
#[test]
fn the_tag_covers_the_key_and_every_region_of_the_body() {
    let mut rng = SplitMix64::new(0x7A6);
    let key: [u8; 32] = std::array::from_fn(|_| rng.next_u64() as u8);
    for len in [1, 47, 48, 49, 783, MAX_LEN - TAG_LEN] {
        let body = bytes(&mut rng, len);
        let base = tag(&key, DOMAIN, &body);
        for at in [0, len / 2, len - 1] {
            let mut edited = body.clone();
            edited[at] ^= 0x80;
            assert_ne!(tag(&key, DOMAIN, &edited), base, "byte {at} of {len}");
        }
        let mut other = key;
        other[31] ^= 1;
        assert_ne!(tag(&other, DOMAIN, &body), base, "the key at {len}");
        assert_ne!(tag(&key, DOMAIN, &body[..len - 1]), base, "{len} - 1");
        let longer = [&body[..], &[0][..]].concat();
        assert_ne!(tag(&key, DOMAIN, &longer), base, "{len} + 1");
    }
}

/// The one-chain kernel compresses as `compress256` does from arbitrary states over runs of 0 to 129 blocks, and
/// hashes the three FIPS 180-4 example messages (an empty message, `abc` and the 56-byte message whose padding
/// takes a second block) to their published digests.
#[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
#[test]
fn the_one_chain_kernel_matches_compression_alone_and_the_published_digests() {
    use sha2::block_api::compress256;

    use super::sha256::chain::{BLOCK, State, finish};
    use crate::net::SHA256_IV;
    use crate::net::sha_one::{compress, detected};

    if !detected() {
        return;
    }
    let mut rng = SplitMix64::new(0x5A11);
    for count in [0, 1, 2, 3, 7, 129] {
        let blocks: Vec<[u8; BLOCK]> = (0..count)
            .map(|_| std::array::from_fn(|_| rng.next_u64() as u8))
            .collect();
        let start: State = std::array::from_fn(|_| rng.next_u64() as u32);
        let (mut state, mut expected) = (start, start);
        // SAFETY: `detected` reported every CPU feature `compress` enables.
        unsafe { compress(&mut state, &blocks) };
        compress256(&mut expected, &blocks);
        assert_eq!(state, expected, "{count} blocks");
    }
    let published: [(&[u8], &str); 3] = [
        (
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ];
    for (message, digest) in published {
        // SAFETY: `detected` reported every CPU feature `finish` enables.
        let found = unsafe { finish(SHA256_IV, message, message.len()) };
        let hex: String = found.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, digest, "{} bytes", message.len());
    }
}
