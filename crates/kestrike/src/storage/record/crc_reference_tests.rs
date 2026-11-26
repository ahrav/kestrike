//! Every CRC-32C mechanism this host executes, checked against the bitwise
//! reference, the Castagnoli polynomial folded one bit at a time, through
//! every interface shape: the one-shot checksum; incremental updates split
//! at every listed point; word and masked-word updates; the copying update,
//! with the target's bytes and the canaries around it checked; zero runs,
//! cached and built; append, combine, the zero-register fold and its
//! inverse; chunk combination; and, on a host whose mechanism folds
//! aarch64 lanes, the checksum of freshly written words. The bitwise
//! reference returns the check value for the check vector. Mechanism
//! inputs cover the empty slice, start offsets 0, 1, 7, 8 and 15 within a
//! 16-byte vector load, every length up to 64 bytes, each fold level's group
//! boundary and each kernel's entry and step threshold. Each specialized
//! kernel counts its own runs, so the report credits a kernel as executed
//! only when its own body ran on this thread.

use super::super::layout::IO_UNIT;
use super::crc32c::{Chunks, LEVELS};
use super::crc32c_tests::{group_lengths, mechanisms, seeded};
use super::fuzz_tests::crc32c as bitwise;
use super::{Crc32c, ZeroRuns};
use crate::isa_witness::{Detected, Kernel, detected, runs};

/// The listed lengths and each kernel's entry and step threshold: the
/// aarch64 carry-less fold's 240-byte step, and the x86_64 128-byte step
/// and 176-byte three-chain minimum, either side, and one past the AVX-512
/// fold's 256-byte minimum.
fn lengths() -> Vec<usize> {
    let mut lengths = group_lengths();
    lengths.extend([127, 128, 129, 175, 176, 177, 239, 240, 241, 257]);
    lengths.sort_unstable();
    lengths.dedup();
    lengths
}

/// The register an update of `bytes` from the initial register leaves.
fn register_of(crc: Crc32c, bytes: &[u8]) -> u32 {
    let mut running = crc.start();
    running.update(bytes);
    running.register()
}

/// Each specialized CRC-32C kernel with the runtime features its entry
/// requires: the aarch64 CRC instruction loop, carry-less fold and lane
/// fold, and the x86_64 chains, narrow and wide kernels.
fn kernels() -> [(&'static str, Kernel, Detected); 6] {
    [
        (
            "crc-instruction",
            Kernel::CrcInstruction,
            detected!(aarch64: "crc"),
        ),
        (
            "crc-pmull",
            Kernel::CrcPmull,
            detected!(aarch64: "crc", "aes"),
        ),
        (
            "crc-lanes",
            Kernel::CrcLanes,
            detected!(aarch64: "crc", "aes"),
        ),
        (
            "crc-chains",
            Kernel::CrcChains,
            detected!(x86_64: "sse4.2", "pclmulqdq"),
        ),
        (
            "crc-narrow",
            Kernel::CrcNarrow,
            detected!(x86_64: "sse4.2", "pclmulqdq"),
        ),
        (
            "crc-wide",
            Kernel::CrcWide,
            detected!(x86_64: "sse4.2", "pclmulqdq", "avx512f", "vpclmulqdq"),
        ),
    ]
}

/// Every reference comparison of this file once, on this thread.
fn every_comparison() {
    one_shot_incremental_and_zero_run_paths();
    word_and_masked_word_updates();
    copying_update_keeps_target_and_canaries();
    block_runs_combine();
    written_words();
}

/// Each specialized kernel runs during the reference comparisons exactly
/// when the host reports every feature its entry requires, by the kernel's
/// own count. The output names each executed kernel with its run count and
/// each other kernel as unavailable, both with the host's feature report,
/// and the bitwise reference returns the check value `0xE306_9283`.
#[test]
fn ib_crc_bitwise_reference_reports_executed_and_unavailable_mechanisms() {
    assert_eq!(bitwise(b"123456789"), 0xE306_9283);
    assert_eq!(bitwise(&[]), 0);
    let names: Vec<&str> = mechanisms().into_iter().map(|(name, _)| name).collect();
    println!("crc32c mechanisms: {names:?}");
    let before = kernels().map(|(_, kernel, _)| runs(kernel));
    every_comparison();
    for ((name, kernel, detected), before) in kernels().into_iter().zip(before) {
        let ran = runs(kernel) - before;
        match ran {
            0 => println!("crc32c kernel {name}: unavailable; {}", detected.features),
            _ => println!(
                "crc32c kernel {name}: executed {ran} times; {}",
                detected.features
            ),
        }
        assert_eq!(
            ran > 0,
            detected.present,
            "{name} ran {ran} times on {}",
            detected.features
        );
    }
}

/// One-shot checksums at each start offset and listed length, incremental
/// updates split at both ends, word boundaries and the middle, and the
/// append, combine, zero-register and zero-run paths over the same splits,
/// each equal to the bitwise reference of the concatenated bytes.
#[test]
fn ib_crc_bitwise_reference_one_shot_incremental_and_zero_run_paths() {
    one_shot_incremental_and_zero_run_paths();
}

fn one_shot_incremental_and_zero_run_paths() {
    let longest = lengths().into_iter().max().unwrap_or(0);
    let bytes = seeded(longest + 16, 0x5eed);
    // `ZeroRuns` keys runs on length alone, so each mechanism keeps its own
    // cache and every run it reads was built by that mechanism.
    let mut caches: Vec<ZeroRuns> = mechanisms().iter().map(|_| ZeroRuns::default()).collect();
    for len in lengths() {
        for start in [0, 1, 7, 8, 15] {
            let data = &bytes[start..start + len];
            let expected = bitwise(data);
            for ((name, crc), runs) in mechanisms().into_iter().zip(&mut caches) {
                assert_eq!(crc.checksum(data), expected, "{name} {start}+{len}");
                let run = crc.zero_run(len as u64);
                assert_eq!(
                    crc.checksum_of(crc.fold_from_zero(data), &run),
                    expected,
                    "{name} {start}+{len}"
                );
                assert_eq!(crc.from_zero(expected, &run), crc.fold_from_zero(data));
                if start != 0 {
                    continue;
                }
                for at in [0, 1, 7, 8, 9, len / 2, len.saturating_sub(1), len] {
                    let at = at.min(len);
                    let (head, tail) = data.split_at(at);
                    let mut running = crc.start();
                    running.update(head);
                    running.update(tail);
                    assert_eq!(running.finish(), expected, "{name} {len} split {at}");
                    let tail_run = runs.run(crc, tail.len() as u64);
                    assert_eq!(
                        crc.combine(crc.checksum(head), &tail_run, crc.checksum(tail)),
                        expected,
                        "{name} {len} split {at}"
                    );
                    let register =
                        crc.append(register_of(crc, head), &tail_run, crc.fold_from_zero(tail));
                    assert_eq!(!register, expected, "{name} {len} split {at}");
                }
            }
        }
    }
    // A zero run carries a register past that many zero bytes.
    for ((name, crc), runs) in mechanisms().into_iter().zip(&mut caches) {
        for len in [0, 1, 31, 32, 33, LEVELS[0], LEVELS[2] + 5] {
            let mut padded = bytes[..40].to_vec();
            padded.resize(40 + len, 0);
            let run = runs.run(crc, len as u64);
            assert_eq!(
                !run.advance(register_of(crc, &bytes[..40])),
                bitwise(&padded),
                "{name} {len}"
            );
        }
    }
}

/// Checks `checksum_words` over the first `N` words of `bytes`,
/// `update_words` after a 3-byte prefix, and `update_words_masked` with
/// each listed mask on each listed word `AT`, each against the bitwise
/// reference of the bytes it folds.
macro_rules! words_case {
    ($bytes:expr, $n:literal, [$($at:literal),*]) => {{
        let words: &[[u8; 8]; $n] = $bytes[..8 * $n].as_chunks::<8>().0.try_into().expect("N words");
        let flat = words.as_flattened();
        for (name, crc) in mechanisms() {
            assert_eq!(crc.checksum_words(words), bitwise(flat), "{name} {}", $n);
            let mut running = crc.start();
            running.update(&$bytes[..3]);
            running.update_words(words);
            assert_eq!(running.finish(), bitwise(&[&$bytes[..3], flat].concat()), "{name} {}", $n);
            for mask in [0, u64::MAX, 0xFFFF_FFFF, !0xFFFF_FFFF, 0x00FF_00FF_00FF_00FF] {
                $(
                    let mut masked = flat.to_vec();
                    let word = u64::from_le_bytes(words[$at]) & mask;
                    masked[8 * $at..8 * $at + 8].copy_from_slice(&word.to_le_bytes());
                    let mut running = crc.start();
                    running.update_words_masked::<$n, $at>(words, mask);
                    assert_eq!(running.finish(), bitwise(&masked), "{name} {} at {} mask {mask:#x}", $n, $at);
                )*
            }
        }
    }};
}

/// Word updates over 1, 2, 3, 6, 7, 8, 13, 22, 28, 33, 64 and 130 words,
/// masked at the first, the last and listed interior words, equal the
/// bitwise reference.
#[test]
fn ib_crc_bitwise_reference_word_and_masked_word_updates() {
    word_and_masked_word_updates();
}

fn word_and_masked_word_updates() {
    let bytes = seeded(8 * 130, 0x77);
    words_case!(bytes, 1, [0]);
    words_case!(bytes, 2, [0, 1]);
    words_case!(bytes, 3, [0, 1, 2]);
    words_case!(bytes, 6, [0, 5]);
    words_case!(bytes, 7, [0, 3, 6]);
    words_case!(bytes, 8, [0, 6, 7]);
    words_case!(bytes, 13, [0, 12]);
    words_case!(bytes, 22, [0, 20, 21]);
    words_case!(bytes, 28, [0, 27]);
    words_case!(bytes, 33, [0, 32]);
    words_case!(bytes, 64, [0, 63]);
    words_case!(bytes, 130, [0, 129]);
}

/// The copying update folds what the plain update folds and writes exactly
/// the source bytes at each listed target offset, in one piece and, after a
/// 3-byte prefix, in two; after the two-piece copy every `0xA5` canary
/// around the target holds its value.
#[test]
fn ib_crc_bitwise_reference_copying_update_keeps_target_and_canaries() {
    copying_update_keeps_target_and_canaries();
}

fn copying_update_keeps_target_and_canaries() {
    let longest = lengths().into_iter().max().unwrap_or(0);
    let bytes = seeded(longest, 0xc0);
    for len in lengths() {
        let source = &bytes[..len];
        let expected = bitwise(source);
        for (name, crc) in mechanisms() {
            for offset in [16, 17, 23, 24, 31] {
                let mut target = vec![0xA5; len + 48];
                let mut running = crc.start();
                running.update_and_copy(source, &mut target[offset..offset + len]);
                assert_eq!(running.finish(), expected, "{name} {len} at {offset}");
                assert_eq!(
                    &target[offset..offset + len],
                    source,
                    "{name} {len} at {offset} one piece"
                );
                target.fill(0xA5);
                // After a prefix, and in two pieces, the copy carries the
                // register it is given.
                let mut running = crc.start();
                running.update(b"pre");
                let half = len / 2;
                running.update_and_copy(&source[..half], &mut target[offset..offset + half]);
                running.update_and_copy(&source[half..], &mut target[offset + half..offset + len]);
                assert_eq!(
                    running.finish(),
                    bitwise(&[&b"pre"[..], source].concat()),
                    "{name} {len} at {offset} after a prefix"
                );
                assert_eq!(
                    &target[offset..offset + len],
                    source,
                    "{name} {len} at {offset}"
                );
                assert!(
                    target[..offset]
                        .iter()
                        .chain(&target[offset + len..])
                        .all(|&b| b == 0xA5),
                    "{name} {len} at {offset}: a canary changed"
                );
            }
        }
    }
}

/// A payload's chunk checksums combine with the checksum of the 37 leading
/// bytes to the bitwise reference of the leading bytes and the payload, over
/// one to 40 chunks of windows from one to five units, a run of chunks that
/// the aarch64 join splits into groups, first chunks of 1 to 4095 bytes and
/// last chunks of 1 to 4097 bytes.
#[test]
fn ib_crc_bitwise_reference_block_runs_combine() {
    block_runs_combine();
}

fn block_runs_combine() {
    let bytes = seeded(1 << 19, 0xb10c);
    // A first chunk of `first` bytes, then for two chunks or more `count - 2` windows of `units` units and a last chunk of `last` bytes; on aarch64, a run whose first chunk's carry past the windows reaches 65 units or more splits into groups.
    for (first, units, count, last) in [
        (1usize, 1usize, 1usize, 1usize),
        (8, 1, 2, 4096),
        (4095, 1, 5, 4097),
        (100, 2, 4, 3),
        (3, 1, 31, 8),
        (7, 1, 33, 1),
        (5, 1, 40, 13),
        (64, 3, 9, 4096),
        (5, 5, 16, 13),
    ] {
        let window = units * IO_UNIT;
        let lens: Vec<usize> = std::iter::once(first)
            .chain(std::iter::repeat_n(window, count.saturating_sub(2)))
            .chain((count > 1).then_some(last))
            .collect();
        let end = 37 + lens.iter().sum::<usize>();
        let expected = bitwise(&bytes[..end]);
        for (name, crc) in mechanisms() {
            let mut at = 37;
            let checksums: Vec<[u8; 4]> = lens
                .iter()
                .map(|&len| {
                    let block = &bytes[at..at + len];
                    at += len;
                    crc.checksum(block).to_le_bytes()
                })
                .collect();
            let chunks = Chunks {
                checksums: &checksums,
                units: units as u64,
                last_len: *lens.last().expect("a chunk") as u64,
                len: (end - 37) as u64,
            };
            assert_eq!(
                crc.combine_chunks(crc.checksum(&bytes[..37]), &chunks),
                expected,
                "{name} first {first}, {count} chunks of {units} units, last {last}"
            );
        }
    }
}

/// On a host whose mechanism folds aarch64 lanes, `checksum_written` over
/// 22 words, unmasked and with word 20 masked, equals the bitwise reference
/// of the same words; every other host reports the shape unavailable.
#[test]
fn ib_crc_bitwise_reference_written_words() {
    written_words();
}

fn written_words() {
    #[cfg(target_arch = "aarch64")]
    {
        let crc = Crc32c::detect();
        if !crc.folds_lanes() {
            println!("checksum_written: unavailable on this host");
            return;
        }
        let bytes = seeded(8 * 22, 0x22);
        let words: &[[u8; 8]; 22] = bytes.as_chunks::<8>().0.try_into().expect("22 words");
        let mut masked = bytes.clone();
        let word = u64::from_le_bytes(words[20]) & !0xFFFF_FFFF;
        masked[160..168].copy_from_slice(&word.to_le_bytes());
        // SAFETY: `folds_lanes` shows the running CPU implements the CRC and
        // AES extensions `checksum_written` requires.
        let (whole, with_mask) = unsafe {
            (
                Crc32c::checksum_written::<22, 22>(words, 0),
                Crc32c::checksum_written::<22, 20>(words, !0xFFFF_FFFF),
            )
        };
        assert_eq!(whole, bitwise(&bytes));
        assert_eq!(with_mask, bitwise(&masked));
        println!("checksum_written: executed");
    }
    #[cfg(not(target_arch = "aarch64"))]
    println!("checksum_written: unavailable on this architecture");
}
