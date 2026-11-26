//! The check value, hardware and table agreement over tails, unaligned starts and folding-step boundaries, incremental agreement at every split, the compile-time word-count folds against the variable-length fold at every chain count, with the first, last and frame-crc words masked, the byte-fold calls a masked fold spends near a span's end, the polynomial arithmetic behind the fold and shift constants, the zero-shift tables against zero bytes fed through the table, the three-chain copying fold under the table's step, the wide fold and its copy against the table for every count of blocks after its last group, and the copying update against the plain one at every group shape and every target offset in a line, for each mechanism the host has.

use super::super::layout::IO_UNIT;
use super::super::seeded::SplitMix64;
use super::Crc32c;
use super::crc32c::RunningCrc;
#[cfg(target_arch = "aarch64")]
use super::crc32c::crc_instruction;
#[cfg(target_arch = "x86_64")]
use super::crc32c::narrow;
use super::crc32c::{
    Chunks, LEVELS, SHIFTS, TABLE, fold_words_copy, hardware, mul_mod, register_after, shift,
    times_x, update_table, x_pow_mod,
};

pub(super) fn mechanisms() -> Vec<(&'static str, Crc32c)> {
    let mut all = vec![("table", TABLE), ("detected", Crc32c::detect())];
    all.extend(hardware_mechanisms());
    all
}

/// Every hardware mechanism the host has: the detected one and the narrower one it extends, which is the detected one itself on a host without the wider extension.
fn hardware_mechanisms() -> Vec<(&'static str, Crc32c)> {
    let mut all = Vec::new();
    if let Some(hardware) = hardware() {
        all.push(("hardware", hardware));
    }
    #[cfg(target_arch = "x86_64")]
    if let Some(narrow) = narrow() {
        all.push(("narrow", narrow));
    }
    #[cfg(target_arch = "aarch64")]
    if let Some(instruction) = crc_instruction() {
        all.push(("crc instruction", instruction));
    }
    all
}

pub(super) fn seeded(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = SplitMix64::new(seed);
    (0..len).map(|_| rng.next_u64() as u8).collect()
}

#[test]
fn every_mechanism_returns_the_check_value() {
    for (name, crc) in mechanisms() {
        assert_eq!(crc.checksum(b"123456789"), 0xE306_9283, "{name}");
        assert_eq!(crc.checksum(&[0; 32]), 0x8A91_36AA, "{name}");
        assert_eq!(crc.checksum(&[0xFF; 32]), 0x62A8_AB43, "{name}");
        let ascending: Vec<u8> = (0..32).collect();
        assert_eq!(crc.checksum(&ascending), 0x46DD_794E, "{name}");
        assert_eq!(crc.checksum(&[]), 0, "{name}");
    }
}

/// Lengths around every three-chain group boundary: three blocks of each level, one less and one more, a level's group followed by the next level's, and the record shapes a fill and a read fold, up to a whole 40 KB payload.
pub(super) fn group_lengths() -> Vec<usize> {
    let mut lengths: Vec<usize> = (0..=64).chain([127, 255, 256, 511]).collect();
    for len in LEVELS {
        lengths.extend([3 * len - 1, 3 * len, 3 * len + 1, 3 * len + 8, 3 * len + 17]);
    }
    let all: usize = LEVELS.iter().map(|len| 3 * len).sum();
    lengths.extend([
        all - 1,
        all,
        all + 1,
        all + 7,
        6 * LEVELS[0],
        8088,
        8192,
        16384,
        40000,
    ]);
    lengths
}

#[test]
fn hardware_and_table_agree_on_every_tail_and_unaligned_start() {
    let bytes = seeded(16 + 66_177, 11);
    // Starts 0 to 15 reach every 16-byte alignment of the aarch64 fold's vector loads.
    // Lengths straddle the x86_64 step (128 bytes), the AVX-512 fold's four-block minimum (256), the x86_64 four-chain threshold (384) and the aarch64 240-byte fold step, below which one CRC chain runs, and end past the 2048-word carry table: 65,536 bytes is a whole number of segments and takes one segment entry, and 66,177 bytes leaves 80 words past four segments, so its shift constant combines a word entry with a segment entry.
    for start in 0..16 {
        for len in (0..=64).chain([
            127,
            128,
            129,
            239,
            240,
            241,
            255,
            256,
            257,
            383,
            384,
            385,
            511,
            512,
            513,
            1023,
            1024,
            1025,
            1024 + 239,
            1024 + 240,
            1024 + 241,
            4095,
            4096,
            4097,
            4096 + 127,
            8191,
            8192,
            8192 + 239,
            65_536,
            66_177,
        ]) {
            let input = &bytes[start..start + len];
            let expected = TABLE.checksum(input);
            for (name, crc) in hardware_mechanisms() {
                assert_eq!(
                    crc.checksum(input),
                    expected,
                    "{name} start {start} len {len}"
                );
            }
        }
    }
}

#[test]
fn every_count_of_blocks_after_the_last_group_matches_the_table() {
    let bytes = seeded(3 * 256 + 3 * 64 + 64, 41);
    let mut target = vec![0_u8; bytes.len() + 64];
    let line = target.as_ptr().addr().wrapping_neg() % 64;
    for groups in 1..=3 {
        for rest in 0..4 {
            for tail in [0, 1, 8, 63] {
                let len = 256 * groups + 64 * rest + tail;
                let input = &bytes[..len];
                let expected = TABLE.checksum(input);
                for (name, crc) in hardware_mechanisms() {
                    let shape = format!("{name} groups {groups} rest {rest} tail {tail}");
                    assert_eq!(crc.checksum(input), expected, "{shape}");
                    let to = &mut target[line..line + len];
                    to.fill(0);
                    let mut running = crc.start();
                    running.update_and_copy(input, to);
                    assert_eq!(running.finish(), expected, "{shape}");
                    assert_eq!(&*to, input, "{shape}");
                }
            }
        }
    }
}

/// Every length from the shortest three-chain input through the first streaming step agrees with the table, at every start: each third from 7 to 15 words takes a different set of unrolled blocks, and each length a different count of leftover words and tail bytes.
#[test]
fn hardware_and_table_agree_at_every_length_through_the_three_chain_range() {
    let Some(hardware) = hardware() else {
        return;
    };
    let bytes = seeded(8 + 512, 23);
    for start in 0..8 {
        for len in 160..=512 {
            let input = &bytes[start..start + len];
            assert_eq!(
                hardware.checksum(input),
                TABLE.checksum(input),
                "start {start} len {len}"
            );
        }
    }
}

#[test]
fn incremental_updates_finish_to_the_one_shot_checksum_at_every_split() {
    // Long enough that both sides of many splits take the parallel path, so its seeded register and its remainder both round-trip.
    let bytes = seeded(3000, 5);
    for (name, crc) in mechanisms() {
        let whole = crc.checksum(&bytes);
        for split in 0..=bytes.len() {
            let mut running = crc.start();
            running.update(&bytes[..split]);
            running.update(&bytes[split..]);
            assert_eq!(running.finish(), whole, "{name} split {split}");
        }
        for piece_len in [7, 1500] {
            let mut running = crc.start();
            for piece in bytes.chunks(piece_len) {
                running.update(piece);
            }
            assert_eq!(running.finish(), whole, "{name} {piece_len}-byte pieces");
        }
    }
}

/// Each zero-shift table advances a register through exactly its level's zero bytes.
#[test]
fn zero_shift_tables_match_zero_bytes_fed_through_the_table() {
    let mut rng = SplitMix64::new(17);
    for (len, table) in LEVELS.into_iter().zip(&SHIFTS) {
        let zeros = vec![0u8; len];
        for register in [0, 1, 0x80, 0x8000_0000, !0]
            .into_iter()
            .chain((0..64).map(|_| rng.next_u64() as u32))
        {
            assert_eq!(
                shift(table, register),
                update_table(register, &zeros),
                "level {len} register {register:#x}"
            );
        }
    }
}

/// The three-chain copying fold, stepped with the table, copies exactly what it folds and finishes to the table's one-shot value at every group shape.
#[test]
fn the_three_chain_copying_fold_under_the_table_step_matches_the_one_shot_table() {
    let step =
        |register: u64, word: u64| u64::from(update_table(register as u32, &word.to_le_bytes()));
    let bytes = seeded(40000 + 64, 19);
    for start in 0..3 {
        for len in group_lengths() {
            let input = &bytes[start..start + len];
            let whole = update_table(0x1234_5678, input);
            let mut target = vec![0xA5; len];
            let (register, folded) = fold_words_copy(0x1234_5678, input, &mut target, step);
            assert_eq!(folded % 8, 0);
            assert_eq!(
                &target[..folded],
                &input[..folded],
                "start {start} len {len}"
            );
            assert!(target[folded..].iter().all(|&byte| byte == 0xA5));
            assert_eq!(
                update_table(register as u32, &input[folded..]),
                whole,
                "start {start} len {len}"
            );
        }
    }
}

#[test]
fn a_copying_update_writes_exactly_its_input_and_folds_what_update_folds() {
    let bytes = seeded(64 + 16 + 40000, 13);
    for (name, crc) in mechanisms() {
        for start in 0..16 {
            for len in group_lengths() {
                let input = &bytes[start..start + len];
                let mut target = vec![0xA5; len + 32];
                let mut running = crc.start();
                running.update(&bytes[..3]);
                running.update_and_copy(input, &mut target[16..16 + len]);
                let mut expected = crc.start();
                expected.update(&bytes[..3]);
                expected.update(input);
                assert_eq!(
                    running.finish(),
                    expected.finish(),
                    "{name} start {start} len {len}"
                );
                assert_eq!(
                    &target[16..16 + len],
                    input,
                    "{name} start {start} len {len}"
                );
                assert!(
                    target[..16]
                        .iter()
                        .chain(&target[16 + len..])
                        .all(|&byte| byte == 0xA5),
                    "{name} start {start} len {len}: a byte outside the target changed"
                );
            }
        }
    }
}

#[test]
fn a_copying_update_matches_update_at_every_target_offset_in_a_line() {
    let bytes = seeded(8192 + 64 + 64, 29);
    let mut target = vec![0xA5_u8; 8192 + 3 * 64];
    let line = target.as_ptr().addr().wrapping_neg() % 64;
    for (name, crc) in mechanisms() {
        for offset in 0..64 {
            let head = (64 - offset) % 64;
            for len in [
                head + 255,
                head + 256,
                head + 257,
                head + 256 + 64 + 7,
                head + 256 + 2 * 64 + 7,
                head + 256 + 3 * 64 + 7,
                head + 4 * 64 + 63,
                head + 8 * 64 + 1,
                8191,
            ] {
                let input = &bytes[offset..offset + len];
                target.fill(0xA5);
                let at = line + 64 + offset;
                let mut running = crc.start();
                running.update(&bytes[..5]);
                running.update_and_copy(input, &mut target[at..at + len]);
                let mut expected = crc.start();
                expected.update(&bytes[..5]);
                expected.update(input);
                assert_eq!(
                    running.finish(),
                    expected.finish(),
                    "{name} offset {offset} len {len}"
                );
                assert_eq!(
                    &target[at..at + len],
                    input,
                    "{name} offset {offset} len {len}"
                );
                assert!(
                    target[..at]
                        .iter()
                        .chain(&target[at + len..])
                        .all(|&byte| byte == 0xA5),
                    "{name} offset {offset} len {len}: a byte outside the target changed"
                );
            }
        }
    }
}

#[test]
fn x_pow_mod_matches_repeated_multiplication_by_x_and_adds_exponents() {
    let mut value = 1 << 31;
    for power in 0..=4096u64 {
        assert_eq!(x_pow_mod(power), value, "power {power}");
        value = times_x(value);
    }
    // The fold and shift constants rely on x^(a + b) = x^a * x^b far past the range walked above.
    for (a, b) in [
        (1u64 << 40, 4096u64),
        (u64::MAX >> 1, 33),
        (64 * 3 * 517, 64 * 4 * 517),
    ] {
        assert_eq!(
            x_pow_mod(a.wrapping_add(b)),
            mul_mod(x_pow_mod(a), x_pow_mod(b)),
            "exponents {a} + {b}"
        );
    }
}

#[test]
fn checksums_allocate_nothing() {
    let bytes = seeded(4096, 3);
    let crc = Crc32c::detect();
    let before = crate::instrument::allocations();
    let mut running = crc.start();
    running.update(&bytes);
    assert_eq!(running.finish(), crc.checksum(&bytes));
    assert_eq!(crate::instrument::allocations(), before);
}

#[test]
fn hardware_and_table_agree_across_every_pass_length_and_split() {
    for (name, hardware) in hardware_mechanisms() {
        agree_across_pass_lengths_and_splits(name, hardware);
    }
}

fn agree_across_pass_lengths_and_splits(name: &str, hardware: Crc32c) {
    let bytes = seeded(20_008, 13);
    let boundaries = [2720, 2728, 4080, 6800, 8160, 12_240];
    let lengths = (0..=1200).chain(
        boundaries
            .into_iter()
            .flat_map(|at| at - 16..=at + 16)
            .chain([4096, 8192, 16_384, 20_000]),
    );
    for len in lengths {
        for start in 0..8 {
            let input = &bytes[start..start + len];
            assert_eq!(
                hardware.checksum(input),
                TABLE.checksum(input),
                "{name} start {start} len {len}"
            );
        }
    }
    let mut rng = SplitMix64::new(17);
    for _ in 0..200 {
        let len = rng.below(20_000) as usize;
        let split = rng.below(len as u64 + 1) as usize;
        let input = &bytes[..len];
        let mut running = hardware.start();
        running.update(&input[..split]);
        running.update(&input[split..]);
        assert_eq!(
            running.finish(),
            TABLE.checksum(input),
            "{name} len {len} split {split}"
        );
    }
}

/// A zero run advances a register exactly as feeding that many zero bytes does, for every mechanism, at lengths through the word and multi-word boundaries the mechanisms treat differently.
#[test]
fn a_zero_run_advances_a_register_like_zero_bytes_fed_through_the_mechanism() {
    let mut rng = SplitMix64::new(23);
    let lengths = (0..70u64).chain([
        127, 128, 129, 596, 1024, 2132, 4095, 4096, 7596, 8191, 8192, 16_384, 16_391, 16_392,
        65_539,
    ]);
    for (name, crc) in mechanisms() {
        for len in lengths.clone() {
            let run = crc.zero_run(len);
            let zeros = vec![0u8; len as usize];
            for register in [0, 1, 0x8000_0000, !0]
                .into_iter()
                .chain((0..8).map(|_| rng.next_u64() as u32))
            {
                let mut fed = RunningCrc::from_register(crc, register);
                fed.update(&zeros);
                assert_eq!(
                    run.advance(register),
                    fed.register(),
                    "{name} len {len} register {register:#x}"
                );
            }
        }
    }
}

/// The zero-byte step of the reflected Castagnoli register as a GF(2) matrix:
/// column `i` is the register holding only bit `i` after one zero byte. Each
/// of the byte's eight bit steps shifts the register right and xors in the
/// polynomial when the bit shifted out is set.
fn byte_step() -> [u32; 32] {
    let mut columns = [0u32; 32];
    for (bit, column) in columns.iter_mut().enumerate() {
        let mut register = 1u32 << bit;
        for _ in 0..8 {
            let carry = register & 1;
            register >>= 1;
            if carry == 1 {
                register ^= 0x82F6_3B78;
            }
        }
        *column = register;
    }
    columns
}

/// The matrix `columns` applied to `register`: the xor of the columns of its set bits.
fn apply_matrix(columns: &[u32; 32], mut register: u32) -> u32 {
    let (mut sum, mut column) = (0, 0);
    while register != 0 {
        if register & 1 == 1 {
            sum ^= columns[column];
        }
        register >>= 1;
        column += 1;
    }
    sum
}

/// The matrix product `outer * inner`: `inner` applied first.
fn compose_matrices(outer: &[u32; 32], inner: &[u32; 32]) -> [u32; 32] {
    std::array::from_fn(|column| apply_matrix(outer, inner[column]))
}

/// The matrix that carries a register past `len` zero bytes, by square-and-multiply
/// of the byte-step matrix over all 64 bits of `len`. It is independent of the
/// mechanisms' run constants, shift tables and word counts, and every value it
/// forms is a 32-by-32 GF(2) matrix.
fn oracle_matrix(len: u64) -> [u32; 32] {
    let mut power = byte_step();
    let mut result = core::array::from_fn(|bit| 1u32 << bit);
    let mut remaining = len;
    while remaining > 0 {
        if remaining & 1 == 1 {
            result = compose_matrices(&power, &result);
        }
        power = compose_matrices(&power, &power);
        remaining >>= 1;
    }
    result
}

/// Advances `register` through `len` zero bytes using the byte-step oracle of
/// [`oracle_matrix`].
pub(super) fn oracle_advance(mut register: u32, len: u64) -> u32 {
    let mut power = byte_step();
    let mut remaining = len;
    while remaining > 0 {
        if remaining & 1 == 1 {
            register = apply_matrix(&power, register);
        }
        remaining >>= 1;
        if remaining > 0 {
            power = compose_matrices(&power, &power);
        }
    }
    register
}

/// The lengths the zero-run contract is checked at: every length through 70,
/// 16,376 through 16,400 around the word-shift table's end, where 16,392 bytes
/// is the first length past it, both sides of `2^32`, `2^61` and `2^62`, and `u64::MAX - 1` and
/// `u64::MAX`, where a byte count times eight leaves `u64`.
fn exact_lengths() -> Vec<u64> {
    let mut lengths: Vec<u64> = (0..=70).chain(16_376..=16_400).collect();
    for edge in [1u64 << 32, 1 << 61, 1 << 62] {
        lengths.extend([edge - 1, edge, edge + 1]);
    }
    lengths.extend([u64::MAX - 1, u64::MAX]);
    lengths
}

/// For every mechanism the host has, a zero run of every checked length, up to
/// `u64::MAX`, carries each checked register, `0`, `!0`, `1`, `0x8000_0000`
/// and four seeded values, exactly as the independent byte-step oracle does, and the run's initial register, which `from_zero` exposes for
/// a checksum of `!0`, is the oracle's advance of `!0`.
/// [`oracle_advance`] agrees with [`oracle_matrix`] on `!0` at every checked length.
#[test]
fn a_zero_run_of_any_u64_length_matches_the_byte_step_oracle() {
    let mut rng = SplitMix64::new(61);
    let registers: Vec<u32> = [0, !0, 1, 0x8000_0000]
        .into_iter()
        .chain((0..4).map(|_| rng.next_u64() as u32))
        .collect();
    for len in exact_lengths() {
        let oracle = oracle_matrix(len);
        let expected: Vec<u32> = registers
            .iter()
            .map(|&r| apply_matrix(&oracle, r))
            .collect();
        let initial = apply_matrix(&oracle, !0);
        assert_eq!(oracle_advance(!0, len), initial, "oracle advance len {len}");
        for (name, crc) in mechanisms() {
            let run = crc.zero_run(len);
            for (&register, &expected) in registers.iter().zip(&expected) {
                assert_eq!(
                    run.advance(register),
                    expected,
                    "{name} len {len} register {register:#x}"
                );
            }
            assert_eq!(crc.from_zero(!0, &run), initial, "{name} len {len} initial");
        }
    }
}

/// `append`, `combine`, `from_zero` and `checksum_of` keep their identities at
/// lengths from `2^61 - 1` to `u64::MAX` on every mechanism, partial-word
/// lengths included, matching the oracle's carry of each checksum past each
/// length.
#[test]
fn zero_run_algebra_holds_at_lengths_a_slice_cannot_hold() {
    let mut rng = SplitMix64::new(67);
    let large = [
        (1u64 << 61) - 1,
        1 << 61,
        (1 << 61) + 8,
        1 << 62,
        (1 << 62) + 1,
        u64::MAX - 7,
        u64::MAX,
    ];
    for len in large {
        let oracle = oracle_matrix(len);
        let carried = |register| apply_matrix(&oracle, register);
        let (first, second) = (rng.next_u64() as u32, rng.next_u64() as u32);
        let initial = carried(!0);
        for (name, crc) in mechanisms() {
            let run = crc.zero_run(len);
            assert_eq!(
                crc.combine(first, &run, second),
                carried(first) ^ second,
                "{name} combine {len}"
            );
            assert_eq!(
                crc.append(first, &run, second),
                carried(first) ^ second,
                "{name} append {len}"
            );
            assert_eq!(
                crc.from_zero(first, &run),
                !first ^ initial,
                "{name} from_zero {len}"
            );
            assert_eq!(
                crc.checksum_of(second, &run),
                !(initial ^ second),
                "{name} checksum_of {len}"
            );
            assert_eq!(
                crc.checksum_of(crc.from_zero(first, &run), &run),
                first,
                "{name} from_zero and checksum_of invert at {len}"
            );
        }
    }
}

/// `combine` joins two checksums into the checksum of the concatenation, `append` joins two registers, and `from_zero` and `checksum_of` invert each other, for every mechanism and across unaligned splits.
#[test]
fn combine_and_append_rebuild_the_checksum_of_a_concatenation() {
    let bytes = seeded(20_000, 29);
    for (name, crc) in mechanisms() {
        for (first_len, second_len) in [
            (0usize, 0usize),
            (0, 7),
            (7, 0),
            (1, 1),
            (5, 13),
            (596, 7596),
            (7596, 596),
            (8192, 8192),
            (3, 16_384),
            (12_345, 7_000),
        ] {
            let (first, second) = (
                &bytes[..first_len],
                &bytes[first_len..first_len + second_len],
            );
            let whole = crc.checksum(&bytes[..first_len + second_len]);
            let tail = crc.zero_run(second_len as u64);
            assert_eq!(
                crc.combine(crc.checksum(first), &tail, crc.checksum(second)),
                whole,
                "{name} combine {first_len} + {second_len}"
            );
            let joined = crc.append(!crc.checksum(first), &tail, crc.fold_from_zero(second));
            assert_eq!(!joined, whole, "{name} append {first_len} + {second_len}");
            let run = crc.zero_run(first_len as u64);
            let from_zero = crc.from_zero(crc.checksum(first), &run);
            assert_eq!(
                from_zero,
                crc.fold_from_zero(first),
                "{name} from_zero {first_len}"
            );
            assert_eq!(
                crc.checksum_of(from_zero, &run),
                crc.checksum(first),
                "{name} checksum_of {first_len}"
            );
        }
    }
}

/// `combine_chunks` rebuilds the checksum of the bytes before a payload and the payload itself from the checksum of the first bytes and each chunk's checksum, for every mechanism, over chunk counts on both sides of the aarch64 group size, windows from one unit to past the carry table, and first and last chunks of one byte, a few bytes and a whole window.
#[test]
fn combine_chunks_rebuilds_the_checksum_of_a_payload() {
    // Units the inner chunks of a case span at most, and the widest window.
    const LIMIT_UNITS: usize = 300;
    const WIDEST: usize = 66;
    let reference = Crc32c::detect();
    let bytes = seeded((LIMIT_UNITS + 2 * WIDEST) * IO_UNIT + 64, 0x1284);
    let counts = [
        0usize, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 32, 33, 62, 63, 64, 65, 66, 67, 129, 130,
        131,
    ];
    let mechanisms = mechanisms();
    for units in [1usize, 2, 3, 7, 16, 21, 32, 33, 63, 64, 65, WIDEST] {
        let window = units * IO_UNIT;
        for head in [0, 37] {
            let before = reference.checksum(&bytes[..head]);
            for first in [1, 4, window] {
                // Each inner window's checksum, the windows starting after the first chunk.
                let windows: Vec<[u8; 4]> = (0..LIMIT_UNITS / units)
                    .map(|i| {
                        let at = head + first + i * window;
                        reference.checksum(&bytes[at..at + window]).to_le_bytes()
                    })
                    .collect();
                for &count in &counts {
                    if count.saturating_sub(2) * units > LIMIT_UNITS {
                        continue;
                    }
                    for last in [1, 13, window] {
                        let (checksums, len) = match count {
                            0 => (Vec::new(), 0),
                            1 => (
                                vec![reference.checksum(&bytes[head..head + last]).to_le_bytes()],
                                last,
                            ),
                            _ => {
                                let at = head + first + (count - 2) * window;
                                let mut checksums = vec![
                                    reference.checksum(&bytes[head..head + first]).to_le_bytes(),
                                ];
                                checksums.extend_from_slice(&windows[..count - 2]);
                                checksums
                                    .push(reference.checksum(&bytes[at..at + last]).to_le_bytes());
                                (checksums, first + (count - 2) * window + last)
                            }
                        };
                        let chunks = Chunks {
                            checksums: &checksums,
                            units: units as u64,
                            last_len: if count == 0 { 0 } else { last as u64 },
                            len: len as u64,
                        };
                        let expected = reference.checksum(&bytes[..head + len]);
                        for (name, crc) in &mechanisms {
                            assert_eq!(
                                crc.combine_chunks(before, &chunks),
                                expected,
                                "{name}: head {head}, first {first}, {count} chunks of {units} units, last {last}",
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn the_compile_time_register_fold_matches_every_mechanism() {
    let mut rng = SplitMix64::new(41);
    let bytes = seeded(24, 43);
    for (name, crc) in mechanisms() {
        for len in 0..=bytes.len() {
            for register in [0, !0, rng.next_u64() as u32] {
                let mut running = RunningCrc::from_register(crc, register);
                running.update(&bytes[..len]);
                assert_eq!(
                    register_after(register, &bytes[..len]),
                    running.register(),
                    "{name} {len} bytes from {register:#x}"
                );
            }
        }
    }
}

/// `combine_chunks` joins a first chunk, 0 to 63 whole 4096-byte windows and a last chunk in order, for every mechanism, with first chunks of 5 to 4092 bytes, including the 3744 bytes behind a 352-byte header, and last chunks of 1 to 4100 bytes.
#[test]
fn combine_chunks_joins_a_first_chunk_windows_and_a_last_chunk_in_order() {
    let bytes = seeded(13 + 3 * 4100 + 63 * 4096, 37);
    let (first, rest) = bytes.split_at(13);
    for (name, crc) in mechanisms() {
        for (head, tail) in [(3744, 352), (3988, 108), (4092, 1), (5, 4100), (8, 7)] {
            for count in [0usize, 1, 7, 8, 9, 17, 26, 31, 32, 33, 47, 48, 61, 63] {
                let (head_bytes, rest) = rest.split_at(head);
                let (middle_bytes, rest) = rest.split_at(count * 4096);
                let tail_bytes = &rest[..tail];
                let mut checksums = vec![crc.checksum(head_bytes).to_le_bytes()];
                checksums.extend(
                    middle_bytes
                        .chunks(4096)
                        .map(|block| crc.checksum(block).to_le_bytes()),
                );
                checksums.push(crc.checksum(tail_bytes).to_le_bytes());
                let chunks = Chunks {
                    checksums: &checksums,
                    units: 1,
                    last_len: tail as u64,
                    len: (head + count * 4096 + tail) as u64,
                };
                assert_eq!(
                    crc.combine_chunks(crc.checksum(first), &chunks),
                    crc.checksum(&bytes[..13 + head + count * 4096 + tail]),
                    "{name} {head} then {count} windows then {tail}"
                );
            }
        }
    }
}

/// `update_words` over `N` words from a seeded register folds what `update` folds over the same bytes, and `checksum_words` is their checksum.
fn word_folds_agree<const N: usize>(name: &str, crc: Crc32c, bytes: &[u8]) {
    let (prefix, rest) = bytes.split_at(13);
    let words: &[[u8; 8]; N] = rest.as_chunks::<8>().0.first_chunk().unwrap();
    let mut running = crc.start();
    running.update(prefix);
    let mut expected = running;
    running.update_words(words);
    expected.update(words.as_flattened());
    assert_eq!(running.finish(), expected.finish(), "{name} {N} words");
    assert_eq!(
        crc.checksum_words(words),
        crc.checksum(words.as_flattened()),
        "{name} checksum of {N} words"
    );
}

/// `update_words_masked` reads word `AT` under the mask: it folds what `update` folds over the bytes with that word masked.
fn masked_word_fold_agrees<const N: usize, const AT: usize>(name: &str, crc: Crc32c, bytes: &[u8]) {
    let words: &[[u8; 8]; N] = bytes.as_chunks::<8>().0.first_chunk().unwrap();
    for mask in [0, !0xFFFF_FFFF, 0xFFFF_FFFF, 0x00FF_00FF_00FF_00FF, !0] {
        let mut masked = *words;
        masked[AT] = (u64::from_le_bytes(words[AT]) & mask).to_le_bytes();
        let mut running = crc.start();
        running.update(&bytes[..5]);
        let mut expected = running;
        running.update_words_masked::<N, AT>(words, mask);
        expected.update(masked.as_flattened());
        assert_eq!(
            running.finish(),
            expected.finish(),
            "{name} {N} words, word {AT} under {mask:#x}"
        );
    }
}

/// Word counts on both sides of each chain-count boundary through four chains, the 22 words the frame header uses and their neighbours, fold as the variable-length fold does, under every mechanism.
#[test]
fn compile_time_word_counts_fold_like_the_variable_length_fold() {
    let bytes = seeded(400, 11);
    for (name, crc) in mechanisms() {
        word_folds_agree::<1>(name, crc, &bytes);
        word_folds_agree::<2>(name, crc, &bytes);
        word_folds_agree::<3>(name, crc, &bytes);
        word_folds_agree::<5>(name, crc, &bytes);
        word_folds_agree::<6>(name, crc, &bytes);
        word_folds_agree::<7>(name, crc, &bytes);
        word_folds_agree::<11>(name, crc, &bytes);
        word_folds_agree::<12>(name, crc, &bytes);
        word_folds_agree::<17>(name, crc, &bytes);
        word_folds_agree::<18>(name, crc, &bytes);
        word_folds_agree::<20>(name, crc, &bytes);
        word_folds_agree::<22>(name, crc, &bytes);
        word_folds_agree::<23>(name, crc, &bytes);
        word_folds_agree::<24>(name, crc, &bytes);
        word_folds_agree::<25>(name, crc, &bytes);
        word_folds_agree::<40>(name, crc, &bytes);
        masked_word_fold_agrees::<1, 0>(name, crc, &bytes);
        masked_word_fold_agrees::<2, 1>(name, crc, &bytes);
        masked_word_fold_agrees::<7, 0>(name, crc, &bytes);
        masked_word_fold_agrees::<7, 6>(name, crc, &bytes);
        masked_word_fold_agrees::<22, 0>(name, crc, &bytes);
        masked_word_fold_agrees::<22, 7>(name, crc, &bytes);
        masked_word_fold_agrees::<22, 20>(name, crc, &bytes);
        masked_word_fold_agrees::<22, 21>(name, crc, &bytes);
    }
}

thread_local! {
    static BYTE_FOLDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn counted_update(register: u32, bytes: &[u8]) -> u32 {
    BYTE_FOLDS.with(|folds| folds.set(folds.get() + 1));
    update_table(register, bytes)
}

/// The byte-fold calls and the checksum of `update_words_masked::<22, AT>` under the table mechanism, whose word folds run through its byte fold as the AArch64 mechanisms' do.
fn masked_header_folds<const AT: usize>(words: &[[u8; 8]; 22]) -> (usize, u32) {
    let crc = Crc32c::over_update(counted_update);
    BYTE_FOLDS.with(|folds| folds.set(0));
    let mut running = crc.start();
    running.update_words_masked::<22, AT>(words, !0xFFFF_FFFF);
    (BYTE_FOLDS.with(std::cell::Cell::get), running.finish())
}

/// A masked word among a span's last two words folds together with the words after it, so the frame header, whose checksum field lies in word 20 of 22, costs two byte-fold calls: the prefix, then one tail.
#[test]
fn a_masked_word_near_the_end_folds_with_the_rest_of_the_span_in_one_call() {
    let bytes = seeded(176, 23);
    let words: &[[u8; 8]; 22] = bytes.as_chunks::<8>().0.first_chunk().unwrap();
    for (at, (folds, checksum)) in [
        (20, masked_header_folds::<20>(words)),
        (21, masked_header_folds::<21>(words)),
    ] {
        let mut masked = *words;
        masked[at] = (u64::from_le_bytes(words[at]) & !0xFFFF_FFFF).to_le_bytes();
        assert_eq!(folds, 2, "word {at}");
        assert_eq!(checksum, TABLE.checksum(masked.as_flattened()), "word {at}");
    }
}

/// `checksum_written` folds what `checksum` folds over the words with word `AT` masked, from every start offset of a buffer, with the frame header's 22 words and its crc word.
#[cfg(target_arch = "aarch64")]
#[test]
fn written_word_folds_match_the_variable_length_fold() {
    let bytes = seeded(16 + 22 * 8 * 8, 17);
    let mut lanes_ran = false;
    for (name, crc) in mechanisms() {
        if !crc.folds_lanes() {
            continue;
        }
        lanes_ran = true;
        for start in 0..16 {
            for at in (start..bytes.len() - 22 * 8).step_by(22 * 8) {
                let words: &[[u8; 8]; 22] = bytes[at..].as_chunks::<8>().0.first_chunk().unwrap();
                let mut masked = *words;
                masked[20] = (u64::from_le_bytes(words[20]) & !0xFFFF_FFFF).to_le_bytes();
                // SAFETY: a mechanism folds lanes only on a CPU with the CRC and AES extensions.
                let (whole, holed) = unsafe {
                    (
                        Crc32c::checksum_written::<22, 22>(words, 0),
                        Crc32c::checksum_written::<22, 20>(words, !0xFFFF_FFFF),
                    )
                };
                assert_eq!(whole, crc.checksum(words.as_flattened()), "{name} at {at}");
                assert_eq!(
                    holed,
                    crc.checksum(masked.as_flattened()),
                    "{name} masked at {at}"
                );
            }
        }
    }
    assert_eq!(
        lanes_ran,
        std::arch::is_aarch64_feature_detected!("crc")
            && std::arch::is_aarch64_feature_detected!("aes")
    );
}

#[test]
fn mul_mod_matches_shift_and_add_multiplication() {
    let shift_and_add = |a: u32, b: u32| {
        let mut product = 0;
        let mut term = a;
        for degree in 0..32 {
            if b >> (31 - degree) & 1 == 1 {
                product ^= term;
            }
            term = times_x(term);
        }
        product
    };
    let mut operands: Vec<u32> = (0..32).map(|bit| 1 << bit).collect();
    operands.extend([0, !0, 0x82F6_3B78, 0x1234_5678]);
    for &a in &operands {
        for &b in &operands {
            assert_eq!(mul_mod(a, b), shift_and_add(a, b), "{a:#x} * {b:#x}");
        }
    }
    let mut rng = SplitMix64::new(71);
    for _ in 0..20_000 {
        let (a, b) = (rng.next_u64() as u32, rng.next_u64() as u32);
        assert_eq!(mul_mod(a, b), shift_and_add(a, b), "{a:#x} * {b:#x}");
    }
}

#[test]
fn zero_runs_at_every_reachable_digit_constant_match_the_byte_step_oracle() {
    let mut rng = SplitMix64::new(73);
    let seed_words = oracle_matrix(16_376);
    let mut check = |len: u64, oracle: &[u32; 32]| {
        let register = rng.next_u64() as u32;
        for (name, crc) in mechanisms() {
            let run = crc.zero_run(len);
            assert_eq!(
                run.advance(register),
                apply_matrix(oracle, register),
                "{name} len {len} register {register:#x}"
            );
            assert_eq!(
                crc.from_zero(!0, &run),
                apply_matrix(oracle, !0),
                "{name} len {len} initial"
            );
        }
    };
    for k in 0..8 {
        let unit = 1u64 << (8 * k);
        let step = oracle_matrix(unit);
        let mut oracle = step;
        for d in 1..256 {
            check(d * unit, &oracle);
            oracle = compose_matrices(&step, &oracle);
        }
        let Some(segments) = unit.checked_mul(16_384) else {
            continue;
        };
        let step = oracle_matrix(segments);
        let mut oracle = step;
        for d in 1..256 {
            let Some(len) = segments.checked_mul(d) else {
                break;
            };
            // `len` is a multiple of 16,384 at most `u64::MAX`, so 16,376 more stays below `2^64`.
            check(len + 16_376, &compose_matrices(&seed_words, &oracle));
            check(len, &oracle);
            oracle = compose_matrices(&step, &oracle);
        }
    }
}

/// Holds `crc` to the table at every shape its kernels divide on: empty and short inputs, every length from 0 to 64, the lengths around the aarch64 fold's 240-byte step and the x86_64 chain, stream and AVX-512 thresholds, long and odd inputs, each at every start within a 16-byte line; every input also folds and copies in two pieces at several splits, and copies whole into a target between guard bytes at a start that varies within a line, so a lane's contribution, a tail, a copied byte or a byte past the copy that differs fails.
fn mechanism_matches_the_table(name: &str, crc: Crc32c) {
    // 258 whole AVX-512 groups of 256 bytes and 275 aarch64 fold steps of 240 bytes, past 64 KiB, and odd, so the longest input ends on a tail.
    const LONGEST: usize = 66_177;
    assert_eq!(crc.checksum(b"123456789"), 0xE306_9283, "{name}");
    let bytes = seeded(16 + LONGEST, 0x15A);
    let lengths = (0..=64).chain([
        127,
        128,
        129,
        175,
        176,
        239,
        240,
        241,
        255,
        256,
        257,
        383,
        384,
        385,
        511,
        512,
        513,
        1023,
        1024,
        1025,
        4095,
        4096,
        4097,
        8191,
        8192,
        8192 + 239,
        LONGEST,
    ]);
    let mut target = vec![0; LONGEST + 128];
    for start in 0..16 {
        for len in lengths.clone() {
            let input = &bytes[start..start + len];
            let expected = TABLE.checksum(input);
            let shape = format!("{name} start {start} len {len}");
            assert_eq!(crc.checksum(input), expected, "{shape}");
            let at = 64 + start * 7 % 64;
            for split in [1, len / 3, len / 2, len.saturating_sub(1)] {
                let split = split.min(len);
                let mut running = crc.start();
                running.update(&input[..split]);
                running.update(&input[split..]);
                assert_eq!(running.finish(), expected, "{shape} split {split}");
                target.fill(0xA5);
                let (head, tail) = target[at..at + len].split_at_mut(split);
                let mut running = crc.start();
                running.update_and_copy(&input[..split], head);
                running.update_and_copy(&input[split..], tail);
                assert_eq!(
                    running.finish(),
                    expected,
                    "{shape} copied in two at {split}"
                );
                assert_eq!(
                    &target[at..at + len],
                    input,
                    "{shape} copied in two at {split}"
                );
            }
            target.fill(0xA5);
            let mut running = crc.start();
            running.update_and_copy(input, &mut target[at..at + len]);
            assert_eq!(running.finish(), expected, "{shape} copied");
            assert_eq!(&target[at..at + len], input, "{shape} copied bytes");
            assert!(
                target[..at]
                    .iter()
                    .chain(&target[at + len..])
                    .all(|&byte| byte == 0xA5),
                "{shape} bytes outside the copy"
            );
        }
    }
}

/// The aarch64 CRC-instruction mechanism runs its kernel and matches the table at every shape; on a host without `crc` it reports itself unreached.
#[test]
fn the_crc_instruction_kernel_runs_and_matches_the_table() {
    use crate::isa_witness::{Kernel, detected, runs, witness};
    witness(
        "crc-instruction",
        detected!(aarch64: "crc"),
        || runs(Kernel::CrcInstruction),
        || {
            #[cfg(target_arch = "aarch64")]
            if let Some(crc) = crc_instruction() {
                mechanism_matches_the_table("crc instruction", crc);
            }
        },
    );
}

/// The aarch64 carry-less multiply mechanism folds its inputs of one 240-byte step or more and matches the table at every shape; on a host without `crc` and `aes` it reports itself unreached.
#[test]
fn the_pmull_fold_runs_and_matches_the_table() {
    use crate::isa_witness::{Kernel, detected, runs, witness};
    witness(
        "crc-pmull",
        detected!(aarch64: "crc", "aes"),
        || runs(Kernel::CrcPmull),
        || {
            #[cfg(target_arch = "aarch64")]
            if let Some(crc) = hardware() {
                mechanism_matches_the_table("pmull", crc);
            }
        },
    );
}

/// The x86_64 SSE4.2 and carry-less multiply mechanism runs its kernels and matches the table at every shape; on a host without `sse4.2` and `pclmulqdq` it reports itself unreached.
#[test]
fn the_narrow_x86_kernels_run_and_match_the_table() {
    use crate::isa_witness::{Kernel, detected, runs, witness};
    witness(
        "crc-narrow",
        detected!(x86_64: "sse4.2", "pclmulqdq"),
        || runs(Kernel::CrcNarrow),
        || {
            #[cfg(target_arch = "x86_64")]
            if let Some(crc) = narrow() {
                mechanism_matches_the_table("narrow", crc);
            }
        },
    );
}

/// The x86_64 AVX-512 mechanism folds its inputs of four blocks or more in its accumulators and matches the table at every shape; on a host without `sse4.2`, `pclmulqdq`, `avx512f` and `vpclmulqdq` it reports itself unreached.
#[test]
fn the_wide_x86_fold_runs_and_matches_the_table() {
    use crate::isa_witness::{Kernel, detected, runs, witness};
    witness(
        "crc-wide",
        detected!(x86_64: "sse4.2", "pclmulqdq", "avx512f", "vpclmulqdq"),
        || runs(Kernel::CrcWide),
        || {
            #[cfg(target_arch = "x86_64")]
            if let Some(crc) = hardware() {
                mechanism_matches_the_table("wide", crc);
            }
        },
    );
}
