//! crc32c (Castagnoli): reflected polynomial `0x82F63B78`, initial value and final xor `0xFFFFFFFF`, check value `0xE3069283` for `"123456789"`.
//!
//! [`Crc32c::detect`] returns the same mechanism on every call in a process: on x86_64 the SSE4.2 `crc32` instruction together with the carry-less multiply, with AVX-512 carry-less folding for inputs of `WIDE_MIN` bytes or more when the CPU also reports `avx512f` and `vpclmulqdq`, on aarch64 the CRC and AES extensions together, or the CRC extension alone when that is all the standard library's runtime detection reports, and a slicing-by-8 table otherwise.
//! The x86_64 mechanism runs one `crc32` chain over inputs shorter than `CHAINS_MIN`, three chains over thirds of inputs below `STREAMS_MIN`, joined with two carry-less multiplies, and otherwise four chains and two carry-less fold lanes over five regions of the input at once, combined with carry-less multiplies.
//! With the AVX-512 extensions, inputs shorter than `WIDE_MIN` take that path and inputs of `WIDE_MIN` bytes or more fold in four 64-byte AVX-512 accumulators over consecutive blocks, each stepping 256 bytes; the four and the blocks after the last whole group each carry straight to the last whole block's final 16 bytes, which then pass through the `crc32` chain with the tail.
//! The aarch64 mechanism passes inputs shorter than its 240-byte step through one chain of CRC instructions; from one step it folds from a zero register, so the fold starts before the caller's register is known, and carries that register past the input's length with one carry-less multiply to join the two at the end.
//! Inputs of a whole step or more fold in [`LANES`] 16-byte accumulators with the AES extension's carry-less multiply; each step also leads with [`LEAD`] bytes for the CRC instructions, which run on their own pipe while the vector pipes fold.
//! The accumulators then fold into one, which folds forward past the last step's lead before two CRC instructions reduce it; the lead's register joins the result, and the bytes after the last step pass through the CRC instructions from that register.
//! A span of words fixed at compile time, an even count from 4 to 22, folds on aarch64 as 16-byte lanes in one straight-line pass, each lane carried to the last by its distance's constants; for words a caller just wrote in eight-byte stores, the first six instead pass through the CRC instructions on eight-byte loads, which those stores forward to.
//! Every mechanism computes the same function, so a record written under one verifies under another.
//! A hardware function is reachable only through the value detection returned, which is what makes its `unsafe` call sound.
//! Checksums are incremental: [`RunningCrc`] folds successive slices and finishes to the checksum of their concatenation, a [`ZeroRun`] carries a register past any `u64` count of zero bytes with one carry-less multiply, so [`Crc32c::combine`] joins two checksums into their concatenation's and [`Crc32c::combine_chunks`] joins a checksum with a payload's chunk checksums through one mechanism dispatch, and nothing here allocates.
//!
//! A fill copies each received piece into its receive-write buffer while folding it, through `update_and_copy`; when a piece of at least the fill's `DERIVE_MIN` bytes arrives with its verified crc32c, the fill copies each run within one chunk that is at least as long as the piece's bytes after it with `copy_from_slice` and derives that run's register from the crc32c with [`Crc32c::from_zero`], [`Crc32c::fold_from_zero`] and [`Crc32c::append`].
//! On aarch64 with the AES extension, `update_and_copy` runs the same folding steps as `update`, storing each loaded word and vector through a [`Sink`] as the fold consumes it, so every input byte is loaded once. With the x86_64 AVX-512 extensions, `update_and_copy` copies inside the wide fold once the target reaches a 64-byte boundary. The other hardware mechanisms copy through [`fold_words_copy`].
//! The hardware instruction folds eight bytes per issue but each result waits two or three cycles on the one before it, so [`fold_words_copy`] folds three consecutive blocks of equal length on three independent chains while it stores them, and joins the three registers with the zero-shift tables of [`SHIFTS`]: the register is linear in its bytes, so the register after `A ++ B ++ C` is the register after `A` advanced through `len(B ++ C)` zero bytes, xor the register of `B` from zero advanced through `len(C)` zero bytes, xor the register of `C` from zero.
//! The block lengths come from [`LEVELS`], largest first, so an input of 384 bytes or more spends most of its words on three chains; the remainder below three smallest blocks, and any shorter input, folds on one.

use std::sync::atomic::{Ordering, compiler_fence};

use super::super::layout::IO_UNIT;
use super::super::prefetch::hint;
#[cfg(target_arch = "x86_64")]
use super::super::prefetch::hint_read;

/// The reflected Castagnoli polynomial.
const POLY: u32 = 0x82F6_3B78;

/// Block lengths of the three-chain groups, in bytes, each a multiple of 32: a group folds three consecutive blocks of one length, and an input takes groups of each length in turn while three blocks of it remain.
pub(super) const LEVELS: [usize; 3] = [2048, 512, 128];

const _: () = assert!(
    LEVELS[0].is_multiple_of(32) && LEVELS[1].is_multiple_of(32) && LEVELS[2].is_multiple_of(32)
);

/// `SHIFTS[k][i][b]` is the register a register holding byte `b` at byte position `i` becomes after `LEVELS[k]` zero bytes; [`shift`] sums the four positions of a whole register.
pub(super) static SHIFTS: [[[u32; 256]; 4]; 3] = [
    zero_shift(LEVELS[0]),
    zero_shift(LEVELS[1]),
    zero_shift(LEVELS[2]),
];

/// One crc32c mechanism, chosen once by [`Crc32c::detect`].
#[derive(Debug, Clone, Copy)]
pub struct Crc32c {
    /// Folds bytes into a register that holds the inverted running value.
    update: fn(u32, &[u8]) -> u32,
    /// `update_and_copy` uses `update`'s inverted-register convention and requires a target with the source's length.
    update_and_copy: fn(u32, &[u8], &mut [u8]) -> u32,
    /// The constant [`advance`](Self::advance) multiplies a register by to carry it past a run of zero bytes, and the initial register `!0` carried past the run, both from the run's length.
    run: fn(u64) -> (u32, u32),
    /// Carries a register past a run of zero bytes: the register, then the run's constant from `run`.
    advance: fn(u32, u32) -> u32,
    /// Joins a checksum with a payload's chunks, as [`Crc32c::combine_chunks`] states.
    combine_chunks: fn(u32, &Chunks<'_>) -> u32,
    words: WordFold,
}

/// A payload by its chunks: every chunk but the first and the last spans `units` I/O units, where `units` is at least one, the last spans `last_len` bytes, and the whole payload spans `len` bytes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Chunks<'a> {
    /// Each chunk's crc32c, little-endian, in payload order.
    pub(crate) checksums: &'a [[u8; 4]],
    pub(crate) units: u64,
    pub(crate) last_len: u64,
    pub(crate) len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WordFold {
    Update,
    #[cfg(target_arch = "x86_64")]
    X86Chains,
    /// Folds a span of up to 22 words, an even count of at least 4, as 16-byte lanes with the AES extension's carry-less multiply; longer, shorter and odd spans pass through one CRC instruction chain in `update_words` and through the mechanism's `update` in `update_words_masked`.
    #[cfg(target_arch = "aarch64")]
    Aarch64Lanes,
}

/// A run of zero bytes a register can be carried past in constant time, with the constant the mechanism that built it multiplies by.
#[derive(Debug, Clone, Copy)]
pub struct ZeroRun {
    len: u64,
    constant: u32,
    /// The initial register advanced past the run: the register of `len` zero bytes alone.
    from_initial: u32,
    advance: fn(u32, u32) -> u32,
}

impl ZeroRun {
    /// The register `register` becomes after this run of zero bytes.
    #[inline]
    pub fn advance(&self, register: u32) -> u32 {
        (self.advance)(register, self.constant)
    }
}

/// The most recent zero runs by length, for a caller that meets the same few lengths again and again: a run found here costs a scan of the entries; a new length builds its run and replaces the oldest entry.
#[derive(Debug, Clone, Copy)]
pub struct ZeroRuns {
    entries: [Option<ZeroRun>; ZERO_RUNS],
    /// The entry the next new length replaces.
    next: usize,
}

const ZERO_RUNS: usize = 8;

impl Default for ZeroRuns {
    fn default() -> Self {
        Self::new()
    }
}

impl ZeroRuns {
    pub const fn new() -> Self {
        Self {
            entries: [None; ZERO_RUNS],
            next: 0,
        }
    }

    /// The run of `len` zero bytes under `crc`, kept for the next call with the same length.
    #[inline]
    pub fn run(&mut self, crc: Crc32c, len: u64) -> ZeroRun {
        for run in self.entries.iter().flatten() {
            if run.len == len {
                return *run;
            }
        }
        let run = crc.zero_run(len);
        #[cfg(test)]
        BUILT.with(|built| built.set(built.get() + 1));
        self.entries[self.next] = Some(run);
        self.next = if self.next + 1 == ZERO_RUNS {
            0
        } else {
            self.next + 1
        };
        run
    }
}

#[cfg(test)]
thread_local! {
    /// Counts [`ZeroRuns::run`] builds on this thread so tests can bound rebuild frequency.
    static BUILT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn take_zero_run_builds() -> usize {
    BUILT.with(|built| built.replace(0))
}

/// A checksum in progress; [`finish`](Self::finish) yields the checksum of every byte passed to [`update`](Self::update) or `update_and_copy`, in order.
#[derive(Debug, Clone, Copy)]
pub struct RunningCrc {
    crc: Crc32c,
    register: u32,
}

/// The portable mechanism.
pub(super) const TABLE: Crc32c = Crc32c {
    update: update_table,
    update_and_copy: |register, from, to| {
        to.copy_from_slice(from);
        update_table(register, from)
    },
    run: |len| {
        let constant = zero_bytes_mod(len);
        (constant, mul_mod(!0, constant))
    },
    advance: mul_mod,
    combine_chunks: |first, chunks| {
        join_chunks(first, chunks, zero_bytes_mod, carryless_mul, reduce_mod)
    },
    words: WordFold::Update,
};

impl Crc32c {
    /// The hardware mechanism when the running CPU has it, else the table.
    pub fn detect() -> Self {
        hardware().unwrap_or(TABLE)
    }

    #[cfg(test)]
    pub(super) const fn over_update(update: fn(u32, &[u8]) -> u32) -> Self {
        Self { update, ..TABLE }
    }

    /// `checksum` returns 0 for empty `bytes`.
    pub fn checksum(self, bytes: &[u8]) -> u32 {
        !(self.update)(!0, bytes)
    }

    /// `checksum_words(w) == checksum(w.as_flattened())` for `N >= 1`.
    #[inline]
    pub fn checksum_words<const N: usize>(self, words: &[[u8; 8]; N]) -> u32 {
        let mut running = self.start();
        running.update_words(words);
        running.finish()
    }

    /// Whether this mechanism folds words as aarch64 lanes, which also shows that the running CPU implements the CRC and AES extensions [`checksum_written`](Self::checksum_written) uses.
    #[cfg(target_arch = "aarch64")]
    #[inline]
    pub fn folds_lanes(self) -> bool {
        self.words == WordFold::Aarch64Lanes
    }

    /// [`checksum_words`](Self::checksum_words) with word `AT` read as `words[AT] & mask` (no word when `AT == N`), for words a caller just wrote in eight-byte stores: the first six pass through the CRC instructions on eight-byte loads, which those stores forward to, and the fold is marked for inlining into a caller compiled for the CRC and AES extensions.
    ///
    /// # Safety
    ///
    /// The running CPU implements the CRC and AES extensions.
    #[cfg(target_arch = "aarch64")]
    #[inline]
    #[target_feature(enable = "crc,aes")]
    pub fn checksum_written<const N: usize, const AT: usize>(
        words: &[[u8; 8]; N],
        mask: u64,
    ) -> u32 {
        const { assert!(lanes_fit(N, 6) && AT >= 6 && AT <= N) };
        !fold_lanes::<N, AT, 6>(!0, words, mask)
    }

    pub fn start(self) -> RunningCrc {
        RunningCrc {
            crc: self,
            register: !0,
        }
    }

    /// A run of `len` zero bytes, which [`ZeroRun::advance`] then carries any register past: the register after `bytes ++ [0; len]` is the run advanced from the register after `bytes`.
    pub fn zero_run(self, len: u64) -> ZeroRun {
        let (constant, from_initial) = (self.run)(len);
        ZeroRun {
            len,
            constant,
            from_initial,
            advance: self.advance,
        }
    }

    /// The register of `bytes ++ tail` from the register `register` of `bytes` and the register `from_zero` of `tail` folded from a zero register: the register is linear in its bytes, so the first register advanced past `tail`'s length of zero bytes, xor the second, is the register of the concatenation.
    #[inline]
    pub fn append(self, register: u32, tail: &ZeroRun, from_zero: u32) -> u32 {
        tail.advance(register) ^ from_zero
    }

    /// The checksum of `first ++ second` from the checksum `first` of the first bytes, the zero run `tail` of the second bytes' length, and the checksum `second` of those bytes.
    pub fn combine(self, first: u32, tail: &ZeroRun, second: u32) -> u32 {
        tail.advance(first) ^ second
    }

    /// The checksum of the bytes `first` covers followed by the payload `chunks` describes: `first` carried past the payload's length, xor every chunk's checksum carried past the bytes after that chunk. Each chunk's carry depends only on the bytes after it, so the first chunk may have any length.
    #[inline]
    pub(crate) fn combine_chunks(self, first: u32, chunks: &Chunks<'_>) -> u32 {
        (self.combine_chunks)(first, chunks)
    }

    /// The register of `bytes` folded from a zero register, the mechanism's inverted-register convention set aside: the register [`checksum`](Self::checksum) inverts, xor the zero run of the same length advanced from the initial register.
    #[inline]
    pub fn from_zero(self, checksum: u32, len: &ZeroRun) -> u32 {
        !checksum ^ len.from_initial
    }

    /// The checksum of bytes whose register folded from a zero register is `from_zero` and whose length is `len`.
    #[inline]
    pub fn checksum_of(self, from_zero: u32, len: &ZeroRun) -> u32 {
        !(len.from_initial ^ from_zero)
    }

    /// The register of `bytes` folded from a zero register.
    #[inline]
    pub fn fold_from_zero(self, bytes: &[u8]) -> u32 {
        (self.update)(0, bytes)
    }
}

impl RunningCrc {
    /// A checksum in progress resumed at `register`, the register after some bytes from the initial register `!0`, such as [`register_after`] computes at compile time; [`finish`](Self::finish) yields the checksum of those bytes followed by every later update.
    pub(crate) fn from_register(crc: Crc32c, register: u32) -> Self {
        Self { crc, register }
    }

    /// The register as it stands, for tests of the register algebra.
    #[cfg(test)]
    pub(super) fn register(&self) -> u32 {
        self.register
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.register = (self.crc.update)(self.register, bytes);
    }

    /// `update_words(words)` has the same effect as `update(words.as_flattened())` for `N >= 1`.
    #[inline]
    pub fn update_words<const N: usize>(&mut self, words: &[[u8; 8]; N]) {
        const { assert!(N >= 1) };
        self.register = match self.crc.words {
            WordFold::Update => (self.crc.update)(self.register, words.as_flattened()),
            // SAFETY: `narrow` sets `X86Chains` only after runtime detection confirmed `sse4.2` and `pclmulqdq`, and the field is private, so every call runs on a CPU that implements the instructions `chains_x86` uses.
            #[cfg(target_arch = "x86_64")]
            WordFold::X86Chains => unsafe { chains_x86::<N, N>(self.register, words, 0) },
            // SAFETY: `hardware` sets `Aarch64Lanes` only after runtime detection confirmed `crc` and `aes`, and the field is private, so every call runs on a CPU that implements the instructions `fold_lanes` uses.
            #[cfg(target_arch = "aarch64")]
            WordFold::Aarch64Lanes if lanes_fit(N, 0) => unsafe {
                fold_lanes::<N, N, 0>(self.register, words, 0)
            },
            // SAFETY: `hardware` sets `Aarch64Lanes` only after runtime detection confirmed `crc`, which `crc_words` uses, and the field is private.
            #[cfg(target_arch = "aarch64")]
            WordFold::Aarch64Lanes => unsafe { crc_words(self.register, words.as_flattened()) },
        };
    }

    /// [`update_words`](Self::update_words) with word `AT` read as `words[AT] & mask`, for a span that holds its own checksum field.
    #[inline]
    pub fn update_words_masked<const N: usize, const AT: usize>(
        &mut self,
        words: &[[u8; 8]; N],
        mask: u64,
    ) {
        const { assert!(AT < N) };
        // The two-word copy lets a checksum field in the span's last two words use one byte-fold call after the prefix.
        let pieces = |update: fn(u32, &[u8]) -> u32, register: u32| {
            let tail = const { if N - AT < 2 { N - AT } else { 2 } };
            let mut copy = [[0; 8]; 2];
            copy[..tail].copy_from_slice(&words[AT..AT + tail]);
            copy[0] = (u64::from_le_bytes(words[AT]) & mask).to_le_bytes();
            let mut register = update(register, words[..AT].as_flattened());
            register = update(register, copy[..tail].as_flattened());
            if AT + tail < N {
                register = update(register, words[AT + tail..].as_flattened());
            }
            register
        };
        self.register = match self.crc.words {
            WordFold::Update => pieces(self.crc.update, self.register),
            // SAFETY: as in `update_words`.
            #[cfg(target_arch = "x86_64")]
            WordFold::X86Chains => unsafe { chains_x86::<N, AT>(self.register, words, mask) },
            // SAFETY: as in `update_words`.
            #[cfg(target_arch = "aarch64")]
            WordFold::Aarch64Lanes if lanes_fit(N, 0) => unsafe {
                fold_lanes::<N, AT, 0>(self.register, words, mask)
            },
            #[cfg(target_arch = "aarch64")]
            WordFold::Aarch64Lanes => pieces(self.crc.update, self.register),
        };
    }

    /// Folds `from` into the checksum and copies it into `to` in the same pass.
    ///
    /// # Panics
    ///
    /// - If `to`'s length differs from `from`'s.
    #[inline]
    pub(crate) fn update_and_copy(&mut self, from: &[u8], to: &mut [u8]) {
        assert_eq!(from.len(), to.len(), "a copy target of another length");
        self.register = (self.crc.update_and_copy)(self.register, from, to);
    }

    pub fn finish(self) -> u32 {
        !self.register
    }
}

/// The hardware mechanism, when runtime detection finds it.
#[cfg(target_arch = "x86_64")]
pub(super) fn hardware() -> Option<Crc32c> {
    let wide = std::arch::is_x86_feature_detected!("avx512f")
        && std::arch::is_x86_feature_detected!("vpclmulqdq");
    narrow().map(|narrow| Crc32c {
        update: if wide { update_x86_wide } else { narrow.update },
        update_and_copy: if wide {
            update_and_copy_x86_wide
        } else {
            narrow.update_and_copy
        },
        ..narrow
    })
}

#[cfg(target_arch = "x86_64")]
fn run_x86(len: u64) -> (u32, u32) {
    // SAFETY: `narrow` installs this function only after runtime detection confirmed `sse4.2` and `pclmulqdq`, and the field is private, so every call runs on a CPU that implements the instructions `run_shifts` uses.
    unsafe { run_shifts(len) }
}

#[cfg(target_arch = "x86_64")]
fn advance_x86(register: u32, constant: u32) -> u32 {
    // SAFETY: as for `run_x86`, which `narrow` installs alongside this function.
    unsafe { shift_mul(register, constant) }
}

#[cfg(target_arch = "x86_64")]
fn combine_chunks_x86(first: u32, chunks: &Chunks<'_>) -> u32 {
    // SAFETY: as for `run_x86`, which `narrow` installs alongside this function.
    unsafe { join_chunks_x86(first, chunks) }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2,pclmulqdq")]
fn join_chunks_x86(first: u32, chunks: &Chunks<'_>) -> u32 {
    join_chunks(
        first,
        chunks,
        |len| run_shift(len),
        |a, b| clmul_low(a, b),
        |product| reduce(product),
    )
}

/// The SSE4.2 and carry-less multiply mechanism, which the wide one extends; tests also exercise it on hosts that have the wide one.
#[cfg(target_arch = "x86_64")]
pub(super) fn narrow() -> Option<Crc32c> {
    (std::arch::is_x86_feature_detected!("sse4.2")
        && std::arch::is_x86_feature_detected!("pclmulqdq"))
    .then_some(Crc32c {
        update: update_x86,
        update_and_copy: update_and_copy_x86,
        run: run_x86,
        advance: advance_x86,
        combine_chunks: combine_chunks_x86,
        words: WordFold::X86Chains,
    })
}

#[cfg(target_arch = "x86_64")]
const MAX_CHAINS: usize = 4;

#[cfg(target_arch = "x86_64")]
const fn chains(words: usize) -> usize {
    let chains = words / 6;
    if chains == 0 {
        1
    } else if chains > MAX_CHAINS {
        MAX_CHAINS
    } else {
        chains
    }
}

#[cfg(target_arch = "x86_64")]
const fn chain_bounds(words: usize) -> [(usize, usize); MAX_CHAINS] {
    let chains = chains(words);
    let (base, extra) = (words / chains, words % chains);
    let mut bounds = [(words, words); MAX_CHAINS];
    let mut start = 0;
    let mut chain = 0;
    while chain < chains {
        let len = base + if chain < extra { 1 } else { 0 };
        bounds[chain] = (start, start + len);
        start += len;
        chain += 1;
    }
    bounds
}

#[cfg(target_arch = "x86_64")]
const fn join_constants(words: usize) -> [u32; MAX_CHAINS] {
    let bounds = chain_bounds(words);
    let mut constants = [0; MAX_CHAINS];
    let mut chain = 0;
    while chain + 1 < chains(words) {
        constants[chain] = x_pow_mod(64 * (words - bounds[chain].1) as u64 - 33);
        chain += 1;
    }
    constants
}

/// Word `AT` is read as `words[AT] & mask`; `AT == N` reads every word unmasked.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2,pclmulqdq")]
fn chains_x86<const N: usize, const AT: usize>(
    register: u32,
    words: &[[u8; 8]; N],
    mask: u64,
) -> u32 {
    use std::arch::x86_64::_mm_crc32_u64;
    const { assert!(N >= 1 && AT <= N) };
    #[cfg(test)]
    crate::isa_witness::ran(crate::isa_witness::Kernel::CrcChains);
    let chains = const { chains(N) };
    let bounds = const { chain_bounds(N) };
    let constants = const { join_constants(N) };
    let word = |at: usize| {
        let word = u64::from_le_bytes(words[at]);
        if at == AT { word & mask } else { word }
    };
    let mut registers = [u64::from(register), 0, 0, 0];
    let longest = bounds[0].1 - bounds[0].0;
    for step in 0..longest {
        for chain in 0..MAX_CHAINS {
            let (start, end) = bounds[chain];
            let end = if chain + 1 == chains { end - 1 } else { end };
            let at = start + step;
            if at < end {
                registers[chain] = _mm_crc32_u64(registers[chain], word(at));
            }
        }
    }
    let mut folded = word(N - 1);
    for chain in 0..chains - 1 {
        folded ^= clmul_low(registers[chain] as u32, constants[chain]);
    }
    _mm_crc32_u64(registers[chains - 1], folded) as u32
}

/// The standard library reports PMULL support through the `aes` feature.
#[cfg(target_arch = "aarch64")]
pub(super) fn hardware() -> Option<Crc32c> {
    let instruction = crc_instruction()?;
    if !std::arch::is_aarch64_feature_detected!("aes") {
        return Some(instruction);
    }
    Some(Crc32c {
        update: update_aarch64,
        update_and_copy: update_and_copy_aarch64,
        run: run_aarch64,
        advance: advance_aarch64,
        combine_chunks: combine_chunks_aarch64,
        words: WordFold::Aarch64Lanes,
    })
}

/// The CRC-instruction mechanism, which [`hardware`] returns on hosts without PMULL; tests also exercise it on hosts that have it.
#[cfg(target_arch = "aarch64")]
pub(super) fn crc_instruction() -> Option<Crc32c> {
    std::arch::is_aarch64_feature_detected!("crc").then_some(Crc32c {
        update: update_crc_instruction,
        update_and_copy: update_and_copy_crc_instruction,
        run: TABLE.run,
        advance: TABLE.advance,
        combine_chunks: TABLE.combine_chunks,
        words: WordFold::Update,
    })
}

#[cfg(target_arch = "aarch64")]
fn run_aarch64(len: u64) -> (u32, u32) {
    // SAFETY: `hardware` installs this function only after runtime detection confirmed `crc` and `aes`, and the field is private, so every call runs on a CPU that implements the instructions `run_shifts` uses.
    unsafe { run_shifts(len) }
}

#[cfg(target_arch = "aarch64")]
fn advance_aarch64(register: u32, constant: u32) -> u32 {
    // SAFETY: as for `run_aarch64`, which `hardware` installs alongside this function.
    unsafe { shift_mul(register, constant) }
}

#[cfg(target_arch = "aarch64")]
fn combine_chunks_aarch64(first: u32, chunks: &Chunks<'_>) -> u32 {
    // SAFETY: as for `run_aarch64`, which `hardware` installs alongside this function.
    unsafe { join_chunks_aarch64(first, chunks) }
}

/// [`Crc32c::combine_chunks`] with the carries of every chunk but the last summed in the vector registers by [`unit_sum`].
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "crc,aes")]
fn join_chunks_aarch64(first: u32, chunks: &Chunks<'_>) -> u32 {
    let Some((last, earlier)) = chunks.checksums.split_last() else {
        return first;
    };
    let carried = shift_mul(first, run_shift(chunks.len)) ^ u32::from_le_bytes(*last);
    if earlier.is_empty() {
        return carried;
    }
    carried ^ shift_mul(unit_sum(earlier, chunks.units), run_shift(chunks.last_len))
}

/// The xor of every checksum of `checksums`, which holds at least one, carried past the `units`-unit blocks after it. A run whose first block's carry spans fewer than [`UNIT_SHIFT_LEN`] units is one group; a longer run splits into groups of `(UNIT_SHIFT_LEN - 1) / units` blocks, at least one, the first taking `(checksums.len() - 1) % group + 1` of them, and each group's sum joins the next by one multiply.
#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "crc,aes")]
fn unit_sum(checksums: &[[u8; 4]], units: u64) -> u32 {
    let reach = (checksums.len() as u64 - 1).saturating_mul(units);
    if reach < UNIT_SHIFT_LEN as u64 {
        return group_sum(checksums, units as usize);
    }
    let group = ((UNIT_SHIFT_LEN as u64 - 1) / units).max(1) as usize;
    let lead = (checksums.len() - 1) % group + 1;
    let (head, rest) = checksums.split_at(lead);
    let span = group as u64 * units;
    let step = if span < UNIT_SHIFT_LEN as u64 {
        UNIT_SHIFT[UNIT_SHIFT_LEN - 1 - span as usize] as u32
    } else {
        run_shift(span * IO_UNIT as u64)
    };
    let mut sum = group_sum(head, units as usize);
    for blocks in rest.chunks_exact(group) {
        sum = shift_mul(sum, step) ^ group_sum(blocks, units as usize);
    }
    sum
}

/// The xor of every checksum of `blocks` carried past the `units`-unit blocks after it, where `(blocks.len() - 1) * units` is below [`UNIT_SHIFT_LEN`]: four checksums load as one vector and widen to two, each carry-less product with its [`UNIT_SHIFT`] constant stays unreduced in one of two vector accumulators, an odd last block's product joins their sum unreduced, and one CRC instruction reduces it.
#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "crc,aes")]
fn group_sum(blocks: &[[u8; 4]], units: usize) -> u32 {
    use std::arch::aarch64::{
        __crc32cd, poly64x2_t, uint8x16_t, uint64x2_t, vdupq_n_u8, veorq_u8, vget_low_u32,
        vgetq_lane_p64, vgetq_lane_u64, vld1_u32, vld1q_lane_u64, vld1q_u32, vld1q_u64,
        vmovl_high_u32, vmovl_u32, vmull_high_p64, vmull_p64, vreinterpretq_p64_u64,
        vreinterpretq_u8_p128, vreinterpretq_u64_u8,
    };
    // The widened checksums stay in a vector register: the template, an assembler comment that emits no instruction, makes their lanes opaque to the optimizer, so each product below reads its operands directly from vector lanes.
    let lanes = |mut checksums: uint64x2_t| -> poly64x2_t {
        // SAFETY: the template is an assembler comment that emits no instruction; it reads and writes `checksums` in place and touches no memory, flags or stack.
        unsafe {
            std::arch::asm!("/* {0:v} */", inout(vreg) checksums, options(pure, nomem, nostack, preserves_flags));
        }
        vreinterpretq_p64_u64(checksums)
    };
    // The constants of two blocks `units` apart, the first at `at`, as the two lanes of one vector.
    let pair = |at: usize| -> poly64x2_t {
        let constants = if units == 1 {
            let both = &UNIT_SHIFT[at..at + 2];
            // SAFETY: `both` is two readable `u64`s.
            unsafe { vld1q_u64(both.as_ptr()) }
        } else {
            let (first, second) = (&UNIT_SHIFT[at], &UNIT_SHIFT[at + units]);
            // SAFETY: the first load reads the two `u64`s of the temporary `[*first, 0]`, which lives through the call, and the lane load reads the `u64` `second` refers to, aligned as its type requires.
            unsafe { vld1q_lane_u64::<1>(second, vld1q_u64([*first, 0].as_ptr())) }
        };
        vreinterpretq_p64_u64(constants)
    };
    // The unreduced carries of two checksums, the two lanes of `checksums`, by the two lanes of `constants`.
    let carries = |checksums: poly64x2_t, constants: poly64x2_t| -> uint8x16_t {
        let low = vmull_p64(
            vgetq_lane_p64::<0>(checksums),
            vgetq_lane_p64::<0>(constants),
        );
        let high = vmull_high_p64(checksums, constants);
        veorq_u8(vreinterpretq_u8_p128(low), vreinterpretq_u8_p128(high))
    };
    // `UNIT_SHIFT` runs from the longest carry down, so block `g` takes entry `first + g * units`.
    let first = UNIT_SHIFT_LEN - 1 - (blocks.len() - 1) * units;
    let (quads, rest) = blocks.as_chunks::<4>();
    let (mut even, mut odd) = (vdupq_n_u8(0), vdupq_n_u8(0));
    let mut at = first;
    for quad in quads {
        // SAFETY: `quad` is 16 readable bytes, four little-endian checksums, and `vld1q_u32` has no alignment requirement.
        let checksums = unsafe { vld1q_u32(quad.as_ptr().cast()) };
        let low = lanes(vmovl_u32(vget_low_u32(checksums)));
        let high = lanes(vmovl_high_u32(checksums));
        even = veorq_u8(even, carries(low, pair(at)));
        odd = veorq_u8(odd, carries(high, pair(at + 2 * units)));
        at += 4 * units;
    }
    let (twos, last) = rest.as_chunks::<2>();
    if let [two] = twos {
        // SAFETY: `two` is 8 readable bytes, two little-endian checksums, and `vld1_u32` has no alignment requirement.
        let checksums = lanes(vmovl_u32(unsafe { vld1_u32(two.as_ptr().cast()) }));
        even = veorq_u8(even, carries(checksums, pair(at)));
        at += 2 * units;
    }
    let mut sum = vgetq_lane_u64::<0>(vreinterpretq_u64_u8(veorq_u8(even, odd)));
    if let [last] = last {
        sum ^= vmull_p64(u64::from(u32::from_le_bytes(*last)), UNIT_SHIFT[at]) as u64;
    }
    __crc32cd(0, sum)
}

/// The low 64 bits of the carry-less product of two 32-bit values: `a * b * x` as a reflected 64-bit polynomial.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes")]
fn clmul_low(a: u32, b: u32) -> u64 {
    use std::arch::aarch64::vmull_p64;
    vmull_p64(u64::from(a), u64::from(b)) as u64
}

/// `a * b * x^33 mod P`: the carry-less product reduced by the CRC instruction, which multiplies its data by `x^32`.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "crc,aes")]
fn shift_mul(a: u32, b: u32) -> u32 {
    reduce(clmul_low(a, b))
}

/// `product * x^32 mod P`, which the CRC instruction computes from an initial crc of zero.
#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "crc")]
fn reduce(product: u64) -> u32 {
    std::arch::aarch64::__crc32cd(0, product)
}

/// On architectures other than x86_64 and aarch64, detection yields the table mechanism.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(super) fn hardware() -> Option<Crc32c> {
    None
}

#[cfg(target_arch = "x86_64")]
fn update_x86_wide(register: u32, bytes: &[u8]) -> u32 {
    if bytes.len() < WIDE_MIN {
        return update_x86(register, bytes);
    }
    // SAFETY: this function is private to the module, which names it only in `hardware` after `is_x86_feature_detected!` reported `sse4.2`, `pclmulqdq`, `avx512f` and `vpclmulqdq`, and `Crc32c::update` is private, so no other value holds it; the CPU therefore implements every instruction `wide_fold` uses.
    unsafe { wide_fold::<false>(register, bytes, &mut []) }
}

/// Copies the target's bytes before its next 64-byte boundary through `copy_then_update_x86`, so each block the wide fold stores fills one whole target line; an input shorter than those bytes plus [`WIDE_MIN`] goes through `copy_then_update_x86` whole.
#[cfg(target_arch = "x86_64")]
fn update_and_copy_x86_wide(register: u32, from: &[u8], to: &mut [u8]) -> u32 {
    let head = to.as_ptr().addr().wrapping_neg() % 64;
    if from.len() < head + WIDE_MIN {
        return copy_then_update_x86(register, from, to);
    }
    let (head_from, from) = from.split_at(head);
    let (head_to, to) = to.split_at_mut(head);
    debug_assert!(to.as_ptr().addr().is_multiple_of(64));
    let register = if head > 0 {
        copy_then_update_x86(register, head_from, head_to)
    } else {
        register
    };
    // SAFETY: as for `update_x86_wide`, which `hardware` installs alongside this function; `Crc32c::update_and_copy` is private as well.
    unsafe { wide_fold::<true>(register, from, to) }
}

/// The wide copy uses `copy_then_update_x86` for the alignment prefix and for entire inputs shorter than the prefix length plus [`WIDE_MIN`].
/// It stays out of line so that the wide copy's entry keeps its short prologue.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
fn copy_then_update_x86(register: u32, from: &[u8], to: &mut [u8]) -> u32 {
    to.copy_from_slice(from);
    update_x86(register, from)
}

/// Bytes from which the wide mechanism folds: four 64-byte blocks, one per accumulator.
#[cfg(target_arch = "x86_64")]
const WIDE_MIN: usize = 4 * 64;

/// The 16-byte lane constants that carry a lane `distance` bytes ahead, as [`FOLD_LANE`] does for 32 bytes: `x^(8 * distance + 63) mod P` for its first eight bytes and `x^(8 * distance - 1) mod P` for its last eight, each in the high half of its 64-bit word.
#[cfg(target_arch = "x86_64")]
const fn lane_constants(distance: u64) -> [u64; 2] {
    [
        (x_pow_mod(8 * distance + 63) as u64) << 32,
        (x_pow_mod(8 * distance - 1) as u64) << 32,
    ]
}

/// [`lane_constants`] for 256 bytes, the stride of a four-accumulator step.
#[cfg(target_arch = "x86_64")]
const WIDE_STEP: [u64; 2] = lane_constants(256);

/// Blocks [`reduce_blocks`] takes at most: the four accumulators and the up to three blocks after the last whole group.
#[cfg(target_arch = "x86_64")]
const TAIL_BLOCKS: usize = 7;

/// `TAIL[d]` holds, in the lane order of a 512-bit register, the [`lane_constants`] that carry each 16-byte lane of a block `d` blocks before the last to the last block's final 16 bytes; that final lane itself has zero constants, since it enters the sum unmoved.
#[cfg(target_arch = "x86_64")]
const TAIL: [[u64; 8]; TAIL_BLOCKS] = {
    let mut table = [[0; 8]; TAIL_BLOCKS];
    let mut d = 0;
    while d < TAIL_BLOCKS {
        let mut lane = 0;
        while lane < 4 {
            let distance = 64 * d as u64 + 48 - 16 * lane as u64;
            if distance > 0 {
                let [low, high] = lane_constants(distance);
                table[d][2 * lane] = low;
                table[d][2 * lane + 1] = high;
            }
            lane += 1;
        }
        d += 1;
    }
    table
};

/// Returns the `crc32` register, from zero, over `parts`: 1 to [`TAIL_BLOCKS`] consecutive folded 64-byte blocks.
///
/// Each 16-byte lane folds directly into the last block's final 16 bytes using its [`TAIL`] constants, so the carry-less products are independent; two `crc32` instructions then reduce the lanes' xor.
///
/// # Panics
///
/// - If `parts` is empty or holds more than [`TAIL_BLOCKS`] blocks.
#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "sse4.2,avx512f,vpclmulqdq")]
fn reduce_blocks(parts: &[std::arch::x86_64::__m512i]) -> u32 {
    use std::arch::x86_64::{
        _mm_crc32_u64, _mm_cvtsi128_si64, _mm_extract_epi64, _mm_xor_si128, _mm256_castsi256_si128,
        _mm256_extracti128_si256, _mm256_xor_si256, _mm512_castsi512_si256,
        _mm512_clmulepi64_epi128, _mm512_extracti64x4_epi64, _mm512_loadu_si512,
        _mm512_maskz_mov_epi64, _mm512_ternarylogic_epi64,
    };
    // `wide_fold` passes its four accumulators and up to three trailing blocks, so `parts` holds 4 to 7 blocks.
    let mut sum = _mm512_maskz_mov_epi64(0xC0, parts[parts.len() - 1]);
    for (part, constants) in parts.iter().zip(TAIL[..parts.len()].iter().rev()) {
        // SAFETY: `constants` is 64 readable bytes, and `_mm512_loadu_si512` has no alignment requirement.
        let constants = unsafe { _mm512_loadu_si512(constants.as_ptr().cast()) };
        let low = _mm512_clmulepi64_epi128::<0x00>(*part, constants);
        let high = _mm512_clmulepi64_epi128::<0x11>(*part, constants);
        sum = _mm512_ternarylogic_epi64::<0x96>(low, high, sum);
    }
    let half = _mm256_xor_si256(
        _mm512_castsi512_si256(sum),
        _mm512_extracti64x4_epi64::<1>(sum),
    );
    let lane = _mm_xor_si128(
        _mm256_castsi256_si128(half),
        _mm256_extracti128_si256::<1>(half),
    );
    let register = _mm_crc32_u64(0, _mm_cvtsi128_si64(lane) as u64);
    _mm_crc32_u64(register, _mm_extract_epi64::<1>(lane) as u64) as u32
}

/// Folds `bytes` into `register`; `update_x86_wide` and `update_and_copy_x86_wide` pass it inputs of at least [`WIDE_MIN`] bytes, and a shorter input runs the single `crc32` chain.
///
/// Every 16-byte lane of a 64-byte accumulator folds as one fold lane of [`streams_and_fold`] does: its two carry-less products with the lane constants of a distance stand in for it that many bytes later, so xoring them into the bytes there keeps the checksum.
/// The register enters as the first four bytes' xor, the `crc32` instruction's own convention, and four accumulators step 256 bytes over each group of four blocks, so their carry-less products do not wait on one another.
/// [`reduce_blocks`] carries the four accumulators and the blocks after the groups to the last whole block's final 16 bytes and reduces them, and the tail under 64 bytes passes through the `crc32` chain after them.
/// With `COPY`, `to` must have `bytes`' length.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2,avx512f,vpclmulqdq")]
fn wide_fold<const COPY: bool>(register: u32, bytes: &[u8], to: &mut [u8]) -> u32 {
    use std::arch::x86_64::{
        __m512i, _mm_cvtsi32_si128, _mm512_clmulepi64_epi128, _mm512_loadu_si512, _mm512_set_epi64,
        _mm512_storeu_si512, _mm512_ternarylogic_epi64, _mm512_xor_si512, _mm512_zextsi128_si512,
    };
    let (blocks, tail) = bytes.as_chunks::<64>();
    let (groups, rest) = blocks.as_chunks::<4>();
    let Some((first, groups)) = groups.split_first() else {
        if COPY {
            to.copy_from_slice(bytes);
        }
        return sse42(register, bytes);
    };
    #[cfg(test)]
    crate::isa_witness::ran(crate::isa_witness::Kernel::CrcWide);
    let (targets, target_tail) = to.as_chunks_mut::<64>();
    let mut index = 0;
    let mut take = |block: &[u8; 64]| -> __m512i {
        // SAFETY: `block` is 64 readable bytes, and `_mm512_loadu_si512` has no alignment requirement.
        let data = unsafe { _mm512_loadu_si512(block.as_ptr().cast()) };
        if COPY {
            // SAFETY: `targets[index]` is 64 writable bytes, and `_mm512_storeu_si512` has no alignment requirement.
            unsafe { _mm512_storeu_si512(targets[index].as_mut_ptr().cast(), data) };
        }
        index += 1;
        data
    };
    let every_lane = |[low, high]: [u64; 2]| {
        _mm512_set_epi64(
            high as i64,
            low as i64,
            high as i64,
            low as i64,
            high as i64,
            low as i64,
            high as i64,
            low as i64,
        )
    };
    let by_256 = every_lane(WIDE_STEP);
    // The two carry-less products of every lane of `accumulator` with `constants`, xored into `data`.
    let fold = |accumulator: __m512i, constants: __m512i, data: __m512i| {
        let low = _mm512_clmulepi64_epi128::<0x00>(accumulator, constants);
        let high = _mm512_clmulepi64_epi128::<0x11>(accumulator, constants);
        _mm512_ternarylogic_epi64::<0x96>(low, high, data)
    };
    let mut lanes = first.each_ref().map(&mut take);
    let seed = _mm512_zextsi128_si512(_mm_cvtsi32_si128(register as i32));
    lanes[0] = _mm512_xor_si512(lanes[0], seed);
    for group in groups {
        for (lane, block) in lanes.iter_mut().zip(group) {
            *lane = fold(*lane, by_256, take(block));
        }
    }
    let mut parts = [lanes[0]; TAIL_BLOCKS];
    parts[..4].copy_from_slice(&lanes);
    for (part, block) in parts[4..].iter_mut().zip(rest) {
        *part = take(block);
    }
    if COPY {
        target_tail.copy_from_slice(tail);
    }
    sse42(reduce_blocks(&parts[..4 + rest.len()]), tail)
}

#[cfg(target_arch = "x86_64")]
fn update_x86(register: u32, bytes: &[u8]) -> u32 {
    // SAFETY: `narrow` returns this mechanism only after runtime detection confirmed `sse4.2` and `pclmulqdq`, and `hardware` selects `update_x86_wide`, the other caller, only when `narrow` succeeds. The function is private to the module and `Crc32c::update` is a private field, so every call reaches it through one of those two values, on a CPU that implements every instruction `sse42`, `three_chains` and `streams_and_fold` use.
    if bytes.len() < CHAINS_MIN {
        unsafe { sse42(register, bytes) }
    } else if bytes.len() < STREAMS_MIN {
        unsafe { three_chains(register, bytes) }
    } else {
        unsafe { streams_and_fold(register, bytes) }
    }
}

/// Bytes from which [`three_chains`] runs. Three chains shorten the dependent latency of the checksum and spend more instructions on the join and the per-block steps; this is the measured length where a caller that overlaps the checksum with its own work breaks even, and one that waits on it gains.
#[cfg(target_arch = "x86_64")]
const CHAINS_MIN: usize = 176;

/// Bytes from which the parallel regions plus their combination beat three chains; the measured crossover lies near three steps.
#[cfg(target_arch = "x86_64")]
const STREAMS_MIN: usize = 3 * STEP;

/// `PAST[t]` holds `x^(64 * 2t - 33) mod P` and `x^(64 * t - 33) mod P`, each in a 64-bit lane: multiplying a register by one with a carry-less multiply and reducing the product with the `crc32` instruction advances the register past `2t` or `t` zero words, the distances from the first and second thirds of [`three_chains`] to the last word. The entries cover every third below [`STREAMS_MIN`].
#[cfg(target_arch = "x86_64")]
const PAST: [[u64; 2]; STREAMS_MIN / 24] = {
    let mut table = [[0; 2]; STREAMS_MIN / 24];
    let mut t = 1;
    while t < table.len() {
        table[t] = [
            x_pow_mod(64 * 2 * t as u64 - 33) as u64,
            x_pow_mod(64 * t as u64 - 33) as u64,
        ];
        t += 1;
    }
    table
};

/// The [`PAST`] products advance `ra` and `rb` across the words after their thirds; xoring both into `c`'s last word lets one `crc32` reduce both products and fold that word.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2,pclmulqdq")]
fn three_chains(register: u32, bytes: &[u8]) -> u32 {
    use std::arch::x86_64::{
        _mm_clmulepi64_si128, _mm_crc32_u8, _mm_crc32_u64, _mm_cvtsi128_si64, _mm_loadu_si128,
        _mm_set_epi64x, _mm_xor_si128,
    };
    #[cfg(test)]
    crate::isa_witness::ran(crate::isa_witness::Kernel::CrcNarrow);
    let third = bytes.len() / 24;
    let (thirds, rest) = bytes.split_at(24 * third);
    let (a, rest_bc) = thirds.split_at(8 * third);
    let (b, c) = rest_bc.split_at(8 * third);
    let mut chains = Chains {
        registers: [u64::from(register), 0, 0],
        words: [
            a.as_chunks::<8>().0,
            b.as_chunks::<8>().0,
            c.as_chunks::<8>().0,
        ],
    };
    // Every word but each third's last, in blocks sized by the bits of the count.
    let before_last = third - 1;
    if before_last & 8 != 0 {
        chains.fold::<8>();
    }
    if before_last & 4 != 0 {
        chains.fold::<4>();
    }
    if before_last & 2 != 0 {
        chains.fold::<2>();
    }
    if before_last & 1 != 0 {
        chains.fold::<1>();
    }
    let [ra, rb, rc] = chains.registers;
    let [a, b, c] = chains.words;
    let ra = _mm_crc32_u64(ra, u64::from_le_bytes(a[0]));
    let rb = _mm_crc32_u64(rb, u64::from_le_bytes(b[0]));
    // SAFETY: `PAST[third]` is 16 readable bytes, and `_mm_loadu_si128` has no alignment requirement.
    let past = unsafe { _mm_loadu_si128(PAST[third].as_ptr().cast()) };
    let registers = _mm_set_epi64x(rb as u32 as i64, ra as u32 as i64);
    let products = _mm_xor_si128(
        _mm_clmulepi64_si128::<0x00>(registers, past),
        _mm_clmulepi64_si128::<0x11>(registers, past),
    );
    let folded = _mm_cvtsi128_si64(products) as u64 ^ u64::from_le_bytes(c[0]);
    let mut wide = _mm_crc32_u64(rc, folded);
    // `rest` is under 24 bytes: at most two words and a byte tail.
    let (extra, tail) = rest.as_chunks::<8>();
    if let Some(word) = extra.first() {
        wide = _mm_crc32_u64(wide, u64::from_le_bytes(*word));
    }
    if let Some(word) = extra.get(1) {
        wide = _mm_crc32_u64(wide, u64::from_le_bytes(*word));
    }
    let mut register = wide as u32;
    for &byte in tail {
        register = _mm_crc32_u8(register, byte);
    }
    register
}

/// Three `crc32` chains and the words each has left.
#[cfg(target_arch = "x86_64")]
struct Chains<'w> {
    registers: [u64; 3],
    words: [&'w [[u8; 8]]; 3],
}

#[cfg(target_arch = "x86_64")]
impl Chains<'_> {
    /// Folds the next `K` words of every chain, interleaved so the three dependency chains overlap.
    #[inline]
    #[target_feature(enable = "sse4.2")]
    fn fold<const K: usize>(&mut self) {
        use std::arch::x86_64::_mm_crc32_u64;
        let [a, b, c] = self.words;
        let (wa, a) = a.split_at(K);
        let (wb, b) = b.split_at(K);
        let (wc, c) = c.split_at(K);
        for i in 0..K {
            self.registers[0] = _mm_crc32_u64(self.registers[0], u64::from_le_bytes(wa[i]));
            self.registers[1] = _mm_crc32_u64(self.registers[1], u64::from_le_bytes(wb[i]));
            self.registers[2] = _mm_crc32_u64(self.registers[2], u64::from_le_bytes(wc[i]));
        }
        self.words = [a, b, c];
    }
}

// `run_shift`, which every hardware run constant and join goes through, counts a run's words in `usize`; with 64-bit pointers that holds every word count a `u64` byte count names, up to `u64::MAX / 8`.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const _: () = assert!(usize::BITS == 64);

/// `SEGMENTS[k][d]` is `x^(64 * 2048 * d * 256^k - 33) mod P` for `d >= 1`: multiplying a register by it with [`shift_mul`] advances the register past `d * 256^k` segments of 2048 zero words.
/// The seven bytes of a word count's segment count index every word count a `usize` holds.
/// `SEGMENTS[k][1]` is the step for `256^k` segments, and each later entry is the one before it times that step times `x^33`, which keeps the exponent's `-33` offset as [`shift_mul`] does.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
static SEGMENTS: [[u32; 256]; 7] = {
    let x33 = x_pow_mod(33);
    let mut table = [[0; 256]; 7];
    let mut step = WORD_SHIFT[WORD_SHIFT_LEN - 1];
    let mut k = 0;
    while k < 7 {
        table[k][1] = step;
        let mut d = 2;
        while d < 256 {
            table[k][d] = mul_mod(mul_mod(table[k][d - 1], step), x33);
            d += 1;
        }
        step = mul_mod(mul_mod(table[k][255], step), x33);
        k += 1;
    }
    table
};

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2")]
fn sse42(register: u32, bytes: &[u8]) -> u32 {
    use std::arch::x86_64::{_mm_crc32_u8, _mm_crc32_u16, _mm_crc32_u32, _mm_crc32_u64};
    let (words, mut tail) = bytes.as_chunks::<8>();
    let mut wide = u64::from(register);
    for word in words {
        wide = _mm_crc32_u64(wide, u64::from_le_bytes(*word));
    }
    // The instruction's result is a 32-bit crc zero-extended to 64 bits.
    let mut register = wide as u32;
    if let Some((quad, rest)) = tail.split_first_chunk::<4>() {
        register = _mm_crc32_u32(register, u32::from_le_bytes(*quad));
        tail = rest;
    }
    if let Some((half, rest)) = tail.split_first_chunk::<2>() {
        register = _mm_crc32_u16(register, u16::from_le_bytes(*half));
        tail = rest;
    }
    if let Some(&byte) = tail.first() {
        register = _mm_crc32_u8(register, byte);
    }
    register
}

#[cfg(target_arch = "x86_64")]
fn update_and_copy_x86(register: u32, from: &[u8], to: &mut [u8]) -> u32 {
    // SAFETY: this function is private to the module, which names it only in `narrow` after `is_x86_feature_detected!("sse4.2")` returned true, and `Crc32c::update_and_copy` is private; the CPU therefore implements every instruction `sse42_copy` uses.
    unsafe { sse42_copy(register, from, to) }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2")]
fn sse42_copy(register: u32, from: &[u8], to: &mut [u8]) -> u32 {
    use std::arch::x86_64::_mm_crc32_u64;
    let (wide, folded) = fold_words_copy(u64::from(register), from, to, |register, word| {
        _mm_crc32_u64(register, word)
    });
    to[folded..].copy_from_slice(&from[folded..]);
    sse42(wide as u32, &from[folded..])
}

/// Bytes one iteration of [`streams_and_fold`] consumes: three words for each of four `crc32` chains and two 16-byte fold lanes.
#[cfg(target_arch = "x86_64")]
const STEP: usize = 4 * 24 + 32;

/// `x^(8 * 32 + 63) mod P` and `x^(8 * 32 - 1) mod P`, each in the high half of a 64-bit lane: carry-less multiplying a fold lane's first and last eight bytes by them yields 16 bytes whose crc contribution 32 bytes later equals the lane's own.
/// The exponents are the fold distance `8 * 32` bits plus 64 for the first eight bytes and plus 0 for the last eight, each less one because a reflected carry-less multiply yields the product times `x`.
#[cfg(target_arch = "x86_64")]
const FOLD_LANE: [u64; 2] = [
    (x_pow_mod(8 * 32 + 63) as u64) << 32,
    (x_pow_mod(8 * 32 - 1) as u64) << 32,
];

/// Splits `bytes`, at least one [`STEP`] long, into four equal `crc32` regions and a fold region a third longer, runs a chain over each `crc32` region and two carry-less fold lanes over the fold region in one loop, then combines the five results: each chain's register, advanced past the regions after it, joins the fold's last word.
/// The bytes after the regions pass through the single chain.
///
/// The `crc32` unit retires one word per cycle, four independent chains of three words keep it full with latency to spare, and the carry-less multiplier folds 32 bytes in the same twelve cycles.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2,pclmulqdq")]
fn streams_and_fold(register: u32, bytes: &[u8]) -> u32 {
    use std::arch::x86_64::{
        __m128i, _mm_clmulepi64_si128, _mm_crc32_u64, _mm_extract_epi64, _mm_loadu_si128,
        _mm_set_epi64x, _mm_setzero_si128, _mm_xor_si128,
    };
    #[cfg(test)]
    crate::isa_witness::ran(crate::isa_witness::Kernel::CrcNarrow);
    let steps = bytes.len() / STEP;
    let region = steps * 24;
    let (regions, rest) = bytes.split_at(steps * STEP);
    let (a, regions) = regions.split_at(region);
    let (b, regions) = regions.split_at(region);
    let (c, regions) = regions.split_at(region);
    let (d, fold) = regions.split_at(region);
    let load = |lane: &[u8; 16]| -> __m128i {
        // SAFETY: `lane` is 16 readable bytes, and `_mm_loadu_si128` has no alignment requirement.
        unsafe { _mm_loadu_si128(lane.as_ptr().cast()) }
    };
    // Passing the constants through `black_box` keeps both halves in one vector register; when the compiler sees their values it rematerializes them into two registers, and the loop then runs about two cycles slower per step on the measured host.
    let fold_lane = std::hint::black_box(FOLD_LANE);
    let constants = _mm_set_epi64x(fold_lane[1] as i64, fold_lane[0] as i64);
    // A `crc32` region is `3 * steps` words and the fold region `4 * steps`; the shifts advance past the fold region and then past one `crc32` region at a time.
    let past_region = past_words(3 * steps);
    let past_d = past_words(4 * steps);
    let past_c = shift_mul(past_d, past_region);
    let past_b = shift_mul(past_c, past_region);
    let past_a = shift_mul(past_b, past_region);
    // Each region is a fresh stream for the cache prefetchers, and its first lines would miss in series; hinting the first two lines of every region overlaps those misses.
    for region in [a, b, c, d, fold] {
        hint_read(region.as_ptr());
        hint_read(region.as_ptr().wrapping_add(64));
    }
    let mut lanes = [_mm_setzero_si128(); 2];
    let (mut ra, mut rb, mut rc, mut rd) = (u64::from(register), 0u64, 0u64, 0u64);
    for ((((wa, wb), wc), wd), block) in a
        .as_chunks::<24>()
        .0
        .iter()
        .zip(b.as_chunks::<24>().0)
        .zip(c.as_chunks::<24>().0)
        .zip(d.as_chunks::<24>().0)
        .zip(fold.as_chunks::<32>().0)
    {
        for (lane, data) in lanes.iter_mut().zip(block.as_chunks::<16>().0) {
            let low = _mm_clmulepi64_si128::<0x00>(*lane, constants);
            let high = _mm_clmulepi64_si128::<0x11>(*lane, constants);
            *lane = _mm_xor_si128(_mm_xor_si128(low, high), load(data));
        }
        for (((wa, wb), wc), wd) in wa
            .as_chunks::<8>()
            .0
            .iter()
            .zip(wb.as_chunks::<8>().0)
            .zip(wc.as_chunks::<8>().0)
            .zip(wd.as_chunks::<8>().0)
        {
            ra = _mm_crc32_u64(ra, u64::from_le_bytes(*wa));
            rb = _mm_crc32_u64(rb, u64::from_le_bytes(*wb));
            rc = _mm_crc32_u64(rc, u64::from_le_bytes(*wc));
            rd = _mm_crc32_u64(rd, u64::from_le_bytes(*wd));
        }
    }
    // The 32 accumulated bytes stand in for the fold region; the last eight of them join the shifted registers.
    let mut register = 0;
    register = _mm_crc32_u64(register, _mm_extract_epi64::<0>(lanes[0]) as u64);
    register = _mm_crc32_u64(register, _mm_extract_epi64::<1>(lanes[0]) as u64);
    register = _mm_crc32_u64(register, _mm_extract_epi64::<0>(lanes[1]) as u64);
    let folded = clmul_low(ra as u32, past_a)
        ^ clmul_low(rb as u32, past_b)
        ^ clmul_low(rc as u32, past_c)
        ^ clmul_low(rd as u32, past_d)
        ^ _mm_extract_epi64::<1>(lanes[1]) as u64;
    sse42(_mm_crc32_u64(register, folded) as u32, rest)
}

/// `x^(64 * words - 33) mod P` for `words >= 1`: multiplying a register by it with [`shift_mul`] advances the register past `words` zero words.
/// The words below a whole 2048-word segment take one [`WORD_SHIFT`] entry and the segment count one [`SEGMENTS`] entry per nonzero byte, so any `usize` count costs at most seven products.
/// [`shift_mul`] of the constants for `a` and `b` words is the constant for `a + b` words: its extra `x^33` makes the exponents add up.
#[cfg_attr(target_arch = "x86_64", target_feature(enable = "sse4.2,pclmulqdq"))]
#[cfg_attr(target_arch = "aarch64", target_feature(enable = "crc,aes"))]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[inline(never)]
fn past_words(words: usize) -> u32 {
    let low = words % (WORD_SHIFT_LEN - 1);
    let mut segments = words / (WORD_SHIFT_LEN - 1);
    let mut past = if low == 0 {
        let k = segments.trailing_zeros() / 8;
        let lowest = SEGMENTS[k as usize][segments >> (8 * k) & 0xFF];
        segments &= !(0xFF << (8 * k));
        lowest
    } else {
        WORD_SHIFT[low]
    };
    while segments != 0 {
        let k = segments.trailing_zeros() / 8;
        past = shift_mul(past, SEGMENTS[k as usize][segments >> (8 * k) & 0xFF]);
        segments &= !(0xFF << (8 * k));
    }
    past
}

/// The low 64 bits of the carry-less product of two 32-bit values: `a * b * x` as a reflected 64-bit polynomial.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq")]
fn clmul_low(a: u32, b: u32) -> u64 {
    use std::arch::x86_64::{_mm_clmulepi64_si128, _mm_cvtsi64_si128, _mm_cvtsi128_si64};
    let product =
        _mm_clmulepi64_si128::<0>(_mm_cvtsi64_si128(a as i64), _mm_cvtsi64_si128(b as i64));
    _mm_cvtsi128_si64(product) as u64
}

/// `a * b * x^33 mod P`: the carry-less product reduced by the `crc32` instruction, which multiplies its data by `x^32`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2,pclmulqdq")]
fn shift_mul(a: u32, b: u32) -> u32 {
    reduce(clmul_low(a, b))
}

/// `product * x^32 mod P`, which the `crc32` instruction computes from an initial crc of zero.
#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "sse4.2")]
fn reduce(product: u64) -> u32 {
    // The instruction's result is a 32-bit crc zero-extended to 64 bits.
    std::arch::x86_64::_mm_crc32_u64(0, product) as u32
}

/// Whether [`fold_lanes`] takes `words` words after a lead of `lead`: an even count after the lead, which makes from 2 to 11 16-byte lanes, the most [`LANE_FOLDS`] reaches.
#[cfg(target_arch = "aarch64")]
const fn lanes_fit(words: usize, lead: usize) -> bool {
    words > lead
        && (words - lead).is_multiple_of(2)
        && (words - lead) / 2 >= 2
        && (words - lead) / 2 <= 11
}

/// Folds `N` words into `register`, where [`lanes_fit`] holds for `N` and `LEAD`, word `AT` read as `words[AT] & mask` (no word when `AT == N`, and `AT` is not among the lead): the first `LEAD` words pass through the CRC instructions, and the register then folds as the xor of the four bytes after them; the rest load as 16-byte lanes, each lane before the last carried to the last by the constants for its distance, and the lanes sum pairwise before two CRC instructions reduce the sum.
/// With no lead every lane multiplies at once, the shortest wait for words already in memory; a lead loads its words eight bytes at a time, which a caller's fresh eight-byte stores forward to.
#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "crc,aes")]
fn fold_lanes<const N: usize, const AT: usize, const LEAD: usize>(
    register: u32,
    words: &[[u8; 8]; N],
    mask: u64,
) -> u32 {
    use std::arch::aarch64::{
        __crc32cd, vandq_u8, vcombine_u64, vcreate_u64, vdupq_n_u8, veorq_u8, vgetq_lane_p64,
        vgetq_lane_u64, vld1q_u8, vmull_high_p64, vmull_p64, vreinterpretq_p64_u8,
        vreinterpretq_u8_p128, vreinterpretq_u8_u64, vreinterpretq_u64_u8,
    };
    let (lead, rest) = words.split_at(LEAD);
    #[cfg(test)]
    crate::isa_witness::ran(crate::isa_witness::Kernel::CrcLanes);
    let mut register = register;
    for word in lead {
        register = __crc32cd(register, u64::from_le_bytes(*word));
    }
    let chunks = rest.as_flattened().as_chunks::<16>().0;
    let last = chunks.len() - 1;
    let pair = |low: u64, high: u64| {
        vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(low), vcreate_u64(high)))
    };
    let seed = pair(u64::from(register), 0);
    let mut lanes = [vdupq_n_u8(0); 11];
    for (lane, (slot, chunk)) in lanes.iter_mut().zip(chunks).enumerate() {
        // SAFETY: `chunk` is 16 readable bytes, and `vld1q_u8` has no alignment requirement.
        let mut bytes = unsafe { vld1q_u8(chunk.as_ptr()) };
        if AT < N && AT >= LEAD && (AT - LEAD) / 2 == lane {
            let (low, high) = if (AT - LEAD).is_multiple_of(2) {
                (mask, !0)
            } else {
                (!0, mask)
            };
            bytes = vandq_u8(bytes, pair(low, high));
        }
        *slot = if lane == last {
            bytes
        } else {
            let bytes = if lane == 0 {
                veorq_u8(bytes, seed)
            } else {
                bytes
            };
            // SAFETY: the entry is a valid, aligned, initialized element of a static. The read is volatile so the pair stays one vector load from the table.
            let constants = unsafe { std::ptr::read_volatile(&LANE_FOLDS[last - lane]) };
            let bits = vreinterpretq_p64_u8(bytes);
            let low = vreinterpretq_u8_p128(vmull_p64(
                vgetq_lane_p64::<0>(bits),
                vgetq_lane_p64::<0>(constants),
            ));
            let high = vreinterpretq_u8_p128(vmull_high_p64(bits, constants));
            veorq_u8(low, high)
        };
    }
    let mut width = chunks.len();
    while width > 1 {
        let half = width / 2;
        for at in 0..half {
            lanes[at] = veorq_u8(lanes[at], lanes[width - 1 - at]);
        }
        width -= half;
    }
    let halves = vreinterpretq_u64_u8(lanes[0]);
    let register = __crc32cd(0, vgetq_lane_u64::<0>(halves));
    __crc32cd(register, vgetq_lane_u64::<1>(halves))
}

#[cfg(target_arch = "aarch64")]
fn update_aarch64(register: u32, bytes: &[u8]) -> u32 {
    // SAFETY: this function is private to the module, which names it only in `hardware` after `is_aarch64_feature_detected!("crc")` and `is_aarch64_feature_detected!("aes")` returned true, and `Crc32c::update` is private, so no other value holds it; the CPU therefore implements every instruction `crc_fold` uses.
    unsafe { crc_fold(register, bytes) }
}

#[cfg(target_arch = "aarch64")]
fn update_crc_instruction(register: u32, bytes: &[u8]) -> u32 {
    // SAFETY: `hardware` and `crc_instruction` select this private function only after `is_aarch64_feature_detected!("crc")` returned true, and `Crc32c::update` is private, which satisfies `crc_words`' CPU-feature requirement.
    unsafe { crc_words(register, bytes) }
}

/// Passes `bytes` through the CRC instructions sixteen bytes per iteration, then the remaining eight, four, two and one.
#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "crc")]
fn crc_words(register: u32, bytes: &[u8]) -> u32 {
    use std::arch::aarch64::{__crc32cb, __crc32cd, __crc32ch, __crc32cw};
    #[cfg(test)]
    if !bytes.is_empty() {
        crate::isa_witness::ran(crate::isa_witness::Kernel::CrcInstruction);
    }
    let (pairs, tail) = bytes.as_chunks::<16>();
    let mut register = register;
    for pair in pairs {
        for word in pair.as_chunks::<8>().0 {
            register = __crc32cd(register, u64::from_le_bytes(*word));
        }
    }
    let (words, tail) = tail.as_chunks::<8>();
    for word in words {
        register = __crc32cd(register, u64::from_le_bytes(*word));
    }
    let (quads, tail) = tail.as_chunks::<4>();
    for quad in quads {
        register = __crc32cw(register, u32::from_le_bytes(*quad));
    }
    let (halves, tail) = tail.as_chunks::<2>();
    for half in halves {
        register = __crc32ch(register, u16::from_le_bytes(*half));
    }
    for &byte in tail {
        register = __crc32cb(register, byte);
    }
    register
}

#[cfg(target_arch = "aarch64")]
fn update_and_copy_aarch64(register: u32, from: &[u8], to: &mut [u8]) -> u32 {
    // SAFETY: this function is private to the module, which names it only in `hardware` after `is_aarch64_feature_detected!("crc")` and `is_aarch64_feature_detected!("aes")` returned true, and `Crc32c::update_and_copy` is private, so no other value holds it; the CPU therefore implements every instruction `crc_fold_copy` uses.
    unsafe { crc_fold_copy(register, from, to) }
}

#[cfg(target_arch = "aarch64")]
fn update_and_copy_crc_instruction(register: u32, from: &[u8], to: &mut [u8]) -> u32 {
    // SAFETY: `hardware` and `crc_instruction` select this private function only after `is_aarch64_feature_detected!("crc")` returned true, and `Crc32c::update_and_copy` is private, which satisfies `crc_extension_copy`'s CPU-feature requirement.
    unsafe { crc_extension_copy(register, from, to) }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "crc")]
fn crc_extension_copy(register: u32, from: &[u8], to: &mut [u8]) -> u32 {
    use std::arch::aarch64::__crc32cd;
    #[cfg(test)]
    if !from.is_empty() {
        crate::isa_witness::ran(crate::isa_witness::Kernel::CrcInstruction);
    }
    let (wide, folded) = fold_words_copy(u64::from(register), from, to, |register, word| {
        u64::from(__crc32cd(register as u32, word))
    });
    to[folded..].copy_from_slice(&from[folded..]);
    crc_words(wide as u32, &from[folded..])
}

/// Bytes each folding step leads with through the CRC instructions, and 16-byte accumulators it folds: the CRC pipe folds eight bytes a cycle while the vector pipes fold about sixteen, so a step keeps both busy.
#[cfg(target_arch = "aarch64")]
const LEAD: usize = 80;
#[cfg(target_arch = "aarch64")]
const LANES: usize = 10;
/// Bytes one folding step consumes.
#[cfg(target_arch = "aarch64")]
const STEP: usize = LEAD + 16 * LANES;

/// Entries of [`WORD_SHIFT`]: 0 through 2048 words, so one table read supplies the word constant for a carry past one 16 KiB segment or for a run shorter than 16,392 bytes.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const WORD_SHIFT_LEN: usize = 2048 + 1;

/// `WORD_SHIFT[n]` is `x^(64 * n - 33) mod P`: multiplying a register by it with [`shift_mul`] advances the register past `n` zero words, and entry 0, `x^-33`, leaves the register as it is.
/// Each entry is the one before it times `x^64`, so building the table costs one modular product per entry.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
static WORD_SHIFT: [u32; WORD_SHIFT_LEN] = {
    let x64 = x_pow_mod(64);
    let mut table = [BYTE_SHIFT[0]; WORD_SHIFT_LEN];
    let mut n = 1;
    while n < WORD_SHIFT_LEN {
        table[n] = mul_mod(table[n - 1], x64);
        n += 1;
    }
    table
};

/// Entries of [`UNIT_SHIFT`]: 0 through 64 I/O units, so one table read supplies the constant for a carry past any whole number of units an extent's payload spans.
#[cfg(target_arch = "aarch64")]
const UNIT_SHIFT_LEN: usize = 64 + 1;

/// `UNIT_SHIFT[UNIT_SHIFT_LEN - 1 - n]` is `x^(8 * IO_UNIT * n - 33) mod P`, zero-extended: multiplying a register by it with [`shift_mul`] advances the register past `n` I/O units of zero bytes. The entries run from the longest carry down to the last entry, `x^-33`, which leaves a register as it is.
#[cfg(target_arch = "aarch64")]
static UNIT_SHIFT: [u64; UNIT_SHIFT_LEN] = {
    let unit = x_pow_mod(8 * IO_UNIT as u64);
    let mut table = [BYTE_SHIFT[0] as u64; UNIT_SHIFT_LEN];
    let mut n = UNIT_SHIFT_LEN - 1;
    while n > 0 {
        table[n - 1] = mul_mod(table[n] as u32, unit) as u64;
        n -= 1;
    }
    table
};

/// `BYTE_SHIFT[b]` is `x^(8 * b - 33) mod P`: multiplying a register by it with [`shift_mul`] advances the register past `b` zero bytes.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const BYTE_SHIFT: [u32; 8] = {
    // `x^-1` is `x^31 + (p(x) + 1) / x`, where `x^32 = p(x) mod P` and `p(x)` has constant term 1.
    let inverse = ((POLY ^ 1 << 31) << 1) | 1;
    let mut table = [1 << 31; 8];
    let mut k = 0;
    while k < 33 {
        table[0] = mul_mod(table[0], inverse);
        k += 1;
    }
    let x8 = x_pow_mod(8);
    let mut b = 1;
    while b < 8 {
        table[b] = mul_mod(table[b - 1], x8);
        b += 1;
    }
    table
};

/// `x^(8 * len - 33) mod P` for every `u64` `len`: multiplying a register by it with [`shift_mul`] advances the register past `len` zero bytes.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[inline]
#[cfg_attr(target_arch = "x86_64", target_feature(enable = "sse4.2,pclmulqdq"))]
#[cfg_attr(target_arch = "aarch64", target_feature(enable = "crc,aes"))]
fn run_shift(len: u64) -> u32 {
    let words = word_shift((len / 8) as usize);
    match len % 8 {
        0 => words,
        bytes => shift_mul(words, BYTE_SHIFT[bytes as usize]),
    }
}

/// The [`run_shift`] constant of `len` and the initial register `!0` carried past `len` zero bytes by it.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[cfg_attr(target_arch = "x86_64", target_feature(enable = "sse4.2,pclmulqdq"))]
#[cfg_attr(target_arch = "aarch64", target_feature(enable = "crc,aes"))]
fn run_shifts(len: u64) -> (u32, u32) {
    let constant = run_shift(len);
    (constant, shift_mul(!0, constant))
}

/// `x^(64 * words - 33) mod P`, the [`shift_mul`] constant for `words` zero words.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[inline]
#[cfg_attr(target_arch = "x86_64", target_feature(enable = "sse4.2,pclmulqdq"))]
#[cfg_attr(target_arch = "aarch64", target_feature(enable = "crc,aes"))]
fn word_shift(words: usize) -> u32 {
    match WORD_SHIFT.get(words) {
        Some(&constant) => constant,
        None => past_words(words),
    }
}

/// Sends inputs shorter than one [`STEP`] through the CRC instructions from `register`, and folds inputs of one step or more from zero while carrying `register` past their length.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "crc,aes")]
fn crc_fold(register: u32, bytes: &[u8]) -> u32 {
    crc_fold_into(register, bytes, &mut Discard)
}

/// `crc_fold_copy` performs [`crc_fold`] on `from`, copying each piece into equal-length `to` as the fold consumes it.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "crc,aes")]
fn crc_fold_copy(register: u32, from: &[u8], to: &mut [u8]) -> u32 {
    crc_fold_into(register, from, &mut CopyTo(to))
}

/// Inputs shorter than one [`STEP`] pass through one CRC instruction chain from `register`. Inputs of one step or more fold from zero: the register is linear in its bytes, so the register after `register` then `bytes` is the register after `register` then as many zero bytes, xor the register after `bytes` from zero. Folding from zero lets the fold begin before the caller's register is known, and the carry past the length is one multiply.
#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "crc,aes")]
fn crc_fold_into(register: u32, bytes: &[u8], sink: &mut impl Sink) -> u32 {
    if bytes.len() < STEP {
        sink.put(0, bytes);
        return crc_words(register, bytes);
    }
    #[cfg(test)]
    crate::isa_witness::ran(crate::isa_witness::Kernel::CrcPmull);
    // The carry comes first in program order, so its multiply chain, the only work that waits for the caller's register, issues before the fold.
    let carried = carry(register, bytes.len());
    carried ^ fold_steps(bytes, sink)
}

/// `register` after `len` zero bytes: a multiply past the whole words, then the CRC instructions over the remaining bytes.
#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "crc,aes")]
fn carry(register: u32, len: usize) -> u32 {
    use std::arch::aarch64::{__crc32cb, __crc32ch, __crc32cw};
    let words = len / 8;
    let mut register = if words > 0 {
        shift_mul(register, word_shift(words))
    } else {
        register
    };
    if len & 4 != 0 {
        register = __crc32cw(register, 0);
    }
    if len & 2 != 0 {
        register = __crc32ch(register, 0);
    }
    if len & 1 != 0 {
        register = __crc32cb(register, 0);
    }
    register
}

/// `Sink` takes the fold's input by its byte offset, whole steps as the words and vectors the fold loaded and everything else as bytes; the fold may hand over pieces out of order, and hands over every byte once.
#[cfg(target_arch = "aarch64")]
trait Sink {
    fn put(&mut self, at: usize, bytes: &[u8]);
    /// One step's bytes from `at`: the lane vectors, then `lead`.
    fn put_step(
        &mut self,
        at: usize,
        lanes: [std::arch::aarch64::uint8x16_t; LANES],
        lead: [u64; LEAD / 8],
    );
}

/// `Discard` drops every piece; [`crc_fold`] uses it.
#[cfg(target_arch = "aarch64")]
struct Discard;

#[cfg(target_arch = "aarch64")]
impl Sink for Discard {
    #[inline(always)]
    fn put(&mut self, _at: usize, _bytes: &[u8]) {}

    #[inline(always)]
    fn put_step(
        &mut self,
        _at: usize,
        _lanes: [std::arch::aarch64::uint8x16_t; LANES],
        _lead: [u64; LEAD / 8],
    ) {
    }
}

/// `CopyTo` requires a target with the fold input's length.
#[cfg(target_arch = "aarch64")]
struct CopyTo<'t>(&'t mut [u8]);

#[cfg(target_arch = "aarch64")]
impl Sink for CopyTo<'_> {
    #[inline(always)]
    fn put(&mut self, at: usize, bytes: &[u8]) {
        self.0[at..at + bytes.len()].copy_from_slice(bytes);
    }

    #[inline(always)]
    fn put_step(
        &mut self,
        at: usize,
        lanes: [std::arch::aarch64::uint8x16_t; LANES],
        lead: [u64; LEAD / 8],
    ) {
        use std::arch::aarch64::vst1q_u8;
        let (vectors, words) = self.0[at..at + STEP].split_at_mut(16 * LANES);
        for (target, lane) in vectors.as_chunks_mut::<16>().0.iter_mut().zip(lanes) {
            // SAFETY: `target` is 16 writable bytes, and `vst1q_u8` has no alignment requirement.
            unsafe { vst1q_u8(target.as_mut_ptr(), lane) }
        }
        for (target, word) in words.as_chunks_mut::<8>().0.iter_mut().zip(lead) {
            *target = word.to_le_bytes();
        }
    }
}

/// Folds `bytes`, at least one [`STEP`] long, from a zero register: whole steps through the accumulators, and the bytes after them through one CRC instruction chain from the reduced register.
///
/// A step is [`LANES`] vectors, then its lead. The lead goes through the CRC instructions from zero while the vector pipes fold, and its register is xored into the first vector of the next step, where it has the same crc contribution.
/// At the end every accumulator folds to the last one's position, the sum folds forward past the last lead, two CRC instructions reduce it, and the last lead's register joins the result.
/// The bytes after the last step, fewer than one step, pass through one CRC instruction chain after the reduction.
/// It stays out of line so that inputs under one step run only the CRC instructions.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
#[target_feature(enable = "crc,aes")]
fn fold_steps<S: Sink>(bytes: &[u8], sink: &mut S) -> u32 {
    use std::arch::aarch64::{
        __crc32cd, uint8x16_t, vcombine_p64, vcombine_u64, vcreate_p64, vcreate_u64, veorq_u8,
        vgetq_lane_p64, vgetq_lane_u64, vld1q_u8, vmull_high_p64, vmull_p64, vreinterpretq_p64_u8,
        vreinterpretq_u8_p128, vreinterpretq_u8_u64, vreinterpretq_u64_u8,
    };
    let [fold_low, fold_high] = const { fold_constants(STEP) };
    let fold = vcombine_p64(vcreate_p64(fold_low), vcreate_p64(fold_high));
    // Loads one step: its lane vectors and its lead words, whose register from zero it returns beside them; the sink takes both. A closure, so it inlines into the loop with this function's features.
    let load_step = |at: usize, step: &[u8; STEP], sink: &mut S| -> ([uint8x16_t; LANES], u32) {
        let (vectors, lead) = step.split_at(16 * LANES);
        let words = vectors.as_chunks::<16>().0;
        // SAFETY: each word is 16 readable bytes, and `vld1q_u8` has no alignment requirement.
        let lanes: [uint8x16_t; LANES] =
            std::array::from_fn(|i| unsafe { vld1q_u8(words[i].as_ptr()) });
        let lead: [u64; LEAD / 8] =
            std::array::from_fn(|i| u64::from_le_bytes(lead.as_chunks::<8>().0[i]));
        sink.put_step(at, lanes, lead);
        let seed = lead
            .iter()
            .fold(0, |register, &word| __crc32cd(register, word));
        (lanes, seed)
    };
    let seed_vector = |seed: u32| {
        vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(u64::from(seed)), vcreate_u64(0)))
    };
    let (steps, rest) = bytes.as_chunks::<STEP>();
    let folded = steps.len() * STEP;
    let Some((first, steps)) = steps.split_first() else {
        unreachable!("the caller folds at least one step");
    };
    let (mut lanes, mut seed) = load_step(0, first, sink);
    let mut at = STEP;
    for step in steps {
        let (data, next) = load_step(at, step, sink);
        at += STEP;
        for (lane, word) in lanes.iter_mut().zip(data) {
            let bits = vreinterpretq_p64_u8(*lane);
            let low = vreinterpretq_u8_p128(vmull_p64(vgetq_lane_p64::<0>(bits), fold_low));
            let high = vreinterpretq_u8_p128(vmull_high_p64(bits, fold));
            *lane = veorq_u8(veorq_u8(low, high), word);
        }
        lanes[0] = veorq_u8(lanes[0], seed_vector(seed));
        seed = next;
    }
    let mut last = lanes[LANES - 1];
    for (lane, &earlier) in lanes[..LANES - 1].iter().enumerate() {
        // SAFETY: the entry is a valid, aligned, initialized element of a static. The read is volatile so the pair stays one vector load from the table.
        let constants = unsafe { std::ptr::read_volatile(&LANE_FOLDS[LANES - 1 - lane]) };
        let bits = vreinterpretq_p64_u8(earlier);
        let low = vreinterpretq_u8_p128(vmull_p64(
            vgetq_lane_p64::<0>(bits),
            vgetq_lane_p64::<0>(constants),
        ));
        let high = vreinterpretq_u8_p128(vmull_high_p64(bits, constants));
        last = veorq_u8(last, veorq_u8(low, high));
    }
    // The last lead follows the accumulators, so the sum folds forward by the lead's length before the CRC instructions reduce it, and the lead's register joins the result.
    // SAFETY: as above.
    let constants = unsafe { std::ptr::read_volatile(&LANE_FOLDS[LEAD / 16]) };
    let bits = vreinterpretq_p64_u8(last);
    let low = vreinterpretq_u8_p128(vmull_p64(
        vgetq_lane_p64::<0>(bits),
        vgetq_lane_p64::<0>(constants),
    ));
    let high = vreinterpretq_u8_p128(vmull_high_p64(bits, constants));
    let halves = vreinterpretq_u64_u8(veorq_u8(low, high));
    let register = __crc32cd(0, vgetq_lane_u64::<0>(halves));
    let register = __crc32cd(register, vgetq_lane_u64::<1>(halves)) ^ seed;
    sink.put(folded, rest);
    crc_words(register, rest)
}

/// `x^(8 * distance + 63) mod P` and `x^(8 * distance - 1) mod P`, each in the high half of a reflected 64-bit value: carry-less multiplying a 16-byte accumulator's first and last eight bytes by them yields 16 bytes whose crc contribution `distance` bytes later equals the accumulator's own.
/// The exponents are the distance in bits plus 64 for the first eight bytes and plus 0 for the last eight, each less one because a reflected carry-less multiply yields the product times `x`.
#[cfg(target_arch = "aarch64")]
const fn fold_constants(distance: usize) -> [u64; 2] {
    let bits = 8 * distance as u64;
    [
        (x_pow_mod(bits + 63) as u64) << 32,
        (x_pow_mod(bits - 1) as u64) << 32,
    ]
}

/// `LANE_FOLDS[k]`, for `k` from 1, holds [`fold_constants`] for `16 * k` bytes, the distance from accumulator `LANES - 1 - k` to the last one, as one vector whose lanes are the two constants; entry 0 is zero, the reduction reads entries 1 through `LANES - 1`, and [`fold_lanes`] reads entries 1 through 10.
#[cfg(target_arch = "aarch64")]
static LANE_FOLDS: [std::arch::aarch64::poly64x2_t; 11] = {
    let mut folds = [[0; 2]; 11];
    let mut k = 1;
    while k < folds.len() {
        folds[k] = fold_constants(16 * k);
        k += 1;
    }
    // SAFETY: `poly64x2_t` is two 64-bit lanes laid out as `[u64; 2]`, lane 0 first, so both arrays have the same size and every bit pattern is valid.
    unsafe { std::mem::transmute::<[[u64; 2]; 11], [std::arch::aarch64::poly64x2_t; 11]>(folds) }
};

/// The register `register` becomes after `bytes`, computed bit by bit in a const fn so a fixed prefix's register is a compile-time constant; every mechanism's `update` computes the same function.
pub(super) const fn register_after(mut register: u32, bytes: &[u8]) -> u32 {
    let mut at = 0;
    while at < bytes.len() {
        register ^= bytes[at] as u32;
        let mut bit = 0;
        while bit < 8 {
            register = times_x(register);
            bit += 1;
        }
        at += 1;
    }
    register
}

/// `value * x mod P` in the reflected representation, where bit `i` holds the coefficient of `x^(31 - i)`.
pub(super) const fn times_x(value: u32) -> u32 {
    if value & 1 == 1 {
        (value >> 1) ^ POLY
    } else {
        value >> 1
    }
}

/// Blocks from which [`join_blocks`] steps 16 at a time: below it, building 8 more powers costs more than halving the dependent steps saves.
const WIDE_JOIN_MIN: usize = 32;

/// [`Crc32c::combine_chunks`] through a mechanism's operations: `reduce(product(checksum, constant(len)))` carries `checksum` past `len` bytes, and every chunk but the last joins through [`join_blocks`] from zero.
#[inline(always)]
fn join_chunks(
    first: u32,
    chunks: &Chunks<'_>,
    constant: impl Fn(u64) -> u32,
    product: impl Fn(u32, u32) -> u64,
    reduce: impl Fn(u64) -> u32,
) -> u32 {
    let Some((last, earlier)) = chunks.checksums.split_last() else {
        return first;
    };
    let carried = reduce(product(first, constant(chunks.len))) ^ u32::from_le_bytes(*last);
    if earlier.is_empty() {
        return carried;
    }
    let window = constant(chunks.units * IO_UNIT as u64);
    let joined = join_blocks(0, window, earlier, &product, &reduce);
    carried ^ reduce(product(joined, constant(chunks.last_len)))
}

/// The checksum of the bytes `first` covers followed by the blocks `checksums` covers, in order, where `constant` carries a checksum past one block.
/// `reduce(product(checksum, k))` carries `checksum` past the length the constant `k` represents, `reduce(product(a, b))` of two length constants represents their combined length, and `reduce` is linear over xor.
/// Runs of [`WIDE_JOIN_MIN`] blocks or more step 16 blocks at a time, shorter runs 8.
// Forced inlining lets `product` and `reduce` inline into the loop with their defining caller's target features.
#[inline(always)]
fn join_blocks(
    first: u32,
    constant: u32,
    checksums: &[[u8; 4]],
    product: impl Fn(u32, u32) -> u64,
    reduce: impl Fn(u64) -> u32,
) -> u32 {
    if checksums.len() >= WIDE_JOIN_MIN {
        join_steps::<16>(first, constant, checksums, product, reduce)
    } else {
        join_steps::<8>(first, constant, checksums, product, reduce)
    }
}

/// [`join_blocks`] in steps of `W` blocks: a leading step of `checksums.len() % W` blocks, then steps of `W`. Each step xors its unreduced carry products before one reduction, so one product and one reduction per step wait on the running checksum.
#[inline(always)]
fn join_steps<const W: usize>(
    first: u32,
    constant: u32,
    checksums: &[[u8; 4]],
    product: impl Fn(u32, u32) -> u64,
    reduce: impl Fn(u64) -> u32,
) -> u32 {
    let mul = |a, b| reduce(product(a, b));
    // `powers[k]` carries a checksum past `k + 1` blocks; entries from `reach` on hold `constant` and stay unread.
    let mut powers = [constant; W];
    let reach = checksums.len().min(W);
    if reach > 1 {
        powers[1] = mul(constant, constant);
    }
    if reach > 2 {
        powers[2] = mul(powers[1], constant);
    }
    if reach > 3 {
        powers[3] = mul(powers[1], powers[1]);
    }
    for k in 4..reach {
        powers[k] = mul(powers[3], powers[k - 4]);
    }
    let step = |joined: u32, blocks: &[[u8; 4]]| {
        let Some((last, before)) = blocks.split_last() else {
            return joined;
        };
        let carried = before.iter().enumerate().fold(
            product(joined, powers[before.len()]),
            |sum, (at, block)| {
                sum ^ product(u32::from_le_bytes(*block), powers[before.len() - 1 - at])
            },
        );
        reduce(carried) ^ u32::from_le_bytes(*last)
    };
    let (head, steps) = checksums.split_at(checksums.len() % W);
    let (steps, _) = steps.as_chunks::<W>();
    steps
        .iter()
        .fold(step(first, head), |joined, blocks| step(joined, blocks))
}

/// `x^power mod P` in the reflected representation.
pub(super) const fn x_pow_mod(power: u64) -> u32 {
    let mut result = 1 << 31;
    let mut base = 1 << 30;
    let mut remaining = power;
    while remaining > 0 {
        if remaining & 1 == 1 {
            result = mul_mod(result, base);
        }
        base = mul_mod(base, base);
        remaining >>= 1;
    }
    result
}

/// `ZERO_BYTES[k][d]` is `x^(8 * d * 256^k) mod P`, the constant that carries a register past `d * 256^k` zero bytes.
/// A length takes one entry per nonzero byte, so the run constant of a length below 65,536 takes at most one product.
static ZERO_BYTES: [[u32; 256]; 8] = {
    let mut table = [[1 << 31; 256]; 8];
    let mut step = x_pow_mod(8);
    let mut k = 0;
    while k < 8 {
        let mut d = 1;
        while d < 256 {
            table[k][d] = mul_mod(table[k][d - 1], step);
            d += 1;
        }
        step = mul_mod(table[k][255], step);
        k += 1;
    }
    table
};

/// `x^(8 * len) mod P`, the constant that carries a register past `len` zero bytes, exact for every `u64` length, including lengths whose exponent `8 * len` exceeds `u64::MAX`.
const fn zero_bytes_mod(len: u64) -> u32 {
    if len == 0 {
        return 1 << 31;
    }
    let lowest = len.trailing_zeros() / 8;
    let mut result = ZERO_BYTES[lowest as usize][(len >> (8 * lowest)) as u8 as usize];
    let mut rest = len & !(0xFF << (8 * lowest));
    while rest != 0 {
        let k = rest.trailing_zeros() / 8;
        result = mul_mod(
            result,
            ZERO_BYTES[k as usize][(rest >> (8 * k)) as u8 as usize],
        );
        rest &= !(0xFF << (8 * k));
    }
    result
}

/// `a * b mod P` in the reflected representation.
pub(super) const fn mul_mod(a: u32, b: u32) -> u32 {
    reduce_mod(carryless_mul(a, b))
}

/// The carry-less product `a * b` as a reflected 64-bit value, whose bit `k` is the coefficient of `x^(63 - k)`.
const fn carryless_mul(a: u32, b: u32) -> u64 {
    // `multiples[i]` is the carry-less product `a * i`.
    let mut multiples = [0u64; 16];
    let mut i = 1;
    while i < 16 {
        multiples[i] = if i & 1 == 1 {
            multiples[i - 1] ^ a as u64
        } else {
            multiples[i / 2] << 1
        };
        i += 1;
    }
    let mut product = 0;
    let mut nibble = 0;
    while nibble < 8 {
        product ^= multiples[(b >> (4 * nibble) & 15) as usize] << (4 * nibble);
        nibble += 1;
    }
    // The integer product's bit `k` is the coefficient of `x^(62 - k)`.
    product << 1
}

/// `product mod P` for a reflected 64-bit `product`: the integer's high half holds the degrees below 32 and is already reduced, and folding the low half's four bytes from a zero register reduces its `x^32` factor.
const fn reduce_mod(product: u64) -> u32 {
    let low = product as u32;
    (product >> 32) as u32
        ^ TABLES[3][(low & 0xFF) as usize]
        ^ TABLES[2][((low >> 8) & 0xFF) as usize]
        ^ TABLES[1][((low >> 16) & 0xFF) as usize]
        ^ TABLES[0][(low >> 24) as usize]
}

/// Folds the whole words of `from` into `register` with `step`, a hardware fold of one little-endian word whose result is the 32-bit register zero-extended, copying every word it folds to the same offset of `to`, which [`RunningCrc::update_and_copy`] checked has `from`'s length: three chains over each [`LEVELS`] group the input still holds, then one chain over the remaining words. Returns the register and the bytes folded and copied, a multiple of eight.
// Forced inline so that `step`, a closure defined inside a `target_feature` function, inlines into the loops with that function's features.
#[inline(always)]
pub(super) fn fold_words_copy(
    mut register: u64,
    from: &[u8],
    to: &mut [u8],
    step: impl Fn(u64, u64) -> u64,
) -> (u64, usize) {
    let mut at = 0;
    for (len, table) in LEVELS.into_iter().zip(&SHIFTS) {
        while from.len() - at >= 3 * len {
            let (a, after) = from[at..].split_at(len);
            let (b, c) = after.split_at(len);
            let (ta, after) = to[at..].split_at_mut(len);
            let (tb, tc) = after.split_at_mut(len);
            let (mut ra, mut rb, mut rc) = (register, 0, 0);
            let sources = quads(a).iter().zip(quads(b)).zip(quads(c));
            let targets = quads_mut(ta)
                .iter_mut()
                .zip(quads_mut(tb))
                .zip(quads_mut(tc));
            for (((a, b), c), ((ta, tb), tc)) in sources.zip(targets) {
                // The target is a receive-write buffer whose lines left the first-level cache when the device last read them; stores wait for such a line in order, while the hint fetches it beside the chains.
                hint(ta.as_ptr());
                hint(tb.as_ptr());
                hint(tc.as_ptr());
                (*ta, *tb, *tc) = (*a, *b, *c);
                // The fence orders each store ahead of the folds that follow it, so the loop stays one loop whose stores issue interleaved with the chains.
                compiler_fence(Ordering::Release);
                let (a, b, c) = (
                    a.as_chunks::<8>().0,
                    b.as_chunks::<8>().0,
                    c.as_chunks::<8>().0,
                );
                for i in 0..4 {
                    ra = step(ra, u64::from_le_bytes(a[i]));
                    rb = step(rb, u64::from_le_bytes(b[i]));
                    rc = step(rc, u64::from_le_bytes(c[i]));
                }
            }
            register = join(table, ra, rb, rc);
            at += 3 * len;
        }
    }
    let (sources, _) = from[at..].as_chunks::<8>();
    let (targets, _) = to[at..].as_chunks_mut::<8>();
    for (word, target) in sources.iter().zip(targets) {
        *target = *word;
        // As above: the store issues beside the fold of the same word.
        compiler_fence(Ordering::Release);
        register = step(register, u64::from_le_bytes(*word));
    }
    (register, at + sources.len() * 8)
}

/// `bytes` as runs of four words; `bytes` has a whole number of them.
#[inline(always)]
fn quads(bytes: &[u8]) -> &[[u8; 32]] {
    bytes.as_chunks::<32>().0
}

#[inline(always)]
fn quads_mut(bytes: &mut [u8]) -> &mut [[u8; 32]] {
    bytes.as_chunks_mut::<32>().0
}

/// The register of three consecutive equal blocks from the registers `a`, `b` and `c` of their chains, `b` and `c` started from zero, with `table` the zero-shift of one block.
#[inline(always)]
fn join(table: &[[u32; 256]; 4], a: u64, b: u64, c: u64) -> u64 {
    u64::from(shift(table, shift(table, a as u32) ^ b as u32) ^ c as u32)
}

/// `register` after the zero bytes `table` was built for.
#[inline(always)]
pub(super) fn shift(table: &[[u32; 256]; 4], register: u32) -> u32 {
    table[0][(register & 0xFF) as usize]
        ^ table[1][((register >> 8) & 0xFF) as usize]
        ^ table[2][((register >> 16) & 0xFF) as usize]
        ^ table[3][(register >> 24) as usize]
}

/// The zero-shift table of `len` zero bytes: entry `[i][b]` is the register that byte `b` alone at byte position `i` becomes.
///
/// Advancing the register through one zero byte is linear over GF(2), so it is a 32 by 32 bit matrix; the matrix for `len` bytes is its `len`th power, taken by squaring, and each entry applies that power to one byte of a register.
const fn zero_shift(len: usize) -> [[u32; 256]; 4] {
    let mut one_byte = [0u32; 32];
    let mut bit = 0;
    while bit < 32 {
        let register = 1u32 << bit;
        one_byte[bit] = (register >> 8) ^ TABLES[0][(register & 0xFF) as usize];
        bit += 1;
    }
    let mut power = identity();
    let mut square = one_byte;
    let mut remaining = len;
    while remaining > 0 {
        if remaining & 1 == 1 {
            power = compose(&square, &power);
        }
        square = compose(&square, &square);
        remaining >>= 1;
    }
    let mut table = [[0u32; 256]; 4];
    let mut position = 0;
    while position < 4 {
        let mut byte = 0;
        while byte < 256 {
            table[position][byte] = apply(&power, (byte as u32) << (8 * position));
            byte += 1;
        }
        position += 1;
    }
    table
}

/// The identity matrix; matrices are `[u32; 32]` over GF(2), one column per input bit.
const fn identity() -> [u32; 32] {
    let mut matrix = [0u32; 32];
    let mut bit = 0;
    while bit < 32 {
        matrix[bit] = 1 << bit;
        bit += 1;
    }
    matrix
}

const fn apply(matrix: &[u32; 32], mut register: u32) -> u32 {
    let mut out = 0;
    let mut bit = 0;
    while register != 0 {
        if register & 1 == 1 {
            out ^= matrix[bit];
        }
        register >>= 1;
        bit += 1;
    }
    out
}

/// `outer` applied after `inner`.
const fn compose(outer: &[u32; 32], inner: &[u32; 32]) -> [u32; 32] {
    let mut matrix = [0u32; 32];
    let mut bit = 0;
    while bit < 32 {
        matrix[bit] = apply(outer, inner[bit]);
        bit += 1;
    }
    matrix
}

/// `TABLES[0]` is the byte-at-a-time table; `TABLES[k][b]` advances `TABLES[0][b]` through `k` more zero bytes, so eight lookups fold eight bytes.
static TABLES: [[u32; 256]; 8] = tables();

const fn tables() -> [[u32; 256]; 8] {
    let mut tables = [[0; 256]; 8];
    let mut byte = 0;
    while byte < 256 {
        let mut crc = byte as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = times_x(crc);
            bit += 1;
        }
        tables[0][byte] = crc;
        byte += 1;
    }
    let mut byte = 0;
    while byte < 256 {
        let mut slice = 1;
        while slice < 8 {
            let previous = tables[slice - 1][byte];
            tables[slice][byte] = (previous >> 8) ^ tables[0][(previous & 0xFF) as usize];
            slice += 1;
        }
        byte += 1;
    }
    tables
}

pub(super) fn update_table(mut register: u32, bytes: &[u8]) -> u32 {
    let (words, tail) = bytes.as_chunks::<8>();
    for word in words {
        let low = register ^ u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        let high = u32::from_le_bytes([word[4], word[5], word[6], word[7]]);
        register = TABLES[7][(low & 0xFF) as usize]
            ^ TABLES[6][((low >> 8) & 0xFF) as usize]
            ^ TABLES[5][((low >> 16) & 0xFF) as usize]
            ^ TABLES[4][(low >> 24) as usize]
            ^ TABLES[3][(high & 0xFF) as usize]
            ^ TABLES[2][((high >> 8) & 0xFF) as usize]
            ^ TABLES[1][((high >> 16) & 0xFF) as usize]
            ^ TABLES[0][(high >> 24) as usize];
    }
    for &byte in tail {
        register = (register >> 8) ^ TABLES[0][((register ^ u32::from(byte)) & 0xFF) as usize];
    }
    register
}
