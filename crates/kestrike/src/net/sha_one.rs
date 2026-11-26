//! One chain of SHA-256 compressions in the aarch64 `sha2` instructions: every chain [`super::sha_lanes::lone`] compresses for a frame's tag or a session's data key, the two hashes of a failover report's tag, and the two hashes of a planned request's tag.
//!
//! Invariant owned by this module:
//!
//! - ONE-CHAIN-COMPRESSION: [`compress`] applies FIPS 180-4 compression (section 6.2.2) to its blocks in order and leaves the state `sha2::block_api::compress256` leaves.
//!
//! A chain's time is its latency: each compression takes the state the previous one produced, and within a compression each four-round step takes the state of the step before. A step runs `SHA256H` on the state's first half and `SHA256H2` on its second; each overwrites its own half and reads the other as it stood before the step, so a step copies one half first. The kernel copies the first half with `EOR3` and a zero register. Arm's Neoverse V2 software optimization guide lists `SHA256H` and `SHA256H2` at four cycles and `EOR3` at two; with the copy forwarding to `SHA256H2` at that latency, two steps take ten cycles on the chain, and a block's sixteen steps and its closing addition 84. Over runs of 1,024 blocks a Graviton4 core (Neoverse V2) compresses one chain through the kernel in 30.0 ns a block (83.7 cycles, 2.13 GB/s) and through `sha2::block_api::compress256` in 41.4 ns (1.55 GB/s).
//!
//! The kernel reads a block's words and the state as a little-endian target lays them out, so the module builds for little-endian aarch64 outside Miri, and its callers enter it after [`detected`] reports the `sha2` and `sha3` features.

use super::sha_lanes::{Block, K, State};

/// Whether the CPU has every feature [`compress`] and [`with_features`] enable.
pub(crate) fn detected() -> bool {
    std::arch::is_aarch64_feature_detected!("sha2")
        && std::arch::is_aarch64_feature_detected!("sha3")
}

/// The macro enables the target features required for safe calls to [`compress`] inside the wrapped function. Call the wrapped function only after [`detected`] returns true. [`detected`] must check every feature the macro enables.
macro_rules! with_features {
    ($(#[$attribute:meta])* $visibility:vis fn $($function:tt)+) => {
        $(#[$attribute])*
        #[target_feature(enable = "sha2,sha3")]
        $visibility fn $($function)+
    };
}
pub(crate) use with_features;

/// One four-round step of the block whose message words are in v4 to v7: the step's round constants at byte `$k` of the table join its words `$w` in v16, `EOR3` copies the state's first half from v0 to v2 before `SHA256H` overwrites it, and `SHA256H2` takes the copy.
macro_rules! rounds {
    ($k:literal, $w:literal) => {
        concat!(
            "ldr q16, [{k}, #",
            $k,
            "]\n",
            "add v16.4s, v16.4s, ",
            $w,
            ".4s\n",
            "eor3 v2.16b, v0.16b, v3.16b, v3.16b\n",
            "sha256h q0, q1, v16.4s\n",
            "sha256h2 q1, q2, v16.4s\n",
        )
    };
}

/// [`rounds!`] for one of the first twelve steps, which also replaces the step's words `$w` by the message schedule's words sixteen rounds later, from the three registers that follow `$w` in the schedule's order.
macro_rules! scheduled {
    ($k:literal, $w:literal, $w1:literal, $w2:literal, $w3:literal) => {
        concat!(
            "ldr q16, [{k}, #",
            $k,
            "]\n",
            "add v16.4s, v16.4s, ",
            $w,
            ".4s\n",
            "sha256su0 ",
            $w,
            ".4s, ",
            $w1,
            ".4s\n",
            "eor3 v2.16b, v0.16b, v3.16b, v3.16b\n",
            "sha256h q0, q1, v16.4s\n",
            "sha256h2 q1, q2, v16.4s\n",
            "sha256su1 ",
            $w,
            ".4s, ",
            $w2,
            ".4s, ",
            $w3,
            ".4s\n",
        )
    };
}

/// Compresses `blocks` into `state` in order (FIPS 180-4, section 6.2.2), as `sha2::block_api::compress256` does.
#[target_feature(enable = "sha2,sha3")]
pub(crate) fn compress(state: &mut State, blocks: &[Block]) {
    if blocks.is_empty() {
        return;
    }
    #[cfg(test)]
    crate::isa_witness::ran(crate::isa_witness::Kernel::Sha2One);
    let data = blocks.as_ptr_range();
    // SAFETY: the return above leaves at least one block, so `data` starts below `end`. The loop tests after each pass: a pass reads one block of 64 bytes at `data` and advances it by 64, and the loop ends when `data` equals `end`, one past the last block, a whole number of blocks on. The first instruction reads the eight words of `state` and the last writes them, through the exclusive borrow. Each pass reads the 64 words of the round constants at `k`. No load or store needs an alignment. Every register the instructions write is an output or a clobber, the flags are not declared preserved, and the instructions touch no stack.
    unsafe {
        core::arch::asm!(
            "ld1 {{v0.4s, v1.4s}}, [{state}]",
            "movi v3.16b, #0",
            "2:",
            "ld1 {{v4.16b, v5.16b, v6.16b, v7.16b}}, [{data}], #64",
            "mov v18.16b, v0.16b",
            "mov v19.16b, v1.16b",
            "rev32 v4.16b, v4.16b",
            "rev32 v5.16b, v5.16b",
            "rev32 v6.16b, v6.16b",
            "rev32 v7.16b, v7.16b",
            scheduled!(0, "v4", "v5", "v6", "v7"),
            scheduled!(16, "v5", "v6", "v7", "v4"),
            scheduled!(32, "v6", "v7", "v4", "v5"),
            scheduled!(48, "v7", "v4", "v5", "v6"),
            scheduled!(64, "v4", "v5", "v6", "v7"),
            scheduled!(80, "v5", "v6", "v7", "v4"),
            scheduled!(96, "v6", "v7", "v4", "v5"),
            scheduled!(112, "v7", "v4", "v5", "v6"),
            scheduled!(128, "v4", "v5", "v6", "v7"),
            scheduled!(144, "v5", "v6", "v7", "v4"),
            scheduled!(160, "v6", "v7", "v4", "v5"),
            scheduled!(176, "v7", "v4", "v5", "v6"),
            rounds!(192, "v4"),
            rounds!(208, "v5"),
            rounds!(224, "v6"),
            rounds!(240, "v7"),
            "add v0.4s, v0.4s, v18.4s",
            "add v1.4s, v1.4s, v19.4s",
            "cmp {data}, {end}",
            "b.ne 2b",
            "st1 {{v0.4s, v1.4s}}, [{state}]",
            state = in(reg) state.as_mut_ptr(),
            data = inout(reg) data.start => _,
            end = in(reg) data.end,
            k = in(reg) K.as_ptr(),
            out("v0") _,
            out("v1") _,
            out("v2") _,
            out("v3") _,
            out("v4") _,
            out("v5") _,
            out("v6") _,
            out("v7") _,
            out("v16") _,
            out("v18") _,
            out("v19") _,
            options(nostack),
        );
    }
}
