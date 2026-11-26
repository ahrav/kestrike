//! The integer operations whose LLVM intrinsics the patched checker lowers.
//! rustc emits `llvm.uadd.sat` and `llvm.usub.sat` for the saturating
//! operations at every optimization level; `llvm.umin`, `llvm.umax`,
//! `llvm.smin` and `llvm.smax` appear only once LLVM canonicalizes a compare
//! and select, so the package builds this crate at `opt-level = 1`. The GenMC
//! lane checks that the built bitcode calls all six before it credits the
//! case.
#![no_std]

#[inline(never)]
pub fn uadd_sat(a: u64, b: u64) -> u64 {
    a.saturating_add(b)
}

#[inline(never)]
pub fn usub_sat(a: u64, b: u64) -> u64 {
    a.saturating_sub(b)
}

#[inline(never)]
pub fn umin(a: u64, b: u64) -> u64 {
    a.min(b)
}

#[inline(never)]
pub fn umax(a: u64, b: u64) -> u64 {
    a.max(b)
}

#[inline(never)]
pub fn smin(a: i64, b: i64) -> i64 {
    a.min(b)
}

#[inline(never)]
pub fn smax(a: i64, b: i64) -> i64 {
    a.max(b)
}
