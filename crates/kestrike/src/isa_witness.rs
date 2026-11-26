//! Per-thread execution counts of the specialized CPU kernels, read by the
//! architecture qualification tests to show that the kernel itself produced
//! the results they check.
//!
//! Each kernel counts itself inside its body, after every fallback and
//! validation exit, so a scalar path or an entry that returns early leaves
//! its count unchanged. The counts are thread-local, so each test reads only
//! the executions on its own thread.
//!
//! A test wraps its checks in [`witness`] with the kernel's full entry
//! predicate as a [`Detected`], from [`detected!`] or, for a build-configuration
//! predicate, from `cfg!`. The test passes when the kernel ran on a
//! host that reports every feature of the predicate, or stayed unreached on
//! a host that lacks one, and it
//! prints one `isa:` line that a qualification lane credits when the line
//! shows a positive count with every feature detected.

use std::cell::Cell;

/// A specialized kernel whose execution a qualification test requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kernel {
    /// One nonempty run of blocks of one SHA-256 chain through the aarch64 `sha2` instructions, each step's state copy an `EOR3`.
    Sha2One,
    /// One block step of two SHA-256 chains through the aarch64 `sha2` instructions.
    Sha2Two,
    /// One block step of three SHA-256 chains through the aarch64 `sha2` instructions.
    Sha2Three,
    /// One block step of four SHA-256 chains through the aarch64 `sha2` instructions.
    Sha2Four,
    /// One pass of two to four HMAC chains through the aarch64 `sha2` instructions, from each chain's middle blocks through its outer block, the fixed block between them compressed from its round words.
    Sha2Tail,
    /// One compile-time span of words folded as aarch64 16-byte lanes, the frame header's crc.
    CrcLanes,
    /// One nonempty run of bytes through the aarch64 CRC instruction loop or its copying entry; a copy with a tail counts once for each.
    CrcInstruction,
    /// One input of one aarch64 fold step, 240 bytes, or more, folded with the aarch64 carry-less multiply.
    CrcPmull,
    /// One compile-time span of words folded as x86_64 `crc32` chains joined by the carry-less multiply.
    CrcChains,
    /// One byte run through an x86_64 kernel that joins `crc32` chains or folds streams with the carry-less multiply.
    CrcNarrow,
    /// One input of at least four 64-byte blocks folded in the x86_64 AVX-512 accumulators.
    CrcWide,
    /// One sixteen-lane AVX-512 pass of HMAC inner chains.
    HmacWide,
    /// One GET DATA body's POLYVAL through the aarch64 carry-less multiply.
    PolyvalPmull,
    /// `EntropySvc` represents one `getrandom` system call issued through the aarch64 `svc` instruction.
    EntropySvc,
}

/// Every kernel, so the count table holds one cell per variant.
const ALL: [Kernel; 14] = [
    Kernel::Sha2One,
    Kernel::Sha2Two,
    Kernel::Sha2Three,
    Kernel::Sha2Four,
    Kernel::Sha2Tail,
    Kernel::CrcLanes,
    Kernel::CrcInstruction,
    Kernel::CrcPmull,
    Kernel::CrcChains,
    Kernel::CrcNarrow,
    Kernel::CrcWide,
    Kernel::HmacWide,
    Kernel::PolyvalPmull,
    Kernel::EntropySvc,
];

const KERNELS: usize = ALL.len();
const _: () = {
    let mut at = 0;
    while at < KERNELS {
        assert!(ALL[at] as usize == at);
        at += 1;
    }
};

thread_local! {
    static RUNS: [Cell<usize>; KERNELS] = const { [const { Cell::new(0) }; KERNELS] };
}

/// Counts one execution of `kernel` on this thread.
pub(crate) fn ran(kernel: Kernel) {
    RUNS.with(|runs| {
        let count = &runs[kernel as usize];
        count.set(count.get() + 1);
    });
}

/// Executions of `kernel` counted on this thread so far.
pub(crate) fn runs(kernel: Kernel) -> usize {
    RUNS.with(|runs| runs[kernel as usize].get())
}

/// A host's answer to one kernel's full entry predicate: CPU feature probes,
/// or the build configuration when the kernel's predicate is a `cfg`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Detected {
    /// `ARCH name=bool ...`, or `host ARCH lacks ARCH` on a host of another architecture.
    pub(crate) features: String,
    /// Whether every feature of the predicate is present.
    pub(crate) present: bool,
}

/// Runs `body` and prints one witness line: `isa: NAME ran N times;
/// FEATURES` when `count` grew by `N > 0` across `body`, and `isa: NAME
/// unreached; FEATURES` when it did not.
///
/// # Panics
///
/// - If `count` grew across `body` while `detected.present` is false.
/// - If `count` stayed unchanged across `body` while `detected.present` is
///   true.
pub(crate) fn witness(
    name: &str,
    detected: Detected,
    count: impl Fn() -> usize,
    body: impl FnOnce(),
) {
    let Detected { features, present } = detected;
    let before = count();
    body();
    let delta = count() - before;
    if delta > 0 {
        println!("isa: {name} ran {delta} times; {features}");
    } else {
        println!("isa: {name} unreached; {features}");
    }
    assert_eq!(
        delta > 0,
        present,
        "{name} ran {delta} times on a host with {features}"
    );
}

/// The host's runtime detection of each named CPU feature of one
/// architecture as a [`Detected`]. The features are a kernel's full entry
/// predicate, so a witness line names what the lane requires and a test can
/// require the kernel to run exactly when the predicate holds.
macro_rules! detected {
    (@detect $arch:literal, $detect:ident: $($feature:tt),+) => {{
        #[cfg(target_arch = $arch)]
        let found = $crate::isa_witness::Detected {
            features: format!(
                concat!($arch, $(" ", $feature, "={}"),+),
                $(std::arch::$detect!($feature)),+
            ),
            present: true $(&& std::arch::$detect!($feature))+,
        };
        #[cfg(not(target_arch = $arch))]
        let found = $crate::isa_witness::Detected {
            features: format!("host {} lacks {}", std::env::consts::ARCH, $arch),
            present: false,
        };
        found
    }};
    (x86_64: $($feature:tt),+) => {
        $crate::isa_witness::detected!(@detect "x86_64", is_x86_feature_detected: $($feature),+)
    };
    (aarch64: $($feature:tt),+) => {
        $crate::isa_witness::detected!(@detect "aarch64", is_aarch64_feature_detected: $($feature),+)
    };
}

pub(crate) use detected;

#[cfg(test)]
mod tests {
    use super::{Detected, witness};

    fn host(present: bool) -> Detected {
        Detected {
            features: "test host".into(),
            present,
        }
    }

    /// A kernel that stays unreached on a host whose predicate holds fails its witness, so the witness fails whenever a suppressed count or a fallback replaces the kernel.
    #[test]
    #[should_panic(expected = "kernel ran 0 times on a host with test host")]
    fn an_unreached_kernel_on_a_capable_host_fails_its_witness() {
        witness("kernel", host(true), || 0, || {});
    }

    /// A kernel that runs on a host whose predicate fails fails its witness, since detection alone may select it.
    #[test]
    #[should_panic(expected = "kernel ran 1 times on a host with test host")]
    fn a_kernel_run_without_its_predicate_fails_its_witness() {
        let count = std::cell::Cell::new(0);
        witness("kernel", host(false), || count.get(), || count.set(1));
    }

    /// A count that grows exactly when the predicate holds passes either way.
    #[test]
    fn a_witness_passes_when_the_count_follows_the_predicate() {
        let count = std::cell::Cell::new(0);
        witness("kernel", host(true), || count.get(), || count.set(2));
        witness("kernel", host(false), || count.get(), || {});
    }
}
