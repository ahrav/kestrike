// The crate's module tree, included by the library root and the
// simulation worker's root so both compile the same modules.

// Outside the four exempt configurations below, an aarch64 build of the crate
// compiles with the `lse` target feature, so its atomic read-modify-writes are
// LSE instructions. `.cargo/config.toml` sets the feature for a Cargo run whose
// working directory is inside the repository, and a set `RUSTFLAGS` or
// `CARGO_ENCODED_RUSTFLAGS` (for rustdoc, `RUSTDOCFLAGS` or
// `CARGO_ENCODED_RUSTDOCFLAGS`) replaces that file's flags, so this guard
// refuses a build that lost it. The exemptions: `miri` interprets the crate
// and emits no machine code; `kani` is a proof build under the Kani driver's
// own flags; `loom` and `protocol_contract` are test builds whose commands set
// `RUSTFLAGS` to their cfg alone, so they compile without `lse`.
// `::core::compile_error!` resolves through the absolute path, so a `use`
// import or macro named `compile_error` in the crate leaves the call intact.
#[cfg(all(
    target_arch = "aarch64",
    not(target_feature = "lse"),
    not(any(miri, kani, loom, protocol_contract))
))]
::core::compile_error!(
    "kestrike on aarch64 requires the `lse` target feature: pass `-C target-feature=+lse`. \
     RUSTFLAGS and CARGO_ENCODED_RUSTFLAGS, or RUSTDOCFLAGS and CARGO_ENCODED_RUSTDOCFLAGS for rustdoc, \
     when set, replace the flags of .cargo/config.toml, which Cargo reads from the working directory's ancestors."
);

pub mod storage;

pub mod failover;

// On 64-bit Linux every binary of the crate links the native SPDK and DPDK
// archives, so their constructor-registered drivers are present in each one.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use spdk_sys as _;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "bind operates on the host; simulated production code calls some bind helpers, so new listed uses in those helpers pass this gate"
)]
pub mod bind;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "the native environment, arena registration and transport serve host hardware; simulation supplies Disk and Datagrams"
)]
pub mod native;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod entropy;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod net;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod records;
#[cfg(all(kani, target_os = "linux", target_pointer_width = "64"))]
mod records_kani;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod records_tests;

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod exact_child;

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod exact_child_tests;

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
#[warn(clippy::disallowed_methods)]
mod oracle;

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod clients_closed_tests;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[cfg_attr(test, warn(clippy::disallowed_methods))]
mod sim;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "the soak tool measures real hardware on the host"
)]
pub mod soak;

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod soak_tests;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod host;

#[cfg(all(
    target_os = "linux",
    target_pointer_width = "64",
    target_has_atomic = "64"
))]
pub mod index;

pub mod instrument;

#[cfg(test)]
mod isa_witness;
