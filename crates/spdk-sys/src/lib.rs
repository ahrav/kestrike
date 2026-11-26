//! Raw bindings to SPDK v25.05.1 and its bundled DPDK 25.03.0.
//!
//! The crate declares the native calls and structures Kestrike's
//! storage driver, memory registration and packet transport need, and C
//! entry points (`spdk_sys_*`) for operations the native headers define as
//! macros, static inline functions or bitfields, plus the registry query and
//! the layout table. It holds no safe wrappers: each image
//! cache module that calls a function owns the wrapper and its invariants.
//!
//! The build links every SPDK and DPDK archive statically with a scoped
//! `+whole-archive` modifier, so constructor-registered components (the NVMe
//! PCIe transport, the PCI bus, the ENA PMD and the ring mempool handlers)
//! stay in every binary that links this crate. [`spdk_sys_registry_query`]
//! reports which of them the live registries hold after environment
//! initialization.
//!
//! # Prerequisite install
//!
//! The build reads the install's static pkg-config metadata from
//! `SPDK_PKG_CONFIG_PATH`, default `/usr/local/lib/pkgconfig`, and fails,
//! naming this prerequisite, when the metadata, an archive, the pinned
//! version or the headers the bindings were generated from are missing or
//! differ. The pinned install is SPDK tag `v25.05.1` (commit
//! `44b23be7c35469bc0aba4b942c08c935125e2315`) with its `dpdk` submodule at
//! `cf36799c473a686fa14fde9af97f917a2125d3d5`, unpatched, built from the
//! SPDK tree with:
//!
//! ```text
//! ./configure --prefix=/usr/local --without-shared --disable-tests --disable-unit-tests \
//!   --disable-examples --disable-apps --without-crypto --without-fuse --without-uring \
//!   --without-rdma --without-vhost --without-virtio --without-vfio-user --without-idxd \
//!   --without-iscsi-initiator --without-xnvme --without-nvme-cuse --without-ocf --without-fio \
//!   --without-usdt --without-avahi --without-golang --without-sma --without-daos --without-rbd \
//!   --without-ublk --without-aio-fsdev --without-fc --without-vtune
//! make DPDKBUILD_FLAGS=-Denable_driver_sdk=true DPDK_DRIVERS="bus bus/pci bus/vdev mempool/ring \
//!   net/ena power/acpi power/amd_pstate power/cppc power/intel_pstate power/intel_uncore power/kvm_vm"
//! sudo make install
//! ```
//!
//! `DPDK_DRIVERS` adds the ENA PMD to SPDK's default DPDK driver set, and the
//! driver SDK installs `bus_pci_driver.h`, which the registry query reads.
//! The configuration targets the build host's CPU (`-march=native`); the
//! shims compile with the install's own pkg-config flags.
//!
//! The portable x86_64 install targets x86-64-v2 (`-march=x86-64-v2`, with
//! the `-mrtm` DPDK adds for x86_64 builds). It is configured
//! with `--prefix=/opt/spdk-v25.05.1-x86-64-v2 --target-arch=x86-64-v2` in
//! place of `--prefix=/usr/local`, installed with `make install`, and
//! selected through
//! `SPDK_PKG_CONFIG_PATH=/opt/spdk-v25.05.1-x86-64-v2/lib/pkgconfig`. Its
//! flags name `-march=x86-64-v2`, so it selects its own install record; the
//! include prefix is normalized away during selection.
//!
//! # Address-sanitized install
//!
//! An install configured with `--enable-asan --prefix=/opt/spdk-v25.05.1-asan`
//! beside the other options above, installed with `make install` and
//! selected through `SPDK_PKG_CONFIG_PATH=/opt/spdk-v25.05.1-asan/lib/pkgconfig`,
//! records `-lasan` in its DPDK link metadata. The build requires the Rust
//! flags to select `-Zsanitizer=address` for this install, and fails naming
//! the Rust flags' sanitizers otherwise. The sanitized configuration runs on
//! the pinned nightly with `RUSTFLAGS="-Zsanitizer=address
//! -Cforce-frame-pointers=yes"`, `-Zbuild-std` and
//! `--target x86_64-unknown-linux-gnu`; `llvm-symbolizer` on the path lets
//! sanitizer reports name their frames, which `shim_tests` requires. Under the
//! sanitized configuration every shim and probe compiles with address
//! sanitizer and frame pointers, the install's `asan` library gives way to
//! the Rust sanitizer runtime, the registry probes carry the target and
//! sanitizer flags, and the crate compiles with `cfg(spdk_sys_asan)`, under
//! which `shim_tests` runs a child that reads a header from a one-byte
//! allocation and requires the sanitizer's report to name the shim.
//!
//! # Generated bindings
//!
//! `crates/spdk-sys/regenerate.sh` writes the bindings and layout tables of
//! the host's install to a directory under `src/generated/outputs/`, named
//! by the digest of the three files, and records the install under
//! `src/generated/installs/` by its target triple and core, the core being
//! the `-mcpu` or `-march` value of the install's compile flags, with `-asan`
//! appended for an address-sanitized install. An aarch64 install targets the
//! build host's core, so Graviton3 (`neoverse-v1`) and Graviton4
//! (`neoverse-v2`) installs each have a record, as do the native, portable
//! (`x86-64-v2`) and sanitized native x86_64 installs. A record holds the
//! install's target, sanitizer and flags, the digest of its installed
//! headers and the name of the output its headers generate; installs whose
//! headers generate the same files share one output. Each output's bindings
//! file records the generator digest of the crate files
//! `native/generator-digest.sh` lists. The build selects the record of the
//! target, the sanitizer and the install's flags, with the install's include
//! root normalized so the same install at another prefix selects the same
//! record, then checks the record's header digest and the output's generator
//! digest. The generated-file test checks every output's generator digest on
//! any host, so a change to those crate files needs a regeneration on a host
//! of each install.
//!
//! The layout tests compare named structures' size, alignment and field
//! offsets, plus the listed reservation and status enums' size and alignment,
//! with the values the C compiler reports for the shim.

#![no_std]

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    clippy::all,
    clippy::pedantic,
    unsafe_op_in_unsafe_fn,
    missing_docs
)]
mod bindings {
    include!(concat!(env!("SPDK_SYS_GENERATED"), "/bindings.rs"));
}

pub use bindings::*;

/// The native build this crate links: the SPDK and bundled DPDK versions
/// and commits, the digest of the installed headers and the digest of the
/// generator files, each under its own label. The build checked the header
/// digest against the selected install record and the generator digest
/// against the selected output's bindings.
pub const PINS: &str = env!("SPDK_SYS_PINS");

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod layout_table {
    include!(concat!(env!("SPDK_SYS_GENERATED"), "/layout_table.rs"));
}

#[cfg(test)]
mod generated_tests;

#[cfg(test)]
mod layout_tests;

#[cfg(test)]
#[path = "../native/metadata.rs"]
mod metadata;

#[cfg(test)]
mod metadata_tests;

#[cfg(test)]
mod registry_tests;

#[cfg(test)]
#[path = "../native/select.rs"]
mod select;

#[cfg(test)]
mod select_tests;

#[cfg(test)]
mod shim_tests;
