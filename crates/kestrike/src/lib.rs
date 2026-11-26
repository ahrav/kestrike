//! A hardware-oriented image cache whose objects live on a block device.
//!
//! The [`storage`] module holds storage for one device volume: validated
//! configuration, checked record layout, capacity accounting and finite
//! work budgets, all without OS calls or heap allocation; and, on 64-bit
//! Linux, the owned, populated control mappings those values describe, with
//! every object held as an extent of the volume's bitmap allocator and a raw-byte
//! ledger conserved across every change, with fallible initialization,
//! exact rollback and exclusive finalization; the 32-byte record a completed
//! reservation binds into its slot, which identifies the object by its key's
//! fingerprint; and the registered lookup
//! that turns one complete key into a lease through a pinned interval, a
//! coherent snapshot, protected validation and a final live witness. On
//! Linux targets with 64-bit pointers and atomics, the [`index`] module
//! holds the concurrent index's foundations: checked geometry, the chained
//! bucket layout and its stores,
//! keyed full-key hashing, the shard sequence protocol and the reader's
//! chain scan. The `storage::device` submodule holds the storage-device
//! substrate's hugepage buffer arena and command table, and
//! [`storage::Volume`] is the one owner-thread device volume a storage
//! attaches. Objects have one payload path, the device: a fill streams its
//! record through [`storage::WritableFill::receive`] into the volume's write
//! commands and publishes only once every write succeeded, and a hit's
//! [`storage::ExtentLease`] reads the object through [`storage::Volume::read`],
//! which exposes only chunks whose header identity and checksums verified.
//!
//! The production device paths bypass the kernel. [`storage::SpdkDisk`] is
//! the SPDK NVMe poll-mode driver over an EBS volume's controller. The
//! [`native`] module holds the process's SPDK and DPDK environment, the
//! arena's registration shared by both drivers, and the DPDK ENA transport.
//! The [`bind`] module and the `kestrike-bind` tool move an owner's
//! controller and dataplane ENI to `vfio-pci` under the approved
//! write-combining modules, record them in the owner's state directory, and
//! release them.
//!
//! Each owner serves one volume from its own process, with its own
//! controller, dataplane ENI, polling core, arena and state directory; a
//! host runs N owner processes for N volumes, and a client host runs one
//! client process on its own ENI. A host runs these paths with hugepages of
//! the arena's configured size reserved, `vfio-pci` loaded in IOMMU mode,
//! or in no-IOMMU mode on an allowlisted host without a guest IOMMU, the
//! approved write-combining VFIO modules and a dedicated dataplane ENI per
//! process, and, at an owner, an EBS volume whose namespace is unmounted and
//! reserved for exclusive access by the owning process's [`storage::SpdkDisk`];
//! the bind tool and the endpoints run as root. The `net` module's
//! documentation lists the production gates by subject.
//!
//! On 64-bit Linux, the [`net`] module holds the network GET and PUT endpoints' substrate: exclusive owner-thread leases over the arena's packet pools, generation-checked request slots with a conserved census, shared request admission and wire routing, the checked fragment-to-buffer geometry, the one datagram seam both endpoint roles drive, which holds transmit sources until the device returns them, the frame codec, authenticated sessions, the owner and client transfer cores, the run-to-completion client endpoint, and the owner endpoint serving GETs and PUTs from a cache, a registration and a volume. Both endpoints run over the DPDK transport, and the client on its caller's thread, which polls it.
//!
//! The [`instrument`] module exposes per-thread heap counters for crate tests.
//!
//! Outside the `miri`, `kani`, `loom` and `protocol_contract` configurations,
//! an aarch64 build of the crate compiles with the `lse` target feature, so its
//! atomic read-modify-writes are LSE instructions, and an aarch64 build without
//! the feature fails to compile.

#![cfg_attr(
    test,
    allow(
        clippy::disallowed_methods,
        clippy::disallowed_types,
        reason = "unit tests can exercise host code outside the simulation harness"
    )
)]

::core::include!("mod.rs");

// `cargo fmt` formats only modules declared outside macros, so this
// declaration, which no build compiles, gives it the module tree the
// `include!` above brings in.
#[cfg(any())]
#[path = "mod.rs"]
mod tree;
