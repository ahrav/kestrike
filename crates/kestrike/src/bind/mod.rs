//! Binding the EBS volume's NVMe controller to `vfio-pci` for the SPDK
//! driver and the dataplane ENI for the DPDK driver, the write-combining
//! module both need, the inventory that records them, and the owner lock
//! they share.
//!
//! Invariants owned by this module:
//!
//! - Binding touches only the one controller whose serial is the configured
//!   volume ID, whose model, PCI identity and single namespace match an EBS
//!   volume, and whose namespace and partitions no mount, swap area, holder,
//!   open descriptor or file registered under the device's name with an
//!   io_uring instance open as a descriptor uses, so the root and boot
//!   devices are never bound.
//!   Every check runs again immediately before the controller leaves its
//!   kernel driver.
//! - The controller moves only through its own `driver_override` and the
//!   explicit unbind and bind files; no global `new_id` is written. The VFIO
//!   posture must be the observed one: `vfio-pci` loaded, IOMMU mode with a
//!   guest IOMMU, or no-IOMMU mode only on an allowlisted host without one. A
//!   shared IOMMU group refuses. A failed step restores the recorded driver
//!   and override where it can and reports the device's actual state.
//! - A failed bind restores only the devices it moved. Release runs only
//!   while no process holds the owner lock, and only on the running kernel
//!   and VFIO modules the record approves. It opens a guard on the VFIO
//!   group file of each recorded device on `vfio-pci`, which the kernel
//!   grants while no process holds the group or one of its devices, checks
//!   the opened file against the group device sysfs names and the group's
//!   status, and holds every guard from before its first write through the
//!   restores. It restores exactly the recorded driver and override,
//!   verifies them, and reports each device's actual state when a step
//!   fails.
//! - The [`Mappings`] file is written atomically and records the instance,
//!   the boot, and each bound device's identity, geometry and original
//!   driver and override, and names its one format; the binder and the
//!   owner refuse a file naming any other. The owner refuses a file from another
//!   instance or boot and re-identifies the device before any payload I/O.
//! - The dataplane ENI is the one secondary interface the configured ENI ID
//!   names in the instance metadata, which lists exactly one IPv4 address
//!   for it, inside its subnet and on its device. Its permanent MAC names
//!   one network device on `ena` with a PCI ID the pinned driver supports,
//!   alone in its IOMMU group, carrying neither the main IPv4 table's
//!   default route, an IPv6 default route, nor a global IPv6 address. Bind
//!   reads the device's network state while it is still on `ena`: the MTU,
//!   the link state, the IPv4 addresses with any broadcast address they
//!   carry and the main-table IPv4 routes, with each peer's next-hop MAC.
//!   Release restores that network state, the MTU first, on the device its
//!   interface index names, once `ena` holds
//!   the device again, and assigns each address a forever lifetime; lease
//!   renewal and network-manager ownership after release belong to the
//!   deployment. The second check reads the MTU, link state, addresses and
//!   routes again under the ENI's device lock and refuses a change before
//!   any ENI driver write. The lock serializes cooperating binders alone, so
//!   the deployment marks the dedicated ENI unmanaged and keeps DHCP, SLAAC
//!   and network managers off it from the first check until a release
//!   succeeds. The capture reads the network namespace of the ENI's device
//!   and refuses a device that another device of that namespace is stacked
//!   on. When the ENI leaves `ena`, the kernel removes each device stacked
//!   on the ENI's device, such as a VLAN, a macvlan or a VXLAN device, in
//!   whichever network namespace it resides, and release recreates none of
//!   them, so the deployment keeps every other network namespace free of a
//!   device stacked on the ENI's device over the same interval.
//! - Each peer's next-hop MAC comes from a `REACHABLE` neighbor entry, the
//!   kernel's confirmation, or a `PERMANENT` one, which the deployment
//!   trusts as configuration. A bind resolves next hops after its first
//!   checks pass, under the ENI's device lock with the ENI still on `ena`:
//!   it removes a hop's `STALE`, `DELAY`, `PROBE`, `FAILED`, `INCOMPLETE` or
//!   `NONE` entry once and solicits each unresolved hop for up to five
//!   rounds, so a bind refused in or after the next-hop resolution, before
//!   the record, writes no driver attribute but can leave the ENI's neighbor
//!   entries refreshed. The recorded MACs hold for the owner's run; a
//!   gateway or peer that changes identity needs a controlled refresh and an
//!   endpoint restart.
//! - The approved write-combining kernel and VFIO modules are checked before
//!   any device moves, and the loaded modules' identity again before each
//!   driver move: kernel release and configuration, with the configuration
//!   exposing VFIO through the classic group and container interface alone
//!   and building the backend the host's VFIO mode uses, each module file's
//!   digest and declared `srcversion`, and each loaded module's
//!   `srcversion`. The tool only reads module state, and runs its network
//!   tools with a cleared environment and a fixed search path.
//!   [`Host::check_wc_mapping`] checks the ENA's write-combining BAR mapping
//!   once `vfio-pci` holds the ENA and the poll-mode driver has probed it:
//!   through the kernel's PAT table on x86_64, and through the loaded
//!   approved modules on aarch64, whose mmap sets the guest mapping's
//!   memory type.
//! - Each owner is one state directory, named by `--state-dir`, holding its
//!   [`OwnerLock`] and its mappings file; one owner per volume and N owners
//!   per host use N directories. Binding, release and the owner's run
//!   serialize on their directory's lock, which the owner holds for its whole
//!   run, so a second owner binds and releases its own devices while the
//!   first runs, and release restores only what its own directory records.
//!   A bind takes each device's [`DeviceLock`] once, before it checks the
//!   other owners' records, and holds it through the record's publication
//!   and the driver move, and each restore holds it too, so two binds naming
//!   one device move it at most once. The device lock directory must have
//!   all group and other permission bits cleared. A bind refuses a device
//!   that another owner's directory, when given, records. A release takes
//!   every recorded device's lock, then refuses when a given other owner's
//!   directory records one of those devices, before it restores anything.
//! - A file or directory under `proc` or `sys` is evidence only as the
//!   kernel's own. A mount the tool's mount table lists over one, as a
//!   container runtime's tmpfs and bind mounts are, shows the mount's text
//!   or entries there, so a bind and a release resolve every such path
//!   through [`Host::shown`] and refuse a covered one as unreadable. The
//!   configfs listings and each process's directory are judged once for a
//!   whole check. The mount table is the one text the covers are judged
//!   by: a table that is itself another file system's text takes
//!   `CAP_SYS_ADMIN` in the tool's mount namespace to place, which is the
//!   privilege to unbind the device directly, and is outside this guard.

mod authority;
#[cfg(test)]
pub(crate) mod authority_tests;
mod binder;
#[cfg(test)]
mod binder_tests;
mod changes;
mod checkpoint;
#[cfg(test)]
mod cut_tests;
mod eni;
#[cfg(test)]
mod eni_tests;
#[cfg(test)]
mod fault_tests;
#[cfg(test)]
pub(crate) mod fixture;
mod group;
#[cfg(test)]
mod group_hardware_tests;
#[cfg(test)]
mod guest_tests;
mod host;
mod identity;
#[cfg(test)]
mod identity_tests;
mod lock;
mod mappings;
#[cfg(test)]
pub(crate) mod mappings_tests;
mod metadata;
#[cfg(test)]
mod metadata_tests;
#[cfg(test)]
mod network_tests;
#[cfg(test)]
mod reading_order_tests;
pub(crate) mod record_step;
#[cfg(test)]
mod rename_tests;
#[cfg(test)]
mod replay_control;
#[cfg(test)]
mod replay_tests;
mod rings;
#[cfg(test)]
mod rings_tests;
#[cfg(test)]
mod round_trip_tests;
mod tool;
#[cfg(test)]
mod tool_tests;
#[cfg(test)]
mod uptime_tests;
mod walk;
#[cfg(test)]
mod walk_thread_capability_tests;
mod wc;
#[cfg(test)]
mod wc_tests;

pub use authority::FreshRecords;
#[cfg(test)]
pub(crate) use authority::private_read;
pub(crate) use authority::{AttachAuthority, REFUSAL_PREFIX};
pub(crate) use binder::VFIO;
pub use binder::{
    BindError, BindRequest, Binder, DeviceState, EniRequest, RELEASE_SCOPE, VfioPosture,
    mappings_path, prepare_state_dir, private_state_dir,
};
pub use eni::{Eni, EniError, NetState, is_eni_id};
pub(crate) use host::serial_of;
pub use host::{Fed, Host, Kernel, Started, SysfsKernel, is_volume_id};
pub(crate) use identity::ControllerIdentity;
pub use identity::{Controller, IdentityError};
pub(crate) use lock::DEVICE_LOCKS;
pub use lock::{DeviceLock, OwnerLock};
pub use mappings::{EniBinding, Mappings, MappingsError, NvmeBinding};
pub use metadata::{ENDPOINT, Imds, LIMITS, Limits, Metadata};
pub use wc::{WcError, WcManifest, WcModule};
