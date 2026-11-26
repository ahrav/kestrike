//! The release group guard against the running kernel, on an approved host
//! with a disposable device bound into `KESTRIKE_RELEASE_STATE_DIR`.
//!
//! Run as root, after `kestrike-bind` binds the disposable device into
//! that directory, with the device reserved for this test:
//!
//! ```text
//! KESTRIKE_RELEASE_STATE_DIR=/run/kestrike-scratch \
//!     cargo test -p kestrike --lib group_hardware_tests -- --ignored --nocapture
//! ```

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;

use super::binder::{BindError, Binder, mappings_path};
use super::group::vfio_request;
use super::host::{Host, SysfsKernel};
use super::mappings::Mappings;

const SET_IOMMU: libc::Ioctl = vfio_request(2);
const GROUP_SET_CONTAINER: libc::Ioctl = vfio_request(4);
const GROUP_GET_DEVICE_FD: libc::Ioctl = vfio_request(6);
const TYPE1_IOMMU: libc::c_ulong = 1;
const NOIOMMU_IOMMU: libc::c_ulong = 8;

/// A classic-container holder that keeps only its device descriptor holds
/// the group file, so `Binder::release` returns `BindError::VfioInUse` and
/// keeps the `vfio-pci` binding, in whichever VFIO mode the host runs; once
/// the descriptor closes, release completes. The run prints the approved
/// kernel, configuration digest and patch, and the mode.
#[test]
#[ignore = "needs root, the approved kernel and a disposable device bound into KESTRIKE_RELEASE_STATE_DIR"]
fn a_device_only_holder_refuses_release() {
    let state_dir = PathBuf::from(
        std::env::var_os("KESTRIKE_RELEASE_STATE_DIR")
            .expect("set KESTRIKE_RELEASE_STATE_DIR; see the module docs"),
    );
    let mappings = Mappings::read(&mappings_path(&state_dir)).unwrap();
    let bdf = mappings.first_bdf().to_owned();
    let host = Host::system();
    assert_eq!(host.driver(&bdf).as_deref(), Some("vfio-pci"));
    let group = std::fs::read_link(host.pci(&bdf).join("iommu_group")).unwrap();
    let group = group.file_name().unwrap().to_str().unwrap().to_owned();
    let (path, mode, iommu) = [
        (format!("/dev/vfio/{group}"), "iommu", TYPE1_IOMMU),
        (
            format!("/dev/vfio/noiommu-{group}"),
            "no-iommu",
            NOIOMMU_IOMMU,
        ),
    ]
    .into_iter()
    .find(|(path, _, _)| std::path::Path::new(path).exists())
    .expect("the bound device's VFIO group node");
    eprintln!(
        "kernel {} config {} patch {} mode {mode}",
        mappings.wc.kernel, mappings.wc.config_sha256, mappings.wc.patch
    );
    let device = {
        let group = File::options().read(true).write(true).open(&path).unwrap();
        let container = File::options()
            .read(true)
            .write(true)
            .open("/dev/vfio/vfio")
            .unwrap();
        let name = std::ffi::CString::new(bdf.as_str()).unwrap();
        let container_fd = container.as_raw_fd();
        // SAFETY: each request takes the argument its kernel interface
        // defines, on descriptors this test owns.
        unsafe {
            assert_eq!(
                libc::ioctl(
                    group.as_raw_fd(),
                    GROUP_SET_CONTAINER,
                    &raw const container_fd
                ),
                0
            );
            assert_eq!(libc::ioctl(container.as_raw_fd(), SET_IOMMU, iommu), 0);
            let fd = libc::ioctl(group.as_raw_fd(), GROUP_GET_DEVICE_FD, name.as_ptr());
            assert!(fd >= 0, "{}", std::io::Error::last_os_error());
            OwnedFd::from_raw_fd(fd)
        }
    };
    let binder = Binder {
        host: Host::system(),
        kernel: SysfsKernel,
        state_dir,
    };
    let refused = binder.release(&[]);
    assert!(matches!(refused, Err(BindError::VfioInUse)), "{refused:?}");
    assert_eq!(binder.host.driver(&bdf).as_deref(), Some("vfio-pci"));
    drop(device);
    // A held guard excludes every other group open.
    let guard = binder.host.guard_group(&SysfsKernel, &bdf).unwrap();
    let competing = File::options().read(true).write(true).open(&path);
    assert_eq!(
        competing.map(drop).map_err(|error| error.raw_os_error()),
        Err(Some(libc::EBUSY))
    );
    drop(guard);
    binder.release(&[]).unwrap();
    assert_ne!(binder.host.driver(&bdf).as_deref(), Some("vfio-pci"));
}
