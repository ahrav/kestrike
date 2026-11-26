//! Binds the configured EBS volume's NVMe controller, the dataplane ENI, or
//! both to `vfio-pci` for Kestrike, or releases them back to their
//! kernel drivers.
//!
//! ```text
//! kestrike-bind --wc-manifest <file> [--volume vol-0123456789abcdef0]
//!     [--eni eni-0123456789abcdef0 --peer <ipv4>...] [--allow-no-iommu] [--state-dir /run/kestrike]
//!     [--other-state-dir <dir>...]
//! kestrike-bind --release [--state-dir /run/kestrike] [--other-state-dir <dir>...]
//! ```
//!
//! An owner binds its volume and its ENI; a client binds its ENI alone. Each
//! `--peer` names a peer's IPv4 address, whose next-hop MAC the bind records.
//! Each `--other-state-dir` names another owner's state directory on this
//! host; a bind or release of a device its mappings file records refuses
//! before any driver write or record change.
//! The manifest names the approved write-combining kernel and VFIO modules;
//! `--wc-manifest` names the manifest file itself, which the tool opens with
//! `O_NOFOLLOW`.
//! Run as root in the host's PID namespace. The state directory and every
//! directory above it, the manifest and each approved module file must be
//! root-owned and writable by root only.
//!
//! A bind admits the ENI's network state only inside the domain release
//! restores: its MTU, link state, global IPv4 addresses and main-table IPv4
//! routes (see [`Host::net_state`]). A route of the ENI in a table other
//! than main, apart from the kernel's local-table entries of its addresses,
//! refuses the bind with `routes`. So does a main-table route of the ENI
//! unless release replays it as the same route. Release replays a unicast
//! or multicast route whose every word is its destination, a `via` gateway
//! or one of these attributes: `proto`, `scope` as `host`, `link`, `global`,
//! `site`, `nowhere` or a number, `src`, `metric`, `tos`, `onlink`, a
//! numeric `realm`, a numeric `realms` pair with each side at most 255,
//! `mtu`, `advmss`, `window`, `ssthresh`, `cwnd`, `initcwnd`, `initrwnd`,
//! `reordering`, `hoplimit` and `congctl`, each with an optional `lock`,
//! `quickack` and `fastopen_no_cookie` of 0 or 1, and `features` of one
//! feature. A route with any other word refuses, for example a tunnel
//! encapsulation, an `rtt`, `rttvar` or `rto_min` metric, an offload or trap
//! flag, a nexthop object, or a realm or scope under a name the host gave
//! it. A route with no listed scope refuses unless it is a unicast route
//! through a gateway, and so does a `default` route through an IPv6
//! gateway. The ENI's routes refuse together when two share one
//! destination, type of service and metric, and when a route's gateway is
//! neither one of the ENI's addresses nor inside a prefix route the kernel
//! adds with an address or a link-scope or host-scope route that release
//! replays first; a route with `onlink` needs neither, and an IPv6 gateway
//! must be link-local or `onlink`, on an ENI whose MTU is at least 1280 and
//! a host whose `net.ipv6.conf.default.disable_ipv6` is 0. An address or
//! route line with whitespace outside ASCII refuses.
//! The routes of the host's other devices, and its `blackhole`,
//! `unreachable`, `prohibit`, `throw`, `nat` and `xresolve` routes, which
//! belong to no device, do not refuse the bind, with these exceptions: a
//! main-table one that shares a destination, type of service and metric
//! with a route of the ENI, or the destination and metric when it has a
//! tunnel encapsulation, which release would write over; a main-table one
//! whose `src` is one of the ENI's addresses, which the kernel removes with
//! the address; a multipath one with a next hop on the ENI; and one through
//! a nexthop object, unless `ip` lists another device for the object, which
//! it does for none when `net.ipv4.nexthop_compat_mode` is 0. Two
//! interfaces in one subnet hold prefix routes under one destination, so
//! give the ENI's addresses a `metric` of their own. Any IPv6 route of
//! the ENI other than the kernel's entries of its link-local address also
//! refuses with `routes`; an IPv4 or IPv6 rule
//! naming the ENI, one of its altnames or one of its addresses refuses with
//! `rules`. Remove those routes and rules before binding, and keep them
//! from returning.
//!
//! Release replays the recorded MTU, link state, addresses and main-table
//! routes. The kernel derives the returned ENI's other entries from those
//! addresses and the host's IPv6 settings at release: the prefix route of
//! the first address of each network and prefix length unless that address
//! has `noprefixroute` or the network lies in 0.0.0.0/8, the local table's
//! entries, and the IPv6 link-local address with its routes. A link-local
//! address assigned
//! by hand, or a derived route deleted before the bind, is replaced by the
//! kernel's own. Release replays an address's `noprefixroute`, which keeps
//! the kernel from adding that address's prefix route. The returned ENI
//! starts from `net.ipv6.conf.default.disable_ipv6`, and the kernel takes
//! a route through an IPv6 gateway only while that setting is 0, so keep it
//! 0 until release.
//!
//! The bind removes the ENI's device with the rest of its state: link
//! attributes such as `alias`, `group` and `qlen`, altnames, nexthop
//! objects that name the device, neighbor entries, queueing disciplines and
//! device sysctls. The returned ENI starts from the kernel's defaults for
//! that state, so apply it again after release. The capture supports Linux
//! 5.14 and later: an earlier kernel's `broadcast` entry for a prefix's
//! network address refuses the bind with `routes`.
//!
//! Arguments are read as OS strings. `--wc-manifest`, `--state-dir` and
//! `--other-state-dir` take any path the OS can name, its bytes passed
//! through unchanged; option names and the `--volume`, `--eni` and `--peer`
//! values must be UTF-8 and match their grammar: a `vol-` or `vol` volume ID, an
//! `eni-` ENI ID, an IPv4 peer. A missing, conflicting, unknown or
//! malformed argument, a non-UTF-8 textual one, a single-valued option
//! given twice, or a bind without `--wc-manifest`, exits 2 with the
//! usage line before the privilege check, the PID-namespace check or any
//! file, kernel or metadata effect. Every other refusal and failure exits 1;
//! a failed driver step, or a recorded address that changed, also prints the
//! device's actual state.
//!
//! Release each binding before installing another build or changing the
//! running kernel or VFIO modules: [`Binder::release`] applies the running
//! binary's kernel and VFIO checks to the running host against the manifest
//! the mappings file records, and refuses a binding those checks reject
//! with `Wc`, leaving its devices on `vfio-pci`.
//! [`kestrike::bind::Mappings::read`] refuses a mappings file whose
//! `format` differs from the one [`kestrike::bind::Mappings::write`]
//! writes.

use std::net::Ipv4Addr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kestrike::bind::{
    BindRequest, Binder, EniRequest, Host, Imds, SysfsKernel, VfioPosture, WcManifest, is_eni_id,
    is_volume_id, prepare_state_dir,
};

/// Seconds the metadata session token stays valid: past the slowest bind, whose next-hop solicitations run five rounds of one second.
const TOKEN_TTL: u32 = 3600;

/// What a validated request does.
enum Action {
    Release,
    /// A bind under the write-combining manifest at this path.
    Bind(PathBuf),
}

fn usage(message: &str) -> ExitCode {
    eprintln!(
        "kestrike-bind: {message}; give --wc-manifest <file> with --volume <id>, --eni <id> --peer <ipv4>..., or both, [--allow-no-iommu]; or --release; and optionally --state-dir <dir> and --other-state-dir <dir>..."
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let (mut volume, mut eni, mut manifest) = (None, None, None::<PathBuf>);
    let (mut peers, mut release, mut allow_no_iommu) = (Vec::<Ipv4Addr>::new(), false, false);
    let mut state_dir = None::<PathBuf>;
    let mut others = Vec::new();
    while let Some(arg) = args.next() {
        let Some(name) = arg.to_str() else {
            return usage(&format!("unknown argument {}", arg.display()));
        };
        let mut value = || {
            args.next()
                .ok_or_else(|| usage(&format!("{name} needs a value")))
        };
        // A textual value must be UTF-8 and match `grammar`; `what` names it.
        let mut text = |grammar: fn(&str) -> bool, what: &str| {
            let text = value()?
                .into_string()
                .map_err(|_| usage(&format!("{name} needs UTF-8")))?;
            if grammar(&text) {
                Ok(text)
            } else {
                Err(usage(&format!("{name} needs {what}")))
            }
        };
        // A single-valued option given twice is a conflict.
        let once = |slot: bool| {
            if slot {
                Err(usage(&format!("{name} given twice")))
            } else {
                Ok(())
            }
        };
        let parsed = match name {
            "--volume" => once(volume.is_some())
                .and_then(|()| text(is_volume_id, "a volume ID"))
                .map(|v| volume = Some(v)),
            "--eni" => once(eni.is_some())
                .and_then(|()| text(is_eni_id, "an ENI ID"))
                .map(|v| eni = Some(v)),
            "--peer" => value().and_then(|v| {
                v.into_string()
                    .ok()
                    .and_then(|v| v.parse::<Ipv4Addr>().ok())
                    .map(|ip| peers.push(ip))
                    .ok_or_else(|| usage("--peer needs an IPv4 address"))
            }),
            "--wc-manifest" => once(manifest.is_some())
                .and_then(|()| value())
                .map(|v| manifest = Some(v.into())),
            "--state-dir" => once(state_dir.is_some())
                .and_then(|()| value())
                .map(|v| state_dir = Some(v.into())),
            "--other-state-dir" => value().map(|v| others.push(PathBuf::from(v))),
            "--release" => {
                release = true;
                Ok(())
            }
            "--allow-no-iommu" => {
                allow_no_iommu = true;
                Ok(())
            }
            other => Err(usage(&format!("unknown argument {other}"))),
        };
        if let Err(code) = parsed {
            return code;
        }
    }
    let state_dir = state_dir.unwrap_or_else(|| PathBuf::from("/run/kestrike"));
    let binding = volume.is_some() || eni.is_some();
    // Peers come with an ENI, and an ENI with at least one peer.
    let peers_fit = eni.is_some() != peers.is_empty();
    if release == binding
        || (release && (allow_no_iommu || manifest.is_some() || !peers.is_empty()))
        || (binding && !peers_fit)
    {
        return usage("choose one action");
    }
    // Every argument is checked before the privilege check and any effect.
    let action = match manifest {
        None if release => Action::Release,
        Some(manifest) => Action::Bind(manifest),
        None => return usage("--wc-manifest is required"),
    };
    // SAFETY: reads the effective user ID.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("kestrike-bind: must run as root");
        return ExitCode::FAILURE;
    }
    let host = Host::system();
    // The in-use check walks this process's view of the process table, which
    // lists every holder of a device only in the host's PID namespace.
    match host.in_initial_pid_namespace() {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("kestrike-bind: must run in the host's PID namespace");
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("kestrike-bind: cannot identify the PID namespace: {error}");
            return ExitCode::FAILURE;
        }
    }
    // A directory another user can write, at or above the state directory,
    // could swap in a planted lock or mappings file, or redirect its creation.
    if let Err(error) = prepare_state_dir(&state_dir, 0) {
        eprintln!("kestrike-bind: {error}");
        return ExitCode::FAILURE;
    }
    let binder = Binder {
        host,
        kernel: SysfsKernel,
        state_dir,
    };
    let result = match action {
        Action::Release => binder.release(&others).map(|()| println!("released")),
        Action::Bind(manifest_path) => {
            let manifest = match WcManifest::read(&manifest_path) {
                Ok(manifest) => manifest,
                Err(error) => {
                    eprintln!(
                        "kestrike-bind: write-combining manifest {}: {error:?}",
                        manifest_path.display()
                    );
                    return ExitCode::FAILURE;
                }
            };
            let root_only = |path: &Path| {
                let trusted = std::fs::metadata(path)
                    .is_ok_and(|meta| meta.uid() == 0 && meta.mode() & 0o022 == 0);
                if !trusted {
                    eprintln!(
                        "kestrike-bind: {} must be root-owned and writable by root only",
                        path.display()
                    );
                }
                trusted
            };
            if !manifest
                .modules
                .iter()
                .all(|module| root_only(&module.file))
            {
                return ExitCode::FAILURE;
            }
            let metadata = match eni.is_some().then(|| Imds::connect(TOKEN_TTL)).transpose() {
                Ok(metadata) => metadata,
                Err(error) => {
                    eprintln!("kestrike-bind: instance metadata: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let request = BindRequest {
                volume: volume.as_deref(),
                eni: eni
                    .as_deref()
                    .zip(metadata.as_ref())
                    .map(|(id, metadata)| EniRequest {
                        id,
                        peers: &peers,
                        metadata,
                    }),
                posture: VfioPosture { allow_no_iommu },
                wc: &manifest,
                others: &others,
            };
            binder
                .bind(&request)
                .map(|mappings| println!("bound {mappings:?}"))
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("kestrike-bind: {error}");
            ExitCode::FAILURE
        }
    }
}
