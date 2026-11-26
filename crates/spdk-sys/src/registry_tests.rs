//! Proves the static link plan retains every constructor-registered
//! component: after environment initialization with no devices, the live
//! registries hold the NVMe PCIe transport, the PCI bus, the ENA PMD and the
//! ring mempool handlers. A negative control links the ENA archive without
//! `+whole-archive` and shows the same query then misses the PMD. Both links
//! succeed and the query's answers distinguish them, so the query carries the
//! evidence. The PCI bus is the exception: the query itself reads the bus
//! object, whose archive member also holds the bus constructor, so every
//! binary that links the query retains the bus.

use std::env;
use std::format;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::string::String;
use std::sync::OnceLock;
use std::vec::Vec;

use crate::{
    spdk_env_init, spdk_env_opts, spdk_env_opts_init, spdk_sys_registry, spdk_sys_registry_query,
    spdk_sys_rte_library_matches_headers,
};

/// Initializes the environment once for this test process: one core, no
/// hugepages, no PCI devices and no shared-memory identity.
fn environment() {
    static INIT: OnceLock<i32> = OnceLock::new();
    let rc = *INIT.get_or_init(|| {
        let mut opts = spdk_env_opts {
            opts_size: size_of::<spdk_env_opts>(),
            ..Default::default()
        };
        // SAFETY: `opts` is a valid, sized options structure, and the name is a static C string.
        unsafe {
            spdk_env_opts_init(&mut opts);
            opts.name = c"spdk-sys-test".as_ptr();
            opts.no_pci = true;
            opts.no_huge = true;
            opts.mem_size = 64;
            opts.shm_id = -1;
            spdk_env_init(&opts)
        }
    });
    assert_eq!(rc, 0, "environment initialization failed");
}

fn query() -> spdk_sys_registry {
    let mut found = spdk_sys_registry::default();
    // SAFETY: the query only reads the initialized registries and writes `found`.
    unsafe { spdk_sys_registry_query(&mut found) };
    found
}

#[test]
fn every_retained_component_is_registered_after_environment_init() {
    environment();
    let found = query();
    assert!(
        found.nvme_pcie_transport,
        "NVMe PCIe transport missing: {found:?}"
    );
    assert!(found.pci_bus, "PCI bus missing: {found:?}");
    assert!(found.ena_pmd, "ENA PMD missing: {found:?}");
    assert!(
        found.ring_mempool,
        "ring mempool handlers missing: {found:?}"
    );
}

#[test]
fn the_linked_dpdk_reports_the_version_its_headers_declare() {
    // SAFETY: the comparison reads static version strings only.
    assert!(unsafe { spdk_sys_rte_library_matches_headers() });
}

#[test]
fn no_shared_spdk_or_dpdk_library_is_mapped() {
    let maps = fs::read_to_string("/proc/self/maps").unwrap();
    let shared: Vec<&str> = maps
        .lines()
        .filter(|line| line.contains("librte_") || line.contains("libspdk_"))
        .collect();
    assert!(
        shared.is_empty(),
        "a second, shared native copy is mapped: {shared:?}"
    );
}

/// glibc's tunable that backs malloc arenas with transparent huge pages.
const HUGE_PAGE_MALLOC: &str = "glibc.malloc.hugetlb=1";

/// Links the probe program with this crate's link plan, linking `plain`
/// (when given) without `+whole-archive`, runs it and returns its registry
/// digits. The probe, `native/probe.c`, initializes the environment as
/// [`environment`] does and prints the registry query's four answers as
/// `0`/`1` digits.
///
/// The rustc that builds this crate links the probe from a `#![no_main]`
/// stub, with the build's target and sanitizer flags, and gives each SPDK
/// and DPDK archive the `+whole-archive` modifier the build script emits, so
/// the probe goes through rustc's native-library handling and default
/// linker. The probe object is the first library, so a
/// linker that resolves archives in command-line order, such as GNU ld, sees
/// its references before the shim archive. The probe links the standard
/// library dynamically, which `-Crpath` lets it find at run time, strips debug
/// information, and runs the linker with huge-page malloc arenas; each of the
/// three shortens a GNU ld link.
fn probe(plain: Option<&str>) -> String {
    let out = Path::new(env!("OUT_DIR"));
    let dir = out.join(format!("probe-{}", plain.unwrap_or("whole")));
    fs::create_dir_all(&dir).unwrap();
    let stub = dir.join("stub.rs");
    fs::write(&stub, "#![no_main]\n").unwrap();
    let binary = dir.join("probe");
    // The linker inherits the tunable through rustc's environment.
    let tunables = env::var("GLIBC_TUNABLES").map_or_else(
        |_| HUGE_PAGE_MALLOC.into(),
        |t| format!("{t}:{HUGE_PAGE_MALLOC}"),
    );
    let mut rustc = Command::new(env!("SPDK_SYS_RUSTC"));
    // The build script's target and sanitizer flags, so the probe links the
    // configuration the archives were built for.
    rustc.args(env!("SPDK_SYS_PROBE_FLAGS").split('\x1f'));
    rustc
        .env("GLIBC_TUNABLES", tunables)
        .arg(&stub)
        .arg("-o")
        .arg(&binary)
        .arg("-Cstrip=debuginfo")
        .args(["-Cprefer-dynamic", "-Crpath"])
        .arg(format!("-Lnative={}", out.display()))
        .arg("-lstatic:+verbatim=probe.o");
    let plan = fs::read_to_string(out.join("link-plan.txt")).unwrap();
    let mut plain_archives = 0;
    for line in plan.lines() {
        let (kind, value) = line.split_once(' ').unwrap();
        if kind == "system" {
            rustc.arg(format!("-ldylib={value}"));
            continue;
        }
        let path = Path::new(value);
        let file = path.file_name().unwrap().to_str().unwrap();
        let name = file
            .strip_prefix("lib")
            .unwrap()
            .strip_suffix(".a")
            .unwrap();
        let modifier = match kind {
            "archive" if plain == Some(file) => {
                plain_archives += 1;
                "static"
            }
            "archive" => "static:+whole-archive",
            "static" => "static",
            _ => panic!("unknown link-plan line {line}"),
        };
        rustc
            .arg(format!("-Lnative={}", path.parent().unwrap().display()))
            .arg(format!("-l{modifier}={name}"));
    }
    assert_eq!(
        plain_archives,
        usize::from(plain.is_some()),
        "the plain archive is not in the plan"
    );
    let linked = rustc.arg("-lstatic=spdk_sys_shim").status().unwrap();
    assert!(linked.success(), "linking the probe failed");
    let run = Command::new(&binary).output().unwrap();
    assert!(
        run.status.success(),
        "the probe failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    String::from_utf8(run.stdout).unwrap().trim().into()
}

#[test]
fn an_ena_archive_linked_without_whole_archive_fails_the_registry_query() {
    let (whole, plain) = std::thread::scope(|scope| {
        let plain = scope.spawn(|| probe(Some("librte_net_ena.a")));
        (probe(None), plain.join().unwrap())
    });
    assert_eq!(
        whole, "1111",
        "the whole-archive probe must find every component"
    );
    assert_eq!(plain, "1101", "a plain ENA archive must drop the PMD");
}
