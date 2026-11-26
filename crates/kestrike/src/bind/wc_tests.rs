//! The write-combining kernel and modules' provenance, and the live BAR mapping.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use super::fixture::{CONFIG, ENI_BDF, Fixture, RELEASE, SRCVERSION};
use super::host::CHUNK;
use super::wc::{Declares, MappingEvidence, WcError, WcManifest, WcModule, sha256};

/// The approved kernel and module pass; each mismatch is refused: another
/// kernel release or configuration, a changed module file or one declaring
/// another `srcversion`, an approved module unloaded or loaded with another
/// `srcversion`, an unapproved VFIO module loaded, and a manifest without
/// `vfio_pci`.
#[test]
fn only_the_approved_modules_pass() {
    let fixture = Fixture::new(512);
    let manifest = Fixture::manifest_of(&fixture.host);
    assert_eq!(fixture.host.check_wc(&manifest), Ok(()));

    let other = WcManifest {
        kernel: "6.1.0-other".into(),
        ..manifest.clone()
    };
    assert_eq!(fixture.host.check_wc(&other), Err(WcError::Kernel));
    let config = WcManifest {
        config_sha256: "00".repeat(32),
        ..manifest.clone()
    };
    assert_eq!(fixture.host.check_wc(&config), Err(WcError::Kernel));
    let mut digest = manifest.clone();
    digest.modules[0].sha256 = "00".repeat(32);
    assert_eq!(
        fixture.host.check_wc(&digest),
        Err(WcError::Module("vfio_pci".into()))
    );

    let module = fixture
        .root
        .join(manifest.modules[0].file.strip_prefix("/").unwrap());
    let original = fs::read(&module).unwrap();
    fs::write(&module, b"\x7fELF\0srcversion=FFFF\0").unwrap();
    let mut declares = manifest.clone();
    declares.modules[0].sha256 = sha256(&fs::read(&module).unwrap());
    assert_eq!(
        fixture.host.check_wc(&declares),
        Err(WcError::Module("vfio_pci".into()))
    );
    fs::write(&module, original).unwrap();

    fixture.file("sys/module/vfio_pci/srcversion", "0000\n");
    assert_eq!(
        fixture.host.check_wc(&manifest),
        Err(WcError::Loaded("vfio_pci".into()))
    );
    fs::remove_file(fixture.root.join("sys/module/vfio_pci/srcversion")).unwrap();
    assert_eq!(
        fixture.host.check_wc(&manifest),
        Err(WcError::Loaded("vfio_pci".into()))
    );
    fixture.file("sys/module/vfio_pci/srcversion", &format!("{SRCVERSION}\n"));
    fixture.file("sys/module/vfio_pci_core/srcversion", "STOCK\n");
    fixture.file("sys/module/vfio_pci_core/initstate", "live\n");
    assert_eq!(
        fixture.host.check_wc(&manifest),
        Err(WcError::Loaded("vfio_pci_core".into()))
    );
    fs::remove_dir_all(fixture.root.join("sys/module/vfio_pci_core")).unwrap();
    let mut without = manifest.clone();
    without.modules.clear();
    assert_eq!(
        fixture.host.check_wc(&without),
        Err(WcError::Loaded("vfio_pci".into()))
    );
}

/// The manifest reads one line per field and per module and names the first missing, repeated, unknown, empty or malformed field.
#[test]
fn malformed_manifests_name_the_field() {
    let good = "kernel=k\nconfig_sha256=c\npatch=p\nmodule=vfio_pci:/m.ko:h:s\n";
    assert_eq!(
        WcManifest::parse(good).unwrap().modules,
        [WcModule {
            name: "vfio_pci".into(),
            file: "/m.ko".into(),
            sha256: "h".into(),
            srcversion: "s".into(),
        }]
    );
    for (text, field) in [
        (good.replace("patch=p\n", ""), "patch"),
        (format!("{good}kernel=k2\n"), "kernel"),
        (format!("{good}extra=1\n"), "key"),
        (
            good.replace("config_sha256=c", "config_sha256="),
            "config_sha256",
        ),
        (format!("{good}no separator\n"), "line"),
        (format!("{good}module=vfio_pci:/n.ko:h:s\n"), "module"),
        (good.replace("/m.ko", "m.ko"), "module"),
        (good.replace(":s\n", "\n"), "module"),
        (good.replace("patch=p", "patch=p=1"), "patch"),
        (good.replace(":h:", ":h=1:"), "module"),
    ] {
        assert_eq!(
            WcManifest::parse(&text),
            Err(WcError::Manifest(field)),
            "{field}"
        );
    }
}

#[test]
fn only_a_manifest_root_alone_can_write_is_read() {
    let fixture = Fixture::new(512);
    let path = fixture.root.join("manifest");
    let good = "kernel=k\nconfig_sha256=c\npatch=p\nmodule=vfio_pci:/m.ko:h:s\n";
    fs::write(&path, good).unwrap();
    let mode = |mode: u32| fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    assert_eq!(
        WcManifest::read(&fixture.root.join("absent")),
        Err(WcError::Manifest("file"))
    );
    let link = fixture.root.join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert_eq!(WcManifest::read(&link), Err(WcError::Manifest("file")));
    for writable in [0o664, 0o646, 0o666] {
        mode(writable);
        assert_eq!(
            WcManifest::read(&path),
            Err(WcError::Manifest("mode")),
            "mode {writable:o}"
        );
    }
    mode(0o644);
    // SAFETY: `geteuid` is valid for any calling process.
    let root = unsafe { libc::geteuid() } == 0;
    let owned = WcManifest::read(&path);
    if root {
        assert_eq!(owned.unwrap(), WcManifest::parse(good).unwrap());
    } else {
        assert_eq!(
            owned,
            Err(WcError::Manifest("owner")),
            "another user's file"
        );
    }
}

#[test]
fn digests_are_lowercase_hex_sha256() {
    assert_eq!(
        sha256(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

/// The declared `srcversion` is the first `srcversion=` entry in the file,
/// wherever the key or its value fall against the read boundaries, and a file
/// whose first entry ends without a NUL or declares another value is refused.
#[test]
fn the_first_srcversion_entry_is_found_across_read_boundaries() {
    let fixture = Fixture::new(512);
    let manifest = Fixture::manifest_of(&fixture.host);
    let module = fixture
        .root
        .join(manifest.modules[0].file.strip_prefix("/").unwrap());
    let check = |bytes: &[u8]| {
        fs::write(&module, bytes).unwrap();
        let mut approved = manifest.clone();
        approved.modules[0].sha256 = sha256(bytes);
        fixture.host.check_wc(&approved)
    };
    let entry = format!("srcversion={SRCVERSION}\0");
    let decoy = "srcversion=FFFF\0";
    for at in (CHUNK - entry.len() - 1)..=(CHUNK + 1) {
        let mut bytes = vec![b'x'; at];
        bytes.extend_from_slice(entry.as_bytes());
        bytes.extend_from_slice(&[b'y'; 3 * CHUNK]);
        assert_eq!(check(&bytes), Ok(()), "entry at {at}");

        let mut first = vec![b'x'; at];
        first.extend_from_slice(decoy.as_bytes());
        first.extend_from_slice(entry.as_bytes());
        assert_eq!(
            check(&first),
            Err(WcError::Module("vfio_pci".into())),
            "decoy at {at}"
        );
    }
    let mut unterminated = vec![b'x'; CHUNK - 4];
    unterminated.extend_from_slice(format!("srcversion={SRCVERSION}").as_bytes());
    assert_eq!(
        check(&unterminated),
        Err(WcError::Module("vfio_pci".into()))
    );
    let mut split = vec![b'x'; 2 * CHUNK - 3];
    split.extend_from_slice(b"src");
    assert_eq!(check(&split), Err(WcError::Module("vfio_pci".into())));
}

#[test]
fn the_first_srcversion_is_found_across_any_split() {
    let declares = |bytes: &[u8], splits: &[usize], expected: &str| {
        let mut declares = Declares::new(expected);
        let mut at = 0;
        for split in splits.iter().copied().chain([bytes.len()]) {
            declares.feed(&bytes[at..split]);
            at = split;
        }
        declares.declared()
    };
    let module = b"\x7fELF srcversio srcversion=ABC123\0srcversion=LATER\0";
    for first in 0..=module.len() {
        for second in first..=module.len() {
            let splits = [first, second];
            assert!(declares(module, &splits, "ABC123"), "split at {splits:?}");
            for other in ["LATER", "ABC12", "ABC1234", ""] {
                assert!(!declares(module, &splits, other), "{other} at {splits:?}");
            }
        }
    }
    let bytewise: Vec<usize> = (1..module.len()).collect();
    assert!(declares(module, &bytewise, "ABC123"));
    for (bytes, expected, declared) in [
        (&b"srcversion=ABC"[..], "ABC", false),
        (b"srcversion=\xff\0", "\u{fffd}", false),
        (b"srcversion=\xff\0srcversion=OK\0", "OK", false),
        (b"no key\0", "", false),
        (b"srcversion=\0", "", true),
        (b"srcversrcversion=Y\0", "Y", true),
    ] {
        for split in 0..=bytes.len() {
            assert_eq!(
                declares(bytes, &[split], expected),
                declared,
                "{expected} split at {split}"
            );
        }
    }
    let mut overlong = b"srcversion=".to_vec();
    overlong.resize(1 << 20, b'A');
    assert!(!declares(&overlong, &[16_384, 32_768], "AAAA"));
}

/// A module larger than one read passes with its entry deep in the file,
/// and one byte changed after the entry refuses it.
#[test]
fn a_module_larger_than_one_read_is_hashed_whole() {
    let fixture = Fixture::new(512);
    let mut manifest = Fixture::manifest_of(&fixture.host);
    let module = fixture
        .root
        .join(manifest.modules[0].file.strip_prefix("/").unwrap());
    // High-bit filler never forms the ASCII key.
    let filler = |len: u32| (0..len).map(|i| (i % 251) as u8 | 0x80);
    // The key straddles the end of the 18th 16 KiB read.
    let mut bytes: Vec<u8> = filler((18 * CHUNK - 5) as u32).collect();
    bytes.extend_from_slice(format!("srcversion={SRCVERSION}\0").as_bytes());
    bytes.extend(filler(100_000));
    fs::write(&module, &bytes).unwrap();
    manifest.modules[0].sha256 = sha256(&bytes);
    assert_eq!(fixture.host.check_wc(&manifest), Ok(()));
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&module, &bytes).unwrap();
    assert_eq!(
        fixture.host.check_wc(&manifest),
        Err(WcError::Module("vfio_pci".into()))
    );
}

/// With several modules hashed on helper threads, the errors keep their
/// order: `Kernel`, then `Loaded`, then the first failing module in
/// manifest order.
#[test]
fn errors_keep_their_order_across_threads() {
    let fixture = Fixture::new(512);
    let mut manifest = Fixture::manifest_of(&fixture.host);
    for (name, file) in [
        ("vfio", "/lib/vfio.ko"),
        ("vfio_pci_core", "/lib/vfio-pci-core.ko"),
    ] {
        let bytes = format!("\x7fELF {name}\0srcversion={SRCVERSION}\0");
        fixture.file(&file[1..], &bytes);
        fixture.file(
            &format!("sys/module/{name}/srcversion"),
            &format!("{SRCVERSION}\n"),
        );
        fixture.file(&format!("sys/module/{name}/initstate"), "live\n");
        manifest.modules.push(WcModule {
            name: name.into(),
            file: file.into(),
            sha256: sha256(bytes.as_bytes()),
            srcversion: SRCVERSION.into(),
        });
    }
    assert_eq!(fixture.host.check_wc(&manifest), Ok(()));
    let mut bad = manifest.clone();
    bad.modules[2].sha256 = "00".repeat(32);
    bad.modules[1].sha256 = "00".repeat(32);
    assert_eq!(
        fixture.host.check_wc(&bad),
        Err(WcError::Module("vfio".into()))
    );
    bad.modules[2].srcversion = "OTHER".into();
    assert_eq!(
        fixture.host.check_wc(&bad),
        Err(WcError::Loaded("vfio_pci_core".into()))
    );
    bad.kernel = "6.1.0-other".into();
    assert_eq!(fixture.host.check_wc(&bad), Err(WcError::Kernel));

    fs::remove_file(fixture.root.join("lib/vfio.ko")).unwrap();
    assert_eq!(
        fixture.host.check_wc(&manifest),
        Err(WcError::Module("vfio".into()))
    );
    fs::remove_file(fixture.root.join(format!("boot/config-{RELEASE}"))).unwrap();
    assert_eq!(fixture.host.check_wc(&manifest), Err(WcError::Kernel));
    fs::remove_file(fixture.root.join("proc/sys/kernel/osrelease")).unwrap();
    assert_eq!(fixture.host.check_wc(&manifest), Err(WcError::Kernel));
}

/// The device must be on `vfio-pci` with a prefetchable memory BAR. Under PAT
/// evidence that BAR must lie inside one write-combining entry: an
/// unreadable table, an uncached entry, a partial cover and a mixed entry
/// refuse. Under loaded-module evidence the approved modules must be loaded
/// with their approved `srcversion`. An architecture without evidence
/// refuses, and every evidence refuses no prefetchable BAR and no resource
/// file.
#[test]
fn the_prefetchable_bar_must_be_mapped_write_combining() {
    use MappingEvidence::{LoadedModule, PatTable, Unavailable};
    let fixture = Fixture::new(512);
    let manifest = Fixture::manifest_of(&fixture.host);
    let check = |evidence| {
        fixture
            .host
            .check_wc_mapping_by(ENI_BDF, &manifest, evidence)
    };
    fixture.file(
        &format!("sys/bus/pci/devices/{ENI_BDF}/resource"),
        "0x00000000febf8000 0x00000000febfbfff 0x0000000000040200\n0x0000000000000000 0x0000000000000000 0x0000000000000000\n0x00000000fe800000 0x00000000fe8fffff 0x000000000014220c\n",
    );
    let pat = "sys/kernel/debug/x86/pat_memtype_list";
    for evidence in [PatTable, LoadedModule, Unavailable] {
        assert_eq!(
            check(evidence),
            Err(WcError::Unverifiable),
            "the device is on ena"
        );
    }
    fs::remove_file(fixture.host.pci(ENI_BDF).join("driver")).unwrap();
    fs::create_dir_all(fixture.host.sys.join("bus/pci/drivers/vfio-pci")).unwrap();
    std::os::unix::fs::symlink(
        fixture.host.sys.join("bus/pci/drivers/vfio-pci"),
        fixture.host.pci(ENI_BDF).join("driver"),
    )
    .unwrap();
    assert_eq!(
        check(PatTable),
        Err(WcError::Unverifiable),
        "the table is unreadable"
    );
    assert_eq!(check(LoadedModule), Ok(()));
    assert_eq!(check(Unavailable), Err(WcError::Unverifiable));
    let mut unloaded = manifest.clone();
    unloaded.modules[0].srcversion = "0".repeat(23);
    assert_eq!(
        fixture
            .host
            .check_wc_mapping_by(ENI_BDF, &unloaded, LoadedModule),
        Err(WcError::Loaded(manifest.modules[0].name.clone()))
    );
    fixture.file(pat, "PAT memtype list:\nPAT: [mem 0x00000000febf8000-0x00000000febfc000] uncached-minus\nPAT: [mem 0x00000000fe800000-0x00000000fe900000] write-combining\n");
    assert_eq!(check(PatTable), Ok(()));
    assert_eq!(
        fixture.host.check_wc_mapping(ENI_BDF, &manifest),
        check(MappingEvidence::HOST)
    );
    for (table, expected) in [
        (
            "PAT: [mem 0x00000000fe800000-0x00000000fe900000] uncached-minus\n",
            Err(WcError::Mapping),
        ),
        (
            "PAT: [mem 0x00000000fe800000-0x00000000fe880000] write-combining\n",
            Err(WcError::Mapping),
        ),
        (
            "PAT: [mem 0x00000000fe800000-0x00000000fe900000] write-combining \t\n",
            Ok(()),
        ),
        (
            "PAT: [mem 0x00000000fe800000-0x00000000fe900000] uncached-minus write-combining\n",
            Err(WcError::Mapping),
        ),
    ] {
        fixture.file(pat, table);
        assert_eq!(check(PatTable), expected, "{table}");
    }
    fixture.file(
        &format!("sys/bus/pci/devices/{ENI_BDF}/resource"),
        "0x00000000febf8000 0x00000000febfbfff 0x0000000000040200\n",
    );
    for evidence in [PatTable, LoadedModule, Unavailable] {
        assert_eq!(
            check(evidence),
            Err(WcError::Mapping),
            "no prefetchable BAR"
        );
    }
    fs::remove_file(fixture.host.pci(ENI_BDF).join("resource")).unwrap();
    for evidence in [PatTable, LoadedModule, Unavailable] {
        assert_eq!(check(evidence), Err(WcError::Mapping), "no resource file");
    }
}

#[test]
fn the_kernel_configuration_exposes_only_the_classic_vfio_interface() {
    let swap = |from: &str, to: &str| {
        assert!(CONFIG.contains(from), "{from}");
        CONFIG.replace(from, to)
    };
    let padding = "# padding\n".repeat(CHUNK * 3 / 10);
    let cases = [
        (CONFIG.to_owned(), false, Ok(())),
        (CONFIG.to_owned(), true, Ok(())),
        (format!("{CONFIG}CONFIG_IOMMUFD_TEST=y\n"), false, Ok(())),
        (format!("CONFIG_VFIO_NOIOMMU=m\n{CONFIG}"), false, Ok(())),
        (
            format!("{CONFIG}CONFIG_VFIO_NOIOMMU=m\n"),
            false,
            Err("CONFIG_VFIO_NOIOMMU"),
        ),
        (
            swap("CONFIG_VFIO_NOIOMMU=y\n", "") + "CONFIG_VFIO_NOIOMMU=y",
            false,
            Ok(()),
        ),
        (
            format!("CONFIG_IOMMUFD=y\n{CONFIG}"),
            false,
            Err("CONFIG_IOMMUFD"),
        ),
        (
            swap("# CONFIG_IOMMUFD is not set", "CONFIG_IOMMUFD=y"),
            false,
            Err("CONFIG_IOMMUFD"),
        ),
        (
            swap("# CONFIG_IOMMUFD is not set", "CONFIG_IOMMUFD=m"),
            true,
            Err("CONFIG_IOMMUFD"),
        ),
        (
            format!("{CONFIG}CONFIG_VFIO_DEVICE_CDEV=y\n"),
            false,
            Err("CONFIG_VFIO_DEVICE_CDEV"),
        ),
        (
            format!("{CONFIG}CONFIG_VFIO_DEVICE_CDEV=m\n"),
            true,
            Err("CONFIG_VFIO_DEVICE_CDEV"),
        ),
        (
            swap("CONFIG_VFIO_NOIOMMU=y", "# CONFIG_VFIO_NOIOMMU is not set"),
            false,
            Err("CONFIG_VFIO_NOIOMMU"),
        ),
        (swap("CONFIG_VFIO_NOIOMMU=y", ""), true, Ok(())),
        (
            swap("CONFIG_VFIO_IOMMU_TYPE1=m", ""),
            true,
            Err("CONFIG_VFIO_IOMMU_TYPE1"),
        ),
        (swap("CONFIG_VFIO_IOMMU_TYPE1=m", ""), false, Ok(())),
        (
            format!("{padding}{CONFIG}CONFIG_IOMMUFD=y\n"),
            false,
            Err("CONFIG_IOMMUFD"),
        ),
    ];
    for (config, iommu, expected) in cases {
        let fixture = Fixture::new(512);
        if iommu {
            fs::create_dir(fixture.host.sys.join("class/iommu/dmar0")).unwrap();
        }
        fixture.file(&format!("boot/config-{RELEASE}"), &config);
        let manifest = Fixture::manifest_of(&fixture.host);
        assert_eq!(
            fixture.host.check_wc(&manifest),
            expected.map_err(WcError::Interface),
            "{config:?} with a guest IOMMU: {iommu}"
        );
    }
}

#[test]
fn a_kernel_before_the_vfio_group_symbol_passes() {
    let linux_6_1 = "CONFIG_VFIO=m\nCONFIG_VFIO_IOMMU_TYPE1=m\nCONFIG_VFIO_VIRQFD=m\nCONFIG_VFIO_NOIOMMU=y\nCONFIG_VFIO_PCI_CORE=m\nCONFIG_VFIO_PCI_MMAP=y\nCONFIG_VFIO_PCI_INTX=y\nCONFIG_VFIO_PCI=m\n";
    let linux_6_5 = "# CONFIG_IOMMUFD is not set\nCONFIG_VFIO=m\nCONFIG_VFIO_CONTAINER=y\nCONFIG_VFIO_IOMMU_TYPE1=m\nCONFIG_VFIO_NOIOMMU=y\nCONFIG_VFIO_VIRQFD=y\nCONFIG_VFIO_PCI_CORE=m\nCONFIG_VFIO_PCI_MMAP=y\nCONFIG_VFIO_PCI_INTX=y\nCONFIG_VFIO_PCI=m\n";
    for config in [linux_6_1, linux_6_5] {
        for iommu in [false, true] {
            let fixture = Fixture::new(512);
            if iommu {
                fs::create_dir(fixture.host.sys.join("class/iommu/dmar0")).unwrap();
            }
            fixture.file(&format!("boot/config-{RELEASE}"), config);
            let manifest = Fixture::manifest_of(&fixture.host);
            let context = format!("{config:?} with a guest IOMMU: {iommu}");
            assert_eq!(fixture.host.check_wc(&manifest), Ok(()), "{context}");
            assert_eq!(
                fixture.host.check_wc_running(&manifest),
                Ok(()),
                "{context}"
            );
        }
    }
}

/// `check_wc_running` refuses `CONFIG_IOMMUFD=y`, naming the symbol,
/// wherever the first read ends, from the byte before the newline that
/// precedes that line through the byte after the line.
#[test]
fn an_assignment_split_across_reads_counts() {
    let line = "CONFIG_IOMMUFD=y\n";
    for start in CHUNK - line.len() - 1..=CHUNK + 1 {
        // A comment line pads the configuration so `line` begins at `start`.
        let pad = "x".repeat(start - CONFIG.len() - 2);
        let config = format!("{CONFIG}#{pad}\n{line}");
        assert_eq!(config.find(line), Some(start));
        let fixture = Fixture::new(512);
        fixture.file(&format!("boot/config-{RELEASE}"), &config);
        let manifest = Fixture::manifest_of(&fixture.host);
        assert_eq!(
            fixture.host.check_wc_running(&manifest),
            Err(WcError::Interface("CONFIG_IOMMUFD")),
            "line at {start}"
        );
    }
}

/// The manifest text of the fixed kernel fields and one `module=` line per name in `names`.
fn manifest_naming(names: &[&str]) -> String {
    let modules: String = names
        .iter()
        .map(|name| format!("module={name}:/m.ko:h:s\n"))
        .collect();
    format!("kernel=k\nconfig_sha256=c\npatch=p\n{modules}")
}

/// An approved module's name is the name sysfs lists one loaded module under, so the loaded check
/// reads its `srcversion` from that module's directory in `sys/module`. A name that spells a path
/// would resolve to another directory, and the manifest refuses it as a malformed module; a name
/// of alphanumerics and `_` parses.
#[test]
fn a_module_name_that_spells_a_path_is_a_malformed_module() {
    for name in [
        "/elsewhere",
        "../../elsewhere",
        "elsewhere/inner",
        "..",
        ".",
        "vfio-pci",
        "vfio pci",
    ] {
        assert_eq!(
            WcManifest::parse(&manifest_naming(&[name])),
            Err(WcError::Manifest("module")),
            "{name} names no module"
        );
    }
    for name in ["vfio_pci", "vfio_pci_core", "8021q", "Elsewhere_2"] {
        let manifest = WcManifest::parse(&manifest_naming(&[name])).unwrap();
        assert_eq!(manifest.modules[0].name, name);
    }
}

/// The manifest refuses a repeated module, and a loaded module has one spelling, so the same
/// module under a second spelling of its directory is refused too.
#[test]
fn one_module_approved_under_two_spellings_is_refused() {
    for second in ["vfio_pci", "./vfio_pci", "../module/vfio_pci"] {
        assert_eq!(
            WcManifest::parse(&manifest_naming(&["vfio_pci", second])),
            Err(WcError::Manifest("module")),
            "vfio_pci beside {second}"
        );
    }
    let two = WcManifest::parse(&manifest_naming(&["vfio_pci", "vfio_pci_core"])).unwrap();
    assert_eq!(two.modules.len(), 2);
}

/// A device whose six BAR rows hold no prefetchable memory BAR has none,
/// whatever the `resource` rows after them hold: row 6 is the expansion ROM,
/// which the kernel flags `IORESOURCE_MEM | IORESOURCE_PREFETCH |
/// IORESOURCE_READONLY | IORESOURCE_SIZEALIGN`, rows 7 to 12 are the
/// virtual-function BARs, and `vfio-pci` maps none of them for user space.
/// Every evidence refuses it `Mapping`, as it refuses a device with the one
/// plain BAR alone (the sibling), and admits the same range in a BAR row
/// (the control).
#[test]
fn an_expansion_rom_row_is_not_the_prefetchable_bar() {
    use MappingEvidence::{LoadedModule, PatTable, Unavailable};
    let fixture = Fixture::new(512);
    let manifest = Fixture::manifest_of(&fixture.host);
    let check = |evidence| {
        fixture
            .host
            .check_wc_mapping_by(ENI_BDF, &manifest, evidence)
    };
    fs::remove_file(fixture.host.pci(ENI_BDF).join("driver")).unwrap();
    fs::create_dir_all(fixture.host.sys.join("bus/pci/drivers/vfio-pci")).unwrap();
    std::os::unix::fs::symlink(
        fixture.host.sys.join("bus/pci/drivers/vfio-pci"),
        fixture.host.pci(ENI_BDF).join("driver"),
    )
    .unwrap();
    fixture.file(
        "sys/kernel/debug/x86/pat_memtype_list",
        "PAT memtype list:\nPAT: [mem 0x00000000fe800000-0x00000000fe900000] write-combining\n",
    );
    let resource = format!("sys/bus/pci/devices/{ENI_BDF}/resource");
    let plain = "0x00000000febf8000 0x00000000febfbfff 0x0000000000040200\n";
    let unused = "0x0000000000000000 0x0000000000000000 0x0000000000000000\n";
    let range = "0x00000000fe800000 0x00000000fe8fffff";
    // Sibling: the plain BAR alone.
    fixture.file(&resource, &format!("{plain}{}", unused.repeat(5)));
    for evidence in [PatTable, LoadedModule, Unavailable] {
        assert_eq!(check(evidence), Err(WcError::Mapping), "{evidence:?}");
    }
    // Control: the range as BAR 2, prefetchable.
    fixture.file(
        &resource,
        &format!(
            "{plain}{unused}{range} 0x000000000014220c\n{}",
            unused.repeat(3)
        ),
    );
    assert_eq!(check(PatTable), Ok(()));
    assert_eq!(check(LoadedModule), Ok(()));
    // The range as row 6, the expansion ROM.
    fixture.file(
        &resource,
        &format!("{plain}{}{range} 0x0000000000046200\n", unused.repeat(5)),
    );
    let refused = Err(WcError::Mapping);
    assert_eq!(
        [check(PatTable), check(LoadedModule), check(Unavailable)],
        [refused.clone(), refused.clone(), refused],
        "PatTable, LoadedModule, Unavailable: the only prefetchable row is the expansion ROM"
    );
    // The range as a prefetchable memory row past the expansion ROM.
    for row in 7..13 {
        fixture.file(
            &resource,
            &format!(
                "{plain}{}{range} 0x000000000014220c\n",
                unused.repeat(row - 1)
            ),
        );
        for evidence in [PatTable, LoadedModule, Unavailable] {
            assert_eq!(
                check(evidence),
                Err(WcError::Mapping),
                "{evidence:?}: the only prefetchable row is row {row}"
            );
        }
    }
}

/// Every loaded module among `vfio`, `vfio_pci_core` and `vfio_pci` is
/// approved, and unreadable sysfs state does not establish that a change is
/// safe. An unapproved module whose `initstate` exists and cannot be
/// observed, behind a symbolic link that resolves to itself or a module
/// directory that cannot be searched, refuses as loaded in `check_wc`,
/// `check_wc_running` and `check_wc_loaded`; removing `initstate` passes,
/// so the refusal is for the unobserved state and not the directory. A
/// user who passes mode bits cannot produce the unsearchable directory, so
/// that fault is judged only where the stat fails.
#[test]
fn an_unapproved_module_whose_initstate_cannot_be_observed_refuses_as_loaded() {
    use std::os::unix::fs::PermissionsExt;
    for name in ["vfio", "vfio_pci_core"] {
        let fixture = Fixture::new(512);
        let manifest = Fixture::manifest_of(&fixture.host);
        let refused = Err(WcError::Loaded(name.into()));
        let directory = fixture.root.join(format!("sys/module/{name}"));
        let initstate = directory.join("initstate");
        let checks = || {
            [
                fixture.host.check_wc(&manifest),
                fixture.host.check_wc_running(&manifest),
                fixture.host.check_wc_loaded(&manifest),
            ]
        };

        fs::create_dir_all(&directory).unwrap();
        std::os::unix::fs::symlink(&initstate, &initstate).unwrap();
        let looped = fs::metadata(&initstate)
            .map(drop)
            .map_err(|error| error.kind());
        assert!(
            looped.is_err_and(|kind| kind != std::io::ErrorKind::NotFound),
            "premise: the stat fails with another error than absence, {name}"
        );
        assert_eq!(checks(), [(); 3].map(|()| refused.clone()), "{name}: loop");
        fs::remove_file(&initstate).unwrap();
        assert_eq!(checks(), [Ok(()), Ok(()), Ok(())], "{name}: absent");

        fixture.file(&format!("sys/module/{name}/initstate"), "live\n");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o000)).unwrap();
        let denied = fs::metadata(&initstate)
            .map(drop)
            .map_err(|error| error.kind());
        let checked = checks();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        if denied == Err(std::io::ErrorKind::PermissionDenied) {
            assert_eq!(checked, [(); 3].map(|()| refused.clone()), "{name}: denied");
        }
    }
}

/// The kernel prints a loaded module's `srcversion` and one newline. A
/// module that reports the approved text with any other byte around it
/// reports another `srcversion`, so it is refused as `Loaded`.
#[test]
fn a_loaded_srcversion_padded_with_whitespace_is_another_srcversion() {
    let fixture = Fixture::new(512);
    let manifest = Fixture::manifest_of(&fixture.host);
    assert_eq!(fixture.host.check_wc_loaded(&manifest), Ok(()));
    let padded = [
        format!("{SRCVERSION} \n"),
        format!(" {SRCVERSION}\n"),
        format!("{SRCVERSION}\t\n"),
        format!("{SRCVERSION}\n\n"),
        format!("\u{b}{SRCVERSION}\u{c}\n"),
    ];
    let mut passed = Vec::new();
    for reported in &padded {
        fixture.file("sys/module/vfio_pci/srcversion", reported);
        if fixture.host.check_wc_loaded(&manifest) != Err(WcError::Loaded("vfio_pci".into())) {
            passed.push(reported);
        }
    }
    assert!(passed.is_empty(), "passed as approved: {passed:?}");
}

/// A loaded module's `srcversion` ties it to its approved file, and the
/// kernel's PAT table is the evidence of a write-combining mapping. A mount
/// the mount table lists over either shows its own text: here the approved
/// `srcversion` in place of the loaded module's, and a table with a
/// write-combining range over the BAR. Neither passes under the cover, and
/// each passes with the same text and no mount over it.
#[test]
fn a_srcversion_or_a_pat_table_a_mount_covers_is_no_evidence() {
    let mounts = |tail: &str| {
        format!(
            "/dev/nvme0n1p1 / xfs rw 0 0\nsysfs /sys sysfs rw 0 0\ndebugfs /sys/kernel/debug debugfs rw 0 0\n{tail}"
        )
    };
    // Every VFIO module is approved and loaded, so the `srcversion` reads
    // decide the check.
    let loaded = |tail: Option<&str>| {
        let fixture = Fixture::new(512);
        let mut manifest = Fixture::manifest_of(&fixture.host);
        for name in ["vfio", "vfio_pci_core"] {
            let mut module = manifest.modules[0].clone();
            module.name = name.to_owned();
            fixture.file(&format!("sys/module/{name}/initstate"), "live\n");
            fixture.file(
                &format!("sys/module/{name}/srcversion"),
                &format!("{}\n", module.srcversion),
            );
            manifest.modules.push(module);
        }
        match tail {
            Some(tail) => fixture.file("proc/self/mounts", &mounts(tail)),
            None => fs::remove_file(fixture.root.join("proc/self/mounts")).unwrap(),
        }
        fixture.host.check_wc_loaded(&manifest)
    };
    assert_eq!(
        loaded(Some("")),
        Ok(()),
        "premise: the approved srcversions, uncovered"
    );
    assert_eq!(
        loaded(Some("tmpfs /sys/module/vfio_pci tmpfs rw 0 0\n")),
        Err(WcError::Loaded("vfio_pci".into())),
        "a covered srcversion passed as the loaded module's"
    );
    assert!(
        matches!(loaded(None), Err(WcError::Loaded(_))),
        "a srcversion beside an unreadable mount table passed"
    );

    let mapped = |tail: Option<&str>| {
        let fixture = Fixture::new(512);
        let manifest = Fixture::manifest_of(&fixture.host);
        fixture.file(
            &format!("sys/bus/pci/devices/{ENI_BDF}/resource"),
            "0x00000000febf8000 0x00000000febfbfff 0x0000000000040200\n0x0000000000000000 0x0000000000000000 0x0000000000000000\n0x00000000fe800000 0x00000000fe8fffff 0x000000000014220c\n",
        );
        fs::remove_file(fixture.host.pci(ENI_BDF).join("driver")).unwrap();
        fs::create_dir_all(fixture.host.sys.join("bus/pci/drivers/vfio-pci")).unwrap();
        std::os::unix::fs::symlink(
            fixture.host.sys.join("bus/pci/drivers/vfio-pci"),
            fixture.host.pci(ENI_BDF).join("driver"),
        )
        .unwrap();
        fixture.file(
            "sys/kernel/debug/x86/pat_memtype_list",
            "PAT memtype list:\nPAT: [mem 0x00000000fe800000-0x00000000fe900000] write-combining\n",
        );
        match tail {
            Some(tail) => fixture.file("proc/self/mounts", &mounts(tail)),
            None => fs::remove_file(fixture.root.join("proc/self/mounts")).unwrap(),
        }
        fixture
            .host
            .check_wc_mapping_by(ENI_BDF, &manifest, MappingEvidence::PatTable)
    };
    assert_eq!(
        mapped(Some("")),
        Ok(()),
        "premise: the table under debugfs alone"
    );
    assert_eq!(
        mapped(None),
        Err(WcError::Unverifiable),
        "a PAT table beside an unreadable mount table passed"
    );
    // The device's `resource` file gives the range the table is compared
    // with, so a mount over it is as much a cover as one over the table.
    let resource = format!("tmpfs /sys/bus/pci/devices/{ENI_BDF}/resource tmpfs rw 0 0\n");
    for cover in [
        "tmpfs /sys/kernel/debug/x86 tmpfs rw 0 0\n",
        "tmpfs /sys/kernel/debug tmpfs rw 0 0\n",
        "tmpfs /sys/kernel tmpfs rw 0 0\n",
        resource.as_str(),
    ] {
        assert_eq!(
            mapped(Some(cover)),
            Err(WcError::Unverifiable),
            "a covered PAT table or range passed under {cover:?}"
        );
    }
}

/// The kernel check compares the manifest's release with the one
/// `proc/sys/kernel/osrelease` prints. A mount the mount table lists at that
/// path shows its own text there, which can be the approved release on
/// another kernel, so the release read under it is no evidence and the check
/// refuses as `Kernel`; so does a host whose mount table cannot be read. The
/// same release with no mount over it passes.
#[test]
fn a_kernel_release_a_mount_covers_does_not_pass_the_manifest() {
    let checked = |mounts: Option<&str>| {
        let fixture = Fixture::new(512);
        let manifest = Fixture::manifest_of(&fixture.host);
        match mounts {
            Some(tail) => fixture.file(
                "proc/self/mounts",
                &format!("/dev/nvme0n1p1 / xfs rw 0 0\nproc /proc proc rw 0 0\n{tail}"),
            ),
            None => fs::remove_file(fixture.root.join("proc/self/mounts")).unwrap(),
        }
        fixture.host.check_wc(&manifest)
    };
    assert_eq!(
        checked(Some("")),
        Ok(()),
        "premise: the release as the kernel shows it"
    );
    assert_eq!(
        checked(Some("tmpfs /proc/sys/kernel/osrelease tmpfs rw 0 0\n")),
        Err(WcError::Kernel),
        "a covered release passed the manifest"
    );
    assert_eq!(
        checked(None),
        Err(WcError::Kernel),
        "a release beside an unreadable mount table passed the manifest"
    );
}

/// `check_wc_loaded` reads an unapproved VFIO module as unloaded only on the
/// observed absence of its `initstate`. A tmpfs the mount table lists at
/// `/sys/module/vfio` covers the loaded module's directory, so its absence
/// there is not observed: the module stays loaded and unapproved. Without
/// the cover the module refuses as loaded.
#[test]
fn an_unapproved_module_under_a_covered_module_directory_is_not_read_as_unloaded() {
    let checked = |cover: bool| {
        let fixture = Fixture::new(512);
        let manifest = Fixture::manifest_of(&fixture.host);
        fixture.file("sys/module/vfio/initstate", "live\n");
        let mut mounts = String::from("/dev/nvme0n1p1 / xfs rw 0 0\nsysfs /sys sysfs rw 0 0\n");
        if cover {
            let covered = fixture.root.join("sys/module/vfio");
            fs::remove_dir_all(&covered).unwrap();
            fs::create_dir_all(&covered).unwrap();
            mounts.push_str("tmpfs /sys/module/vfio tmpfs rw 0 0\n");
        }
        fixture.file("proc/self/mounts", &mounts);
        assert!(
            !manifest.modules.iter().any(|m| m.name == "vfio"),
            "premise: vfio unapproved"
        );
        fixture.host.check_wc_loaded(&manifest)
    };
    assert_eq!(
        checked(false),
        Err(WcError::Loaded("vfio".into())),
        "premise"
    );
    assert_eq!(
        checked(true),
        Err(WcError::Loaded("vfio".into())),
        "an unapproved module under a covered directory admitted"
    );
}

/// The mount table alone shows whether a mount covers a module's
/// directory. With the table unreadable, the missing `initstate` of an
/// unapproved VFIO module under such a cover is not an observed absence:
/// the module stays loaded and unapproved, and the check refuses it.
#[test]
fn an_unapproved_module_missing_beside_an_unreadable_mount_table_is_not_read_as_unloaded() {
    let fixture = Fixture::new(512);
    let manifest = Fixture::manifest_of(&fixture.host);
    assert!(
        !manifest.modules.iter().any(|m| m.name == "vfio"),
        "premise: vfio unapproved"
    );
    assert_eq!(
        fixture.host.check_wc_loaded(&manifest),
        Ok(()),
        "premise: the approved modules alone are loaded"
    );
    fixture.file("sys/module/vfio/initstate", "live\n");
    assert_eq!(
        fixture.host.check_wc_loaded(&manifest),
        Err(WcError::Loaded("vfio".into())),
        "premise: the loaded module refuses"
    );
    let covered = fixture.root.join("sys/module/vfio");
    fs::remove_dir_all(&covered).unwrap();
    fs::create_dir_all(&covered).unwrap();
    fs::remove_file(fixture.root.join("proc/self/mounts")).unwrap();
    assert_eq!(
        fixture.host.check_wc_loaded(&manifest),
        Err(WcError::Loaded("vfio".into())),
        "an unapproved module whose absence no mount table vouches for admitted"
    );
}
