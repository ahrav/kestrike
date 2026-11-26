//! The mappings file format, its atomic write, and the stale-file checks.

use std::fs;
use std::num::NonZeroU32;

use super::eni::{Eni, NetState};
use super::fixture::Live;
use super::host::serial_of;
use super::lock::OwnerLock;
use super::mappings::{EniBinding, Mappings, MappingsError, NvmeBinding};
use super::wc::{WcManifest, WcModule};

pub(crate) fn sample(original_override: Option<&str>) -> Mappings {
    Mappings {
        instance: "i-0123456789abcdef0".into(),
        boot: "6f2a9a1c-0000-4000-8000-000000000001".into(),
        wc: WcManifest {
            kernel: "6.1.0-wc".into(),
            config_sha256: "aa".repeat(32),
            patch: "wc-1".into(),
            modules: vec![WcModule {
                name: "vfio_pci".into(),
                file: "/lib/modules/6.1.0-wc/extra/vfio-pci.ko".into(),
                sha256: "bb".repeat(32),
                srcversion: "4C1D2E3F4A5B6C7D8E9F0A1".into(),
            }],
        },
        nvme: Some(NvmeBinding {
            volume: "vol-0123456789abcdef0".into(),
            bdf: "0000:00:1f.0".into(),
            nsid: 1,
            sector_size: 512,
            capacity: 64 << 30,
            original_driver: "nvme".into(),
            original_override: original_override.map(str::to_owned),
        }),
        eni: None,
    }
}

pub(crate) fn eni(next_hops: usize) -> EniBinding {
    EniBinding {
        eni: Eni {
            id: "eni-0123456789abcdef0".into(),
            mac: [0x0a, 0x11, 0x22, 0x33, 0x44, 0x55],
            ipv4: [10, 0, 1, 5].into(),
            subnet: "subnet-0123".into(),
            cidr: ([10, 0, 1, 0].into(), 24),
            device_number: 1,
            network_card: 0,
            netdev: "ens6".into(),
            bdf: "0000:00:06.0".into(),
        },
        original_driver: "ena".into(),
        original_override: None,
        net: NetState {
            mtu: NonZeroU32::new(9001).unwrap(),
            up: true,
            addresses: vec!["10.0.1.5/24 brd 10.0.1.255 metric 1003 noprefixroute".into()],
            routes: vec![
                "10.0.1.0/24 proto kernel scope link src 10.0.1.5".into(),
                "10.9.0.0/16 via 10.0.1.1".into(),
            ],
        },
        next_hops: (0..next_hops)
            .map(|at| {
                (
                    [10, 0, 1, 9 + at as u8].into(),
                    [0x0a, 0, 0, 0, 1, at as u8],
                )
            })
            .collect(),
    }
}

/// Owner and client files round-trip: the controller with the ENI, the ENI alone with no or several next hops, and empty network lists.
#[test]
fn owner_and_client_files_round_trip() {
    let dir = scratch("sections");
    let path = dir.join("mappings");
    let mut owner = sample(None);
    owner.eni = Some(eni(2));
    let mut client = sample(None);
    client.nvme = None;
    client.eni = Some(eni(1));
    let mut bare = client.clone();
    let quiet = bare.eni.as_mut().unwrap();
    quiet.net = NetState {
        mtu: NonZeroU32::new(1500).unwrap(),
        up: false,
        addresses: Vec::new(),
        routes: Vec::new(),
    };
    quiet.next_hops.clear();
    for mappings in [owner, client, bare] {
        mappings.write(&path).unwrap();
        assert_eq!(Mappings::read(&path).unwrap(), mappings);
    }
    let mut forged = sample(None);
    let mut route = eni(1);
    route.net.routes.push("10.8.0.0/16;default".into());
    forged.eni = Some(route);
    assert!(
        forged.write(&dir.join("forged")).is_err(),
        "a list item cannot forge another"
    );
    fs::remove_dir_all(dir).unwrap();
}

/// A file with no device, or with a device section missing a field, is refused naming it.
#[test]
fn incomplete_sections_are_refused() {
    let dir = scratch("incomplete");
    let path = dir.join("mappings");
    let mut owner = sample(None);
    owner.eni = Some(eni(1));
    owner.write(&path).unwrap();
    let good = fs::read_to_string(&path).unwrap();
    let only_head: String = good
        .lines()
        .filter(|line| !line.starts_with("nvme.") && !line.starts_with("eni."))
        .map(|line| format!("{line}\n"))
        .collect();
    let cases = [
        (only_head, "device"),
        (good.replace("eni.netdev=ens6\n", ""), "eni.netdev"),
        (good.replace("eni.mtu=9001\n", ""), "eni.mtu"),
        (good.replace("eni.mtu=9001", "eni.mtu=0"), "eni.mtu"),
        (good.replace("eni.mtu=9001", "eni.mtu=jumbo"), "eni.mtu"),
        (
            good.replace("eni.mtu=9001", "eni.mtu=4294967296"),
            "eni.mtu",
        ),
        (good.replace("eni.up=1", "eni.up=yes"), "eni.up"),
        (
            good.replace("eni.mac=0a:11:22:33:44:55", "eni.mac=0a:11"),
            "eni.mac",
        ),
        (good.replace("@0a:00:00:00:01:00", "@zz"), "eni.next_hops"),
        (
            good.replace("eni.original_driver=ena", "eni.original_driver=e/na"),
            "eni.original_driver",
        ),
        (good.replace("wc.patch=wc-1\n", ""), "wc.patch"),
        (good.replace(":4C1D2E3F4A5B6C7D8E9F0A1", ""), "wc.modules"),
    ];
    for (text, field) in cases {
        fs::write(&path, text).unwrap();
        assert!(
            matches!(Mappings::read(&path), Err(MappingsError::Format(f)) if f == field),
            "{field}"
        );
    }
    fs::remove_dir_all(dir).unwrap();
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("mappings-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_written_file_reads_back_identically_and_leaves_no_temporary() {
    let dir = scratch("round-trip");
    for original in [None, Some("nvme")] {
        let mappings = sample(original);
        mappings.write(&dir.join("mappings")).unwrap();
        assert_eq!(Mappings::read(&dir.join("mappings")).unwrap(), mappings);
        assert!(!dir.join("mappings.tmp").exists());
    }
    let mut bad = sample(None);
    bad.nvme.as_mut().unwrap().bdf = "0000:00:1f.0\ninstance=i-1".into();
    assert!(
        bad.write(&dir.join("other")).is_err(),
        "a value cannot forge a field"
    );
    assert!(!dir.join("other").exists());
    let mut colon = sample(None);
    colon.wc.modules[0].file = "/lib/modules/a:b/vfio-pci.ko".into();
    assert!(
        colon.write(&dir.join("other")).is_err(),
        "a module that would not read back as itself is refused"
    );
    assert!(!dir.join("other").exists());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_files_name_the_bad_field() {
    let dir = scratch("format");
    let path = dir.join("mappings");
    let good = fs::read_to_string({
        sample(None).write(&path).unwrap();
        &path
    })
    .unwrap();
    let cases = [
        (good.replace("nvme.nsid=1\n", ""), "nvme.nsid"),
        (good.replace("nvme.nsid=1", "nvme.nsid=one"), "nvme.nsid"),
        (format!("{good}instance=i-2\n"), "instance"),
        (format!("{good}unknown=1\n"), "key"),
        (format!("{good}no separator\n"), "line"),
        (good.replace("0000:00:1f.0", "00:1f.0"), "nvme.bdf"),
        (good.replace("0000:00:1f.0", "0000:00:1F.0"), "nvme.bdf"),
        (good.replace("0000:00:1f.0", "0000:00:20.0"), "nvme.bdf"),
    ];
    for (text, field) in cases {
        fs::write(&path, text).unwrap();
        assert!(
            matches!(Mappings::read(&path), Err(MappingsError::Format(f)) if f == field),
            "{field}"
        );
    }
    fs::remove_dir_all(dir).unwrap();
}

/// A reader finds each field by its key in any line order, refuses a
/// duplicate field in a section with `Format` naming the key, and reports
/// as unknown a key unrecognized by its prefix-selected section or the head.
#[test]
fn fields_read_in_any_order_and_repeats_or_unknown_keys_of_every_section_are_refused() {
    let dir = scratch("order");
    let path = dir.join("mappings");
    let mut owner = sample(Some("nvme"));
    owner.eni = Some(eni(2));
    owner.write(&path).unwrap();
    let good = fs::read_to_string(&path).unwrap();
    let reversed: String = good.lines().rev().map(|line| format!("{line}\n")).collect();
    fs::write(&path, reversed).unwrap();
    assert_eq!(Mappings::read(&path).unwrap(), owner);
    for line in good.lines() {
        let (key, _) = line.split_once('=').unwrap();
        fs::write(&path, format!("{good}{line}\n")).unwrap();
        assert!(
            matches!(Mappings::read(&path), Err(MappingsError::Format(f)) if f == key),
            "{key}"
        );
    }
    for unknown in ["nvme.unknown=1", "eni.unknown=1", "wc.unknown=1"] {
        fs::write(&path, format!("{good}{unknown}\n")).unwrap();
        assert!(
            matches!(Mappings::read(&path), Err(MappingsError::Format("key"))),
            "{unknown}"
        );
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_file_from_another_instance_or_boot_is_stale() {
    let mappings = sample(None);
    assert!(
        mappings
            .check_current(
                "i-0123456789abcdef0",
                "6f2a9a1c-0000-4000-8000-000000000001"
            )
            .is_ok()
    );
    assert!(matches!(
        mappings.check_current("i-0fffffffffffffff0", &mappings.boot),
        Err(MappingsError::Instance)
    ));
    assert!(matches!(
        mappings.check_current(&mappings.instance, "another-boot"),
        Err(MappingsError::Boot)
    ));
}

#[test]
fn volume_ids_map_to_their_controller_serial() {
    assert_eq!(serial_of("vol-0abc").as_deref(), Some("vol0abc"));
    assert_eq!(serial_of("vol0abc").as_deref(), Some("vol0abc"));
    for bad in ["", "vol-", "vol-xyz", "VOL-0123"] {
        assert_eq!(serial_of(bad), None, "{bad:?}");
    }
}

#[test]
fn the_owner_lock_admits_one_holder_at_a_time() {
    let _live = Live::enter();
    let dir = scratch("lock");
    let held = OwnerLock::acquire(&dir).unwrap();
    assert_eq!(
        OwnerLock::acquire(&dir).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(held);
    assert!(OwnerLock::acquire(&dir).is_ok());
    fs::remove_dir_all(dir).unwrap();
}

/// Serializes the tests that change the process's working directory, which
/// every thread of the test binary shares.
static CURRENT_DIR: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn the_owner_lock_of_an_empty_path_locks_the_current_directory() {
    // `Path::parent` of a bare `mappings` name is the empty path, which names
    // the current directory as the state directory.
    let _cwd = CURRENT_DIR
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _live = Live::enter();
    let dir = scratch("empty-lock");
    sample(None).write(&dir.join("mappings")).unwrap();
    std::env::set_current_dir(&dir).unwrap();
    let held = OwnerLock::acquire(std::path::Path::new("mappings").parent().unwrap());
    std::env::set_current_dir(std::env::temp_dir()).unwrap();
    let held = held.unwrap();
    assert_eq!(held.mappings().unwrap(), sample(None));
    assert_eq!(
        OwnerLock::acquire(&dir).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(held);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_bare_file_name_syncs_the_current_directory() {
    let _cwd = CURRENT_DIR
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = scratch("bare-name");
    std::env::set_current_dir(&dir).unwrap();
    sample(None)
        .write(std::path::Path::new("mappings"))
        .unwrap();
    assert_eq!(Mappings::read(&dir.join("mappings")).unwrap(), sample(None));
    std::env::set_current_dir(std::env::temp_dir()).unwrap();
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_destination_ending_in_tmp_stays_in_place_through_a_rewrite() {
    let dir = scratch("tmp-name");
    let path = dir.join("mappings.tmp");
    sample(None).write(&path).unwrap();
    let watched = path.clone();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen_missing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watcher = {
        let (stop, seen_missing) = (stop.clone(), seen_missing.clone());
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                if !watched.exists() {
                    seen_missing.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
        })
    };
    for _ in 0..200 {
        sample(Some("nvme")).write(&path).unwrap();
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    watcher.join().unwrap();
    assert!(
        !seen_missing.load(std::sync::atomic::Ordering::Relaxed),
        "a reader saw the live file missing during a rewrite"
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn the_lock_reads_the_mappings_of_its_own_directory() {
    let _live = Live::enter();
    let dir = scratch("locked-mappings");
    sample(None).write(&dir.join("mappings")).unwrap();
    let held = OwnerLock::acquire(&dir).unwrap();
    assert_eq!(held.mappings().unwrap(), sample(None));
    drop(held);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn the_lock_reads_the_next_hops_of_the_longest_peer_list() {
    let _live = Live::enter();
    let dir = scratch("longest-peer-list");
    let mut mappings = sample(None);
    let mut binding = eni(0);
    binding.next_hops = (0..crate::net::MAX_PEERS)
        .map(|at| {
            let octet = |place: usize| 100 + (at / place % 156) as u8;
            (
                [octet(1), octet(156), octet(156 * 156), 255].into(),
                [0xff; 6],
            )
        })
        .collect();
    mappings.eni = Some(binding);
    mappings.write(&dir.join("mappings")).unwrap();
    assert!(fs::metadata(dir.join("mappings")).unwrap().len() > 1 << 20);
    let held = OwnerLock::acquire(&dir).unwrap();
    assert_eq!(held.mappings().unwrap(), mappings);
    drop(held);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_file_over_the_byte_bound_refuses_as_invalid_data_before_its_parse() {
    use std::io::Write;
    let dir = scratch("over-the-bound");
    let path = dir.join("mappings");
    let mut file = fs::File::create(&path).unwrap();
    file.write_all(b"format=3\n").unwrap();
    let line = b"nvme.bdf=0000:00:1f.0\n";
    let lines = usize::try_from(super::mappings::MAPPINGS_BYTES).unwrap() / line.len() + 1;
    for _ in 0..lines {
        file.write_all(line).unwrap();
    }
    drop(file);
    assert!(fs::metadata(&path).unwrap().len() > super::mappings::MAPPINGS_BYTES);
    assert!(matches!(
        Mappings::read(&path),
        Err(MappingsError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidData
    ));
    fs::remove_dir_all(dir).unwrap();
}

/// The recorded MTU round-trips at 1500 and at 9001, and a file naming
/// format 2 without the MTU, or format 4 with a key this format lacks,
/// refuses as `Version`.
#[test]
fn the_eni_s_mtu_round_trips_in_the_current_format_alone() {
    let dir = scratch("mtu");
    let path = dir.join("mappings");
    for mtu in [1500, 9001] {
        let mut client = sample(None);
        client.nvme = None;
        let mut binding = eni(1);
        binding.net.mtu = NonZeroU32::new(mtu).unwrap();
        client.eni = Some(binding);
        client.write(&path).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains(&format!("eni.mtu={mtu}\n")), "{text}");
        assert_eq!(Mappings::read(&path).unwrap(), client);
        let previous = text
            .replace("format=3\n", "format=2\n")
            .replace(&format!("eni.mtu={mtu}\n"), "");
        fs::write(&path, previous).unwrap();
        assert!(matches!(Mappings::read(&path), Err(MappingsError::Version)));
        let later = text.replace("format=3\n", "format=4\neni.later=1\n");
        fs::write(&path, later).unwrap();
        assert!(matches!(Mappings::read(&path), Err(MappingsError::Version)));
    }
    fs::remove_dir_all(dir).unwrap();
}

/// Every `u8` prefix in a mappings file reads as the resolver's shared
/// CIDR rule admits it: 1 through 30 read back their masked network, and
/// `/0`, `/31`, `/32` and every larger value refuse as `Format("eni.cidr")`;
/// malformed CIDR text refuses the same way.
#[test]
fn ib_cidr_admission_every_mapping_prefix_reads_under_the_shared_rule() {
    let dir = scratch("cidr");
    let path = dir.join("mappings");
    let mut mappings = sample(None);
    mappings.eni = Some(eni(1));
    mappings.write(&path).unwrap();
    let good = fs::read_to_string(&path).unwrap();
    assert!(good.contains("eni.cidr=10.0.1.0/24\n"));
    let read = |cidr: &str| {
        fs::write(
            &path,
            good.replace("eni.cidr=10.0.1.0/24\n", &format!("eni.cidr={cidr}\n")),
        )
        .unwrap();
        Mappings::read(&path).map(|mappings| mappings.eni.unwrap().eni.cidr)
    };
    for prefix in 0..=255u8 {
        let text = format!("10.0.1.77/{prefix}");
        let expected = super::eni::parse_cidr(&text).ok_or(MappingsError::Format("eni.cidr"));
        let read = read(&text);
        assert!(
            matches!((&read, &expected), (Ok(a), Ok(b)) if a == b)
                || matches!((&read, &expected), (Err(MappingsError::Format(a)), Err(MappingsError::Format(b))) if a == b),
            "/{prefix}: {read:?}"
        );
        assert_eq!(read.is_ok(), (1..=30).contains(&prefix), "/{prefix}");
    }
    assert_eq!(read("10.0.1.77/24").unwrap(), ([10, 0, 1, 0].into(), 24));
    for text in super::eni_tests::MALFORMED_CIDRS {
        assert!(
            matches!(read(text), Err(MappingsError::Format("eni.cidr"))),
            "{text:?}"
        );
    }
    fs::remove_dir_all(dir).unwrap();
}

/// The writer's own rule, stated beside its module check, is that the record
/// never holds a field it later refuses: a record `write` admits reads back
/// as itself, and any other record refuses as `InvalidInput`. The cases are
/// a PCI domain above `0xffff`, which Linux prints in five digits, a driver
/// name outside the reader's token, and a value ending in a carriage
/// return, which the reader's line split drops.
#[test]
fn a_record_the_writer_admits_reads_back_as_itself() {
    let dir = scratch("writer-admits");
    let path = dir.join("mappings");
    let mut owner = sample(None);
    owner.eni = Some(eni(1));
    let change = |edit: fn(&mut Mappings)| {
        let mut mappings = owner.clone();
        edit(&mut mappings);
        mappings
    };
    let cases = [
        ("the sample", owner.clone()),
        (
            "a controller in a five-digit domain",
            change(|m| m.nvme.as_mut().unwrap().bdf = "10000:00:1f.0".into()),
        ),
        (
            "an ENI in a five-digit domain",
            change(|m| m.eni.as_mut().unwrap().eni.bdf = "10000:00:06.0".into()),
        ),
        (
            "a driver name with a dot",
            change(|m| m.nvme.as_mut().unwrap().original_driver = "nvme.v2".into()),
        ),
        (
            "an instance ending in a carriage return",
            change(|m| m.instance.push('\r')),
        ),
    ];
    assert!(owner.write(&path).is_ok(), "the sample is admitted");
    let mut wrong = Vec::new();
    for (name, mappings) in cases {
        let _ = fs::remove_file(&path);
        match mappings.write(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                assert!(!path.exists(), "{name}");
            }
            written => {
                let read = Mappings::read(&path);
                if !matches!(&read, Ok(found) if *found == mappings) {
                    wrong.push(format!("{name}: write {written:?}, read {read:?}"));
                }
            }
        }
    }
    fs::remove_dir_all(dir).unwrap();
    assert!(wrong.is_empty(), "{wrong:#?}");
}
