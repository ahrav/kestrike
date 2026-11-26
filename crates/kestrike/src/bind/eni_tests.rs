//! ENI resolution from metadata to one network device and function on `ena`, its network state, and next hops.

use std::fs;
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::path::Path;
use std::time::Duration;

use super::eni::{Eni, EniError, LISTING_LIMIT, NetState, Sighting, next_hop};
use super::fixture::{
    ENI, ENI_BDF, ENS6_LINK, FakeKernel, FakeMetadata, Fixture, NET_DEV_HEADER, hold_readers,
    make_fifo, neighbor_entry, net_dev_line, rename_listed,
};
use super::host::{Fed, Host, Kernel, Started, SysfsKernel};
use super::metadata::body;

/// Every kernel file and listing the ENI's resolution and the capture of its
/// network state take as evidence is the kernel's own only where no mount
/// covers it. A mount the mount table lists at one of them shows the
/// mount's text there, which can read as a route table without a default
/// route or a counter that stands still. Each row lists a mount over one
/// entry of a host both readings otherwise accept, leaves the entry's
/// content as it is, and the reading that takes the entry refuses. The same
/// host under the mounts a stock distribution lists is accepted.
#[test]
fn a_network_entry_a_mount_covers_is_no_evidence_of_the_eni() {
    const STOCK: &str = "/dev/nvme0n1p1 / xfs rw 0 0\n\
        proc /proc proc rw 0 0\n\
        sysfs /sys sysfs rw 0 0\n\
        cgroup2 /sys/fs/cgroup cgroup2 rw 0 0\n\
        binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc rw 0 0\n\
        debugfs /sys/kernel/debug debugfs rw 0 0\n\
        configfs /sys/kernel/config configfs rw 0 0\n";
    let read = |cover: Option<&str>, resolution: bool| {
        let fixture = Fixture::new(512);
        let tail = cover.map_or(String::new(), |at| format!("tmpfs {at} tmpfs rw 0 0\n"));
        fixture.file("proc/self/mounts", &format!("{STOCK}{tail}"));
        if resolution {
            (fixture.host)
                .resolve_eni(&FakeMetadata::new(), ENI)
                .map(drop)
        } else {
            let kernel = FakeKernel::new(&fixture.host);
            fixture.host.net_state(&kernel, "ens6").map(drop)
        }
    };
    for resolution in [true, false] {
        assert_eq!(read(None, resolution), Ok(()), "premise: a stock table");
    }
    // A link is read in its directory, so the mount that covers the
    // device's function link or the function's driver link is one over the
    // directory that holds it.
    let function = format!("/sys/bus/pci/devices/{ENI_BDF}");
    let vendor = format!("{function}/vendor");
    let resolved = [
        "/sys/class/net",
        "/sys/class/net/ens6",
        "/sys/class/net/ens6/address",
        "/sys/class/net/ens6/addr_assign_type",
        function.as_str(),
        vendor.as_str(),
        "/sys/kernel/uevent_seqnum",
        "/proc/net/dev",
        "/proc/net/route",
        "/proc/net/ipv6_route",
        "/proc/net/rt6_stats",
    ];
    let captured = [
        "/sys/kernel/uevent_seqnum",
        "/sys/class/net/ens6/master",
        "/sys/class/net/ens6/flags",
        "/sys/class/net/ens6/mtu",
        "/proc/net/if_inet6",
    ];
    let mut accepted = Vec::new();
    for (covers, resolution) in [(&resolved[..], true), (&captured[..], false)] {
        for cover in covers {
            if read(Some(cover), resolution).is_ok() {
                accepted.push((*cover, resolution));
            }
        }
    }
    assert_eq!(accepted, [], "entries read as the kernel's under a mount");
}

/// The configured ENI resolves to its one device and function with its metadata identity, and `resolve_eni_while` hands that device to `during`.
#[test]
fn the_configured_eni_resolves_to_its_device() {
    let fixture = Fixture::new(512);
    let eni = fixture.host.resolve_eni(&FakeMetadata::new(), ENI).unwrap();
    assert_eq!((eni.netdev.as_str(), eni.bdf.as_str()), ("ens6", ENI_BDF));
    assert_eq!(eni.mac, [0x0a, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(
        (eni.ipv4, eni.cidr),
        (Ipv4Addr::new(10, 0, 1, 5), (Ipv4Addr::new(10, 0, 1, 0), 24))
    );
    assert_eq!((eni.device_number, eni.network_card), (1, 0));
    let (_, during, _) = fixture
        .host
        .resolve_eni_while(&SysfsKernel, &FakeMetadata::new(), ENI, None, |netdev| {
            netdev.to_owned()
        })
        .unwrap();
    assert_eq!(
        during, "ens6",
        "the work beside the field requests gets the device"
    );
}

/// What one resolution saw lets the next resolution of the same ENI send
/// every request at once, and it resolves the same ENI whether the listing
/// still holds or not.
#[test]
fn a_sighting_resolves_the_same_eni() {
    struct Counting(FakeMetadata, std::sync::Mutex<usize>);
    impl super::metadata::Metadata for Counting {
        fn get(&self, path: &str) -> std::io::Result<String> {
            *self.1.lock().unwrap() += 1;
            self.0.get(path)
        }
    }
    let fixture = Fixture::new(512);
    let (plain, (), seen) = fixture
        .host
        .resolve_eni_while(&SysfsKernel, &FakeMetadata::new(), ENI, None, |_| ())
        .unwrap();
    let grown = FakeMetadata::new();
    {
        let mut paths = grown.0.lock().unwrap();
        let base = "network/interfaces/macs/";
        let listing = paths.get(base).unwrap().clone();
        paths.insert(base.into(), format!("{listing}0a:77:77:77:77:77/\n"));
        paths.insert(
            format!("{base}0a:77:77:77:77:77/interface-id"),
            "eni-0bbbbbbbbbbbbbbbb".into(),
        );
    }
    // The listing, two IDs and five fields at once; a grown listing then
    // asks for its three IDs and the fields again.
    for (metadata, requests, runs) in [(FakeMetadata::new(), 8, 1), (grown, 16, 2)] {
        let counting = Counting(metadata, std::sync::Mutex::new(0));
        let ran = std::cell::Cell::new(0);
        let (again, netdev, _) = fixture
            .host
            .resolve_eni_while(&SysfsKernel, &counting, ENI, Some(&seen), |netdev| {
                ran.set(ran.get() + 1);
                netdev.to_owned()
            })
            .unwrap();
        assert_eq!((again, netdev.as_str()), (plain.clone(), "ens6"));
        assert_eq!(*counting.1.lock().unwrap(), requests);
        assert_eq!(ran.get(), runs);
    }
}

/// A sighting's early device work serves only while the same one device
/// carries the matched MAC: a device renamed while the round is out has the
/// work run again under its new name.
#[test]
fn a_sighting_reruns_the_device_work_on_a_renamed_device() {
    let fixture = Fixture::new(512);
    let (_, (), seen) = fixture
        .host
        .resolve_eni_while(&SysfsKernel, &FakeMetadata::new(), ENI, None, |_| ())
        .unwrap();
    let net = fixture.host.sys.join("class/net");
    let ran = std::cell::RefCell::new(Vec::new());
    let (eni, netdev, _) = fixture
        .host
        .resolve_eni_while(
            &SysfsKernel,
            &FakeMetadata::new(),
            ENI,
            Some(&seen),
            |netdev| {
                if ran.borrow().is_empty() {
                    fs::rename(net.join("ens6"), net.join("ens9")).unwrap();
                    rename_listed(&fixture.host.proc.join("net/dev"), "ens6", "ens9");
                }
                ran.borrow_mut().push(netdev.to_owned());
                netdev.to_owned()
            },
        )
        .unwrap();
    assert_eq!(*ran.borrow(), ["ens6", "ens9"]);
    assert_eq!((eni.netdev.as_str(), netdev.as_str()), ("ens9", "ens9"));
}

/// A resolution from a sighting runs the device work while its one round of
/// requests is out: the work waits for a request to arrive, and every
/// request waits for the work to start.
#[test]
fn a_sighting_overlaps_the_device_work_with_its_requests() {
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;
    /// Whether a request arrived and whether the device work started.
    #[derive(Default)]
    struct Seen {
        request: bool,
        work: bool,
    }
    struct Gated(FakeMetadata, Mutex<Seen>, Condvar);
    impl Gated {
        /// Marks one side arrived and waits up to five seconds for the
        /// other, returning whether it came.
        fn meet(&self, arrive: fn(&mut Seen), other: fn(&Seen) -> bool) -> bool {
            let mut seen = self.1.lock().unwrap();
            arrive(&mut seen);
            self.2.notify_all();
            let (seen, _) = self
                .2
                .wait_timeout_while(seen, Duration::from_secs(5), |seen| !other(seen))
                .unwrap();
            other(&seen)
        }
    }
    impl super::metadata::Metadata for Gated {
        fn get(&self, path: &str) -> std::io::Result<String> {
            if !self.meet(|seen| seen.request = true, |seen| seen.work) {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            self.0.get(path)
        }
    }
    let fixture = Fixture::new(512);
    let (plain, (), seen) = fixture
        .host
        .resolve_eni_while(&SysfsKernel, &FakeMetadata::new(), ENI, None, |_| ())
        .unwrap();
    let gated = Gated(FakeMetadata::new(), Mutex::default(), Condvar::new());
    let (again, met, _) = fixture
        .host
        .resolve_eni_while(&SysfsKernel, &gated, ENI, Some(&seen), |_| {
            gated.meet(|seen| seen.work = true, |seen| seen.request)
        })
        .unwrap();
    assert_eq!(again, plain);
    assert!(met, "a request was out while the device work ran");
}

/// Each identity failure is refused with its own reason: a malformed ID, an unknown one, the primary interface, two interfaces or devices with the ENI's identity, a device off `ena`, an unsupported PCI ID, a main-table default route, and missing metadata.
#[test]
fn ambiguous_primary_or_foreign_interfaces_are_refused() {
    let resolve = |fixture: &Fixture, metadata: &FakeMetadata, id: &str| {
        fixture.host.resolve_eni(metadata, id)
    };
    let fixture = Fixture::new(512);
    let metadata = FakeMetadata::new();
    assert_eq!(resolve(&fixture, &metadata, "eni-xyz"), Err(EniError::Id));
    assert_eq!(
        resolve(&fixture, &metadata, "eni-0fff"),
        Err(EniError::NotFound)
    );
    assert_eq!(
        resolve(&fixture, &metadata, "eni-0aaaaaaaaaaaaaaaa"),
        Err(EniError::Primary)
    );

    let twice = FakeMetadata::new();
    twice.0.lock().unwrap().insert(
        "network/interfaces/macs/0a:00:00:00:00:01/interface-id".into(),
        ENI.into(),
    );
    assert_eq!(resolve(&fixture, &twice, ENI), Err(EniError::Duplicate));

    let second_card = FakeMetadata::new();
    second_card.0.lock().unwrap().insert(
        "network/interfaces/macs/0a:11:22:33:44:55/device-number".into(),
        "0".into(),
    );
    second_card.0.lock().unwrap().insert(
        "network/interfaces/macs/0a:11:22:33:44:55/network-card".into(),
        "1".into(),
    );
    assert!(
        resolve(&fixture, &second_card, ENI).is_ok(),
        "index zero on another card is not primary"
    );

    let missing = FakeMetadata::new();
    missing
        .0
        .lock()
        .unwrap()
        .remove("network/interfaces/macs/0a:11:22:33:44:55/subnet-id");
    assert!(matches!(
        resolve(&fixture, &missing, ENI),
        Err(EniError::Metadata(_))
    ));

    let duplicate = Fixture::new(512);
    duplicate.netdev("ens7", "0000:00:07.0", "0A:11:22:33:44:55", 0x1003);
    assert_eq!(
        resolve(&duplicate, &metadata, ENI),
        Err(EniError::Duplicate)
    );
    let ran = std::cell::Cell::new(false);
    assert_eq!(
        duplicate
            .host
            .resolve_eni_while(&SysfsKernel, &metadata, ENI, None, |_| ran.set(true))
            .map(drop),
        Err(EniError::Duplicate)
    );
    assert!(
        !ran.get(),
        "no device-specific work runs for an ambiguous MAC"
    );

    let unsupported = Fixture::new(512);
    unsupported.file(&format!("sys/bus/pci/devices/{ENI_BDF}/device"), "0xec21\n");
    assert!(
        resolve(&unsupported, &metadata, ENI).is_ok(),
        "both pinned IDs are supported"
    );
    unsupported.file(&format!("sys/bus/pci/devices/{ENI_BDF}/device"), "0xec22\n");
    assert_eq!(resolve(&unsupported, &metadata, ENI), Err(EniError::NotEna));

    let unbound = Fixture::new(512);
    fs::remove_file(unbound.host.pci(ENI_BDF).join("driver")).unwrap();
    assert_eq!(resolve(&unbound, &metadata, ENI), Err(EniError::NotEna));

    let managing = Fixture::new(512);
    managing.file(
        "proc/net/route",
        "Iface\tDestination\tGateway\tFlags\nens6\t00000000\t0101000A\t0003\n",
    );
    assert_eq!(
        resolve(&managing, &metadata, ENI),
        Err(EniError::Management)
    );
    fs::remove_file(managing.root.join("proc/net/route")).unwrap();
    assert_eq!(
        resolve(&managing, &metadata, ENI),
        Err(EniError::Unverifiable("route"))
    );
}

/// The network state reads the link flag, the addresses and the routes;
/// peers in the subnet are their own next hop, others go through the
/// subnet's router. A hop with a `REACHABLE` or `PERMANENT` entry on the
/// ENI's device needs no solicitation, and one read serves every hop; an
/// incomplete entry is removed once and its hop solicited, resolving at the
/// first poll; a hop that never answers is solicited each round and refused
/// after 5 s.
#[test]
fn network_state_and_next_hops_come_from_the_kernel() {
    let fixture = Fixture::new(512);
    let kernel = FakeKernel::new(&fixture.host);
    let state = fixture.host.net_state(&kernel, "ens6").unwrap();
    assert_eq!(
        state,
        NetState {
            mtu: NonZeroU32::new(9001).unwrap(),
            up: true,
            addresses: vec!["10.0.1.5/24 brd 10.0.1.255 metric 1003".into()],
            routes: vec!["10.0.1.0/24 proto kernel scope link src 10.0.1.5 metric 1003".into()],
        }
    );
    let eni = fixture.host.resolve_eni(&FakeMetadata::new(), ENI).unwrap();
    let peers = [
        Ipv4Addr::new(10, 0, 1, 9),
        Ipv4Addr::new(10, 0, 2, 7),
        Ipv4Addr::new(10, 0, 3, 8),
    ];
    let runs = kernel.runs.borrow().len();
    let hops = fixture.host.next_hops(&kernel, &eni, &peers).unwrap();
    assert_eq!(
        hops,
        [
            (peers[0], [0x0a, 0, 0, 0, 1, 9]),
            (peers[1], [0x0a, 0, 0, 0, 1, 1]),
            (peers[2], [0x0a, 0, 0, 0, 1, 1]),
        ]
    );
    assert!(
        kernel.solicits.borrow().is_empty(),
        "entries already reachable"
    );
    assert_eq!(
        kernel.runs.borrow()[runs..],
        READ,
        "one read serves every hop"
    );

    // An incomplete entry, an entry on another device only, and a permanent one.
    fixture.neighbor("ens6", &neighbor_entry("10.0.1.20", None, "INCOMPLETE"));
    fixture.neighbor(
        "ens5",
        &neighbor_entry("10.0.1.21", Some("0a:00:00:00:01:21"), "REACHABLE"),
    );
    fixture.neighbor(
        "ens6",
        &neighbor_entry("10.0.1.22", Some("0a:00:00:00:01:22"), "PERMANENT"),
    );
    kernel.answers.borrow_mut().extend([
        (Ipv4Addr::new(10, 0, 1, 20), "0a:00:00:00:01:20"),
        (Ipv4Addr::new(10, 0, 1, 21), "0a:00:00:00:01:31"),
    ]);
    let fresh = [
        Ipv4Addr::new(10, 0, 1, 20),
        Ipv4Addr::new(10, 0, 1, 21),
        Ipv4Addr::new(10, 0, 1, 22),
    ];
    let (runs, started) = (kernel.runs.borrow().len(), kernel.now());
    assert_eq!(
        fixture.host.next_hops(&kernel, &eni, &fresh).unwrap(),
        [
            (fresh[0], [0x0a, 0, 0, 0, 1, 0x20]),
            (fresh[1], [0x0a, 0, 0, 0, 1, 0x31]),
            (fresh[2], [0x0a, 0, 0, 0, 1, 0x22]),
        ]
    );
    assert_eq!(
        *kernel.solicits.borrow(),
        ["10.0.1.20 dev ens6", "10.0.1.21 dev ens6"],
        "one round solicits both unresolved hops"
    );
    assert_eq!(
        kernel.runs.borrow()[runs..],
        [
            READ[0],
            READ[1],
            "ip -4 neigh flush to 10.0.1.20 dev ens6",
            READ[0],
            READ[1],
        ],
        "the incomplete entry is removed once; the first read after the solicitations resolves"
    );
    assert_eq!(kernel.now() - started, Duration::from_millis(1));

    kernel.solicits.borrow_mut().clear();
    let unknown = Ipv4Addr::new(10, 0, 1, 77);
    let (runs, started) = (kernel.runs.borrow().len(), kernel.now());
    assert_eq!(
        fixture.host.next_hops(&kernel, &eni, &[peers[0], unknown]),
        Err(EniError::NextHop(unknown))
    );
    assert_eq!(
        *kernel.solicits.borrow(),
        ["10.0.1.77 dev ens6"; 5],
        "five rounds, none for the resolved hop"
    );
    assert_eq!(
        kernel.runs.borrow()[runs..],
        READ.repeat(21)[..],
        "one read, then four a round"
    );
    assert_eq!(kernel.now() - started, Duration::from_secs(5));

    fixture.neighbor("ens6", "10.0.1.x lladdr 0a:00:00:00:01:09 REACHABLE\n");
    assert_eq!(
        fixture.host.next_hops(&kernel, &eni, &peers),
        Err(EniError::Unverifiable("neighbors"))
    );
    kernel
        .outputs
        .borrow_mut()
        .insert("ip -4 -o neigh show dev ens6 nud all".into(), None);
    assert_eq!(
        fixture.host.next_hops(&kernel, &eni, &peers),
        Err(EniError::Unverifiable("neighbors"))
    );

    // `next_hops` returns `Unverifiable("neighbors")` before solicitation
    // because `batch` rejects `#` in the device name.
    let split = super::eni::Eni {
        netdev: "ens6#".into(),
        ..eni.clone()
    };
    fixture.neighbor(
        "ens6#",
        &neighbor_entry("10.0.1.9", Some("0a:00:00:00:01:09"), "STALE"),
    );
    kernel.solicits.borrow_mut().clear();
    assert_eq!(
        fixture.host.next_hops(&kernel, &split, &peers[..1]),
        Err(EniError::Unverifiable("neighbors"))
    );
    assert!(kernel.solicits.borrow().is_empty());
    assert_eq!(
        next_hop(
            (Ipv4Addr::new(10, 0, 1, 0), 24),
            Ipv4Addr::new(10, 0, 1, 255)
        ),
        Ipv4Addr::new(10, 0, 1, 255)
    );
    assert_eq!(
        next_hop((Ipv4Addr::new(10, 0, 0, 0), 16), Ipv4Addr::new(10, 1, 0, 1)),
        Ipv4Addr::new(10, 0, 0, 1)
    );
}

/// A metadata response yields its body for 200, `NotFound` for 404, and refuses anything else.
#[test]
fn metadata_responses_yield_only_successful_bodies() {
    assert_eq!(
        body("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc".to_owned()).unwrap(),
        "abc"
    );
    assert_eq!(
        body("HTTP/1.1 404 Not Found\r\n\r\n".to_owned())
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        body("HTTP/1.1 401 Unauthorized\r\n\r\n".to_owned())
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidData
    );
    assert_eq!(
        body("garbage".to_owned()).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
}

#[test]
fn addresses_keep_the_attributes_of_their_prefix_route() {
    let fixture = Fixture::new(512);
    let kernel = FakeKernel::new(&fixture.host);
    let show = "ip -4 -o addr show dev ens6".to_owned();
    kernel.outputs.borrow_mut().insert(
        show.clone(),
        Some(
            "3: ens6    inet 10.0.1.5/24 metric 1003 brd 10.0.1.255 scope global dynamic noprefixroute ens6\\       valid_lft 3000sec preferred_lft 3000sec\n\
             3: ens6    inet 10.0.1.6/24 brd 10.0.1.255 scope global secondary ens6\\       valid_lft forever preferred_lft forever\n"
                .into(),
        ),
    );
    assert_eq!(
        fixture.host.net_state(&kernel, "ens6").unwrap().addresses,
        [
            "10.0.1.5/24 brd 10.0.1.255 metric 1003 noprefixroute",
            "10.0.1.6/24 brd 10.0.1.255"
        ]
    );
    kernel.outputs.borrow_mut().insert(
        show,
        Some("3: ens6    inet 10.0.1.5/24 metric dev scope global ens6\n".into()),
    );
    assert_eq!(
        fixture.host.net_state(&kernel, "ens6"),
        Err(EniError::Unverifiable("addresses"))
    );
}

/// Resolution drops kernel-derived route flags and rejects multipath routes, route words or device names incompatible with release's `ip -batch`, malformed listed MACs, and ENIs bound to `vfio-pci`.
#[test]
fn routes_listings_and_drivers_fail_closed() {
    let fixture = Fixture::new(512);
    let kernel = FakeKernel::new(&fixture.host);
    kernel.outputs.borrow_mut().insert(
        "ip -4 -o route show table all dev ens6".into(),
        Some("10.0.1.0/24 proto kernel scope link src 10.0.1.5 linkdown\n".into()),
    );
    assert_eq!(
        fixture.host.net_state(&kernel, "ens6").unwrap().routes,
        ["10.0.1.0/24 proto kernel scope link src 10.0.1.5"]
    );
    kernel.outputs.borrow_mut().insert(
        "ip -4 -o route show table all dev ens6".into(),
        Some("10.9.0.0/16 proto static\n\tnexthop via 10.0.1.1 dev ens6 weight 1\n".into()),
    );
    assert_eq!(
        fixture.host.net_state(&kernel, "ens6"),
        Err(EniError::Unverifiable("routes"))
    );
    // Release replays the state through `ip -batch`, where `#` starts a comment.
    kernel.outputs.borrow_mut().insert(
        "ip -4 -o route show table all dev ens6".into(),
        Some("10.0.1.0/24 proto my#proto scope link\n".into()),
    );
    assert_eq!(
        fixture.host.net_state(&kernel, "ens6"),
        Err(EniError::Unverifiable("routes"))
    );
    fixture.file("sys/class/net/ens#6/flags", "0x1003\n");
    // The missing sysfs MTU takes precedence over the `ip -batch`
    // restriction on `#` in interface names.
    assert_eq!(
        fixture.host.net_state(&kernel, "ens#6"),
        Err(EniError::Unverifiable("mtu"))
    );
    fixture.file("sys/class/net/ens#6/mtu", "9001\n");
    assert_eq!(
        fixture.host.net_state(&kernel, "ens#6"),
        Err(EniError::Unverifiable("ip"))
    );

    let metadata = FakeMetadata::new();
    metadata.0.lock().unwrap().insert(
        "network/interfaces/macs/".into(),
        "0a:00:00:00:00:01/\n../../../latest/api/\n".into(),
    );
    assert_eq!(
        fixture.host.resolve_eni(&metadata, ENI),
        Err(EniError::Attribute("mac"))
    );

    fs::remove_file(fixture.host.pci(ENI_BDF).join("driver")).unwrap();
    fs::create_dir_all(fixture.host.sys.join("bus/pci/drivers/vfio-pci")).unwrap();
    std::os::unix::fs::symlink(
        fixture.host.sys.join("bus/pci/drivers/vfio-pci"),
        fixture.host.pci(ENI_BDF).join("driver"),
    )
    .unwrap();
    assert_eq!(
        fixture.host.resolve_eni(&FakeMetadata::new(), ENI),
        Err(EniError::NotEna)
    );
}

/// A MAC the host assigned, an IPv6 default route through the device, and
/// any IPv6 address beyond one link-local address, which lie outside what
/// release restores, all refuse.
#[test]
fn assigned_macs_and_ipv6_state_refuse() {
    let fixture = Fixture::new(512);
    let metadata = FakeMetadata::new();
    fixture.file("sys/class/net/ens6/addr_assign_type", "3\n");
    assert_eq!(
        fixture.host.resolve_eni(&metadata, ENI),
        Err(EniError::Attribute("addr_assign_type"))
    );
    fixture.file("sys/class/net/ens6/addr_assign_type", "0\n");
    fixture.file(
        "proc/net/ipv6_route",
        &format!(
            "{} 00 {} 00 {} 00000400 00000001 00000000 00000003     ens6\n",
            "0".repeat(32),
            "0".repeat(32),
            "0".repeat(32)
        ),
    );
    assert_eq!(
        fixture.host.resolve_eni(&metadata, ENI),
        Err(EniError::Management)
    );
    fs::remove_file(fixture.root.join("proc/net/ipv6_route")).unwrap();
    assert!(
        fixture.host.resolve_eni(&metadata, ENI).is_ok(),
        "a host without IPv6 has no table"
    );
    let kernel = FakeKernel::new(&fixture.host);
    let local = "fe800000000000000000000000000005 03 40 20 80     ens6\n\
                 00000000000000000000000000000001 01 80 10 80       lo\n\
                 26001f18000000000000000000000004 02 80 00 80     ens5\n";
    fixture.file("proc/net/if_inet6", local);
    assert!(
        fixture.host.net_state(&kernel, "ens6").is_ok(),
        "one link-local address and other devices' addresses pass"
    );
    for extra in [
        "26001f18000000000000000000000005 03 80 00 80     ens6",
        "fec00000000000000000000000000005 03 40 40 80     ens6",
        "fe800000000000000000000000000006 03 40 20 80     ens6",
    ] {
        fixture.file("proc/net/if_inet6", &format!("{local}{extra}\n"));
        assert_eq!(
            fixture.host.net_state(&kernel, "ens6"),
            Err(EniError::Unverifiable("ipv6")),
            "{extra}"
        );
    }
    fixture.file("proc/net/if_inet6", "26001f18 03 80 00 ens6\n");
    assert_eq!(
        fixture.host.net_state(&kernel, "ens6"),
        Err(EniError::Unverifiable("addresses"))
    );
    fs::remove_file(fixture.root.join("proc/net/if_inet6")).unwrap();
    fs::create_dir(fixture.root.join("proc/net/if_inet6")).unwrap();
    assert_eq!(
        fixture.host.net_state(&kernel, "ens6"),
        Err(EniError::Unverifiable("addresses"))
    );
}

/// The capture keeps a supported address's represented words, drops the
/// derived flags and lifetimes, and refuses each address word outside the
/// restoration domain with the detail that names it.
#[test]
fn the_capture_refuses_each_unrepresented_address_word() {
    let fixture = Fixture::new(512);
    let kernel = FakeKernel::new(&fixture.host);
    let show = "ip -4 -o addr show dev ens6".to_owned();
    let set = |line: &str| {
        kernel
            .outputs
            .borrow_mut()
            .insert(show.clone(), Some(format!("{line}\n")));
    };
    set(
        "3: ens6    inet 10.0.1.5/24 metric 1003 brd 10.0.1.255 scope global secondary dynamic noprefixroute ens6\\       valid_lft 3000sec preferred_lft 2000sec",
    );
    assert_eq!(
        fixture.host.net_state(&kernel, "ens6").unwrap().addresses,
        ["10.0.1.5/24 brd 10.0.1.255 metric 1003 noprefixroute"]
    );
    let refused = [
        ("inet 10.0.1.5/24 scope link ens6", "scope"),
        ("inet 10.0.1.5/24 scope host ens6", "scope"),
        ("inet 10.0.1.5/24 ens6", "scope"),
        ("inet 10.0.1.5/24 scope global ens6:x", "label"),
        ("inet 10.0.1.5/24 scope global", "label"),
        ("inet 10.0.1.5 peer 10.0.1.6/32 scope global ens6", "peer"),
        (
            "inet 10.0.1.5/24 scope global deprecated dynamic ens6",
            "deprecated",
        ),
        ("inet 10.0.1.5/24 scope global tentative ens6", "addresses"),
        ("inet 10.0.1.5/24 scope global home ens6", "addresses"),
        ("inet 10.0.1.5/24 scope global ens6 eth0", "label"),
        ("inet 10.0.1.5/24 scope global ens6x", "label"),
        ("inet 10.0.1.5/24 scope global foo", "label"),
    ];
    for (words, detail) in refused {
        set(&format!("3: ens6    {words}"));
        assert_eq!(
            fixture.host.net_state(&kernel, "ens6"),
            Err(EniError::Unverifiable(detail)),
            "{words}"
        );
    }
}

/// The capture keeps main-table routes, drops the local table's kernel
/// entries of the device's addresses, and refuses a route in any other table
/// and an `ip rule` naming the device or one of its addresses, while the
/// default rules and a rule on another address pass.
#[test]
fn the_capture_refuses_other_tables_and_rules_naming_the_eni() {
    let fixture = Fixture::new(512);
    let kernel = FakeKernel::new(&fixture.host);
    let (routes, rules) = (
        "ip -4 -o route show table all dev ens6".to_owned(),
        "ip -4 -o rule show".to_owned(),
    );
    let main =
        "10.0.1.0/24 proto kernel scope link src 10.0.1.5 metric 1003\n10.9.0.0/16 via 10.0.1.1\n";
    let derived = "local 10.0.1.5 table local proto kernel scope host src 10.0.1.5\n\
                   broadcast 10.0.1.255 table local proto kernel scope link src 10.0.1.5\n";
    let defaults = "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n32767:\tfrom all lookup default\n";
    let mut outputs = kernel.outputs.borrow_mut();
    outputs.insert(routes.clone(), Some(format!("{main}{derived}")));
    outputs.insert(
        rules.clone(),
        Some(format!("{defaults}32765:\tfrom 10.0.2.5 lookup 7\n")),
    );
    drop(outputs);
    assert_eq!(
        fixture.host.net_state(&kernel, "ens6").unwrap().routes,
        [
            "10.0.1.0/24 proto kernel scope link src 10.0.1.5 metric 1003",
            "10.9.0.0/16 via 10.0.1.1"
        ]
    );
    for route in [
        "10.8.0.0/16 via 10.0.1.1 table 7",
        "local 10.0.1.9 table local proto kernel scope host src 10.0.1.5",
        "broadcast 10.0.1.127 table local proto kernel scope link src 10.0.1.5",
        "broadcast 10.0.1.0 table local proto kernel scope link src 10.0.1.5",
        "local 10.0.1.9 table local proto static scope host",
        "local 10.0.1.5 table local proto static scope host src 10.0.1.5",
        "10.5.0.0/16 nhid 5 via 10.0.1.1",
        "10.5.0.0/16 nhid 5 via 10.0.1.1 proto static",
        "10.8.0.0/16 via 10.0.1.1 table local proto kernel",
    ] {
        kernel
            .outputs
            .borrow_mut()
            .insert(routes.clone(), Some(format!("{main}{route}\n")));
        assert_eq!(
            fixture.host.net_state(&kernel, "ens6"),
            Err(EniError::Unverifiable("routes")),
            "{route}"
        );
    }
    kernel
        .outputs
        .borrow_mut()
        .insert(routes, Some(main.into()));
    for rule in [
        "32765:\tfrom 10.0.1.5 lookup 7",
        "32765:\tfrom all to 10.0.1.5/32 lookup 7",
        "32765:\tfrom all iif ens6 lookup 7",
        "32765:\tnot from all oif ens6 lookup 7",
    ] {
        kernel
            .outputs
            .borrow_mut()
            .insert(rules.clone(), Some(format!("{defaults}{rule}\n")));
        assert_eq!(
            fixture.host.net_state(&kernel, "ens6"),
            Err(EniError::Unverifiable("rules")),
            "{rule}"
        );
    }
}

/// The capture admits the kernel's own IPv6 entries of the device's one
/// link-local address, and refuses any other IPv6 route of the device, an
/// IPv6 rule naming it, a rule of either family naming one of its altnames,
/// and a link line of another device. An altname spelled as the route flag
/// `dead` or `linkdown` names the device like any other: a rule keeps the
/// word, and only a route line sheds it as a flag.
#[test]
fn the_capture_admits_only_derived_ipv6_entries_and_refuses_rules_by_any_name() {
    let fixture = Fixture::new(512);
    let kernel = FakeKernel::new(&fixture.host);
    fixture.file(
        "proc/net/if_inet6",
        "fe80000000000000081122fffe334455 03 40 20 80     ens6\n",
    );
    let (link, routes6, rules6, rules) = (
        "ip -6 -o link show dev ens6".to_owned(),
        "ip -6 -o route show table all dev ens6".to_owned(),
        "ip -6 -o rule show".to_owned(),
        "ip -4 -o rule show".to_owned(),
    );
    let derived = "fe80::/64 proto kernel metric 256 pref medium\n\
                   local fe80::811:22ff:fe33:4455 table local proto kernel metric 0 pref medium\n\
                   multicast ff00::/8 table local proto kernel metric 256 pref medium\n";
    let set = |command: &String, output: String| {
        kernel
            .outputs
            .borrow_mut()
            .insert(command.clone(), Some(output));
    };
    set(
        &link,
        format!(
            "{}\\    altname enp0s6\\    altname dead\\    altname linkdown\n",
            ENS6_LINK.trim_end()
        ),
    );
    set(&routes6, derived.into());
    set(
        &rules6,
        "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n".into(),
    );
    assert!(fixture.host.net_state(&kernel, "ens6").is_ok());
    for route in [
        "2001:db8::/64 table 7 metric 1024 pref medium",
        "2001:db8:1::/64 proto static metric 1024 pref medium",
        "local fe80::5 table local proto kernel metric 0 pref medium",
        "anycast fe80:: table local proto kernel metric 0 pref medium",
        "fe80::/64 proto static metric 256 pref medium",
        "fe80::/64 table 7 proto kernel metric 256 pref medium",
        "multicast ff00::/8 table 7 proto kernel metric 256 pref medium",
        "fe80::/64 via fe80::1 proto kernel metric 1024 pref medium",
        "fe80::/64 proto kernel metric 1024 pref medium",
        "fe80::/64 proto kernel metric 256 pref medium\\\tnexthop via fe80::1 dev ens6 weight 1\\\tnexthop via fe80::2 dev ens6 weight 1",
        "local fe80::811:22ff:fe33:4455 table local proto kernel metric 1024 pref medium",
        "multicast ff00::/8 table local proto kernel metric 1024 pref medium",
        "2001:db8:: metric 1024 pref medium",
        "2001:db8::/64 nhid 6 metric 1024 pref medium",
        "2001:db8:1:: table 7 metric 1024 pref medium",
    ] {
        set(&routes6, format!("{derived}{route}\n"));
        assert_eq!(
            fixture.host.net_state(&kernel, "ens6"),
            Err(EniError::Unverifiable("routes")),
            "{route}"
        );
    }
    set(&routes6, derived.into());
    for (command, rule) in [
        (&rules6, "32765:\tfrom all iif ens6 lookup 7"),
        (&rules6, "32765:\tfrom all oif enp0s6 lookup 7"),
        (&rules, "32765:\tfrom all iif enp0s6 lookup 7"),
        (&rules6, "32765:\tfrom all iif dead lookup 7"),
        (&rules6, "32765:\tnot from all oif linkdown lookup 7"),
        (&rules, "32765:\tfrom all iif dead lookup 7"),
        (&rules, "32765:\tfrom all oif linkdown lookup 7"),
        (&rules6, "32765:\tfrom fe80::811:22ff:fe33:4455 lookup 7"),
        (
            &rules6,
            "32765:\tfrom all to fe80::811:22ff:fe33:4455/128 lookup 7",
        ),
    ] {
        set(command, format!("0:\tfrom all lookup local\n{rule}\n"));
        assert_eq!(
            fixture.host.net_state(&kernel, "ens6"),
            Err(EniError::Unverifiable("rules")),
            "{rule}"
        );
        set(command, String::new());
    }
    // The kernel's `fe80::/64` belongs to a link-local address the device holds.
    fixture.file(
        "proc/net/if_inet6",
        "fe80000000000000081122fffe334466 03 40 20 80     ens5\n",
    );
    set(
        &routes6,
        "fe80::/64 proto kernel metric 256 pref medium\n".into(),
    );
    assert_eq!(
        fixture.host.net_state(&kernel, "ens6"),
        Err(EniError::Unverifiable("routes"))
    );
    set(&link, ENS6_LINK.replace("3: ens6:", "4: ens7:"));
    assert_eq!(
        fixture.host.net_state(&kernel, "ens6"),
        Err(EniError::Unverifiable("ip"))
    );
}

/// The capture admits a link-local address with any interface identifier
/// and treats the IPv4 prefix route, the IPv4 local-table entries,
/// `fe80::/64` and the link-local `local` entry as optional. It drops the
/// kernel-derived local-table and IPv6 entries and keeps the IPv4 prefix
/// route the kernel prints.
#[test]
fn the_capture_admits_a_hand_assigned_link_local_address_and_absent_derived_entries() {
    let fixture = Fixture::new(512);
    let kernel = FakeKernel::new(&fixture.host);
    let set = |command: &str, output: &str| {
        kernel
            .outputs
            .borrow_mut()
            .insert(command.to_owned(), Some(output.to_owned()));
    };
    let (routes, routes6) = (
        "ip -4 -o route show table all dev ens6",
        "ip -6 -o route show table all dev ens6",
    );
    set(
        "ip -4 -o addr show dev ens6",
        "3: ens6    inet 10.0.1.5/24 brd 10.0.1.255 scope global ens6\n",
    );
    set(
        routes,
        "10.0.1.0/24 proto kernel scope link src 10.0.1.5\n\
         10.9.0.0/16 via 10.0.1.1\n\
         local 10.0.1.5 table local proto kernel scope host src 10.0.1.5\n\
         broadcast 10.0.1.255 table local proto kernel scope link src 10.0.1.5\n",
    );
    fixture.file(
        "proc/net/if_inet6",
        "fe80000000000000081122fffe334455 03 40 20 80     ens6\n",
    );
    set(
        routes6,
        "fe80::/64 proto kernel metric 256 pref medium\n\
         local fe80::811:22ff:fe33:4455 table local proto kernel metric 0 pref medium\n\
         multicast ff00::/8 table local proto kernel metric 256 pref medium\n",
    );
    let generated = fixture.host.net_state(&kernel, "ens6").unwrap();
    assert_eq!(generated.addresses, ["10.0.1.5/24 brd 10.0.1.255"]);
    assert_eq!(
        generated.routes,
        [
            "10.0.1.0/24 proto kernel scope link src 10.0.1.5",
            "10.9.0.0/16 via 10.0.1.1"
        ]
    );
    fixture.file(
        "proc/net/if_inet6",
        "fe800000000000000000000000000005 03 40 20 80     ens6\n",
    );
    set(
        routes6,
        "fe80::/64 proto kernel metric 256 pref medium\n\
         local fe80::5 table local proto kernel metric 0 pref medium\n\
         multicast ff00::/8 table local proto kernel metric 256 pref medium\n",
    );
    assert_eq!(fixture.host.net_state(&kernel, "ens6").unwrap(), generated);
    set(routes, "10.9.0.0/16 via 10.0.1.1\n");
    set(
        routes6,
        "multicast ff00::/8 table local proto kernel metric 256 pref medium\n",
    );
    let absent = fixture.host.net_state(&kernel, "ens6").unwrap();
    assert_eq!(absent.addresses, generated.addresses);
    assert_eq!(absent.routes, ["10.9.0.0/16 via 10.0.1.1"]);
}

/// The complete IPv6 listing holds what `ip` before 6.10 leaves out of a
/// listing by device: a multipath route with a next hop on the device, and
/// a route through a nexthop object that lists no device. Each refuses the
/// capture, since the bind removes it and release replays no IPv6 route.
/// The routes of other devices and the listing's own copy of the device's
/// derived entries leave the capture unchanged.
#[test]
fn an_ipv6_route_of_the_device_listed_only_in_the_complete_listing_refuses_the_capture() {
    let fixture = Fixture::new(512);
    let kernel = FakeKernel::new(&fixture.host);
    fixture.file(
        "proc/net/if_inet6",
        "fe80000000000000081122fffe334455 03 40 20 80     ens6\n",
    );
    let set = |output: &str| {
        kernel.outputs.borrow_mut().insert(
            "ip -6 -o route show table all".to_owned(),
            Some(output.to_owned()),
        );
    };
    let alone = fixture.host.net_state(&kernel, "ens6").unwrap();
    set("fe80::/64 dev ens6 proto kernel metric 256 pref medium\n\
         local fe80::811:22ff:fe33:4455 dev ens6 table local proto kernel metric 0 pref medium\n\
         fe80::/64 dev d1 proto kernel metric 256 pref medium\n\
         local ::1 dev lo table local proto kernel metric 0 pref medium\n\
         2001:db8:2::/64 nhid 6 via fe80::1 dev d1 metric 1024 pref medium\n\
         2001:db8:1::/64 metric 1024 pref medium \\\tnexthop via fe80::1 dev d1 weight 1 \\\tnexthop via fe80::2 dev d2 weight 1\n");
    assert_eq!(fixture.host.net_state(&kernel, "ens6").unwrap(), alone);
    for route in [
        "2001:db8:1::/64 metric 1024 pref medium \\\tnexthop via fe80::1 dev d1 weight 1 \\\tnexthop via fe80::2 dev ens6 weight 1",
        "2001:db8:2::/64 nhid 6 metric 1024 pref medium",
    ] {
        set(&format!("{route}\n"));
        assert_eq!(
            fixture.host.net_state(&kernel, "ens6"),
            Err(EniError::Unverifiable("routes")),
            "{route}"
        );
    }
}

#[test]
fn a_link_line_s_alias_group_and_queue_length_leave_the_captured_state_unchanged() {
    let fixture = Fixture::new(512);
    let kernel = FakeKernel::new(&fixture.host);
    let plain = fixture.host.net_state(&kernel, "ens6").unwrap();
    let set = |command: &str, output: String| {
        kernel
            .outputs
            .borrow_mut()
            .insert(command.to_owned(), Some(output));
    };
    let link = ENS6_LINK
        .replace("group default qlen 1000", "group 7 qlen 500")
        .replace('\n', "\\    alias uplink a\\    altname eniA\n");
    assert!(link.contains("group 7 qlen 500") && link.ends_with("altname eniA\n"));
    set("ip -6 -o link show dev ens6", link);
    assert_eq!(fixture.host.net_state(&kernel, "ens6").unwrap(), plain);
    set(
        "ip -4 -o rule show",
        "32765:\tfrom all iif eniA lookup 7\n".into(),
    );
    assert_eq!(
        fixture.host.net_state(&kernel, "ens6"),
        Err(EniError::Unverifiable("rules"))
    );
}

/// On a host with IPv6 disabled, whose `if_inet6` table is absent and whose `ip`
/// fails every IPv6 route and rule read, the capture reads the link line
/// alone and admits the device.
#[test]
fn a_host_without_ipv6_reads_the_link_line_alone() {
    let fixture = Fixture::new(512);
    let kernel = FakeKernel::new(&fixture.host);
    assert!(!fixture.root.join("proc/net/if_inet6").exists());
    let mut outputs = kernel.outputs.borrow_mut();
    outputs.insert("ip -6 -o route show table all dev ens6".into(), None);
    outputs.insert("ip -6 -o rule show".into(), None);
    drop(outputs);
    assert!(fixture.host.net_state(&kernel, "ens6").is_ok());
    let runs = kernel.runs.borrow();
    let ipv6: Vec<&String> = runs.iter().filter(|run| run.starts_with("ip -6")).collect();
    assert_eq!(ipv6, ["ip -6 -o link show dev ens6"]);
}

struct Ordered<'k> {
    kernel: &'k FakeKernel,
    events: std::cell::RefCell<Vec<String>>,
}

struct Noted<'k, T: ?Sized> {
    tool: Box<T>,
    family: String,
    events: &'k std::cell::RefCell<Vec<String>>,
}

impl<'k> Started for Noted<'k, dyn Started + 'k> {
    fn feed<'s>(self: Box<Self>, input: &str) -> Box<dyn Fed + 's>
    where
        Self: 's,
    {
        let Noted {
            tool,
            family,
            events,
        } = *self;
        events.borrow_mut().push(format!("feed {family}"));
        Box::new(Noted {
            tool: tool.feed(input),
            family,
            events,
        })
    }
}

impl<'k> Fed for Noted<'k, dyn Fed + 'k> {
    fn finish(self: Box<Self>) -> std::io::Result<String> {
        self.events
            .borrow_mut()
            .push(format!("finish {}", self.family));
        self.tool.finish()
    }
}

impl Kernel for Ordered<'_> {
    fn write(&self, _: &std::path::Path, _: &str) -> std::io::Result<()> {
        unreachable!("a capture writes nothing")
    }

    fn start<'k>(&'k self, program: &str, args: &[&str]) -> std::io::Result<Box<dyn Started + 'k>> {
        Ok(Box::new(Noted {
            tool: self.kernel.start(program, args)?,
            family: args[0].to_owned(),
            events: &self.events,
        }))
    }

    fn solicit(&self, _: &str, _: Ipv4Addr) -> std::io::Result<()> {
        unreachable!("a capture solicits no neighbor")
    }

    fn settle(&self, _: Duration) {
        unreachable!("a capture waits on its tools alone")
    }

    fn now(&self) -> std::time::Instant {
        self.kernel.now()
    }

    fn open_group(&self, _: &std::path::Path) -> std::io::Result<fs::File> {
        unreachable!("a capture opens no group")
    }

    fn group_status(&self, _: &fs::File) -> std::io::Result<u32> {
        unreachable!("a capture queries no group")
    }
}

#[test]
fn the_capture_feeds_both_programs_before_it_finishes_either() {
    let fixture = Fixture::new(512);
    let kernel = Ordered {
        kernel: &FakeKernel::new(&fixture.host),
        events: std::cell::RefCell::default(),
    };
    assert!(fixture.host.net_state(&kernel, "ens6").is_ok());
    assert_eq!(
        *kernel.events.borrow(),
        ["feed -4", "feed -6", "finish -4", "finish -6"]
    );
}

/// The kernel's `broadcast` entry of an address's prefix broadcast is
/// derived below a /31 prefix, with or without `brd`, and refuses on a /31,
/// whose two addresses are both hosts.
#[test]
fn the_prefix_broadcast_entry_is_derived_below_a_31_prefix_alone() {
    let fixture = Fixture::new(512);
    let kernel = FakeKernel::new(&fixture.host);
    for (address, broadcast, admitted) in [
        ("10.0.2.5/24", "10.0.2.255", true),
        ("10.0.2.4/31", "10.0.2.5", false),
    ] {
        let local = address.split('/').next().unwrap();
        let mut outputs = kernel.outputs.borrow_mut();
        outputs.insert(
            "ip -4 -o addr show dev ens6".into(),
            Some(format!(
                "3: ens6    inet 10.0.1.5/24 scope global ens6\n3: ens6    inet {address} scope global ens6\n"
            )),
        );
        outputs.insert(
            "ip -4 -o route show table all dev ens6".into(),
            Some(format!(
                "broadcast {broadcast} table local proto kernel scope link src {local}\n"
            )),
        );
        drop(outputs);
        let captured = fixture.host.net_state(&kernel, "ens6");
        if admitted {
            assert!(captured.is_ok(), "{address}: {captured:?}");
        } else {
            assert_eq!(captured, Err(EniError::Unverifiable("routes")), "{address}");
        }
    }
}

/// The capture admits a local-table route of a captured address when the
/// route reads `local` with `scope host` or `broadcast` with `scope link`,
/// names as `src` the first captured address of the same prefix, and ends
/// there or with `linkdown`. A secondary address's routes name its primary
/// as `src`. The capture refuses with `"routes"` a `proto kernel` route
/// whose scope or `src` differs, or that adds a `metric`.
#[test]
fn a_local_table_route_is_admitted_only_with_its_derived_scope_and_source() {
    let fixture = Fixture::new(512);
    let kernel = FakeKernel::new(&fixture.host);
    let routes = "ip -4 -o route show table all dev ens6".to_owned();
    kernel.outputs.borrow_mut().insert(
        "ip -4 -o addr show dev ens6".into(),
        Some(
            "3: ens6    inet 10.0.1.5/24 brd 10.0.1.255 scope global ens6\n\
             3: ens6    inet 10.0.1.133/25 brd 10.0.1.255 scope global ens6\n\
             3: ens6    inet 10.0.1.6/24 brd 10.0.1.255 scope global secondary ens6\n"
                .into(),
        ),
    );
    let derived = "local 10.0.1.5 table local proto kernel scope host src 10.0.1.5\n\
                   local 10.0.1.6 table local proto kernel scope host src 10.0.1.5\n\
                   local 10.0.1.133 table local proto kernel scope host src 10.0.1.133\n\
                   broadcast 10.0.1.255 table local proto kernel scope link src 10.0.1.5 linkdown\n\
                   broadcast 10.0.1.255 table local proto kernel scope link src 10.0.1.133\n";
    let set = |output: String| {
        kernel
            .outputs
            .borrow_mut()
            .insert(routes.clone(), Some(output));
    };
    set(derived.into());
    let captured = fixture.host.net_state(&kernel, "ens6");
    assert!(captured.is_ok(), "{captured:?}");
    for route in [
        "local 10.0.1.5 table local proto kernel scope host src 10.0.1.5 metric 7",
        "local 10.0.1.5 table local proto kernel scope link src 10.0.1.5",
        "local 10.0.1.5 table local proto kernel scope host src 10.0.1.9",
        "local 10.0.1.5 table local proto kernel scope host",
        "local 10.0.1.6 table local proto kernel scope host src 10.0.1.6",
        "local 10.0.1.133 table local proto kernel scope host src 10.0.1.5",
        "broadcast 10.0.1.255 table local proto kernel scope host src 10.0.1.5",
        "broadcast 10.0.1.255 table local proto kernel scope link src 10.0.1.6",
        "broadcast 10.0.1.255 table local proto kernel scope link src 10.0.1.5 metric 9",
        "broadcast 10.0.1.255 table local scope link src 10.0.1.5 proto kernel",
    ] {
        set(format!("{derived}{route}\n"));
        assert_eq!(
            fixture.host.net_state(&kernel, "ens6"),
            Err(EniError::Unverifiable("routes")),
            "{route}"
        );
    }
}

/// The capture records the device's MTU as the kernel reports it, 1500 or
/// 9001, and refuses a missing, zero, malformed or overflowing value; a
/// `brd` without a valid IPv4 address after it refuses too, while an address
/// without `brd` keeps none.
#[test]
fn the_mtu_and_broadcast_address_are_captured_or_refused() {
    let fixture = Fixture::new(512);
    let kernel = FakeKernel::new(&fixture.host);
    let mtu = fixture.host.sys.join("class/net/ens6/mtu");
    for value in [1500, 9001] {
        fs::write(&mtu, format!("{value}\n")).unwrap();
        assert_eq!(
            fixture.host.net_state(&kernel, "ens6").unwrap().mtu.get(),
            value
        );
    }
    for value in ["0", "jumbo", "4294967296", ""] {
        fs::write(&mtu, format!("{value}\n")).unwrap();
        assert_eq!(
            fixture.host.net_state(&kernel, "ens6"),
            Err(EniError::Unverifiable("mtu")),
            "{value:?}"
        );
    }
    fs::remove_file(&mtu).unwrap();
    assert_eq!(
        fixture.host.net_state(&kernel, "ens6"),
        Err(EniError::Unverifiable("mtu"))
    );
    fs::write(&mtu, "9001\n").unwrap();
    let show = "ip -4 -o addr show dev ens6".to_owned();
    for line in [
        "3: ens6    inet 10.0.1.5/24 brd scope global ens6\n",
        "3: ens6    inet 10.0.1.5/24 brd 10.0.1 scope global ens6\n",
        "3: ens6    inet 10.0.1.5/24 brd ens6\n",
    ] {
        kernel
            .outputs
            .borrow_mut()
            .insert(show.clone(), Some(line.into()));
        assert_eq!(
            fixture.host.net_state(&kernel, "ens6"),
            Err(EniError::Unverifiable("addresses")),
            "{line:?}"
        );
    }
    kernel.outputs.borrow_mut().insert(
        show,
        Some("3: ens6    inet 10.0.1.5/24 scope global ens6\n".into()),
    );
    assert_eq!(
        fixture.host.net_state(&kernel, "ens6").unwrap().addresses,
        ["10.0.1.5/24"]
    );
}

/// The two command lines of one neighbor read of the fixture ENI: the proxy
/// listing, then every ordinary entry.
const READ: [&str; 2] = [
    "ip -4 -o neigh show proxy dev ens6",
    "ip -4 -o neigh show dev ens6 nud all",
];

/// The fixture, its kernel and its ENI, with the neighbor file of `ens6`
/// replaced by `entries`.
fn resolving(entries: &str) -> (Fixture, FakeKernel, super::eni::Eni) {
    let fixture = Fixture::new(512);
    fs::write(fixture.root.join("neigh/ens6"), entries).unwrap();
    let kernel = FakeKernel::new(&fixture.host);
    let eni = fixture.host.resolve_eni(&FakeMetadata::new(), ENI).unwrap();
    (fixture, kernel, eni)
}

/// A stale entry's old MAC gives way to the one a fresh resolution finds:
/// each stale hop's entry is removed once, before the solicitations, and
/// the peers that share the gateway share its one resolution, while the
/// device's entries for other addresses stay as they were.
#[test]
fn a_stale_next_hop_resolves_afresh() {
    let gateway = Ipv4Addr::new(10, 0, 1, 1);
    let neighbor = Ipv4Addr::new(10, 0, 1, 12);
    let others = neighbor_entry("10.0.1.9", Some("0a:00:00:00:01:09"), "REACHABLE")
        + &neighbor_entry("10.0.1.12", Some("0a:00:00:00:0f:12"), "STALE")
        + &neighbor_entry("10.0.1.50", Some("0a:00:00:00:01:50"), "STALE");
    for state in ["STALE", "DELAY", "PROBE"] {
        let entries = neighbor_entry("10.0.1.1", Some("0a:00:00:00:0f:0f"), state) + &others;
        let (fixture, kernel, eni) = resolving(&entries);
        kernel.answers.borrow_mut().extend([
            (gateway, "0a:00:00:00:01:01"),
            (neighbor, "0a:00:00:00:01:12"),
        ]);
        let peers = [
            Ipv4Addr::new(10, 0, 2, 7),
            Ipv4Addr::new(10, 0, 3, 8),
            neighbor,
        ];
        assert_eq!(
            fixture.host.next_hops(&kernel, &eni, &peers).unwrap(),
            [
                (peers[0], [0x0a, 0, 0, 0, 1, 1]),
                (peers[1], [0x0a, 0, 0, 0, 1, 1]),
                (peers[2], [0x0a, 0, 0, 0, 1, 0x12]),
            ],
            "{state}"
        );
        assert_eq!(
            *kernel.solicits.borrow(),
            ["10.0.1.1 dev ens6", "10.0.1.12 dev ens6"],
            "{state}"
        );
        let removals: Vec<String> = kernel
            .runs
            .borrow()
            .iter()
            .filter(|run| run.contains("neigh flush"))
            .cloned()
            .collect();
        assert_eq!(
            removals,
            [
                "ip -4 neigh flush to 10.0.1.1 dev ens6",
                "ip -4 neigh flush to 10.0.1.12 dev ens6",
            ],
            "{state}"
        );
        let table = fs::read_to_string(fixture.root.join("neigh/ens6")).unwrap();
        assert!(
            table.contains("10.0.1.50 lladdr 0a:00:00:00:01:50 STALE"),
            "{state}"
        );
    }
}

/// A hop whose entry never confirms has its entry removed once, before its
/// first solicitation, and is solicited once a round until the rounds end in
/// `NextHop`; a failed, incomplete or `NONE` entry starts the same way, and
/// a hop with no entry is solicited with no removal.
#[test]
fn an_unconfirmed_next_hop_is_removed_once_and_refused() {
    let hop = Ipv4Addr::new(10, 0, 1, 9);
    for entry in [
        neighbor_entry("10.0.1.9", Some("0a:00:00:00:01:09"), "STALE"),
        neighbor_entry("10.0.1.9", None, "FAILED"),
        neighbor_entry("10.0.1.9", None, "INCOMPLETE"),
        neighbor_entry("10.0.1.9", None, "NONE"),
        neighbor_entry("10.0.1.9", Some("0a:00:00:00:01:09"), "NONE"),
        String::new(),
    ] {
        let (fixture, kernel, eni) = resolving(&entry);
        assert_eq!(
            fixture.host.next_hops(&kernel, &eni, &[hop]),
            Err(EniError::NextHop(hop)),
            "{entry:?}"
        );
        assert_eq!(*kernel.solicits.borrow(), ["10.0.1.9 dev ens6"; 5]);
        let removals = kernel
            .runs
            .borrow()
            .iter()
            .filter(|run| run.contains("neigh flush"))
            .count();
        assert_eq!(removals, usize::from(!entry.is_empty()), "{entry:?}");
    }
}

/// The rounds wait by elapsed time on the kernel's clock: reads that take
/// time shorten the waits after them, and a read slower than the next
/// read's target skips that wait.
#[test]
fn the_rounds_wait_by_elapsed_time() {
    let hop = Ipv4Addr::new(10, 0, 1, 9);
    for (cost, total) in [(40, 5240), (1500, 31505)] {
        let (fixture, kernel, eni) = resolving("");
        // A read is two command lines, and the fake charges each its cost.
        kernel.run_cost.set(Duration::from_millis(cost) / 2);
        let started = kernel.now();
        assert_eq!(
            fixture.host.next_hops(&kernel, &eni, &[hop]),
            Err(EniError::NextHop(hop))
        );
        assert_eq!(
            kernel.now() - started,
            Duration::from_millis(total),
            "{cost} ms a read"
        );
    }
}

/// A proxy entry for a hop refuses it as `Neighbor`, alone or beside an
/// ordinary entry in any state, with both tables left in place and nothing
/// flushed or solicited. The kernel keeps proxy entries apart from the
/// neighbor table, and `ip` lists them only for `neigh show proxy`, so a read
/// of the `nud all` listing alone would resolve the hop from its `REACHABLE`
/// entry, or solicit it as absent. A proxy entry for an address no peer
/// routes through refuses nothing.
#[test]
fn a_proxy_entry_refuses_its_hop_beside_or_without_an_ordinary_entry() {
    let hop = Ipv4Addr::new(10, 0, 1, 9);
    let proxy = |fixture: &Fixture, entries: &str| {
        fs::create_dir_all(fixture.root.join("proxy")).unwrap();
        fs::write(fixture.root.join("proxy/ens6"), entries).unwrap();
    };
    for beside in [
        String::new(),
        neighbor_entry("10.0.1.9", Some("0a:00:00:00:01:09"), "REACHABLE"),
        neighbor_entry("10.0.1.9", Some("0a:00:00:00:01:09"), "PERMANENT"),
        neighbor_entry("10.0.1.9", Some("0a:00:00:00:01:09"), "STALE"),
    ] {
        let (fixture, kernel, eni) = resolving(&beside);
        proxy(&fixture, "10.0.1.9 proxy\n");
        assert_eq!(
            fixture.host.next_hops(&kernel, &eni, &[hop]),
            Err(EniError::Neighbor(hop)),
            "{beside:?}"
        );
        assert!(kernel.solicits.borrow().is_empty(), "{beside:?}");
        assert_eq!(
            fs::read_to_string(fixture.root.join("neigh/ens6")).unwrap(),
            beside,
            "left in place"
        );
        assert_eq!(
            fs::read_to_string(fixture.root.join("proxy/ens6")).unwrap(),
            "10.0.1.9 proxy\n"
        );
    }
    let entries = neighbor_entry("10.0.1.9", Some("0a:00:00:00:01:09"), "REACHABLE");
    let (fixture, kernel, eni) = resolving(&entries);
    proxy(&fixture, "10.0.1.40 proxy\n");
    assert_eq!(
        fixture.host.next_hops(&kernel, &eni, &[hop]),
        Ok(vec![(hop, [0x0a, 0, 0, 0, 1, 9])])
    );
}

/// `NOARP`, proxy, malformed and unknown entries, and reachable or
/// permanent entries whose MAC is zero, multicast or broadcast, refuse as
/// `Neighbor` with the entry left in place and nothing solicited.
#[test]
fn untrusted_neighbor_entries_refuse_without_removal() {
    let hop = Ipv4Addr::new(10, 0, 1, 9);
    for entry in [
        "10.0.1.9 lladdr 0a:00:00:00:01:09 NOARP\n",
        "10.0.1.9 lladdr 0a:00:00:00:01:09 proxy REACHABLE\n",
        "10.0.1.9 lladdr 0a:00:00:00:01 REACHABLE\n",
        "10.0.1.9 lladdr 0a:00:00:00:01:09 GONE\n",
        "10.0.1.9 lladdr 0a:00:00:00:01:09 STALE REACHABLE\n",
        "10.0.1.9 REACHABLE\n",
        "10.0.1.9 lladdr 00:00:00:00:00:00 REACHABLE\n",
        "10.0.1.9 lladdr 01:00:5e:00:00:09 REACHABLE\n",
        "10.0.1.9 lladdr ff:ff:ff:ff:ff:ff PERMANENT\n",
    ] {
        let (fixture, kernel, eni) = resolving(entry);
        assert_eq!(
            fixture.host.next_hops(&kernel, &eni, &[hop]),
            Err(EniError::Neighbor(hop)),
            "{entry:?}"
        );
        assert!(kernel.solicits.borrow().is_empty(), "{entry:?}");
        assert_eq!(
            fs::read_to_string(fixture.root.join("neigh/ens6")).unwrap(),
            entry,
            "left in place"
        );
    }
    // A router entry that is reachable needs nothing more, and entries of
    // addresses no peer routes through refuse nothing.
    let entries = "224.0.0.251 lladdr 01:00:5e:00:00:fb NOARP\n\
                   10.0.1.40 lladdr 0a:00:00:00:01:40 proxy REACHABLE\n\
                   10.0.1.9 lladdr 0a:00:00:00:01:09 router REACHABLE\n";
    let (fixture, kernel, eni) = resolving(entries);
    assert_eq!(
        fixture.host.next_hops(&kernel, &eni, &[hop]),
        Ok(vec![(hop, [0x0a, 0, 0, 0, 1, 9])])
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("neigh/ens6")).unwrap(),
        entries
    );

    // A solicitation whose send fails still resolves from the kernel's
    // answer.
    let (fixture, kernel, eni) = resolving("");
    kernel.answers.borrow_mut().insert(hop, "0a:00:00:00:01:09");
    kernel.solicit_fails.set(true);
    assert_eq!(
        fixture.host.next_hops(&kernel, &eni, &[hop]),
        Ok(vec![(hop, [0x0a, 0, 0, 0, 1, 9])])
    );
}

/// `ip` prints an entry's `NDA_PROTOCOL` as `proto NAME` after its state
/// and an externally validated entry's flag as `extern_valid` before it.
#[test]
fn protocol_and_validation_metadata_leave_the_entry_s_state_alone() {
    let hop = Ipv4Addr::new(10, 0, 1, 9);
    let mac = [0x0a, 0, 0, 0, 1, 9];
    for entry in [
        "10.0.1.9 lladdr 0a:00:00:00:01:09 PERMANENT proto static\n",
        "10.0.1.9 lladdr 0a:00:00:00:01:09 REACHABLE proto babel\n",
        "10.0.1.9 lladdr 0a:00:00:00:01:09 extern_valid PERMANENT proto static\n",
    ] {
        let (fixture, kernel, eni) = resolving(entry);
        assert_eq!(
            fixture.host.next_hops(&kernel, &eni, &[hop]),
            Ok(vec![(hop, mac)]),
            "{entry:?}"
        );
        assert!(kernel.solicits.borrow().is_empty(), "{entry:?}");
    }
    let (fixture, kernel, eni) =
        resolving("10.0.1.9 lladdr 0a:00:00:00:01:08 STALE proto static\n");
    kernel.answers.borrow_mut().insert(hop, "0a:00:00:00:01:09");
    assert_eq!(
        fixture.host.next_hops(&kernel, &eni, &[hop]),
        Ok(vec![(hop, mac)]),
        "a stale entry is solicited afresh"
    );
    assert_eq!(kernel.solicits.borrow()[..], ["10.0.1.9 dev ens6"]);
    let (fixture, kernel, eni) = resolving("10.0.1.9 lladdr 0a:00:00:00:01:09 REACHABLE proto\n");
    assert_eq!(
        fixture.host.next_hops(&kernel, &eni, &[hop]),
        Err(EniError::Neighbor(hop)),
        "a `proto` without its name"
    );
}

/// Metadata that counts the requests sent and the most in flight at once,
/// each request held 20 ms so a round's requests overlap.
struct Concurrent {
    inner: FakeMetadata,
    sent: std::sync::atomic::AtomicUsize,
    active: std::sync::atomic::AtomicUsize,
    peak: std::sync::atomic::AtomicUsize,
}

impl Concurrent {
    fn new(inner: FakeMetadata) -> Self {
        Self {
            inner,
            sent: 0.into(),
            active: 0.into(),
            peak: 0.into(),
        }
    }
}

impl super::metadata::Metadata for Concurrent {
    fn get(&self, path: &str) -> std::io::Result<String> {
        use std::sync::atomic::Ordering::SeqCst;
        self.sent.fetch_add(1, SeqCst);
        let now = self.active.fetch_add(1, SeqCst) + 1;
        self.peak.fetch_max(now, SeqCst);
        std::thread::sleep(Duration::from_millis(20));
        self.active.fetch_sub(1, SeqCst);
        self.inner.get(path)
    }
}

/// The fixture metadata with `extra` more interfaces listed after the two
/// it holds, each with its own ID.
fn listing_with(extra: usize) -> FakeMetadata {
    let metadata = FakeMetadata::new();
    {
        let mut paths = metadata.0.lock().unwrap();
        let base = "network/interfaces/macs/";
        let mut listing = paths.get(base).unwrap().clone();
        for index in 0..extra {
            let mac = format!("0a:66:00:00:00:{index:02x}");
            listing.push_str(&format!("{mac}/\n"));
            paths.insert(
                format!("{base}{mac}/interface-id"),
                format!("eni-0{index:016x}"),
            );
        }
        paths.insert(base.into(), listing);
    }
    metadata
}

#[test]
fn ib_metadata_envelope_oversized_listing_refuses_before_any_request_for_it() {
    use std::sync::atomic::Ordering::SeqCst;
    let fixture = Fixture::new(512);
    let at_cap = Concurrent::new(listing_with(LISTING_LIMIT - 2));
    let (_, (), seen) = fixture
        .host
        .resolve_eni_while(&SysfsKernel, &at_cap, ENI, None, |_| ())
        .unwrap();
    assert_eq!(at_cap.sent.load(SeqCst), 1 + LISTING_LIMIT + 5);
    let again = Concurrent::new(listing_with(LISTING_LIMIT - 2));
    fixture
        .host
        .resolve_eni_while(&SysfsKernel, &again, ENI, Some(&seen), |_| ())
        .unwrap();
    assert_eq!(again.sent.load(SeqCst), 1 + LISTING_LIMIT + 5);
    assert!(again.peak.load(SeqCst) > 1);
    let over = Concurrent::new(listing_with(LISTING_LIMIT - 1));
    assert_eq!(
        fixture
            .host
            .resolve_eni_while(&SysfsKernel, &over, ENI, None, |_| ()),
        Err(EniError::Limit("listing"))
    );
    assert_eq!(over.sent.load(SeqCst), 1);
}

#[test]
fn a_listing_past_32_interfaces_resolves_with_bounded_requests_in_flight() {
    use std::sync::atomic::Ordering::SeqCst;
    let fixture = Fixture::new(512);
    let first = Concurrent::new(listing_with(78));
    let (eni, (), seen) = fixture
        .host
        .resolve_eni_while(&SysfsKernel, &first, ENI, None, |_| ())
        .unwrap();
    assert_eq!(eni.id, ENI);
    assert_eq!(first.sent.load(SeqCst), 1 + 80 + 5);
    let peak = first.peak.load(SeqCst);
    assert!(peak <= 1 + 32 + 5, "{peak}");
    let again = Concurrent::new(listing_with(78));
    let (eni, (), _) = fixture
        .host
        .resolve_eni_while(&SysfsKernel, &again, ENI, Some(&seen), |_| ())
        .unwrap();
    assert_eq!(eni.id, ENI);
    assert_eq!(again.sent.load(SeqCst), 1 + 80 + 5);
    let peak = again.peak.load(SeqCst);
    assert!(peak > 1 && peak <= 1 + 32 + 5, "{peak}");
}

/// A prefetched sighting one past `LISTING_LIMIT` refuses with
/// `Limit("listing")` before issuing a request. Fresh ID and field requests
/// revalidate a sighting at the cap when its listing has changed.
#[test]
fn ib_metadata_envelope_stale_prefetched_sighting() {
    use std::sync::atomic::Ordering::SeqCst;
    let fixture = Fixture::new(512);
    let macs: Vec<[u8; 6]> = (0..=LISTING_LIMIT)
        .map(|index| [0x0a, 0x66, 0, 0, 0, u8::try_from(index).unwrap()])
        .collect();
    let mac = super::eni::parse_mac(super::fixture::ENI_MAC).unwrap();
    let stale = super::eni::Sighting::new(macs.clone(), mac);
    let metadata = Concurrent::new(FakeMetadata::new());
    assert_eq!(
        fixture
            .host
            .resolve_eni_while(&SysfsKernel, &metadata, ENI, Some(&stale), |_| ()),
        Err(EniError::Limit("listing"))
    );
    assert_eq!(metadata.sent.load(SeqCst), 0);
    let changed = super::eni::Sighting::new(macs[..LISTING_LIMIT].to_vec(), mac);
    let metadata = Concurrent::new(FakeMetadata::new());
    let (eni, (), seen) = fixture
        .host
        .resolve_eni_while(&SysfsKernel, &metadata, ENI, Some(&changed), |_| ())
        .unwrap();
    assert_eq!(eni.id, ENI);
    assert_eq!(metadata.sent.load(SeqCst), 1 + LISTING_LIMIT + 5 + 2 + 5);
    assert_ne!(seen, changed);
}

/// A request whose thread fails to start fails only its own path: the
/// resolution names that field's path, and the same metadata resolves
/// once every thread starts.
#[test]
fn ib_metadata_envelope_failed_thread_start() {
    let fixture = Fixture::new(512);
    let path = format!(
        "network/interfaces/macs/{}/subnet-id",
        super::fixture::ENI_MAC
    );
    super::eni::UNSTARTABLE.with_borrow_mut(|unstartable| *unstartable = Some(path.clone()));
    let refused = fixture.host.resolve_eni(&FakeMetadata::new(), ENI);
    super::eni::UNSTARTABLE.with_borrow_mut(|unstartable| *unstartable = None);
    assert_eq!(refused, Err(EniError::Metadata(path)));
    assert!(fixture.host.resolve_eni(&FakeMetadata::new(), ENI).is_ok());
}

/// A resolution whose round of requests ends past the 15-second deadline
/// on the kernel's clock refuses with `Limit("deadline")`; one that ends
/// at the deadline resolves.
#[test]
fn a_resolution_past_its_deadline_refuses() {
    let fixture = Fixture::new(512);
    for (wait, resolved) in [(15, true), (16, false)] {
        let kernel = FakeKernel::new(&fixture.host);
        let result =
            fixture
                .host
                .resolve_eni_while(&kernel, &FakeMetadata::new(), ENI, None, |_| {
                    kernel.settle(Duration::from_secs(wait))
                });
        match resolved {
            true => assert!(result.is_ok(), "{result:?}"),
            false => assert_eq!(result.err(), Some(EniError::Limit("deadline"))),
        }
    }
}

/// A clock the request threads advance: `now` is its start plus the
/// seconds metadata requests have added.
struct SharedClock {
    start: std::time::Instant,
    seconds: std::sync::atomic::AtomicU64,
}

impl Kernel for SharedClock {
    fn write(&self, _: &std::path::Path, _: &str) -> std::io::Result<()> {
        unreachable!("resolution writes nothing")
    }

    fn start<'k>(
        &'k self,
        _: &str,
        _: &[&str],
    ) -> std::io::Result<Box<dyn super::host::Started + 'k>> {
        unreachable!("resolution starts no tool")
    }

    fn solicit(&self, _: &str, _: Ipv4Addr) -> std::io::Result<()> {
        unreachable!("resolution solicits no neighbor")
    }

    fn settle(&self, _: Duration) {}

    fn now(&self) -> std::time::Instant {
        self.start + Duration::from_secs(self.seconds.load(std::sync::atomic::Ordering::SeqCst))
    }

    fn open_group(&self, _: &std::path::Path) -> std::io::Result<fs::File> {
        unreachable!("resolution opens no group")
    }

    fn group_status(&self, _: &fs::File) -> std::io::Result<u32> {
        unreachable!("resolution queries no group")
    }
}

/// Metadata whose request for `slow` advances `clock` by 16 seconds.
struct Slow<'c> {
    inner: FakeMetadata,
    clock: &'c SharedClock,
    slow: String,
    sent: std::sync::atomic::AtomicUsize,
}

impl super::metadata::Metadata for Slow<'_> {
    fn get(&self, path: &str) -> std::io::Result<String> {
        use std::sync::atomic::Ordering::SeqCst;
        self.sent.fetch_add(1, SeqCst);
        if path == self.slow {
            self.clock.seconds.fetch_add(16, SeqCst);
        }
        self.inner.get(path)
    }
}

/// Each round's deadline check refuses the resolution before the next
/// round starts: a slow listing round sends no ID request, a slow ID round
/// no field request, and a slow field round refuses after its fields.
#[test]
fn every_request_round_checks_the_discovery_deadline() {
    let fixture = Fixture::new(512);
    let base = "network/interfaces/macs/";
    let mac = super::fixture::ENI_MAC;
    for (slow, sent) in [
        (base.to_owned(), 1),
        (format!("{base}{mac}/interface-id"), 1 + 2),
        (format!("{base}{mac}/subnet-id"), 1 + 2 + 5),
    ] {
        let clock = SharedClock {
            start: std::time::Instant::now(),
            seconds: 0.into(),
        };
        let metadata = Slow {
            inner: FakeMetadata::new(),
            clock: &clock,
            slow: slow.clone(),
            sent: 0.into(),
        };
        let refused = fixture
            .host
            .resolve_eni_while(&clock, &metadata, ENI, None, |_| ());
        assert_eq!(refused.err(), Some(EniError::Limit("deadline")), "{slow}");
        assert_eq!(
            metadata.sent.load(std::sync::atomic::Ordering::SeqCst),
            sent,
            "{slow}"
        );
    }
}

/// The network and prefix `address/prefix` admits under the shared rule,
/// computed in `u64`: prefixes 1 through 30, the address masked to its
/// top `prefix` bits.
fn admitted(address: Ipv4Addr, prefix: u32) -> Option<(Ipv4Addr, u8)> {
    (1..=30).contains(&prefix).then(|| {
        let size = 1u64 << (32 - prefix);
        let network = u64::from(u32::from(address)) / size * size;
        (Ipv4Addr::from(network as u32), prefix as u8)
    })
}

/// Every `u8` prefix resolves as the shared rule admits: 1 through 30 give
/// the masked network, and every other prefix, `/0`, `/31` and `/32`
/// included, refuses the resolution at the CIDR field.
#[test]
fn ib_cidr_admission_every_prefix_resolves_under_the_shared_rule() {
    let fixture = Fixture::new(512);
    let address = Ipv4Addr::new(10, 0, 1, 7);
    let path = format!(
        "network/interfaces/macs/{}/subnet-ipv4-cidr-block",
        super::fixture::ENI_MAC
    );
    for prefix in 0..=255u32 {
        let metadata = FakeMetadata::new();
        metadata
            .0
            .lock()
            .unwrap()
            .insert(path.clone(), format!("{address}/{prefix}"));
        let resolved = fixture.host.resolve_eni(&metadata, ENI).map(|eni| eni.cidr);
        match admitted(address, prefix) {
            Some(cidr) => assert_eq!(resolved, Ok(cidr), "/{prefix}"),
            None => assert_eq!(
                resolved,
                Err(EniError::Attribute("subnet-ipv4-cidr-block")),
                "/{prefix}"
            ),
        }
    }
}

/// Malformed CIDR text refuses at the shared parser and at the resolver's
/// CIDR field: no prefix, an empty, signed, spaced or non-decimal prefix,
/// an extra field, or a malformed address.
#[test]
fn ib_cidr_admission_malformed_text_refuses() {
    let fixture = Fixture::new(512);
    let path = format!(
        "network/interfaces/macs/{}/subnet-ipv4-cidr-block",
        super::fixture::ENI_MAC
    );
    for text in MALFORMED_CIDRS {
        assert_eq!(super::eni::parse_cidr(text), None, "{text:?}");
        let metadata = FakeMetadata::new();
        metadata
            .0
            .lock()
            .unwrap()
            .insert(path.clone(), text.to_owned());
        assert_eq!(
            fixture.host.resolve_eni(&metadata, ENI).map(|eni| eni.cidr),
            Err(EniError::Attribute("subnet-ipv4-cidr-block")),
            "{text:?}"
        );
    }
}

/// CIDR strings both entry points refuse.
pub(super) const MALFORMED_CIDRS: [&str; 13] = [
    "10.0.1.0",
    "10.0.1.0/",
    "/24",
    "10.0.1/24",
    "10.0.1.0/24/1",
    "10.0.1.0//24",
    "10.0/1.0/24",
    "10.0.1.0/+24",
    "10.0.1.0/ 24",
    "x/24",
    "10.0.1.256/24",
    "10.0.1.0/-1",
    "10.0.1.0/0x18",
];

/// For every admitted prefix, the addresses either side of the subnet's
/// first and last are inside or outside it as `u64` arithmetic says: an
/// address inside is its own next hop, one outside goes through the
/// router, the network address plus one.
#[test]
fn ib_cidr_admission_membership_boundaries_hold_for_every_prefix() {
    for prefix in 1..=30u32 {
        let base = Ipv4Addr::new(172, 31, 200, 77);
        let (network, length) = admitted(base, prefix).unwrap();
        assert_eq!(
            super::eni::parse_cidr(&format!("{base}/{prefix}")),
            Some((network, length))
        );
        let start = u64::from(u32::from(network));
        let end = start + (1u64 << (32 - prefix));
        let router = Ipv4Addr::from(start as u32 + 1);
        for probe in [start.wrapping_sub(1), start, start + 1, end - 1, end] {
            let Ok(ip) = u32::try_from(probe).map(Ipv4Addr::from) else {
                continue;
            };
            let inside = (start..end).contains(&probe);
            let hop = next_hop((network, length), ip);
            assert_eq!(hop, if inside { ip } else { router }, "{ip} in /{prefix}");
        }
    }
}

/// A request batch that ends past the discovery deadline refuses the
/// resolution before the next batch starts, so the refusal comes after the
/// listing and the first batch of 38 ID requests.
#[test]
fn every_request_batch_checks_the_discovery_deadline() {
    let fixture = Fixture::new(512);
    let clock = SharedClock {
        start: std::time::Instant::now(),
        seconds: 0.into(),
    };
    let metadata = Slow {
        inner: listing_with(78),
        clock: &clock,
        slow: "network/interfaces/macs/0a:00:00:00:00:01/interface-id".to_owned(),
        sent: 0.into(),
    };
    let refused = fixture
        .host
        .resolve_eni_while(&clock, &metadata, ENI, None, |_| ());
    assert_eq!(refused.err(), Some(EniError::Limit("deadline")));
    assert_eq!(
        metadata.sent.load(std::sync::atomic::Ordering::SeqCst),
        1 + 38
    );
}

/// The ENI's permanent MAC must name exactly one network device, and a device whose `address` cannot be read may carry that MAC, so the resolution refuses with `Unverifiable("class/net")` rather than take the one readable match. An entry of `class/net` that is no device directory, as the bonding driver's `bonding_masters` file is, refuses nothing. The premises are that the second device, while readable, is a duplicate, and that its address then fails to read.
#[test]
fn a_network_device_whose_address_cannot_be_read_refuses_the_resolution() {
    let fixture = Fixture::new(512);
    let metadata = FakeMetadata::new();
    fixture.file("sys/class/net/bonding_masters", "\n");
    assert!(
        fixture.host.resolve_eni(&metadata, ENI).is_ok(),
        "sibling: an entry that is no device directory refuses nothing"
    );
    fixture.netdev("ens7", "0000:00:07.0", "0A:11:22:33:44:55", 0x1003);
    assert_eq!(
        fixture.host.resolve_eni(&metadata, ENI).map(drop),
        Err(EniError::Duplicate),
        "premise: the second device carries the ENI's MAC"
    );
    // A directory in the attribute's place fails the read for every user, root included.
    let address = fixture.root.join("sys/class/net/ens7/address");
    fs::remove_file(&address).unwrap();
    fs::create_dir(&address).unwrap();
    assert!(
        fs::read(&address).is_err(),
        "premise: the address cannot be read"
    );
    assert_eq!(
        fixture.host.resolve_eni(&metadata, ENI).map(drop),
        Err(EniError::Unverifiable("class/net"))
    );
}

/// The permanent MAC must name exactly one network device, so a
/// second device carrying it, as a VLAN on the ENI's device does, refuses the
/// resolution: `Duplicate` under a name the list can hold, and
/// `Unverifiable` under a name outside UTF-8, which the list cannot hold and
/// must not leave out. A device with such a name and another MAC changes
/// nothing.
#[test]
fn a_second_device_carrying_the_mac_refuses_whatever_its_name() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let resolved = |name: &[u8], address: &str| {
        let fixture = Fixture::new(512);
        let upper = fixture
            .host
            .sys
            .join("class/net")
            .join(OsStr::from_bytes(name));
        fs::create_dir_all(&upper).unwrap();
        fs::write(upper.join("address"), address).unwrap();
        fixture
            .host
            .resolve_eni(&FakeMetadata::new(), ENI)
            .map(|eni| eni.netdev)
    };
    assert_eq!(
        resolved(b"ens6.5", "0a:11:22:33:44:55\n"),
        Err(EniError::Duplicate)
    );
    assert_eq!(
        resolved(b"ens6.\xff", "0a:11:22:33:44:55\n"),
        Err(EniError::Unverifiable("class/net"))
    );
    assert_eq!(
        resolved(b"ens6.\xff", "0a:11:22:33:44:56\n"),
        Ok("ens6".to_owned())
    );
}

/// The judgment of a next hop read from the one neighbor line `entry`, whose `lladdr` is `mac`. The bind
/// records a next hop's MAC only from an entry the kernel reports `REACHABLE`, or from a `PERMANENT` entry the
/// deployment trusts as configuration (`bind/mod.rs`); `Host::next_hops`: "The MAC of the next hop toward each of `peers`, from the
/// kernel's neighbor entries on the ENI's device". A resolution therefore gives the entry's own `lladdr` or an error.
fn judge_mac_of_the_entry(
    entry: &str,
    mac: [u8; 6],
    hops: &Result<Vec<(Ipv4Addr, [u8; 6])>, EniError>,
) {
    let hop = Ipv4Addr::new(10, 0, 1, 9);
    assert!(
        matches!(hops, Ok(found) if found[..] == [(hop, mac)]) || hops.is_err(),
        "a next hop's MAC is its entry's lladdr or the hop is refused: {entry:?} gave {hops:?}"
    );
}

/// `ip` ends a word at ASCII whitespace alone and prints a neighbor entry's protocol by its `rt_protos` name as its
/// bytes, so a name holding a space character outside ASCII lists as one word. The words `lladdr` and a MAC after
/// such a space are part of the name: the hop resolves with the entry's own `lladdr` or is refused
/// ([`judge_mac_of_the_entry`]); it never takes the MAC the name spells.
#[test]
fn a_neighbor_protocol_name_holding_a_space_outside_ascii_gives_no_mac() {
    let hop = Ipv4Addr::new(10, 0, 1, 9);
    for state in ["REACHABLE", "PERMANENT"] {
        for space in ['\u{a0}', '\u{85}', '\u{2003}', '\u{3000}'] {
            let entry = format!(
                "10.0.1.9 lladdr 0a:00:00:00:01:09 {state} proto x{space}lladdr{space}02:00:00:00:00:99 \n"
            );
            let (fixture, kernel, eni) = resolving(&entry);
            let hops = fixture.host.next_hops(&kernel, &eni, &[hop]);
            judge_mac_of_the_entry(&entry, [0x0a, 0, 0, 0, 1, 9], &hops);
        }
    }
}

/// The same alias on the state: an entry the kernel holds in state `NONE`, which `ip` prints as no state word,
/// under a protocol named `x<U+00A0>REACHABLE`. The kernel reports no `REACHABLE` entry, so the hop is not resolved
/// from it at once; with no answer to the solicitations the resolution ends `NextHop`.
#[test]
fn a_neighbor_protocol_name_holding_a_state_word_gives_no_state() {
    let hop = Ipv4Addr::new(10, 0, 1, 9);
    for space in ['\u{a0}', '\u{85}', '\u{2003}', '\u{3000}'] {
        let entry = format!("10.0.1.9 lladdr 0a:00:00:00:01:09 proto x{space}REACHABLE \n");
        let (fixture, kernel, eni) = resolving(&entry);
        assert_eq!(
            fixture.host.next_hops(&kernel, &eni, &[hop]),
            Err(EniError::NextHop(hop)),
            "{entry:?}"
        );
    }
}

/// The sibling without the fault: under a protocol of an ASCII name a `REACHABLE` or `PERMANENT` entry gives its
/// `lladdr`, and a `NONE` entry with no answer ends `NextHop`.
#[test]
fn a_neighbor_protocol_of_an_ascii_name_gives_the_entrys_mac_and_state() {
    let hop = Ipv4Addr::new(10, 0, 1, 9);
    let mac = [0x0a, 0, 0, 0, 1, 9];
    for state in ["REACHABLE", "PERMANENT"] {
        let entry = format!("10.0.1.9 lladdr 0a:00:00:00:01:09 {state} proto static \n");
        let (fixture, kernel, eni) = resolving(&entry);
        let hops = fixture.host.next_hops(&kernel, &eni, &[hop]);
        judge_mac_of_the_entry(&entry, mac, &hops);
        assert_eq!(hops, Ok(vec![(hop, mac)]), "{state}");
    }
    let (fixture, kernel, eni) = resolving("10.0.1.9 lladdr 0a:00:00:00:01:09 proto static \n");
    assert_eq!(
        fixture.host.next_hops(&kernel, &eni, &[hop]),
        Err(EniError::NextHop(hop))
    );
}

/// The control: a resolution that gives the MAC a protocol name spells fails [`judge_mac_of_the_entry`].
#[test]
#[should_panic(expected = "a next hop's MAC is its entry's lladdr or the hop is refused")]
fn negative_control_a_mac_taken_from_a_protocol_name_fails_the_judgment() {
    judge_mac_of_the_entry(
        "10.0.1.9 lladdr 0a:00:00:00:01:09 REACHABLE proto x\u{a0}lladdr\u{a0}02:00:00:00:00:99 \n",
        [0x0a, 0, 0, 0, 1, 9],
        &Ok(vec![(Ipv4Addr::new(10, 0, 1, 9), [2, 0, 0, 0, 0, 0x99])]),
    );
}

/// Entries between the two devices of a listing that the wait falls inside: enough that no directory read returns both devices in one batch.
const LISTING_FILLERS: usize = 8192;

/// Where the fixture's tree lies when the wait falls inside the listing: a tmpfs on Linux. Whether one listing shows a directory renamed while it runs under its old name, its new name or neither depends on the filesystem, so these cases do not follow `TMPDIR`.
const LISTING_BASE: &str = "/dev/shm";

/// Whether one listing of a directory under `base` returns a directory that is renamed while the listing runs under neither name. The directory has the shape `resolve_beside_a_second_device` gives `class/net`: two directories with `fillers` files between them in the listing, and the later-listed one is renamed once the listing has returned the earlier one.
fn a_listing_misses_a_rename_inside_it(base: &Path, fillers: usize) -> bool {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = base.join(format!(
        "listing-probe-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("ens7")).unwrap();
    for filler in 0..fillers {
        fs::write(dir.join(format!("filler{filler}")), "").unwrap();
    }
    fs::create_dir(dir.join("ens8")).unwrap();
    let names = |listing: fs::ReadDir| {
        listing.map(|entry| entry.unwrap().file_name().into_string().unwrap())
    };
    let later = names(fs::read_dir(&dir).unwrap())
        .filter(|name| name.starts_with("ens"))
        .last()
        .unwrap();
    let mut listing = names(fs::read_dir(&dir).unwrap());
    let earlier = listing.find(|name| name.starts_with("ens"));
    assert!(
        earlier.is_some() && earlier.as_ref() != Some(&later),
        "premise: the listing returns the other directory first"
    );
    fs::rename(dir.join(&later), dir.join("ens9")).unwrap();
    let missed = !listing.any(|name| name == later || name == "ens9");
    fs::remove_dir_all(&dir).unwrap();
    missed
}

/// What the second device does while the resolution waits between its listing of `class/net` and its read of that device's `address`.
#[derive(Clone, Copy, PartialEq)]
enum Meanwhile {
    /// It keeps its name.
    Stays,
    /// It takes the name `ens9`, as `ip link set ens7 name ens9` makes it.
    Renamed,
    /// It takes the name `ens9`, and a new device of another MAC takes the name it left.
    Replaced,
    /// It leaves the host, as `ip link delete` makes it.
    Removed,
}

/// Resolves the ENI once beside a second network device that carries the ENI's MAC until `meanwhile` says otherwise, and returns the result with what a resolution of the tree as the first one left it finds.
/// `class/net` lists a third device, of another MAC, ahead of the second. The read of that device's `address` waits in a FIFO, and the second device does `meanwhile` during the wait.
/// `fillers` entries that are no directories lie between the two in the listing, so with enough of them the wait falls inside the listing: the listing has returned the third device and has not yet read the entries that hold the second.
fn resolve_beside_a_second_device(
    meanwhile: Meanwhile,
    fillers: usize,
) -> [Result<(), EniError>; 2] {
    const OTHER_MAC: &str = "0A:11:22:33:44:66\n";
    let fixture = if fillers == 0 {
        Fixture::new(512)
    } else {
        assert!(
            a_listing_misses_a_rename_inside_it(Path::new(LISTING_BASE), fillers),
            "premise: a listing under {LISTING_BASE} returns a directory renamed inside it under neither name"
        );
        Fixture::under(Path::new(LISTING_BASE), 512)
    };
    let metadata = FakeMetadata::new();
    let class = fixture.host.sys.join("class/net");
    fixture.netdev("ens7", "0000:00:07.0", OTHER_MAC.trim(), 0x1003);
    for filler in 0..fillers {
        fs::write(class.join(format!("filler{filler}")), "").unwrap();
    }
    fixture.netdev("ens8", "0000:00:08.0", OTHER_MAC.trim(), 0x1003);
    let listed: Vec<String> = fs::read_dir(&class)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    let order: Vec<usize> = (0..listed.len())
        .filter(|&at| listed[at] == "ens7" || listed[at] == "ens8")
        .collect();
    let [waits, second] = order.as_slice() else {
        panic!("premise: the class lists the two added devices, not {order:?}");
    };
    assert!(
        second - waits > fillers,
        "premise: the listing holds the fillers between the two devices"
    );
    let (waits, second) = (&listed[*waits], &listed[*second]);
    fs::write(class.join(second).join("address"), "0A:11:22:33:44:55\n").unwrap();
    assert_eq!(
        fixture.host.resolve_eni(&metadata, ENI).map(drop),
        Err(EniError::Duplicate),
        "premise: the second device carries the ENI's MAC"
    );
    // The earlier-listed device's address becomes a FIFO for one read, and the staged file takes its place for the reads after it.
    let address = class.join(waits).join("address");
    let staged = fixture.root.join("staged-address");
    fs::rename(&address, &staged).unwrap();
    let path = std::ffi::CString::new(address.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: `path` is a NUL-terminated string that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let first = std::thread::scope(|scope| {
        scope.spawn(|| {
            // The open returns once the resolution has listed the class and opened this address.
            let mut fifo = fs::OpenOptions::new().write(true).open(&address).unwrap();
            match meanwhile {
                Meanwhile::Stays => {}
                Meanwhile::Renamed => fs::rename(class.join(second), class.join("ens9")).unwrap(),
                Meanwhile::Replaced => {
                    fs::rename(class.join(second), class.join("ens9")).unwrap();
                    fixture.netdev(second, "0000:00:09.0", OTHER_MAC.trim(), 0x1003);
                }
                Meanwhile::Removed => fs::remove_dir_all(class.join(second)).unwrap(),
            }
            fs::rename(&staged, &address).unwrap();
            std::io::Write::write_all(&mut fifo, OTHER_MAC.as_bytes()).unwrap();
        });
        fixture.host.resolve_eni(&metadata, ENI).map(drop)
    });
    assert_eq!(
        (class.join(second).is_dir(), class.join("ens9").is_dir()),
        (
            matches!(meanwhile, Meanwhile::Stays | Meanwhile::Replaced),
            matches!(meanwhile, Meanwhile::Renamed | Meanwhile::Replaced)
        ),
        "premise: the device did what the case names during the wait"
    );
    [first, fixture.host.resolve_eni(&metadata, ENI).map(drop)]
}

/// The ENI's permanent MAC must name exactly one network device, so a second device that carries the MAC throughout refuses the resolution although it is renamed between the listing of `class/net` and the read of its `address`. The resolution of the tree after the rename is the premise that the device still carries the MAC.
#[test]
fn a_second_device_renamed_during_the_resolution_refuses_it() {
    let [first, after] = resolve_beside_a_second_device(Meanwhile::Renamed, 0);
    assert_eq!(
        after,
        Err(EniError::Duplicate),
        "premise: the renamed device carries the ENI's MAC"
    );
    assert_eq!(
        first,
        Err(EniError::Duplicate),
        "the resolution took the ENI's device as the only one with its MAC"
    );
}

/// The ENI's permanent MAC must name exactly one network device, so a second device that carries the MAC throughout refuses the resolution although it is renamed between the listing of `class/net` and the read of its `address`, and a new device of another MAC takes its listed name before that read. No listed name then lacks an `address`. The resolution of the tree after the rename is the premise that the renamed device still carries the MAC.
#[test]
fn a_second_device_renamed_and_replaced_during_the_resolution_refuses_it() {
    let [first, after] = resolve_beside_a_second_device(Meanwhile::Replaced, 0);
    assert_eq!(
        after,
        Err(EniError::Duplicate),
        "premise: the renamed device carries the ENI's MAC"
    );
    assert_eq!(
        first,
        Err(EniError::Duplicate),
        "the resolution took the ENI's device as the only one with its MAC"
    );
}

/// The ENI's permanent MAC must name exactly one network device, so a second device that carries the MAC throughout refuses the resolution although it is renamed while `class/net` is being listed: after the listing returned its first entries and before it read the ones that hold the device. A listing that a rename overlaps can return the device under neither name, as a tmpfs and the kernel's sysfs both do on Linux 6.12, and then no listed name lacks an `address`. The resolution of the tree after the rename is the premise that the device still carries the MAC.
#[test]
fn a_second_device_renamed_during_the_listing_refuses_it() {
    let [first, after] = resolve_beside_a_second_device(Meanwhile::Renamed, LISTING_FILLERS);
    assert_eq!(
        after,
        Err(EniError::Duplicate),
        "premise: the renamed device carries the ENI's MAC"
    );
    assert_eq!(
        first,
        Err(EniError::Duplicate),
        "the resolution took the ENI's device as the only one with its MAC"
    );
}

/// The sibling without the rename: the same long listing, with the same wait in the same read, refuses.
#[test]
fn a_second_device_that_keeps_its_name_during_the_listing_refuses_it() {
    assert_eq!(
        resolve_beside_a_second_device(Meanwhile::Stays, LISTING_FILLERS),
        [Err(EniError::Duplicate), Err(EniError::Duplicate)]
    );
}

/// The sibling without the rename: the same tree, with the same wait in the same read, refuses.
#[test]
fn a_second_device_that_keeps_its_name_during_the_resolution_refuses_it() {
    assert_eq!(
        resolve_beside_a_second_device(Meanwhile::Stays, 0),
        [Err(EniError::Duplicate), Err(EniError::Duplicate)]
    );
}

/// A second device removed between the listing of `class/net` and the read of its `address` carries the MAC no longer, so the resolution lists the class again and resolves the ENI's device as the only match, as a resolution of the tree after the removal does.
#[test]
fn a_second_device_removed_during_the_resolution_leaves_the_eni_resolved() {
    assert_eq!(
        resolve_beside_a_second_device(Meanwhile::Removed, 0),
        [Ok(()), Ok(())]
    );
}

/// A name of `class/net` that two successive listings find with no `address` beneath it is no device that left the class, so it refuses nothing: the ENI's device stays the only match. The sibling is the same tree before the directory is added.
#[test]
fn a_listed_name_with_no_address_in_successive_listings_is_no_device() {
    let fixture = Fixture::new(512);
    let metadata = FakeMetadata::new();
    let resolved = fixture.host.resolve_eni(&metadata, ENI);
    assert!(
        resolved.is_ok(),
        "sibling: the tree without the directory resolves"
    );
    fs::create_dir(fixture.host.sys.join("class/net/ens7")).unwrap();
    assert_eq!(fixture.host.resolve_eni(&metadata, ENI), resolved);
}

/// One line of `proc/net/ipv6_route` for a route to `destination/prefix` through `device`.
fn v6_route_line(destination: &str, prefix: &str, device: &str) -> String {
    let zero = "0".repeat(32);
    format!(
        "{destination} {prefix} {zero} 00 {zero} 00000400 00000001 00000000 00000001 {device:>8}\n"
    )
}

/// A case of successive listings: the route table each returned, the census reads around each, and the answer
/// they should give.
type Listings<'a, T> = (&'a [&'a str], &'a [(u32, u32)], T);

/// The census reads of listings in turn, each given as the deletions before and after it, over two routes: a
/// deletion and re-add between the reads leave the route count as it was.
fn censuses(listings: &[(u32, u32)]) -> Vec<String> {
    listings
        .iter()
        .flat_map(|&(before, after)| [rt6_stats(2, before), rt6_stats(2, after)])
        .collect()
}

/// Six listings, each across a deletion.
const EVERY_LISTING_MOVED: [(u32, u32); 6] = [(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6)];

/// Makes `relative` hand each open for reading the next of `reads`, whole, then end of file: the file as the
/// kernel returned it to successive listings. Each read is its own pipe, renamed over the path once the reader
/// holds the pipe before it, so no read sees another's bytes. A read past the last finds a file of one unparsable
/// line.
fn table_reads(fixture: &Fixture, relative: &str, reads: &[&str]) -> TableReads {
    use std::io::Write as _;
    let path = fixture.root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let staged = path.with_extension("next");
    let pipe_at = |at: &std::path::Path| {
        let name = std::ffi::CString::new(at.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `name` is a NUL-terminated path that lives across the call.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    };
    pipe_at(&staged);
    fs::rename(&staged, &path).unwrap();
    let reads: Vec<String> = reads.iter().map(|read| (*read).to_owned()).collect();
    let table = path.clone();
    let feeder = std::thread::spawn(move || {
        let last = reads.len() - 1;
        for (at, read) in reads.into_iter().enumerate() {
            // A blocking open returns once the reader has opened this pipe.
            let mut pipe = fs::OpenOptions::new().write(true).open(&path).unwrap();
            if at == last {
                fs::write(&staged, PAST_THE_LAST).unwrap();
            } else {
                pipe_at(&staged);
            }
            fs::rename(&staged, &path).unwrap();
            pipe.write_all(read.as_bytes()).unwrap();
        }
    });
    TableReads { feeder, table }
}

/// The reads [`table_reads`] hands out.
struct TableReads {
    feeder: std::thread::JoinHandle<()>,
    table: std::path::PathBuf,
}

impl TableReads {
    /// Ends the reads and asserts the code under test took each of them and none past the last.
    fn all_taken(self) {
        let mut left = 0;
        while fs::read_to_string(&self.table).unwrap() != PAST_THE_LAST {
            left += 1;
        }
        self.feeder.join().unwrap();
        assert_eq!(left, 0, "reads the code left untaken");
    }
}

/// What a read past the last of [`table_reads`] returns.
const PAST_THE_LAST: &str = "read past the last\n";

/// `proc/net/rt6_stats` holding `entries` routes after `discarded` deletions.
fn rt6_stats(entries: u32, discarded: u32) -> String {
    format!("0003 0002 0000 {entries:04x} 0000 0000 {discarded:04x}\n")
}

/// Reads of the IPv6 route table that lack the ENI's default route, as the kernel lists the table when another
/// route leaves between two `read` calls of it, are not believed once `rt6_stats` counts a deletion across the
/// listing, even when two consecutive listings agree, nor when only the tables' node count moved, nor alone under a
/// still census, as the kernel has given one; two agreeing listings under a still census refuse `Management`. A
/// deletion across every listing refuses as unverifiable, and so does a table without its census.
#[test]
fn an_ipv6_default_route_a_listing_lost_to_a_deletion_still_refuses() {
    let fixture = Fixture::new(512);
    let metadata = FakeMetadata::new();
    let other = v6_route_line("20010db8000100000000000000000000", "40", "lo");
    let default = v6_route_line(&"0".repeat(32), "00", "ens6");
    let whole = format!("{other}{default}");
    let cases: [Listings<'_, EniError>; 4] = [
        // A listing lost the default route under a still census.
        (
            &[&other, &whole, &whole],
            &[(0, 0), (0, 0), (0, 0)],
            EniError::Management,
        ),
        // Two equal listings both lost the default route, each to a deletion between its reads.
        (
            &[&other, &other, &whole, &whole],
            &[(0, 1), (1, 2), (2, 2), (2, 2)],
            EniError::Management,
        ),
        (
            &[&other, &whole, &whole],
            &[(0, 1), (1, 1), (1, 1)],
            EniError::Management,
        ),
        (
            &[other.as_str(); 6],
            &EVERY_LISTING_MOVED,
            EniError::Unverifiable("ipv6_route"),
        ),
    ];
    for (at, (tables, listings, refusal)) in cases.into_iter().enumerate() {
        let censuses = censuses(listings);
        let census: Vec<&str> = censuses.iter().map(String::as_str).collect();
        let stats = table_reads(&fixture, "proc/net/rt6_stats", &census);
        let table = table_reads(&fixture, "proc/net/ipv6_route", tables);
        assert_eq!(
            fixture.host.resolve_eni(&metadata, ENI),
            Err(refusal),
            "case {at}"
        );
        table.all_taken();
        stats.all_taken();
    }
    let stats = table_reads(&fixture, "proc/net/rt6_stats", &NODES_MOVED);
    let table = table_reads(
        &fixture,
        "proc/net/ipv6_route",
        &[&other, &other, &whole, &whole],
    );
    assert_eq!(
        fixture.host.resolve_eni(&metadata, ENI),
        Err(EniError::Management),
        "a listing across a change to the tables' nodes"
    );
    table.all_taken();
    stats.all_taken();
    fixture.file("proc/net/ipv6_route", &whole);
    fs::remove_file(fixture.root.join("proc/net/rt6_stats")).unwrap();
    assert_eq!(
        fixture.host.resolve_eni(&metadata, ENI),
        Err(EniError::Unverifiable("ipv6_route"))
    );
    fixture.file("proc/net/rt6_stats", "0001 0001 0000 0001\n");
    assert_eq!(
        fixture.host.resolve_eni(&metadata, ENI),
        Err(EniError::Unverifiable("ipv6_route"))
    );
}

/// The capture settles the IPv6 address table as it does the route table. A second link-local address of the ENI
/// that one listing lacks, as the kernel lists the table when another device's address in the same bucket leaves
/// between two `read` calls, still refuses: under a still census the next two listings show it, and listings across
/// a census that moved are not believed even when two agree. A healthy device whose one address a listing shows
/// twice, as an address that arrives in its bucket makes it, passes once two listings agree, and so does a table
/// that two listings under a still census agree lacks the second address. A change across every listing refuses as
/// unverifiable, and so does a table without its census.
#[test]
fn a_second_link_local_address_a_listing_lost_to_a_deletion_still_refuses_the_capture() {
    let fixture = Fixture::new(512);
    let kernel = FakeKernel::new(&fixture.host);
    let line = |address: &str, device: &str| format!("{address} 03 40 20 80 {device:>8}\n");
    let other = "00000000000000000000000000000001 01 80 10 80       lo\n";
    let own = line(&format!("fe80{}5", "0".repeat(27)), "ens6");
    let second = line(&format!("fe80{}1", "0".repeat(27)), "ens6");
    let lost = format!("{other}{own}");
    let whole = format!("{other}{own}{second}");
    let twice = format!("{other}{own}{own}");
    const IPV6: Result<(), EniError> = Err(EniError::Unverifiable("ipv6"));
    const ADDRESSES: Result<(), EniError> = Err(EniError::Unverifiable("addresses"));
    // A capture that passes the address table takes its IPv6 routes from `ip`, so it reads no further census.
    let cases: [Listings<'_, Result<(), EniError>>; 6] = [
        (&[&lost, &whole, &whole], &[(0, 0), (0, 0), (0, 0)], IPV6),
        (
            &[&lost, &lost, &whole, &whole],
            &[(0, 1), (1, 2), (2, 2), (2, 2)],
            IPV6,
        ),
        (&[&lost, &whole, &whole], &[(0, 1), (1, 1), (1, 1)], IPV6),
        (&[&twice, &lost, &lost], &[(0, 1), (1, 1), (1, 1)], Ok(())),
        (&[&lost, &lost], &[(0, 0), (0, 0)], Ok(())),
        (&[lost.as_str(); 6], &EVERY_LISTING_MOVED, ADDRESSES),
    ];
    for (at, (tables, listings, answer)) in cases.into_iter().enumerate() {
        let censuses = censuses(listings);
        let census: Vec<&str> = censuses.iter().map(String::as_str).collect();
        let stats = table_reads(&fixture, "proc/net/rt6_stats", &census);
        let table = table_reads(&fixture, "proc/net/if_inet6", tables);
        assert_eq!(
            fixture.host.net_state(&kernel, "ens6").map(drop),
            answer,
            "case {at}"
        );
        table.all_taken();
        stats.all_taken();
    }
    let stats = table_reads(&fixture, "proc/net/rt6_stats", &NODES_MOVED);
    let table = table_reads(
        &fixture,
        "proc/net/if_inet6",
        &[&lost, &lost, &whole, &whole],
    );
    assert_eq!(
        fixture.host.net_state(&kernel, "ens6").map(drop),
        IPV6,
        "a listing across a change to the tables' nodes"
    );
    table.all_taken();
    stats.all_taken();
    fixture.file("proc/net/if_inet6", &lost);
    fs::remove_file(fixture.root.join("proc/net/rt6_stats")).unwrap();
    assert_eq!(fixture.host.net_state(&kernel, "ens6").map(drop), ADDRESSES);
}

/// Census reads around four listings, as the kernel gave them around a listing that lost a route: the first moved
/// only `fib_nodes`, the route and deletion counts held, and the others moved nothing.
const NODES_MOVED: [&str; 8] = [
    "0034 001c 0001 001d 0000 0000 0319\n",
    "0036 001c 0001 001d 0000 0000 0319\n",
    "0036 001c 0001 001d 0000 0000 0319\n",
    "0036 001c 0001 001d 0000 0000 0319\n",
    "0036 001c 0001 001d 0000 0000 0319\n",
    "0036 001c 0001 001d 0000 0000 0319\n",
    "0036 001c 0001 001d 0000 0000 0319\n",
    "0036 001c 0001 001d 0000 0000 0319\n",
];

/// `ena_function` returns a pass over the device only when `proc/net/dev` lists its name after the route tables, so a host whose listing cannot be read refuses the resolution as `Unverifiable("route")`. The sibling is the same tree with its listing in place.
#[test]
fn a_host_without_a_device_listing_refuses_the_resolution() {
    let fixture = Fixture::new(512);
    let metadata = FakeMetadata::new();
    assert!(
        fixture.host.resolve_eni(&metadata, ENI).is_ok(),
        "sibling: the tree with its device listing resolves"
    );
    fs::remove_file(fixture.host.proc.join("net/dev")).unwrap();
    assert_eq!(
        fixture.host.resolve_eni(&metadata, ENI).map(drop),
        Err(EniError::Unverifiable("route"))
    );
}

/// Resolves the ENI, which carries the main IPv4 table's default route, once while the read of `proc/net/route` waits in a FIFO, and returns the result with what a resolution of the tree as the first one left it finds.
/// With `renamed`, the ENI's device takes the name `ens9` during the wait, as `ip link set ens6 name ens9` makes it, and the table the read then returns lists its routes under that name, as the kernel prints them.
fn resolve_a_managing_eni_beside_the_route_read(renamed: bool) -> [Result<(), EniError>; 2] {
    let fixture = Fixture::new(512);
    let metadata = FakeMetadata::new();
    let class = fixture.host.sys.join("class/net");
    let table = |name: &str| {
        format!("Iface\tDestination\tGateway\tFlags\n{name}\t00000000\t0101000A\t0003\n")
    };
    let route = fixture.root.join("proc/net/route");
    fs::write(&route, table("ens6")).unwrap();
    assert_eq!(
        fixture.host.resolve_eni(&metadata, ENI).map(drop),
        Err(EniError::Management),
        "premise: the ENI carries the default route"
    );
    fs::remove_file(&route).unwrap();
    let path = std::ffi::CString::new(route.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: `path` is a NUL-terminated string that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let name = if renamed { "ens9" } else { "ens6" };
    let first = std::thread::scope(|scope| {
        scope.spawn(|| {
            // The open returns once the resolution has read the device's sysfs entries and opened the route table.
            let mut fifo = fs::OpenOptions::new().write(true).open(&route).unwrap();
            // A rename changes the device's name in the kernel first, where the route tables and `proc/net/dev`
            // read it; the sysfs entry and the uevent follow, after this resolution.
            if renamed {
                fs::write(
                    fixture.host.proc.join("net/dev"),
                    format!(
                        "{NET_DEV_HEADER}{}{}",
                        net_dev_line("ens5"),
                        net_dev_line("ens9")
                    ),
                )
                .unwrap();
            }
            fs::remove_file(&route).unwrap();
            fs::write(&route, table(name)).unwrap();
            std::io::Write::write_all(&mut fifo, table(name).as_bytes()).unwrap();
        });
        fixture.host.resolve_eni(&metadata, ENI).map(drop)
    });
    if renamed {
        fs::rename(class.join("ens6"), class.join("ens9")).unwrap();
        fs::write(fixture.host.sys.join("kernel/uevent_seqnum"), "7066\n").unwrap();
    }
    assert_eq!(
        (class.join("ens6").is_dir(), class.join("ens9").is_dir()),
        (!renamed, renamed),
        "premise: the device did what the case names during the wait"
    );
    [first, fixture.host.resolve_eni(&metadata, ENI).map(drop)]
}

/// `ena_function` refuses a device that carries the default route, so an ENI that carries it throughout refuses the resolution although the kernel renames it between the read of its sysfs entries and the read of `proc/net/route`, and renames its sysfs entry and sends the uevent only after the resolution: `proc/net/dev` no longer lists the name the resolution searched for, on every pass. The resolution of the tree after the rename is the premise that the device still carries the route.
#[test]
fn an_eni_renamed_before_the_route_read_refuses_its_default_route() {
    let [first, after] = resolve_a_managing_eni_beside_the_route_read(true);
    assert_eq!(
        after,
        Err(EniError::Management),
        "premise: the renamed device carries the default route"
    );
    assert_eq!(
        first,
        Err(EniError::Unverifiable("route")),
        "the resolution read the route table under the name the device had left"
    );
}

/// `ena_function` returns a pass over the device only under a still uevent counter, so a host whose counter cannot be read refuses the resolution as `Unverifiable("route")`. The sibling is the same tree with its counter in place.
#[test]
fn a_host_without_a_uevent_counter_refuses_the_resolution() {
    let fixture = Fixture::new(512);
    let metadata = FakeMetadata::new();
    assert!(
        fixture.host.resolve_eni(&metadata, ENI).is_ok(),
        "sibling: the tree with its counter resolves"
    );
    fs::remove_file(fixture.host.sys.join("kernel/uevent_seqnum")).unwrap();
    assert_eq!(
        fixture.host.resolve_eni(&metadata, ENI).map(drop),
        Err(EniError::Unverifiable("route"))
    );
}

/// The sibling without the rename: the same tree, with the same wait in the same read, refuses.
#[test]
fn an_eni_that_keeps_its_name_before_the_route_read_refuses_its_default_route() {
    assert_eq!(
        resolve_a_managing_eni_beside_the_route_read(false),
        [Err(EniError::Management), Err(EniError::Management)]
    );
}

/// Reads the ENI's network state, the device holding a global IPv6 address beside its link-local one, once while the read of `proc/net/if_inet6` waits in a FIFO, and returns the result with what a read of the tree as the first one left it finds.
/// The read settles the table by two listings that agree, so each of its first two listings is its own FIFO and the wait is in the second.
/// With `renamed`, the device takes the name `ens9` during the first listing and takes `ens6` back before the second ends, as `ip link set ens6 name ens9` and its reverse make it, and both listings show its addresses under `ens9`, as the kernel prints them while the device holds that name. The fake `ip` prints the device's link line and no IPv6 route, so the address table alone shows the global address.
fn net_state_beside_a_rename_during_the_address_read(renamed: bool) -> [Result<(), EniError>; 2] {
    let fixture = Fixture::new(512);
    let kernel = FakeKernel::new(&fixture.host);
    let class = fixture.host.sys.join("class/net");
    let table = |name: &str| {
        format!(
            "fe800000000000000000000000000005 03 40 20 80     {name}\n\
             26001f18000000000000000000000005 03 80 00 80     {name}\n"
        )
    };
    let addresses = fixture.root.join("proc/net/if_inet6");
    fs::write(&addresses, table("ens6")).unwrap();
    assert_eq!(
        fixture.host.net_state(&kernel, "ens6").map(drop),
        Err(EniError::Unverifiable("ipv6")),
        "premise: the device's global IPv6 address refuses"
    );
    fs::remove_file(&addresses).unwrap();
    let staged = addresses.with_extension("next");
    let pipe_at = |at: &std::path::Path| {
        let path = std::ffi::CString::new(at.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `path` is a NUL-terminated string that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    };
    pipe_at(&addresses);
    let name = if renamed { "ens9" } else { "ens6" };
    let first = std::thread::scope(|scope| {
        scope.spawn(|| {
            use std::io::Write as _;
            // The open returns once the read has taken the device's flags and MTU and opened the address table.
            let mut listing = fs::OpenOptions::new().write(true).open(&addresses).unwrap();
            let counter = fixture.host.sys.join("kernel/uevent_seqnum");
            if renamed {
                fs::rename(class.join("ens6"), class.join("ens9")).unwrap();
                // The kernel sends a uevent for each rename, which moves the host's uevent counter by one.
                fs::write(&counter, "7066\n").unwrap();
            }
            // The second listing's pipe takes the path before the first listing ends.
            pipe_at(&staged);
            fs::rename(&staged, &addresses).unwrap();
            listing.write_all(table(name).as_bytes()).unwrap();
            drop(listing);
            // The open returns once the read, or the drain below, has opened the second listing.
            let mut listing = fs::OpenOptions::new().write(true).open(&addresses).unwrap();
            fs::write(&staged, table("ens6")).unwrap();
            fs::rename(&staged, &addresses).unwrap();
            listing.write_all(table(name).as_bytes()).unwrap();
            if renamed {
                fs::rename(class.join("ens9"), class.join("ens6")).unwrap();
                fs::write(&counter, "7067\n").unwrap();
            }
        });
        let first = fixture.host.net_state(&kernel, "ens6").map(drop);
        // A read that took fewer than two listings leaves a pipe at the path; draining it ends the wait.
        while fs::read_to_string(&addresses).unwrap() != table("ens6") {}
        first
    });
    assert!(
        class.join("ens6").is_dir() && !class.join("ens9").exists(),
        "premise: the device holds its first name once the wait ends"
    );
    [first, fixture.host.net_state(&kernel, "ens6").map(drop)]
}

/// `net_state` refuses while the device holds an IPv6 address other than one link-local address, so a device that holds a global address throughout refuses although it is renamed away and back while its addresses are read. The address table lists the device under the name it has when the table is read, so the read cannot name the address; it refuses `Unverifiable("name")` because the host's uevent counter moved across it. The read of the tree after the rename is the premise that the device still holds the address.
#[test]
fn a_device_renamed_away_and_back_during_the_address_read_refuses_its_global_address() {
    let [first, after] = net_state_beside_a_rename_during_the_address_read(true);
    assert_eq!(
        after,
        Err(EniError::Unverifiable("ipv6")),
        "premise: the device holds its global address"
    );
    assert_eq!(
        first,
        Err(EniError::Unverifiable("name")),
        "the read matched the address table by the name the device had left"
    );
}

/// `net_state` returns a state only under a still uevent counter, so a host whose counter cannot be read, or holds no number, refuses `Unverifiable("name")`. The sibling is the same tree with its counter in place.
#[test]
fn a_host_without_a_uevent_counter_refuses_the_network_state() {
    let fixture = Fixture::new(512);
    let kernel = FakeKernel::new(&fixture.host);
    let counter = fixture.host.sys.join("kernel/uevent_seqnum");
    assert!(
        fixture.host.net_state(&kernel, "ens6").is_ok(),
        "sibling: the tree with its counter passes"
    );
    fs::write(&counter, "many\n").unwrap();
    assert_eq!(
        fixture.host.net_state(&kernel, "ens6").map(drop),
        Err(EniError::Unverifiable("name"))
    );
    fs::remove_file(&counter).unwrap();
    assert_eq!(
        fixture.host.net_state(&kernel, "ens6").map(drop),
        Err(EniError::Unverifiable("name"))
    );
}

/// The sibling without the rename: the same tree, with the same wait in the same read, refuses.
#[test]
fn a_device_that_keeps_its_name_during_the_address_read_refuses_its_global_address() {
    assert_eq!(
        net_state_beside_a_rename_during_the_address_read(false),
        [
            Err(EniError::Unverifiable("ipv6")),
            Err(EniError::Unverifiable("ipv6"))
        ]
    );
}

/// Resolves the ENI once while `during`, the work the resolution runs on the located device before it reads that
/// device's function, finds the names as the case leaves them, and returns the device and function the resolution
/// gave with what a resolution of the tree after it gives. A second ENA function, `0000:00:07.0`, carries another
/// MAC as `ens7` throughout. With `swapped`, the ENI's device takes the name `ens9` and the second device the
/// name `ens6` during that work, as `ip link set ens6 name ens9` and then `ip link set ens7 name ens6` make them:
/// each rename changes the name in `proc/net/dev` and in sysfs and sends one uevent, and both end before the
/// resolution reads the function.
fn resolve_beside_a_name_swap(swapped: bool) -> [Result<(String, String), EniError>; 2] {
    let fixture = Fixture::new(512);
    let metadata = FakeMetadata::new();
    let class = fixture.host.sys.join("class/net");
    fixture.netdev("ens7", "0000:00:07.0", "0a:11:22:33:44:66", 0x1003);
    let named = |eni: super::eni::Eni| (eni.netdev, eni.bdf);
    let first = fixture
        .host
        .resolve_eni_while(&SysfsKernel, &metadata, ENI, None, |_| {
            if swapped {
                let listing = fixture.host.proc.join("net/dev");
                let counter = fixture.host.sys.join("kernel/uevent_seqnum");
                rename_listed(&listing, "ens6", "ens9");
                fs::rename(class.join("ens6"), class.join("ens9")).unwrap();
                fs::write(&counter, "7066\n").unwrap();
                rename_listed(&listing, "ens7", "ens6");
                fs::rename(class.join("ens7"), class.join("ens6")).unwrap();
                fs::write(&counter, "7067\n").unwrap();
            }
        })
        .map(|(eni, (), _)| named(eni));
    [first, fixture.host.resolve_eni(&metadata, ENI).map(named)]
}

/// The resolution gives the function of the one device that carries the ENI's permanent MAC, so it refuses when a
/// device that never carried it takes the ENI device's name between the listing that located the ENI's device and
/// the read of its function. The resolution of the tree after the swap is the premise that the MAC still names the
/// ENI's own function.
#[test]
fn a_device_that_takes_the_eni_name_during_the_resolution_does_not_lend_its_function() {
    let [first, after] = resolve_beside_a_name_swap(true);
    assert_eq!(
        after,
        Ok(("ens9".to_owned(), ENI_BDF.to_owned())),
        "premise: the ENI's MAC names its own function under the new name"
    );
    assert_eq!(
        first,
        Err(EniError::Unverifiable("class/net")),
        "the resolution gave a function read under a name that no longer carries the ENI's MAC"
    );
}

/// The function the resolution gives is that of a device that carries the ENI's MAC. Here the second device holds
/// the ENI device's name through the whole read of the function, and the ENI's device takes the name back before
/// the MAC is read under it again: the names swap during the work on the located device, as in the case above, and
/// swap back once the function's read has taken its last reading of the uevent counter. The name then carries the
/// ENI's MAC, and the function read under it is the second device's. The resolution refuses.
///
/// Two FIFOs time the second swap. The function's read opens the second device's `addr_assign_type` after its
/// first reading of the counter, and the counter becomes a FIFO there, so its next reading, the read's last, waits
/// for the swap back.
#[test]
fn a_device_that_holds_the_eni_name_only_while_the_function_is_read_does_not_lend_its_function() {
    use std::io::Write;
    let fixture = Fixture::new(512);
    let metadata = FakeMetadata::new();
    let class = fixture.host.sys.join("class/net");
    let listing = fixture.host.proc.join("net/dev");
    let counter = fixture.host.sys.join("kernel/uevent_seqnum");
    let assigned = class.join("ens6/addr_assign_type");
    fixture.netdev("ens7", "0000:00:07.0", "0a:11:22:33:44:66", 0x1003);
    let swap = |from: &str, to: &str| {
        rename_listed(&listing, from, to);
        fs::rename(class.join(from), class.join(to)).unwrap();
    };
    let sink = |fifo: &Path| fs::OpenOptions::new().write(true).open(fifo).unwrap();
    let back = std::thread::scope(|scope| {
        let renamer = std::cell::RefCell::new(None);
        let resolved = fixture
            .host
            .resolve_eni_while(&SysfsKernel, &metadata, ENI, None, |_| {
                swap("ens6", "ens9");
                swap("ens7", "ens6");
                fs::write(&counter, "7067\n").unwrap();
                make_fifo(&assigned);
                let spawned = scope.spawn(|| {
                    let mut pass = sink(&assigned);
                    make_fifo(&counter);
                    fs::remove_file(&assigned).unwrap();
                    fs::write(&assigned, "0\n").unwrap();
                    let _sent = pass.write_all(b"0\n");
                    drop(pass);
                    let mut last = sink(&counter);
                    swap("ens6", "ens7");
                    swap("ens9", "ens6");
                    fs::remove_file(&counter).unwrap();
                    fs::write(&counter, "7069\n").unwrap();
                    let _sent = last.write_all(b"7067\n");
                });
                renamer.replace(Some(spawned));
            })
            .map(|(eni, (), _)| (eni.netdev, eni.bdf));
        // A resolution that ended before either read releases the writer
        // here, with one read end of each FIFO held until the writer has ended.
        hold_readers(&[&assigned, &counter], || {
            (renamer.borrow().as_ref()).is_none_or(|spawned| spawned.is_finished())
        });
        resolved
    });
    assert_eq!(
        fixture
            .host
            .resolve_eni(&metadata, ENI)
            .map(|eni| (eni.netdev, eni.bdf)),
        Ok(("ens6".to_owned(), ENI_BDF.to_owned())),
        "premise: the names swapped back, and the MAC names the ENI's own function"
    );
    assert_eq!(
        back,
        Err(EniError::Unverifiable("class/net")),
        "the resolution gave a function read while another device held the name"
    );
}

/// The sibling without the swap: the same tree and the same second device resolve the ENI's own function.
#[test]
fn a_second_device_that_keeps_its_name_during_the_resolution_leaves_the_eni_function() {
    let own = Ok(("ens6".to_owned(), ENI_BDF.to_owned()));
    assert_eq!(resolve_beside_a_name_swap(false), [own.clone(), own]);
}

/// The addresses captured for `ens6` when `ip` prints one address line whose
/// address word, the word after `inet`, is `word`.
fn captured(word: &str) -> Result<Vec<String>, EniError> {
    let fixture = Fixture::new(512);
    let kernel = FakeKernel::new(&fixture.host);
    kernel.outputs.borrow_mut().insert(
        "ip -4 -o addr show dev ens6".into(),
        Some(format!(
            "3: ens6    inet {word} brd 10.0.1.255 scope global ens6\n"
        )),
    );
    let host: &Host = &fixture.host;
    host.net_state(&kernel, "ens6").map(|state| state.addresses)
}

/// Release replays each address through `ip -batch`, where `#` starts a
/// comment and an opening quote starts a quoted word, so the capture refuses
/// an address whose address word holds a `#` or opens with a quote.
#[test]
fn an_unreplayable_captured_address_word_refuses() {
    for word in [
        "10.0.1.5/24#x",
        "#10.0.1.5/24",
        "\"10.0.1.5/24",
        "'10.0.1.5/24",
    ] {
        assert_eq!(
            captured(word),
            Err(EniError::Unverifiable("addresses")),
            "the capture must refuse the address word {word:?}"
        );
    }
}

/// An address of ordinary words is captured as the specification the bind
/// records and release replays: the address and prefix, then its `brd`.
#[test]
fn an_ordinary_captured_address_is_recorded() {
    assert_eq!(
        captured("10.0.1.5/24"),
        Ok(vec!["10.0.1.5/24 brd 10.0.1.255".to_owned()])
    );
}

/// The metadata path of `field` of the dataplane interface.
fn path(field: &str) -> String {
    format!("network/interfaces/macs/0a:11:22:33:44:55/{field}")
}

/// The fixture's metadata with the dataplane interface at device number
/// `device` and its `network-card` entry absent, or holding `card`.
fn metadata(device: u32, card: Option<u32>) -> FakeMetadata {
    let metadata = FakeMetadata::new();
    {
        let mut paths = metadata.0.lock().unwrap();
        paths.insert(path("device-number"), device.to_string());
        match card {
            Some(card) => paths.insert(path("network-card"), card.to_string()),
            None => paths.remove(&path("network-card")),
        };
    }
    metadata
}

/// What the fixture's unchanged metadata lets a resolution see, for a
/// prefetched resolution of the same interface.
fn sighting(fixture: &Fixture) -> Sighting {
    let (_, (), seen) = fixture
        .host
        .resolve_eni_while(&SysfsKernel, &FakeMetadata::new(), ENI, None, |_| ())
        .unwrap();
    seen
}

/// The dataplane interface resolved through `metadata`, ordinarily and then
/// with every request prefetched.
fn both(metadata: &FakeMetadata) -> [Result<Eni, EniError>; 2] {
    let fixture = Fixture::new(512);
    let seen = sighting(&fixture);
    let ordinary = fixture.host.resolve_eni(metadata, ENI);
    let prefetched = fixture
        .host
        .resolve_eni_while(&SysfsKernel, metadata, ENI, Some(&seen), |_| ())
        .map(|(eni, (), _)| eni);
    [ordinary, prefetched]
}

/// A missing `network-card` entry reads as card 0, so an interface at device
/// number 0 without the entry is the instance's primary interface and
/// refuses, in an ordinary resolution and in a prefetched one.
#[test]
fn device_zero_with_no_network_card_entry_is_refused_as_the_primary_interface() {
    for (resolved, how) in both(&metadata(0, None))
        .into_iter()
        .zip(["ordinary", "prefetched"])
    {
        assert_eq!(
            resolved.map(|eni| (eni.device_number, eni.network_card)),
            Err(EniError::Primary),
            "{how}: device number 0 on the card a missing entry reads as, card 0"
        );
    }
}

/// A missing `network-card` entry reads as card 0: an interface at device
/// number 1 without the entry resolves, on card 0, in an ordinary resolution
/// and in a prefetched one.
#[test]
fn device_one_with_no_network_card_entry_resolves_on_card_zero() {
    for (resolved, how) in both(&metadata(1, None))
        .into_iter()
        .zip(["ordinary", "prefetched"])
    {
        assert_eq!(
            resolved.map(|eni| (eni.device_number, eni.network_card)),
            Ok((1, 0)),
            "{how}: a missing entry reads as card 0"
        );
    }
}

/// Device number 0 on an explicit card 1 resolves, so the refusal of device
/// number 0 without a `network-card` entry comes from the card the missing
/// entry reads as.
#[test]
fn device_zero_on_an_explicit_card_one_resolves() {
    for (resolved, how) in both(&metadata(0, Some(1)))
        .into_iter()
        .zip(["ordinary", "prefetched"])
    {
        assert_eq!(
            resolved.map(|eni| (eni.device_number, eni.network_card)),
            Ok((0, 1)),
            "{how}"
        );
    }
}

/// A MAC other than the ENI's.
const OTHER_MAC: &str = "0a:11:22:33:44:99";

/// The fixture host with a second network device `other` at interface index 9 under [`OTHER_MAC`], holding the
/// address 10.9.0.2/24 and its prefix route, which the host's complete route listing prints. With `stacked`, the
/// device is stacked on `ens6`: sysfs links the two as the kernel links an upper device and its lower one.
fn host_with(other: &str, stacked: bool) -> (Fixture, FakeKernel) {
    let fixture = Fixture::new(512);
    let net = fixture.host.sys.join("class/net");
    fixture.file(
        &format!("sys/class/net/{other}/address"),
        &format!("{OTHER_MAC}\n"),
    );
    fixture.file(&format!("sys/class/net/{other}/ifindex"), "9\n");
    if stacked {
        std::os::unix::fs::symlink(
            format!("../{other}"),
            net.join("ens6").join(format!("upper_{other}")),
        )
        .unwrap();
        std::os::unix::fs::symlink("../ens6", net.join(other).join("lower_ens6")).unwrap();
    }
    let kernel = FakeKernel::new(&fixture.host);
    kernel.outputs.borrow_mut().insert(
        "ip -4 -o route show table all".into(),
        Some(format!(
            "10.0.1.0/24 dev ens6 proto kernel scope link src 10.0.1.5 metric 1003\n\
             10.9.0.0/24 dev {other} proto kernel scope link src 10.9.0.2\n"
        )),
    );
    (fixture, kernel)
}

/// The capture of `ens6` on [`host_with`].
fn captured_with(other: &str, stacked: bool) -> Result<NetState, EniError> {
    let (fixture, kernel) = host_with(other, stacked);
    let host: &Host = &fixture.host;
    host.net_state(&kernel, "ens6")
}

/// Removing the ENI's device also removes any macvlan, VLAN and VXLAN devices stacked on it.
/// Release replays the state of the ENI's device alone.
/// The capture refuses with `"upper"` while sysfs shows an upper device on the ENI's device.
#[test]
fn the_capture_refuses_a_device_another_device_is_stacked_on() {
    let uppers = ["mv0", "ens6.5", "vxlan7"];
    for upper in uppers {
        let (fixture, _) = host_with(upper, true);
        assert_eq!(
            fixture
                .host
                .resolve_eni(&FakeMetadata::new(), ENI)
                .map(|eni| eni.netdev),
            Ok("ens6".to_owned()),
            "premise: the resolution passes a stacked device under another MAC"
        );
    }
    for upper in uppers {
        assert_eq!(
            captured_with(upper, true),
            Err(EniError::Unverifiable("upper")),
            "ens6 under the upper device {upper}, which the bind removes while release replays ens6 alone"
        );
    }
}

/// The same second device with no link to the ENI's device stays when the function leaves `ena`, with its
/// route, so the capture admits the ENI's device and records its own state alone.
#[test]
fn the_capture_admits_a_device_beside_an_unrelated_device() {
    let alone = {
        let fixture = Fixture::new(512);
        let kernel = FakeKernel::new(&fixture.host);
        let host: &Host = &fixture.host;
        host.net_state(&kernel, "ens6")
    };
    assert!(alone.is_ok(), "premise: the fixture's device is admitted");
    for other in ["mv0", "ens6.5", "vxlan7"] {
        assert_eq!(captured_with(other, false), alone, "{other}");
    }
}

const ADDRESS: &str = "3: ens6    inet 10.0.1.5/24 brd 10.0.1.255 scope global ens6\\       valid_lft forever preferred_lft forever\n";
const ADDRESS_METRIC_7: &str = "3: ens6    inet 10.0.1.5/24 metric 7 brd 10.0.1.255 scope global ens6\\       valid_lft forever preferred_lft forever\n";
/// An address of `ens6` whose network holds no gateway other than itself.
const ADDRESS_APART: &str = "3: ens6    inet 10.0.9.5/24 brd 10.0.9.255 scope global ens6\\       valid_lft forever preferred_lft forever\n";

/// The routes captured for `ens6` when `ip` lists `addresses` and, by device,
/// `routes`.
fn captured_routes(addresses: &str, routes: &str) -> Result<Vec<String>, EniError> {
    captured_state(&[(ADDRESSES, addresses), (ROUTES, routes)]).map(|state| state.routes)
}

/// The capture admits a gateway route only when an address or a route that
/// release replays first reaches its gateway. Release assigns the addresses,
/// and the kernel derives a link-scope prefix route for the first address of
/// each network. Release then replays the recorded routes as `route replace`:
/// host scope first, then link scope and every route with no gateway, then
/// the rest, each group in listed order. A `route replace` writes over the
/// route under its key, which is the destination, the type of service and
/// the metric, and neither the gateway nor the type, and the kernel takes a
/// gateway only through a unicast route of a nearer scope that is at least
/// `link`. A recorded route under the key of an address's prefix route
/// therefore replaces that prefix route when it is replayed, and the kernel
/// refuses a gateway route replayed after it whose gateway only that prefix
/// route reached; `ip -batch` stops there and the release fails.
///
/// In each state the gateway 10.0.1.1 of the route to 10.0.2.0/24 is reached
/// only through the prefix route the kernel derives from 10.0.1.5/24, and a
/// recorded route under that prefix route's key is replayed first: a gateway
/// route listed before it, a route with no gateway at scope site, a
/// multicast route, and a gateway route under the metric the address gives
/// its prefix route. The replay of the route to 10.0.2.0/24 finds no unicast
/// route of scope link over its gateway, so the capture must refuse the
/// state.
#[test]
fn the_capture_refuses_a_gateway_whose_prefix_route_an_earlier_replayed_route_replaces() {
    let states = [
        (
            ADDRESS,
            "10.0.1.0/24 via 10.0.1.1\n10.0.2.0/24 via 10.0.1.1\n",
        ),
        (
            ADDRESS,
            "10.0.1.0/24 scope site\n10.0.2.0/24 via 10.0.1.1\n",
        ),
        (
            ADDRESS,
            "multicast 10.0.1.0/24 scope link\n10.0.2.0/24 via 10.0.1.1\n",
        ),
        (
            ADDRESS_METRIC_7,
            "10.0.1.0/24 via 10.0.1.1 metric 7\n10.0.2.0/24 via 10.0.1.1\n",
        ),
    ];
    let admitted: Vec<&str> = states
        .into_iter()
        .filter(|(addresses, routes)| {
            captured_routes(addresses, routes) != Err(EniError::Unverifiable("routes"))
        })
        .map(|(_, routes)| routes)
        .collect();
    assert!(admitted.is_empty(), "the capture admitted {admitted:#?}");
}

/// The states beside those, whose replay the kernel takes: the prefix route
/// stands, or a unicast route of scope link stands in its place, when the
/// gateway route is replayed.
#[test]
fn the_capture_admits_a_gateway_whose_prefix_route_stands_at_its_replay() {
    for (addresses, routes) in [
        // The kernel's own prefix route is listed; its replay writes the same route.
        (
            ADDRESS,
            "10.0.1.0/24 proto kernel scope link src 10.0.1.5\n10.0.2.0/24 via 10.0.1.1\n",
        ),
        // No route stands under the prefix route's key.
        (ADDRESS, "10.0.2.0/24 via 10.0.1.1\n"),
        // The route under the key is itself the gateway route: the kernel resolves its gateway before it
        // replaces the prefix route.
        (ADDRESS, "10.0.1.0/24 via 10.0.1.1\n"),
        // The route under the key is replayed after the gateway route that needs the prefix route.
        (
            ADDRESS,
            "10.0.0.0/24 via 10.0.1.1\n10.0.1.0/24 via 10.0.1.1\n",
        ),
        // A route to the same destination under another metric or type of service leaves the prefix route.
        (
            ADDRESS,
            "10.0.1.0/24 via 10.0.1.1 metric 5\n10.0.2.0/24 via 10.0.1.1\n",
        ),
        (
            ADDRESS,
            "10.0.1.0/24 tos 0x10 via 10.0.1.1\n10.0.2.0/24 via 10.0.1.1\n",
        ),
        (
            ADDRESS_METRIC_7,
            "10.0.1.0/24 via 10.0.1.1\n10.0.2.0/24 via 10.0.1.1\n",
        ),
    ] {
        assert_eq!(
            captured_routes(addresses, routes),
            Ok(listed(routes)),
            "{routes:?}"
        );
    }
}

/// The kernel looks a gateway up among the device's routes with no type of
/// service at scope link or nearer. Of those that hold the gateway, the
/// route with the longest prefix decides, and of several with that prefix
/// the one with the lowest metric: the kernel refuses the gateway when that
/// route is multicast. Release replays a multicast route of scope link or
/// host before every gateway route, so the capture must refuse each state
/// in which the lookup of 10.0.1.1 returns a multicast route: one under a
/// longer prefix than the prefix route of 10.0.1.5/24, with that prefix
/// route listed or not, listed before or after the gateway route, at scope
/// host, and under another metric; one of the prefix route's own network
/// under a lower metric than the address gives the prefix route; and one
/// beside a unicast route of scope link, of its network under a lower
/// metric, or under a longer prefix.
#[test]
fn the_capture_refuses_a_gateway_whose_lookup_returns_a_multicast_route() {
    let states = [
        (
            ADDRESS,
            "10.0.1.0/24 proto kernel scope link src 10.0.1.5\nmulticast 10.0.1.0/28 scope link\n10.0.2.0/24 via 10.0.1.1\n",
        ),
        (
            ADDRESS,
            "multicast 10.0.1.0/28 scope link\n10.0.2.0/24 via 10.0.1.1\n",
        ),
        (
            ADDRESS,
            "10.0.2.0/24 via 10.0.1.1\nmulticast 10.0.1.0/28 scope link\n",
        ),
        (
            ADDRESS,
            "multicast 10.0.1.0/28 scope host\n10.0.2.0/24 via 10.0.1.1\n",
        ),
        (
            ADDRESS,
            "multicast 10.0.1.0/28 scope link metric 50\n10.0.2.0/24 via 10.0.1.1\n",
        ),
        (
            ADDRESS_METRIC_7,
            "multicast 10.0.1.0/24 scope link\n10.0.2.0/24 via 10.0.1.1\n",
        ),
        (
            ADDRESS_APART,
            "10.0.1.0/28 scope link metric 10\nmulticast 10.0.1.0/28 scope link metric 5\n10.0.2.0/24 via 10.0.1.1\n",
        ),
        (
            ADDRESS_APART,
            "10.0.1.0/24 scope link\nmulticast 10.0.1.0/28 scope link\n10.0.2.0/24 via 10.0.1.1\n",
        ),
    ];
    let admitted: Vec<&str> = states
        .into_iter()
        .filter(|(addresses, routes)| {
            captured_routes(addresses, routes) != Err(EniError::Unverifiable("routes"))
        })
        .map(|(_, routes)| routes)
        .collect();
    assert!(admitted.is_empty(), "the capture admitted {admitted:#?}");
}

/// The states beside those, whose replay the kernel takes. The lookup of
/// the gateway passes over a multicast route that does not hold it, one at
/// scope site and one with a type of service. It returns a unicast route
/// before a multicast route under a shorter prefix, and before one of its
/// own network under a higher metric, whether the unicast route is a prefix
/// route or a listed route. The kernel takes a gateway that is one of the
/// device's addresses whatever route holds that address.
#[test]
fn the_capture_admits_a_gateway_whose_lookup_returns_a_unicast_route() {
    for (addresses, routes) in [
        (
            ADDRESS,
            "multicast 10.0.1.0/28 scope link\n10.0.2.0/24 via 10.0.1.17\n",
        ),
        (
            ADDRESS,
            "multicast 10.0.1.0/28 scope site\n10.0.2.0/24 via 10.0.1.1\n",
        ),
        (
            ADDRESS,
            "multicast 10.0.1.0/28 tos 0x10 scope link\n10.0.2.0/24 via 10.0.1.1\n",
        ),
        (
            ADDRESS,
            "multicast 10.0.0.0/16 scope link\n10.0.2.0/24 via 10.0.1.1\n",
        ),
        (
            ADDRESS_METRIC_7,
            "multicast 10.0.1.0/24 scope link metric 8\n10.0.2.0/24 via 10.0.1.1\n",
        ),
        (
            ADDRESS_APART,
            "10.0.1.0/28 scope link metric 10\nmulticast 10.0.1.0/28 scope link metric 20\n10.0.2.0/24 via 10.0.1.1\n",
        ),
        (
            ADDRESS_APART,
            "10.0.1.0/24 scope link\nmulticast 10.0.1.0/28 scope link\n10.0.1.1 scope link\n10.0.2.0/24 via 10.0.1.1\n",
        ),
        (
            ADDRESS_APART,
            "multicast 10.0.9.0/28 scope host\n10.0.3.0/24 via 10.0.9.5 scope link\n",
        ),
        (
            ADDRESS_APART,
            "multicast 10.0.9.5 scope host\n10.0.3.0/24 via 10.0.9.5 scope link\n",
        ),
    ] {
        assert_eq!(
            captured_routes(addresses, routes),
            Ok(listed(routes)),
            "{routes:?}"
        );
    }
}

/// The state captured for `ens6` when `ip -4 -o` prints each of `listings`,
/// a command's words and its output.
fn captured_state(listings: &[(&str, &str)]) -> Result<NetState, EniError> {
    let fixture = Fixture::new(512);
    let kernel = FakeKernel::new(&fixture.host);
    for (command, output) in listings {
        kernel
            .outputs
            .borrow_mut()
            .insert(format!("ip -4 -o {command}"), Some((*output).into()));
    }
    let host: &Host = &fixture.host;
    host.net_state(&kernel, "ens6")
}

/// `routes` as the capture records them, one per listed line.
fn listed(routes: &str) -> Vec<String> {
    routes.lines().map(str::to_owned).collect()
}

/// Three addresses of one network, listed in falling order: the primary
/// 10.0.1.9 and the secondaries 10.0.1.7 and 10.0.1.5.
const THREE_ADDRESSES: &str = "3: ens6    inet 10.0.1.9/24 brd 10.0.1.255 scope global ens6\\       valid_lft forever preferred_lft forever\n\
     3: ens6    inet 10.0.1.7/24 brd 10.0.1.255 scope global secondary ens6\\       valid_lft forever preferred_lft forever\n\
     3: ens6    inet 10.0.1.5/24 brd 10.0.1.255 scope global secondary ens6\\       valid_lft forever preferred_lft forever\n";
const ADDRESSES: &str = "addr show dev ens6";
const ROUTES: &str = "route show table all dev ens6";
const COMPLETE: &str = "route show table all";
const RULES: &str = "rule show";

/// The first route release replays under a prefix route's key writes over
/// that prefix route, so that route's place decides the gateways the prefix
/// route reaches. `ip` lists a metric of zero as no metric, so a listing
/// that spells one holds two routes under the key of the prefix route of
/// 10.0.1.5/24. Each of the two holds `onlink`, so its own gateway needs no
/// route. The route to 10.0.2.0/24 is admitted when both are listed after
/// it, and refused when either is listed before it, whichever comes first.
#[test]
fn the_first_route_replayed_under_a_prefix_route_s_key_decides_its_gateways() {
    let through = "10.0.2.0/24 via 10.0.1.1\n";
    let plain = "10.0.1.0/24 via 10.0.1.1 onlink\n";
    let spelled = "10.0.1.0/24 via 10.0.1.1 metric 0 onlink\n";
    for after in [[through, plain, spelled], [through, spelled, plain]] {
        let routes = after.concat();
        assert_eq!(
            captured_routes(ADDRESS, &routes),
            Ok(listed(&routes)),
            "{routes:?}"
        );
    }
    for before in [
        [plain, through, spelled],
        [spelled, through, plain],
        [plain, spelled, through],
    ] {
        let routes = before.concat();
        assert_eq!(
            captured_routes(ADDRESS, &routes),
            Err(EniError::Unverifiable("routes")),
            "{routes:?}"
        );
    }
}

/// A unicast route of the device at scope link reaches the gateways its
/// network holds: a /24 route its 256 addresses, a host route its one
/// address, a /16 route every address under it, and none outside. A gateway
/// route at scope link takes a route at scope host, and of two routes to
/// one network the lookup passes over the one at scope link, under either
/// metric.
#[test]
fn a_near_route_reaches_the_gateways_its_network_holds_at_its_scope() {
    let near = "10.3.0.0/24 scope link\n10.9.9.9 scope link\n10.16.0.0/16 scope link\n";
    for (gateway, reached) in [
        ("10.3.0.1", true),
        ("10.9.9.9", true),
        ("10.16.200.1", true),
        ("10.3.1.1", false),
        ("10.9.9.8", false),
        ("10.17.0.1", false),
    ] {
        let routes = format!("{near}10.4.0.0/24 via {gateway}\n");
        let expected = if reached {
            Ok(listed(&routes))
        } else {
            Err(EniError::Unverifiable("routes"))
        };
        assert_eq!(captured_routes(ADDRESS, &routes), expected, "{gateway}");
    }
    for (hosts, reached) in [
        ("10.9.9.9 scope link\n", false),
        ("10.9.9.9 scope link\n10.9.9.9 scope link metric 5\n", false),
        ("10.9.9.9 scope link\n10.9.9.9 scope host metric 5\n", true),
        ("10.9.9.9 scope host\n10.9.9.9 scope link metric 5\n", true),
    ] {
        let routes = format!("{hosts}10.4.0.0/24 via 10.9.9.9 scope link\n");
        let expected = if reached {
            Ok(listed(&routes))
        } else {
            Err(EniError::Unverifiable("routes"))
        };
        assert_eq!(captured_routes(ADDRESS, &routes), expected, "{hosts:?}");
    }
}

/// Release's replay of a recorded route writes over a main-table route of
/// another device under the same destination, type of service and metric,
/// so the capture refuses beside one, whichever of its recorded routes
/// holds that key: the first or the last destination, or the second metric
/// of one destination. A host route under another metric, another
/// destination or another table stays as it is.
#[test]
fn a_host_route_under_the_key_of_any_recorded_route_refuses_the_capture() {
    let routes = "10.0.1.0/24 proto kernel scope link src 10.0.1.5\n\
                  10.4.1.0/24 via 10.0.1.1\n\
                  10.4.2.0/24 via 10.0.1.1\n\
                  10.4.2.0/24 via 10.0.1.1 metric 5\n\
                  10.4.3.0/24 via 10.0.1.1\n";
    let captured =
        |host: &str| captured_state(&[(ADDRESSES, ADDRESS), (ROUTES, routes), (COMPLETE, host)]);
    for host in [
        "10.0.1.0/24 via 10.2.64.1 dev ens5\n",
        "10.4.1.0/24 via 10.2.64.1 dev ens5\n",
        "10.4.2.0/24 via 10.2.64.1 dev ens5\n",
        "10.4.2.0/24 via 10.2.64.1 dev ens5 metric 5\n",
        "10.4.3.0/24 via 10.2.64.1 dev ens5\n",
    ] {
        assert_eq!(
            captured(host),
            Err(EniError::Unverifiable("routes")),
            "{host}"
        );
    }
    for host in [
        "10.4.2.0/24 via 10.2.64.1 dev ens5 metric 7\n",
        "10.4.0.0/24 via 10.2.64.1 dev ens5\n",
        "10.4.2.0/24 via 10.2.64.1 dev ens5 table 9\n",
    ] {
        assert_eq!(
            captured(host).map(|state| state.routes),
            Ok(listed(routes)),
            "{host}"
        );
    }
}

/// The kernel removes a main-table route with the address its `src` names,
/// so a route of another device whose `src` is any of the device's
/// addresses refuses the capture: the first listed, the last, or one
/// between. A `src` beside those addresses, and a route of another table,
/// stay as they are.
#[test]
fn a_host_route_whose_src_is_any_address_of_the_device_refuses_the_capture() {
    let routes = "10.0.1.0/24 proto kernel scope link src 10.0.1.9\n";
    let captured = |host: &str| {
        captured_state(&[
            (ADDRESSES, THREE_ADDRESSES),
            (ROUTES, routes),
            (COMPLETE, host),
        ])
    };
    for source in ["10.0.1.9", "10.0.1.7", "10.0.1.5"] {
        let host = format!("10.50.0.0/16 via 10.2.64.1 dev ens5 src {source}\n");
        assert_eq!(
            captured(&host),
            Err(EniError::Unverifiable("routes")),
            "{source}"
        );
    }
    for host in [
        "10.50.0.0/16 via 10.2.64.1 dev ens5 src 10.0.1.8\n",
        "10.50.0.0/16 via 10.2.64.1 dev ens5 table 9 src 10.0.1.9\n",
    ] {
        assert_eq!(
            captured(host).map(|state| state.routes),
            Ok(listed(routes)),
            "{host}"
        );
    }
}

/// Release replays the main table alone, so a rule that names any of the
/// device's addresses, with or without a prefix length, refuses the
/// capture: the first listed, the last, or one between. A rule that names
/// an address beside them stays as it is.
#[test]
fn a_rule_naming_any_address_of_the_device_refuses_the_capture() {
    let routes = "10.0.1.0/24 proto kernel scope link src 10.0.1.9\n";
    let defaults = "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n32767:\tfrom all lookup default\n";
    let captured = |rule: &str| {
        let rules = format!("{defaults}32765:\t{rule}\n");
        captured_state(&[
            (ADDRESSES, THREE_ADDRESSES),
            (ROUTES, routes),
            (RULES, &rules),
        ])
    };
    for rule in [
        "from 10.0.1.9 lookup 7",
        "from 10.0.1.7 lookup 7",
        "from 10.0.1.5/32 lookup 7",
        "from all to 10.0.1.9/32 lookup 7",
    ] {
        assert_eq!(
            captured(rule),
            Err(EniError::Unverifiable("rules")),
            "{rule}"
        );
    }
    assert_eq!(
        captured("from 10.0.1.8 lookup 7").map(|state| state.routes),
        Ok(listed(routes))
    );
}

/// The kernel takes a gateway that is one of the device's own addresses
/// for a route at any scope below host, so a route at scope link through
/// any of them is admitted: the first listed, the last, or one between. A
/// route at scope link through an address beside them finds only the prefix
/// route, which is no nearer than the route itself, and refuses.
#[test]
fn a_gateway_that_is_any_address_of_the_device_is_reached() {
    let prefix = "10.0.1.0/24 proto kernel scope link src 10.0.1.9\n";
    for gateway in ["10.0.1.9", "10.0.1.7", "10.0.1.5"] {
        let routes = format!("{prefix}10.4.0.0/24 via {gateway} scope link\n");
        assert_eq!(
            captured_routes(THREE_ADDRESSES, &routes),
            Ok(listed(&routes)),
            "{gateway}"
        );
    }
    let routes = format!("{prefix}10.4.0.0/24 via 10.0.1.8 scope link\n");
    assert_eq!(
        captured_routes(THREE_ADDRESSES, &routes),
        Err(EniError::Unverifiable("routes"))
    );
}

/// `ip` ends a word at ASCII whitespace alone, and the vertical tab is
/// whitespace outside it, as a no-break space is. An address line that
/// holds one between two words refuses for its addresses, and a route line
/// for its routes.
#[test]
fn a_vertical_tab_in_an_address_or_route_line_refuses_the_capture() {
    let prefix = "10.0.1.0/24 proto kernel scope link src 10.0.1.5\n";
    for space in ['\u{b}', '\u{a0}'] {
        let address = ADDRESS.replacen(" ens6\\", &format!("{space}ens6\\"), 1);
        assert_ne!(address, ADDRESS);
        assert_eq!(
            captured_routes(&address, prefix),
            Err(EniError::Unverifiable("addresses")),
            "{space:?}"
        );
        let routes = format!("{prefix}10.9.0.0/16 via 10.0.1.1 proto{space}static\n");
        assert_eq!(
            captured_routes(ADDRESS, &routes),
            Err(EniError::Unverifiable("routes")),
            "{space:?}"
        );
    }
}

/// A character outside ASCII that is no whitespace is part of its word. A
/// route whose protocol name holds one is recorded with it, and the lines
/// beside it are read as in a listing of ASCII characters.
#[test]
fn a_character_outside_ascii_in_a_word_leaves_the_capture_as_it_is() {
    let routes = "10.0.1.0/24 proto kernel scope link src 10.0.1.5\n\
                  10.9.0.0/16 via 10.0.1.1 proto caf\u{e9}\n\
                  10.4.0.0/24 via 10.0.1.1\n";
    let state = captured_state(&[(ADDRESSES, ADDRESS), (ROUTES, routes)]).unwrap();
    assert_eq!(state.addresses, ["10.0.1.5/24 brd 10.0.1.255"]);
    assert_eq!(state.routes, listed(routes));
}

/// A line ends at its newline, and a carriage return before the newline is
/// whitespace at the line's end. A listing whose lines end in both, with a
/// line of spaces between them, is captured as the same listing with
/// newlines alone.
#[test]
fn a_carriage_return_before_a_newline_leaves_the_capture_as_it_is() {
    let routes = "10.0.1.0/24 proto kernel scope link src 10.0.1.5\n10.9.0.0/16 via 10.0.1.1\n";
    let rules = "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n";
    let unix = captured_state(&[(ADDRESSES, ADDRESS), (ROUTES, routes), (RULES, rules)]);
    let returned = |text: &str| text.replace('\n', "\r\n");
    let dos = captured_state(&[
        (ADDRESSES, &returned(ADDRESS)),
        (ROUTES, &format!("{}   \r\n", returned(routes))),
        (RULES, &returned(rules)),
    ]);
    assert_eq!(
        unix.as_ref().map(|state| &state.routes),
        Ok(&listed(routes))
    );
    assert_eq!(dos, unix);
}

/// An address line names its device's label as its last word, after its
/// address. A line whose label follows `inet` at once, or that ends at
/// `inet`, refuses for its label, before any word of its lifetimes is read
/// as an address. A line whose last word names another device refuses for
/// its label as well.
#[test]
fn an_address_line_with_no_address_before_its_label_refuses_for_the_label() {
    let prefix = "10.0.1.0/24 proto kernel scope link src 10.0.1.5\n";
    for address in [
        "3: ens6    inet ens6\\       valid_lft forever preferred_lft forever\n",
        "3: ens6    inet ens6\n",
        "3: ens6    inet\n",
        "3: ens6    inet 10.0.1.5/24 ens7\n",
    ] {
        assert_eq!(
            captured_routes(address, prefix),
            Err(EniError::Unverifiable("label")),
            "{address:?}"
        );
    }
}

/// A route of the device names its gateway as an address `ip route
/// replace` takes back. A gateway that is no IPv4 address, or no IPv6
/// address after `inet6`, refuses the capture, and `onlink`, which spares a
/// gateway its route, does not admit one.
#[test]
fn a_route_through_a_gateway_that_is_no_address_refuses_the_capture() {
    let prefix = "10.0.1.0/24 proto kernel scope link src 10.0.1.5\n";
    for gateway in ["10.0.1.1", "10.0.1.1 onlink", "inet6 fe80::1"] {
        let routes = format!("{prefix}10.9.0.0/16 via {gateway}\n");
        assert_eq!(
            captured_routes(ADDRESS, &routes),
            Ok(listed(&routes)),
            "{gateway}"
        );
    }
    for gateway in [
        "10.0.1",
        "10.0.1 onlink",
        "gateway onlink",
        "inet6 fe80::zz",
        "inet6 10.0.1.1 onlink",
    ] {
        let routes = format!("{prefix}10.9.0.0/16 via {gateway}\n");
        assert_eq!(
            captured_routes(ADDRESS, &routes),
            Err(EniError::Unverifiable("routes")),
            "{gateway}"
        );
    }
}

/// The device's prefix route and a route through the gateway 10.0.1.1,
/// which that prefix route holds.
const THROUGH_PREFIX: &str =
    "10.0.1.0/24 proto kernel scope link src 10.0.1.5\n10.0.2.0/24 via 10.0.1.1\n";

/// The routes captured for `ens6` when `ip` lists `addresses`, by device
/// `routes`, and in the complete listing `host`.
fn captured_beside(addresses: &str, routes: &str, host: &str) -> Result<Vec<String>, EniError> {
    captured_state(&[(ADDRESSES, addresses), (ROUTES, routes), (COMPLETE, host)])
        .map(|state| state.routes)
}

/// A `blackhole`, `unreachable`, `prohibit` or `throw` route belongs to no
/// device and stays through the bind. The kernel's lookup of a gateway
/// returns such a route of the main table before it compares devices, so
/// one with no type of service at scope link or host under a longer prefix
/// than the prefix route refuses the gateway at release. A route with an
/// `encap` block lists the block's `tos` and refuses all the same. The
/// kernel reads the local table before the main table: a device-less route
/// of the local table refuses the gateway under the prefix route's own
/// prefix at a higher metric, and, on a host that has held a policy rule,
/// under a shorter prefix. A `throw` route of the local table refuses the
/// gateway on a host that has held no policy rule, where the lookup reads
/// both tables as one. The listing does not show which host it is, so the
/// capture must refuse each of these states. Release assigns an address
/// after a device-less route of the local table that stays under that
/// address at metric 0, and the lookup returns the earlier entry, so such a
/// route at an adequate scope also refuses a gateway that is the device's
/// own address.
#[test]
fn the_capture_refuses_a_gateway_whose_lookup_returns_a_device_less_route() {
    let admitted: Vec<&str> = [
        "blackhole 10.0.1.0/28 scope link\n",
        "blackhole 10.0.1.0/28 scope host\n",
        "unreachable 10.0.1.0/28 scope link\n",
        "prohibit 10.0.1.0/28 scope link\n",
        "throw 10.0.1.0/28 scope link\n",
        "blackhole 10.0.1.0/28  encap ip id 5 src 0.0.0.0 dst 192.0.2.1 ttl 0 tos 0 scope link\n",
        "blackhole 10.0.1.0/28 table local scope link\n",
        "blackhole 10.0.1.0/24 table local scope link metric 5\n",
        "blackhole 10.0.0.0/16 table local scope link\n",
        "throw 10.0.1.0/28 table local scope link\n",
    ]
    .into_iter()
    .filter(|host| {
        captured_beside(ADDRESS, THROUGH_PREFIX, host) != Err(EniError::Unverifiable("routes"))
    })
    .collect();
    assert!(admitted.is_empty(), "the capture admitted {admitted:#?}");
    for (own, host) in [
        (
            "10.0.3.0/24 via 10.0.1.5 scope link\n",
            "blackhole 10.0.1.5 table local scope host\n",
        ),
        (
            "10.0.3.0/24 via 10.0.1.5\n",
            "blackhole 10.0.1.5 table local scope host\n",
        ),
        (
            "10.0.3.0/24 via 10.0.1.5\n",
            "blackhole 10.0.1.5 table local scope link\n",
        ),
    ] {
        assert_eq!(
            captured_beside(ADDRESS, own, host),
            Err(EniError::Unverifiable("routes")),
            "{own:?} beside {host:?}"
        );
    }
}

/// The states beside those, whose replay the kernel takes. The lookup of
/// the gateway passes over a device-less route at the default scope or at
/// scope site, in either table, one with a type of service, and one of a
/// table the default rules do not read. It returns the prefix route before
/// a main-table device-less route under a shorter prefix or under the
/// prefix route's own prefix at a higher metric, and it passes over a
/// multicast route of another device. The kernel takes a gateway that is
/// one of the device's addresses beside a main-table device-less route that
/// holds it, and beside a local-table one under a shorter prefix, a higher
/// metric or a scope the lookup passes over.
#[test]
fn the_capture_admits_a_gateway_whose_lookup_passes_over_a_device_less_route() {
    for host in [
        "blackhole 10.0.1.0/28\n",
        "blackhole 10.0.0.0/8\n",
        "blackhole 10.0.1.0/28 scope site\n",
        "blackhole 10.0.1.0/28 table local\n",
        "blackhole 10.0.1.0/28 table local scope site\n",
        "blackhole 10.0.1.0/28 tos 0x10 scope link\n",
        "blackhole 10.0.1.0/28 table 100 scope link\n",
        "blackhole 10.0.0.0/16 scope link\n",
        "blackhole 10.0.1.0/24 scope link metric 5\n",
        "multicast 10.0.1.0/28 dev ens5 scope link\n",
    ] {
        assert_eq!(
            captured_beside(ADDRESS, THROUGH_PREFIX, host),
            Ok(listed(THROUGH_PREFIX)),
            "{host}"
        );
    }
    let own = "10.0.3.0/24 via 10.0.1.5 scope link\n";
    for host in [
        "blackhole 10.0.1.0/28 scope link\n",
        "blackhole 10.0.1.5 scope host\n",
        "blackhole 10.0.1.4/30 table local scope host\n",
        "blackhole 10.0.1.5 table local scope host metric 5\n",
        "blackhole 10.0.1.5 table local scope link\n",
    ] {
        assert_eq!(
            captured_beside(ADDRESS, own, host),
            Ok(listed(own)),
            "{host}"
        );
    }
}

/// The kernel derives a `broadcast` entry of the local table, at scope
/// link, for each address's `brd` and, below a /31 prefix, for the last
/// address of its prefix. Its lookup of a gateway returns that entry before
/// every main-table route and refuses the gateway. Release assigns the
/// addresses before it replays a route, so the capture must refuse a
/// gateway at the `brd` of a primary or a secondary address, at the last
/// address of a prefix whose `brd` is another address or whose address
/// holds `noprefixroute`, and at one a listed unicast /32 of scope link
/// also holds. Release assigns the addresses in listed order, so the entry
/// for an address's `brd` stands before the own entry of a later address
/// under it, and the capture must refuse a gateway at that later address.
#[test]
fn the_capture_refuses_a_gateway_at_a_broadcast_address_of_the_device() {
    let lifetimes = "\\       valid_lft forever preferred_lft forever\n";
    let other_brd =
        format!("3: ens6    inet 10.0.1.5/24 brd 10.0.1.200 scope global ens6{lifetimes}");
    let secondary = format!(
        "{ADDRESS}3: ens6    inet 10.0.1.7/24 brd 10.0.1.100 scope global secondary ens6{lifetimes}"
    );
    let no_prefix_route =
        format!("3: ens6    inet 10.0.1.5/24 scope global noprefixroute ens6{lifetimes}");
    let brd_before_address = format!(
        "3: ens6    inet 10.0.1.5/24 brd 10.0.1.7 scope global ens6{lifetimes}\
         3: ens6    inet 10.0.1.7/24 brd 10.0.1.255 scope global secondary ens6{lifetimes}"
    );
    let states = [
        (ADDRESS, "10.0.2.0/24 via 10.0.1.255\n"),
        (
            ADDRESS,
            "10.0.1.255 scope link\n10.0.2.0/24 via 10.0.1.255\n",
        ),
        (other_brd.as_str(), "10.0.2.0/24 via 10.0.1.200\n"),
        (other_brd.as_str(), "10.0.2.0/24 via 10.0.1.255\n"),
        (secondary.as_str(), "10.0.2.0/24 via 10.0.1.100\n"),
        (
            no_prefix_route.as_str(),
            "10.0.1.0/24 scope link\n10.0.2.0/24 via 10.0.1.255\n",
        ),
        (brd_before_address.as_str(), "10.0.3.0/24 via 10.0.1.7\n"),
    ];
    let admitted: Vec<&str> = states
        .into_iter()
        .filter(|(addresses, routes)| {
            captured_routes(addresses, routes) != Err(EniError::Unverifiable("routes"))
        })
        .map(|(_, routes)| routes)
        .collect();
    assert!(admitted.is_empty(), "the capture admitted {admitted:#?}");
}

/// The states beside those, whose replay the kernel takes: a gateway at the
/// first address of the prefix, for which the kernel derives no entry; a
/// gateway route of scope link, whose lookup takes scope host and passes
/// over the `broadcast` entry to a unicast route of scope host; and a
/// gateway at the second address of a /31 prefix, which has no broadcast
/// address; and a gateway at the last address of a prefix in 0.0.0.0/8, for
/// which the kernel derives no entry. Where an earlier address's `brd` is a
/// later address of the device, a gateway route of scope link through that
/// address passes over the `broadcast` entry, the earlier address stays a
/// gateway, and with the two addresses listed the other way the address's
/// own entry stands first.
#[test]
fn the_capture_admits_a_gateway_beside_the_broadcast_addresses_of_the_device() {
    let lifetimes = "\\       valid_lft forever preferred_lft forever\n";
    let other_brd =
        format!("3: ens6    inet 10.0.1.5/24 brd 10.0.1.200 scope global ens6{lifetimes}");
    let pair = format!("3: ens6    inet 10.0.3.0/31 scope global ens6{lifetimes}");
    let wide = format!("3: ens6    inet 10.0.1.5/4 scope global ens6{lifetimes}");
    let brd_before_address = format!(
        "3: ens6    inet 10.0.1.5/24 brd 10.0.1.7 scope global ens6{lifetimes}\
         3: ens6    inet 10.0.1.7/24 brd 10.0.1.255 scope global secondary ens6{lifetimes}"
    );
    let address_before_brd = format!(
        "3: ens6    inet 10.0.1.7/24 brd 10.0.1.255 scope global ens6{lifetimes}\
         3: ens6    inet 10.0.1.5/24 brd 10.0.1.7 scope global secondary ens6{lifetimes}"
    );
    for (addresses, routes) in [
        (
            brd_before_address.as_str(),
            "10.0.4.0/24 via 10.0.1.7 scope link\n",
        ),
        (brd_before_address.as_str(), "10.0.5.0/24 via 10.0.1.5\n"),
        (address_before_brd.as_str(), "10.0.3.0/24 via 10.0.1.7\n"),
        (other_brd.as_str(), "10.0.2.0/24 via 10.0.1.0\n"),
        (
            ADDRESS,
            "10.0.1.255 scope host\n10.0.2.0/24 via 10.0.1.255 scope link\n",
        ),
        (pair.as_str(), "10.0.2.0/24 via 10.0.3.1\n"),
        (
            wide.as_str(),
            "15.255.255.255 scope link\n10.0.2.0/24 via 15.255.255.255\n",
        ),
    ] {
        assert_eq!(
            captured_routes(addresses, routes),
            Ok(listed(routes)),
            "{routes:?}"
        );
    }
}

/// The routes captured for `ens6` with [`ADDRESS`] when `ip` lists by
/// device `routes`, in the complete listing `host`, and the rules `rules`,
/// one per line in the kernel's order.
fn captured_under(routes: &str, rules: &[&str], host: &str) -> Result<Vec<String>, EniError> {
    let rules: String = rules.iter().map(|rule| format!("{rule}\n")).collect();
    captured_state(&[
        (ADDRESSES, ADDRESS),
        (ROUTES, routes),
        (COMPLETE, host),
        (RULES, &rules),
    ])
    .map(|state| state.routes)
}

const LOCAL_RULE: &str = "0:\tfrom all lookup local";
const MAIN_RULE: &str = "32766:\tfrom all lookup main";
const DEFAULT_RULE: &str = "32767:\tfrom all lookup default";

/// The kernel looks a gateway up through the policy rules in order, with no
/// source address and the gateway as destination. A rule before the one
/// that reads the main table ends the lookup when it matches and its action
/// is `prohibit`, `unreachable`, `blackhole` or a `goto` past the main
/// rule, and when the table it reads holds a device-less route over the
/// gateway at scope link, under any prefix length. A `from` prefix matches
/// when it holds 0.0.0.0, and `not` turns a rule that names another prefix
/// into one that matches. A table the host names `nop` is read as any other
/// table. `ip` ends a word at ASCII whitespace alone, so a
/// `proto` name that holds a no-break space is one word and the rule before
/// it keeps its action. A route with an `encap` block counts in the table
/// it lists. The lookup also fails when no rule reads the main table whole,
/// and when the host holds no rule at all. A rule before the local table's
/// ends the lookup of a gateway that is the device's own address, and with
/// no rule for the local table such a gateway needs a main-table route: a
/// /32 address has none, and the prefix route of another stands at scope
/// link, which the lookup of a link-scope gateway route passes over. A
/// rule that reads the main table before the local table's rule ends the
/// lookup of such a gateway when the main table holds a device-less or a
/// multicast route over it at scope host. The rules stay through the bind,
/// so the capture must refuse each of these states.
#[test]
fn the_capture_refuses_a_gateway_whose_lookup_a_rule_ends() {
    let table = "blackhole 10.0.1.0/28 table 100 scope link\n";
    let before_main: [(&str, &str); 17] = [
        ("100:\tfrom all to 10.0.1.0/28 prohibit", ""),
        (
            "100:\tfrom all prohibit proto lookup\u{a0}main\u{a0}proto\u{a0}x",
            "",
        ),
        ("100:\tfrom all to 10.0.1.0/28 unreachable", ""),
        ("100:\tfrom all to 10.0.1.0/28 blackhole", ""),
        ("100:\tfrom all prohibit", ""),
        ("100:\tfrom 0.0.0.0/8 prohibit", ""),
        ("100:\tnot from all to 10.0.5.0/24 blackhole", ""),
        ("100:\tnot from 10.9.0.0/16 blackhole", ""),
        ("100:\tfrom all to 10.0.1.0/28 iif lo blackhole", ""),
        ("100:\tfrom all goto 32767", ""),
        ("100:\tfrom all lookup 100", table),
        ("100:\tfrom all to 10.0.1.0/24 lookup 100", table),
        (
            "100:\tfrom all lookup 100",
            "blackhole 10.0.0.0/16 table 100 scope link\n",
        ),
        (
            "100:\tfrom all lookup default",
            "blackhole 10.0.1.0/28 table default scope link\n",
        ),
        (
            "100:\tfrom all lookup nop",
            "blackhole 10.0.1.0/28 table nop scope link\n",
        ),
        (
            "100:\tnot from all to 10.0.5.0/24 lookup 100 proto static",
            table,
        ),
        (
            "100:\tfrom all lookup 100",
            "blackhole 10.0.0.0/16  encap ip id 5 src 0.0.0.0 dst 192.0.2.1 ttl 0 tos 0 table 100 scope link\n",
        ),
    ];
    let admitted: Vec<&str> = before_main
        .into_iter()
        .filter(|(rule, host)| {
            let rules = [LOCAL_RULE, rule, MAIN_RULE, DEFAULT_RULE];
            captured_under(THROUGH_PREFIX, &rules, host) != Err(EniError::Unverifiable("routes"))
        })
        .map(|(rule, _)| rule)
        .collect();
    assert!(admitted.is_empty(), "the capture admitted {admitted:#?}");
    let unread: [&[&str]; 3] = [
        &[],
        &[LOCAL_RULE, DEFAULT_RULE],
        &[
            LOCAL_RULE,
            "32766:\tfrom all lookup main suppress_prefixlength 24",
            DEFAULT_RULE,
        ],
    ];
    for rules in unread {
        assert_eq!(
            captured_under(THROUGH_PREFIX, rules, ""),
            Err(EniError::Unverifiable("routes")),
            "{rules:?}"
        );
    }
    let own = "10.0.3.0/24 via 10.0.1.5 scope link\n";
    let moved = [
        "100:\tfrom all to 10.0.1.0/28 prohibit",
        "32765:\tfrom all lookup local",
        MAIN_RULE,
        DEFAULT_RULE,
    ];
    let no_local: [&[&str]; 3] = [&moved, &[], &[MAIN_RULE, DEFAULT_RULE]];
    for rules in no_local {
        assert_eq!(
            captured_under(own, rules, ""),
            Err(EniError::Unverifiable("routes")),
            "{rules:?}"
        );
    }
    let lifetimes = "\\       valid_lft forever preferred_lft forever\n";
    let alone = format!("{ADDRESS}3: ens6    inet 10.0.7.7/32 scope global ens6{lifetimes}");
    let captured = captured_state(&[
        (ADDRESSES, &alone),
        (ROUTES, "10.0.4.0/24 via 10.0.7.7\n"),
        (RULES, &format!("{MAIN_RULE}\n{DEFAULT_RULE}\n")),
    ]);
    assert_eq!(
        captured.map(|state| state.routes),
        Err(EniError::Unverifiable("routes")),
        "a /32 address with no rule for the local table"
    );
    let moved_local = "32765:\tfrom all lookup local";
    let main_first: [&str; 2] = [
        "100:\tfrom all to 10.0.1.0/24 lookup main",
        "100:\tfrom all lookup main suppress_prefixlength 0",
    ];
    let beside = format!("multicast 10.0.1.4/30 scope host\n{own}");
    for rule in main_first {
        let rules = [rule, moved_local, MAIN_RULE, DEFAULT_RULE];
        for (routes, host) in [
            (own, "blackhole 10.0.1.5 scope host\n"),
            (beside.as_str(), ""),
        ] {
            assert_eq!(
                captured_under(routes, &rules, host),
                Err(EniError::Unverifiable("routes")),
                "{rule}: {routes:?} beside {host:?}"
            );
        }
    }
}

/// The capture reads a rule's `not`, `from`, `to` and action, and counts a
/// rule with any other selector as one that matches. The kernel takes the
/// gateway under a rule that selects by mark, and under a `goto` that lands
/// on the main rule; the capture refuses both, since it reads neither the
/// mark nor the target. The kernel also takes the gateway at a lookup of
/// the main table that passes over short prefixes, ahead of a rule that
/// ends every lookup; the capture does not read what that lookup passes
/// over, goes on to the rule behind it and refuses.
#[test]
fn the_capture_refuses_a_gateway_under_a_rule_it_does_not_read() {
    let unread: [&[&str]; 3] = [
        &["100:\tfrom all to 10.0.1.0/28 fwmark 0x1 blackhole"],
        &["100:\tfrom all goto 32766"],
        &[
            "100:\tfrom all lookup main suppress_prefixlength 0",
            "200:\tfrom all prohibit",
        ],
    ];
    for between in unread {
        let rules = [&[LOCAL_RULE], between, &[MAIN_RULE, DEFAULT_RULE]].concat();
        assert_eq!(
            captured_under(THROUGH_PREFIX, &rules, ""),
            Err(EniError::Unverifiable("routes")),
            "{between:?}"
        );
    }
}

/// The states beside those, whose replay the kernel takes. A rule does not
/// match the lookup when its `from` prefix holds no 0.0.0.0 or its `to`
/// prefix does not hold the gateway. A table a rule reads passes the lookup
/// on when its device-less route lies at the default scope or is a `throw`,
/// when it holds a route of another device, and when the route lies in
/// another table. A rule listed after the one that reads the main table is
/// never read, and a lookup of the main table that passes over short
/// prefixes takes the /24 prefix route. A gateway that is the device's own
/// address is taken at the local table's rule, wherever it is listed, when
/// no rule before it matches, and whatever rule follows it. With no rule
/// for the local table, the address's prefix route reaches it for a gateway
/// route at the default scope. A rule `from all to <prefix> lookup main`
/// takes a gateway its prefix holds through the prefix route, whatever rule
/// follows it, and a lookup of the main table that finds no entry at scope
/// host leaves a gateway at the device's own address to the local table's
/// rule behind it. Such a rule is enough with no rule `from all lookup
/// main` behind it, and a rule `from all to <prefix> lookup local` takes a
/// gateway at the device's own address in the same way. A `nop` rule passes
/// the lookup on, and a rule's
/// `realms` and `proto` words leave it the lookup it is. A `broadcast`
/// entry lies in the local table, so a gateway at the device's broadcast
/// address is taken through the prefix route when no rule reads the local
/// table before the main table.
#[test]
fn the_capture_admits_a_gateway_whose_lookup_passes_the_rules() {
    let table = "blackhole 10.0.1.0/28 table 100 scope link\n";
    let before_main: [(&str, &str); 8] = [
        ("100:\tfrom 10.9.0.0/16 prohibit", ""),
        ("100:\tfrom all to 10.0.5.0/24 blackhole", ""),
        ("100:\tfrom 10.9.0.0/16 lookup 100", table),
        ("100:\tfrom all to 10.0.5.0/24 lookup 100", table),
        (
            "100:\tfrom all lookup 100",
            "blackhole 10.0.1.0/28 table 100\n",
        ),
        (
            "100:\tfrom all lookup 100",
            "throw 10.0.1.0/28 table 100 scope link\n",
        ),
        (
            "100:\tfrom all lookup 100",
            "multicast 10.0.1.0/28 dev ens5 table 100 scope link\n",
        ),
        (
            "100:\tfrom all lookup 100",
            "blackhole 10.0.1.0/28 table 101 scope link\n",
        ),
    ];
    for (rule, host) in before_main {
        let rules = [LOCAL_RULE, rule, MAIN_RULE, DEFAULT_RULE];
        assert_eq!(
            captured_under(THROUGH_PREFIX, &rules, host),
            Ok(listed(THROUGH_PREFIX)),
            "{rule} beside {host:?}"
        );
    }
    let after_main: [(&[&str], &str); 4] = [
        (&[LOCAL_RULE, MAIN_RULE, DEFAULT_RULE], table),
        (
            &[
                LOCAL_RULE,
                MAIN_RULE,
                DEFAULT_RULE,
                "40000:\tfrom all to 10.0.1.0/28 blackhole",
            ],
            "",
        ),
        (
            &[
                LOCAL_RULE,
                MAIN_RULE,
                DEFAULT_RULE,
                "40000:\tfrom all lookup 100",
            ],
            table,
        ),
        (
            &[
                LOCAL_RULE,
                "32764:\tfrom all lookup main suppress_prefixlength 0",
                "32765:\tnot from all fwmark 0xca6c lookup 51820",
                MAIN_RULE,
                DEFAULT_RULE,
            ],
            "default dev wg0 table 51820 scope link\n",
        ),
    ];
    for (rules, host) in after_main {
        assert_eq!(
            captured_under(THROUGH_PREFIX, rules, host),
            Ok(listed(THROUGH_PREFIX)),
            "{rules:?} beside {host:?}"
        );
    }
    let own = "10.0.3.0/24 via 10.0.1.5 scope link\n";
    let rules = [
        LOCAL_RULE,
        "100:\tfrom all to 10.0.1.0/28 blackhole",
        MAIN_RULE,
        DEFAULT_RULE,
    ];
    assert_eq!(captured_under(own, &rules, ""), Ok(listed(own)));
    let moved = [
        "100:\tfrom 10.9.0.0/16 prohibit",
        "32765:\tfrom all lookup local",
        MAIN_RULE,
        DEFAULT_RULE,
    ];
    assert_eq!(captured_under(own, &moved, ""), Ok(listed(own)));
    let through_prefix = "10.0.4.0/24 via 10.0.1.5\n";
    assert_eq!(
        captured_under(through_prefix, &[MAIN_RULE, DEFAULT_RULE], ""),
        Ok(listed(through_prefix))
    );
    let passed: [&[&str]; 5] = [
        &[
            LOCAL_RULE,
            "100:\tfrom all to 10.0.1.0/24 lookup main",
            "200:\tfrom all prohibit",
            MAIN_RULE,
            DEFAULT_RULE,
        ],
        &[
            LOCAL_RULE,
            "100:\tfrom all to 10.0.1.0/24 lookup main",
            DEFAULT_RULE,
        ],
        &[LOCAL_RULE, "100:\tfrom all nop", MAIN_RULE, DEFAULT_RULE],
        &[
            LOCAL_RULE,
            "100:\tfrom all lookup main realms 1",
            "200:\tfrom all prohibit",
            MAIN_RULE,
            DEFAULT_RULE,
        ],
        &[
            LOCAL_RULE,
            "101:\tfrom all lookup main suppress_prefixlength 0 realms 3/4 proto static",
            MAIN_RULE,
            DEFAULT_RULE,
        ],
    ];
    for rules in passed {
        assert_eq!(
            captured_under(THROUGH_PREFIX, rules, ""),
            Ok(listed(THROUGH_PREFIX)),
            "{rules:?}"
        );
    }
    let at_broadcast = "10.0.2.0/24 via 10.0.1.255\n";
    let local_unread: [&[&str]; 2] = [
        &[MAIN_RULE, DEFAULT_RULE],
        &[MAIN_RULE, DEFAULT_RULE, "32767:\tfrom all lookup local"],
    ];
    for rules in local_unread {
        assert_eq!(
            captured_under(at_broadcast, rules, ""),
            Ok(listed(at_broadcast)),
            "{rules:?}"
        );
    }
    for rule in [
        "100:\tfrom all to 10.0.1.0/24 lookup main",
        "100:\tfrom all lookup main suppress_prefixlength 0",
    ] {
        let rules = [
            rule,
            "32765:\tfrom all lookup local",
            MAIN_RULE,
            DEFAULT_RULE,
        ];
        assert_eq!(captured_under(own, &rules, ""), Ok(listed(own)), "{rule}");
    }
    let to_own = [
        "100:\tfrom all to 10.0.1.0/24 lookup local",
        "200:\tfrom all prohibit",
        MAIN_RULE,
        DEFAULT_RULE,
    ];
    assert_eq!(captured_under(own, &to_own, ""), Ok(listed(own)));
    let lifetimes = "\\       valid_lft forever preferred_lft forever\n";
    let alone = format!("{ADDRESS}3: ens6    inet 10.0.7.7/32 scope global ens6{lifetimes}");
    let through_alone = "10.0.4.0/24 via 10.0.7.7\n";
    let captured = captured_state(&[
        (ADDRESSES, &alone),
        (ROUTES, through_alone),
        (
            RULES,
            &format!("{LOCAL_RULE}\n{MAIN_RULE}\n{DEFAULT_RULE}\n"),
        ),
    ]);
    assert_eq!(
        captured.map(|state| state.routes),
        Ok(listed(through_alone))
    );
}

/// The kernel derives no `broadcast` entry for the last address of a prefix
/// whose network lies in 0.0.0.0/8, and none for a `brd` of
/// 255.255.255.255. Release assigns the address and replays main-table
/// routes alone, so a listed entry of either shape is one the returned
/// device would lack, and the capture must refuse it. The address's own
/// `local` entry is derived and dropped.
#[test]
fn the_capture_refuses_a_broadcast_entry_the_kernel_does_not_derive() {
    let lifetimes = "\\       valid_lft forever preferred_lft forever\n";
    let wide = format!("3: ens6    inet 10.0.1.5/4 scope global ens6{lifetimes}");
    let own = "local 10.0.1.5 table local proto kernel scope host src 10.0.1.5\n";
    assert_eq!(
        captured_routes(&wide, own),
        Ok(Vec::new()),
        "premise: the address's own entry is derived"
    );
    let listed =
        format!("{own}broadcast 15.255.255.255 table local proto kernel scope link src 10.0.1.5\n");
    assert_eq!(
        captured_routes(&wide, &listed),
        Err(EniError::Unverifiable("routes"))
    );
    let pair =
        format!("3: ens6    inet 10.0.3.0/31 brd 255.255.255.255 scope global ens6{lifetimes}");
    let own = "local 10.0.3.0 table local proto kernel scope host src 10.0.3.0\n";
    assert_eq!(
        captured_routes(&pair, own),
        Ok(Vec::new()),
        "premise: the address's own entry is derived"
    );
    let listed = format!(
        "{own}broadcast 255.255.255.255 table local proto kernel scope link src 10.0.3.0\n"
    );
    assert_eq!(
        captured_routes(&pair, &listed),
        Err(EniError::Unverifiable("routes"))
    );
}
