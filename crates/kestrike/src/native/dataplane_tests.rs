//! The dataplane's inventory-derived inputs and its startup report.

use std::net::Ipv4Addr;
use std::num::NonZeroU32;

use super::dataplane::{
    DataplaneError, SOURCE_PORTS, StartupReport, allowed_devices, current_eni, stations,
};
use super::dma::{DmaMode, DmaReport, IovaMode};
use super::ena::{Llq, PortReport};
use super::env::PciAddress;
use crate::bind::{Eni, EniBinding, Host, Mappings, NetState, NvmeBinding, WcManifest, WcModule};
use crate::net::envelope::{HostBudget, OwnerDemand, Supported, check};

fn mappings(volume: bool) -> Mappings {
    Mappings {
        instance: "i-0123456789abcdef0".into(),
        boot: "boot".into(),
        wc: WcManifest {
            kernel: "6.1.0-wc".into(),
            config_sha256: "aa".into(),
            patch: "wc-1".into(),
            modules: vec![WcModule {
                name: "vfio_pci".into(),
                file: "/lib/modules/6.1.0-wc/extra/vfio-pci.ko".into(),
                sha256: "bb".into(),
                srcversion: "4C1D".into(),
            }],
        },
        nvme: volume.then(|| NvmeBinding {
            volume: "vol-0123".into(),
            bdf: "0000:00:1f.0".into(),
            nsid: 1,
            sector_size: 4096,
            capacity: 1 << 30,
            original_driver: "nvme".into(),
            original_override: None,
        }),
        eni: Some(EniBinding {
            eni: Eni {
                id: "eni-0123".into(),
                mac: [0x0a, 0x11, 0x22, 0x33, 0x44, 0x55],
                ipv4: Ipv4Addr::new(10, 0, 1, 5),
                subnet: "subnet-0123".into(),
                cidr: (Ipv4Addr::new(10, 0, 1, 0), 24),
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
                addresses: Vec::new(),
                routes: Vec::new(),
            },
            next_hops: vec![(Ipv4Addr::new(10, 0, 2, 7), [0x0a, 0, 0, 0, 1, 1])],
        }),
    }
}

/// An owner's environment may attach its controller and its ENI, a client's its ENI alone.
#[test]
fn the_environment_allows_exactly_the_recorded_devices() {
    let eni = PciAddress {
        domain: 0,
        bus: 0,
        device: 6,
        function: 0,
    };
    let nvme = PciAddress {
        device: 0x1f,
        ..eni
    };
    assert_eq!(allowed_devices(&mappings(true)), [nvme, eni]);
    assert_eq!(allowed_devices(&mappings(false)), [eni]);
}

/// This host and each peer get eight source ports at their base port, the peer through its recorded next hop; a peer without one is refused.
#[test]
fn stations_come_from_the_inventory() {
    let peer = Ipv4Addr::new(10, 0, 2, 7);
    let (local, peers) = stations(&mappings(false), 7000, &[(peer, 9000)]).unwrap();
    assert_eq!(
        (local.mac, local.ip, local.port, local.ports),
        (
            [0x0a, 0x11, 0x22, 0x33, 0x44, 0x55],
            [10, 0, 1, 5],
            7000,
            SOURCE_PORTS
        )
    );
    assert_eq!(
        (peers[0].mac, peers[0].ip, peers[0].port, peers[0].ports),
        ([0x0a, 0, 0, 0, 1, 1], [10, 0, 2, 7], 9000, SOURCE_PORTS)
    );
    let stranger = Ipv4Addr::new(10, 0, 3, 3);
    assert_eq!(
        stations(&mappings(false), 7000, &[(stranger, 9000)]).err(),
        Some(DataplaneError::Peer(stranger))
    );
    let mut bare = mappings(true);
    bare.eni = None;
    assert_eq!(
        stations(&bare, 7000, &[]).err(),
        Some(DataplaneError::NoEni)
    );
}

/// The startup report names the DMA posture, the port's effective settings, the low-latency prefix, the checked module and the native build pins.
#[test]
fn the_startup_report_records_every_setting() {
    let report = StartupReport {
        dma: DmaReport {
            iova_mode: IovaMode::Va,
            guest_iommu: true,
            vfio_no_iommu: Some(false),
            mode: DmaMode::Iommu,
            extent: 4 << 21,
            page_size: 2 << 20,
            mappings: 1,
            verified_pages: 4,
            physical_pages: 0,
            translated_bytes: 4 << 21,
        },
        port: PortReport {
            port: 0,
            mac: [0x0a, 0x11, 0x22, 0x33, 0x44, 0x55],
            mtu: 9001,
            max_mtu: 9216,
            rx_offloads: 6,
            tx_offloads: 0x8006,
            rx_ring: 1024,
            tx_ring: 256,
            segments: 3,
            data_room: 9344,
            headroom: 128,
            llq: Llq {
                entry: 128,
                push: 96,
            },
            flr: true,
        },
        wc: mappings(false).wc,
        instance: "i-0123456789abcdef0".into(),
        eni: "eni-0123".into(),
        bdf: "0000:00:06.0".into(),
        allowances: Some([0; 5]),
        configuration: None,
    };
    let text = report.to_string();
    assert!(
        !text.contains("configured:"),
        "no configuration was checked"
    );
    for needle in [
        "eni eni-0123 at 0000:00:06.0",
        "dma Iommu iova Va guest-iommu true",
        "verified 4 translated 8388608 bytes physical 0 mappings 1",
        "mtu 9001 (max 9216)",
        "rings rx 1024 tx 256 segments 3",
        "data-room 9344 headroom 128 llq entry 128 push 96 flr true",
        "wc kernel 6.1.0-wc config aa patch wc-1 vfio_pci /lib/modules/6.1.0-wc/extra/vfio-pci.ko 4C1D bb",
        "mac 0a:11:22:33:44:55",
        "mappings 1",
        "allowances Some([0, 0, 0, 0, 0])",
        &format!("native {}", spdk_sys::PINS),
    ] {
        assert!(text.contains(needle), "{needle} in {text}");
    }
    let budget = HostBudget {
        enis: 2,
        cores: 4,
        memory_bytes: 1 << 30,
        ebs_iops: 1_000,
        ebs_bytes_per_s: 1 << 20,
        network_pps: 1_000,
        network_bytes_per_s: 1 << 30,
    };
    let supported = Supported {
        owners: 2,
        shaping_floor_bytes_per_s: 1 << 29,
        per_owner: OwnerDemand {
            cores: 2,
            memory_bytes: 1 << 29,
            ebs_iops: 500,
            ebs_bytes_per_s: 1 << 19,
            network_pps: 500,
        },
    };
    let configured = StartupReport {
        configuration: Some(check(&supported, &budget).unwrap()),
        ..report
    }
    .to_string();
    let (measured, arithmetic) = configured.rsplit_once('\n').unwrap();
    assert_eq!(measured, text, "the measured lines stay as they were");
    assert!(
        arithmetic.starts_with("configured: 2 owners; Enis demand 2 of budget 2 ENIs"),
        "the arithmetic is its own last line: {arithmetic}"
    );
}

/// A scratch host whose instance and boot IDs are `i-0123456789abcdef0` and `boot`.
fn host() -> (Host, std::path::PathBuf) {
    let root = std::env::temp_dir().join(format!("dataplane-host-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for (file, text) in [
        (
            "sys/devices/virtual/dmi/id/board_asset_tag",
            "i-0123456789abcdef0\n",
        ),
        ("proc/sys/kernel/random/boot_id", "boot\n"),
    ] {
        let path = root.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    let host = Host {
        root: root.clone(),
        sys: root.join("sys"),
        proc: root.join("proc"),
        dev: root.join("dev"),
        ..Host::system()
    };
    (host, root)
}

/// The port attaches only from an inventory of this instance and boot that records an ENI, and the host's identity must be readable.
#[test]
fn only_a_current_inventory_with_an_eni_attaches() {
    let (host, root) = host();
    let current = mappings(false);
    assert_eq!(
        current_eni(&host, &current).unwrap().eni.bdf,
        "0000:00:06.0"
    );
    let mut other = mappings(false);
    other.instance = "i-0fffffffffffffff0".into();
    assert_eq!(
        current_eni(&host, &other).err(),
        Some(DataplaneError::Inventory("instance"))
    );
    let mut stale = mappings(false);
    stale.boot = "earlier".into();
    assert_eq!(
        current_eni(&host, &stale).err(),
        Some(DataplaneError::Inventory("boot"))
    );
    let mut volume_only = mappings(true);
    volume_only.eni = None;
    assert_eq!(
        current_eni(&host, &volume_only).err(),
        Some(DataplaneError::NoEni)
    );
    std::fs::remove_dir_all(&root).unwrap();
    assert_eq!(
        current_eni(&host, &current).err(),
        Some(DataplaneError::Inventory("host"))
    );
}
