//! One endpoint's dataplane over its ENA port, composed in the order the
//! shared registration requires, for an owner, which runs the SPDK driver
//! in the same environment, and for a client.
//!
//! - [`allowed_devices`] lists the PCI devices the bind inventory recorded, the only
//!   ones the environment may attach.
//! - [`attach_port`] refuses an inventory from another instance or boot or
//!   without an ENI, then attaches the PMD's port at the recorded address,
//!   which must report the recorded MAC, and leases it from the
//!   registration. The caller maps and verifies the registration once every
//!   device attached.
//! - [`start_port`] requires the ENA's prefetchable BAR mapped write-combining
//!   by the recorded manifest's modules, as [`Host::check_wc_mapping`] checks it,
//!   then starts the port, which requires the verified registration, and
//!   returns the [`StartupReport`].
//! - [`stop_port`] proves the port's DMA off; its proof releases the packet
//!   mempools and then retires the port's lease, so the registration may
//!   undo.
//!
//! Datagrams to a peer leave from [`SOURCE_PORTS`] consecutive ports at this
//! host's base port, addressed to the peer's base port through the next-hop
//! MAC the inventory recorded.

use std::fmt;
use std::net::Ipv4Addr;
use std::sync::Arc;

use super::burst::{Port, Unproven};
use super::dma::DmaReport;
use super::ena::{EnaConfig, EnaPort, PortError, PortReport};
use super::env::{Environment, PciAddress};
use super::mempool::PacketMempool;
use super::registration::{ArenaRegistration, DeviceStopped};
use super::watchdog::Supervisor;
use super::wire::Station;
use crate::bind::{EniBinding, Host, Mappings, MappingsError, WcError, WcManifest};

/// Source ports per endpoint, from its base port.
pub const SOURCE_PORTS: u16 = 8;

/// What one role records when its port starts. The port's MTU is the
/// path's within the VPC, whose ENIs carry 9001-byte frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupReport {
    pub dma: DmaReport,
    pub port: PortReport,
    pub wc: WcManifest,
    pub instance: String,
    pub eni: String,
    pub bdf: String,
    /// The ENI's allowance-exceeded counters at start, where the driver exposes them.
    pub allowances: Option<[u64; 5]>,
    /// The host's supported-configuration arithmetic from
    /// [`envelope::check`](crate::net::envelope::check), printed on its own line after the measured values.
    /// [`start_port`] leaves it `None` for the caller to set.
    pub configuration: Option<crate::net::envelope::Arithmetic>,
}

impl fmt::Display for StartupReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (d, p) = (&self.dma, &self.port);
        let mac = p.mac.map(|b| format!("{b:02x}")).join(":");
        writeln!(
            f,
            "instance {} eni {} at {} mac {mac}",
            self.instance, self.eni, self.bdf
        )?;
        writeln!(
            f,
            "dma {:?} iova {:?} guest-iommu {} vfio-no-iommu {:?} pages {} of {} bytes verified {} translated {} bytes physical {} mappings {}",
            d.mode,
            d.iova_mode,
            d.guest_iommu,
            d.vfio_no_iommu,
            d.extent / d.page_size.max(1),
            d.page_size,
            d.verified_pages,
            d.translated_bytes,
            d.physical_pages,
            d.mappings
        )?;
        writeln!(
            f,
            "port {} mtu {} (max {}) rx-offloads {:#x} tx-offloads {:#x} rings rx {} tx {} segments {}",
            p.port,
            p.mtu,
            p.max_mtu,
            p.rx_offloads,
            p.tx_offloads,
            p.rx_ring,
            p.tx_ring,
            p.segments
        )?;
        writeln!(
            f,
            "data-room {} headroom {} llq entry {} push {} flr {}",
            p.data_room, p.headroom, p.llq.entry, p.llq.push, p.flr
        )?;
        write!(
            f,
            "wc kernel {} config {} patch {}",
            self.wc.kernel, self.wc.config_sha256, self.wc.patch
        )?;
        for module in &self.wc.modules {
            let file = module.file.display();
            write!(
                f,
                " {} {file} {} {}",
                module.name, module.srcversion, module.sha256
            )?;
        }
        writeln!(f)?;
        writeln!(f, "native {}", spdk_sys::PINS)?;
        write!(f, "allowances {:?}", self.allowances)?;
        if let Some(configuration) = &self.configuration {
            write!(f, "\n{configuration}")?;
        }
        Ok(())
    }
}

/// Why the dataplane did not attach or start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataplaneError {
    /// The inventory is from another instance or boot, the host's identity is unreadable, or it names another port.
    Inventory(&'static str),
    /// The inventory records no ENI.
    NoEni,
    Port(PortError),
    /// The ENA's write-combining mapping is not proven.
    Wc(WcError),
    /// A peer has no recorded next hop.
    Peer(Ipv4Addr),
}

pub(crate) fn pci_address(bdf: &str) -> Option<PciAddress> {
    let hex = |at: std::ops::Range<usize>| {
        bdf.get(at)
            .and_then(|text| u32::from_str_radix(text, 16).ok())
    };
    Some(PciAddress {
        domain: hex(0..4)?,
        bus: u8::try_from(hex(5..7)?).ok()?,
        device: u8::try_from(hex(8..10)?).ok()?,
        function: u8::try_from(hex(11..12)?).ok()?,
    })
}

/// The PCI devices the inventory recorded: the volume's controller, when present, then the ENI.
pub fn allowed_devices(mappings: &Mappings) -> Vec<PciAddress> {
    let nvme = mappings.nvme.iter().map(|n| n.bdf.as_str());
    let eni = mappings.eni.iter().map(|e| e.eni.bdf.as_str());
    nvme.chain(eni).filter_map(pci_address).collect()
}

/// This host's station at base port `port` and each peer's at its base
/// port, through the next-hop MAC the inventory recorded for its address.
///
/// # Errors
///
/// `NoEni`, or `Peer` naming the first peer without a recorded next hop.
pub fn stations(
    mappings: &Mappings,
    port: u16,
    peers: &[(Ipv4Addr, u16)],
) -> Result<(Station, Vec<Station>), DataplaneError> {
    let binding = mappings.eni.as_ref().ok_or(DataplaneError::NoEni)?;
    let local = Station {
        mac: binding.eni.mac,
        ip: binding.eni.ipv4.octets(),
        port,
        ports: SOURCE_PORTS,
    };
    let peers = peers
        .iter()
        .map(|&(ip, port)| {
            let (_, mac) = binding
                .next_hops
                .iter()
                .find(|(peer, _)| *peer == ip)
                .ok_or(DataplaneError::Peer(ip))?;
            Ok(Station {
                mac: *mac,
                ip: ip.octets(),
                port,
                ports: SOURCE_PORTS,
            })
        })
        .collect::<Result<_, _>>()?;
    Ok((local, peers))
}

/// The inventory's ENI, once the inventory is this host's, from this boot.
///
/// # Errors
///
/// `Inventory` naming the host, instance or boot check, or `NoEni`.
pub(crate) fn current_eni<'m>(
    host: &Host,
    mappings: &'m Mappings,
) -> Result<&'m EniBinding, DataplaneError> {
    let (instance, boot) = host
        .instance_and_boot()
        .ok_or(DataplaneError::Inventory("host"))?;
    mappings.check_current(&instance, &boot).map_err(|error| {
        DataplaneError::Inventory(match error {
            MappingsError::Instance => "instance",
            _ => "boot",
        })
    })?;
    mappings.eni.as_ref().ok_or(DataplaneError::NoEni)
}

/// Checks the inventory against the running host, then attaches and leases the recorded ENA port.
///
/// # Errors
///
/// `Inventory`, `NoEni`, or the port's refusal.
pub fn attach_port<'e>(
    env: &'e Environment,
    registration: &mut ArenaRegistration<'_>,
    host: &Host,
    mappings: &Mappings,
    rx_buffers: u32,
    supervisor: Arc<dyn Supervisor>,
) -> Result<EnaPort<'e>, DataplaneError> {
    let eni = &current_eni(host, mappings)?.eni;
    let config = EnaConfig {
        mac: eni.mac,
        rx_buffers,
    };
    EnaPort::attach(env, registration, host, &eni.bdf, config, supervisor)
        .map_err(DataplaneError::Port)
}

/// Proves the attached ENA's write-combining mapping, starts the port over `receive`, and reports.
///
/// # Errors
///
/// `NoEni`, `Wc` before anything starts, or the port's refusal.
pub fn start_port(
    port: &mut EnaPort<'_>,
    receive: &PacketMempool<'_>,
    registration: &ArenaRegistration<'_>,
    host: &Host,
    mappings: &Mappings,
) -> Result<StartupReport, DataplaneError> {
    let eni = &mappings.eni.as_ref().ok_or(DataplaneError::NoEni)?.eni;
    if eni.bdf != port.bdf() {
        return Err(DataplaneError::Inventory("port"));
    }
    host.check_wc_mapping(port.bdf(), &mappings.wc)
        .map_err(DataplaneError::Wc)?;
    port.start(receive, registration)
        .map_err(DataplaneError::Port)?;
    Ok(StartupReport {
        dma: registration.report(),
        port: port.report(),
        wc: mappings.wc.clone(),
        instance: mappings.instance.clone(),
        eni: eni.id.clone(),
        bdf: port.bdf().to_owned(),
        allowances: port.allowances(),
        configuration: None,
    })
}

/// Proves the port's DMA off and returns the stop proof, which releases
/// the packet mempools and then retires the port's lease from the
/// registration.
///
/// # Errors
///
/// [`Unproven`] when the stop is unproven, with the lease kept and the
/// supervisor asked to contain, or when this port's proof was already taken.
pub fn stop_port(port: &mut EnaPort<'_>) -> Result<DeviceStopped, Unproven> {
    port.stop()?;
    port.stop_proof().ok_or(Unproven)
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StopFailure {
    Unproven,
    Late,
}

#[cfg(test)]
pub(crate) fn stop_port_watched(
    port: &mut EnaPort<'_>,
    watchdog: &super::watchdog::Watchdog,
) -> Result<DeviceStopped, StopFailure> {
    let stopped = stop_port(port);
    if watchdog.expired() {
        return Err(StopFailure::Late);
    }
    stopped.map_err(|Unproven| StopFailure::Unproven)
}
