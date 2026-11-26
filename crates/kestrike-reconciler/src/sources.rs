//! The zone loop's three sources as one value, and the report source the service runs with.
//!
//! [`NoReports`] answers `Unreachable` for every host, the default the reconciler takes until a report transport
//! reaches it: each host the directory lists as active or draining reads `Unknown`, which no rule reads as lost, a
//! retired host reads `Lost` from its retirement alone, and the report source reads complete only when the directory
//! lists no host in the reconciler's zone.

use kestrike::failover::attachments::Unlisted;
use kestrike::failover::records::Host;
use kestrike::failover::standbys::Zone;
use kestrike::failover::zone_loop::evidence::Instance;
use kestrike::failover::zone_loop::sources::{
    InstanceSource, ListedVolume, ReportSource, Unreachable, VolumeSource,
};

/// The report source that answers `Unreachable` for every host.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoReports;

impl ReportSource for NoReports {
    fn latest(&mut self, _: Host) -> Result<Option<Vec<u8>>, Unreachable> {
        Err(Unreachable)
    }
}

/// The report, instance and volume sources one zone loop reads; each trait call goes to its own field.
#[derive(Debug)]
pub struct Sources<R, I, V> {
    pub reports: R,
    pub instances: I,
    pub volumes: V,
}

impl<R: ReportSource, I, V> ReportSource for Sources<R, I, V> {
    fn latest(&mut self, host: Host) -> Result<Option<Vec<u8>>, Unreachable> {
        self.reports.latest(host)
    }
}

impl<R, I: InstanceSource, V> InstanceSource for Sources<R, I, V> {
    fn instances(&mut self, zone: Zone) -> Result<Vec<Instance>, Unlisted> {
        self.instances.instances(zone)
    }
}

impl<R, I, V: VolumeSource> VolumeSource for Sources<R, I, V> {
    fn volumes(&mut self, zone: Zone) -> Result<Vec<ListedVolume>, Unlisted> {
        self.volumes.volumes(zone)
    }
}
