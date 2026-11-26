//! The sources of the host part's gauges and detector fields: pure functions over the inputs the host producer
//! supplies. A source reports [`Gauge::Unavailable`] when a required input is missing (NO-INVENTED-VALUES). The
//! standby census reads `recovery` for every new reservation and `attachments` when the reservation needs a new
//! attach, and refuses the reservation when either gauge it reads is unavailable or lacks room (HEADROOM).

use core::cmp::Ordering;
use core::num::NonZeroU64;

use super::{Detector, Gauge, Headroom, Members, RecoveryStatus};
use crate::bind::Mappings;
use crate::failover::detect::host::WatchCensus;
use crate::failover::records::VolumeId;
use crate::storage::{HostShare, Reading};

/// `ops` and `bytes` are one owner's cumulative totals across reads and writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCounts {
    pub volume: VolumeId,
    pub sequence: u64,
    pub ops: u64,
    pub bytes: u64,
}

impl DeviceCounts {
    pub fn of(volume: VolumeId, reading: &Reading) -> Option<Self> {
        let statistics = reading.outcome.as_ref().ok()?;
        Some(Self {
            volume,
            sequence: reading.sequence,
            ops: statistics.read_ops.saturating_add(statistics.write_ops),
            bytes: statistics.read_bytes.saturating_add(statistics.write_bytes),
        })
    }
}

/// Puts `items` in ascending order of their keys and returns whether every key occurs once. One pass that finds each
/// key above the one before it shows both, so items that arrive in ascending key order cost that pass alone; items
/// in any other order are sorted, with each comparison reading the two keys where they lie, and take the pass
/// again, which then fails exactly on two equal neighbors.
fn sort_distinct<T, K: Ord + ?Sized>(items: &mut [T], key: impl Fn(&T) -> &K) -> bool {
    let ascending = |items: &[T]| items.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]));
    ascending(items) || {
        items.sort_unstable_by(|a, b| key(a).cmp(key(b)));
        ascending(items)
    }
}

/// One seal's record of each owner's reading sequence and cumulative counts; `at_us` timestamps the seal on the
/// writer's elapsed clock. The owners ascend by volume and hold each volume once, which [`DeviceSample::of`]
/// establishes, so two samples hold the same volumes exactly when they hold equal volumes at each position.
///
/// A sample is measured when every owner has a successful reading and the sequence for each shared volume exceeds
/// its sequence in the previous sample. Only a measured sample ends a rate interval. Each seal uses the previous
/// sample as its sequence baseline, even after a reused, failed or missing reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSample {
    owners: Vec<DeviceCounts>,
    at_us: u64,
    measured: bool,
}

impl DeviceSample {
    /// `previous` supplies the per-volume sequence baseline. `DeviceSample::of` returns `None` when two owners name
    /// the same volume. It marks the sample measured only when every owner supplies a successful reading whose
    /// sequence exceeds any sequence `previous` holds for that volume; a repeated sequence identifies the same
    /// measurement. An owner with a failed reading holds zero counts under that reading's sequence. An owner with
    /// no reading holds zero counts under the sequence `previous` holds for its volume, or under 0 when `previous`
    /// holds none. The sample holds the owners in ascending volume order.
    pub fn of<'a>(
        owners: impl IntoIterator<Item = (VolumeId, Option<&'a Reading>)>,
        at_us: u64,
        previous: Option<&DeviceSample>,
    ) -> Option<Self> {
        // The map keeps the supplied iterator's size bound, so the vector is sized once and the loop pushes with no
        // capacity check.
        let mut complete = true;
        let counts: Vec<DeviceCounts> = owners
            .into_iter()
            .map(|(volume, reading)| {
                let counts = reading.and_then(|reading| DeviceCounts::of(volume, reading));
                complete &= counts.is_some();
                counts.unwrap_or(DeviceCounts {
                    volume,
                    sequence: reading.map_or(0, |reading| reading.sequence),
                    ops: 0,
                    bytes: 0,
                })
            })
            .collect();
        let mut sample = Self::ordered(counts, at_us)?;
        sample.measured = complete;
        // Both samples ascend by volume, so one pass over `previous` meets each volume the two share.
        let mut earlier = previous.map_or(&[][..], |previous| &previous.owners[..]);
        for now in &mut sample.owners {
            while let Some((before, later)) = earlier.split_first() {
                match before.volume.cmp(&now.volume) {
                    Ordering::Less => earlier = later,
                    Ordering::Equal if before.sequence >= now.sequence => {
                        sample.measured = false;
                        // Sequence 0 marks a missing owner reading at this seal, so the sample retains the sequence
                        // `previous` holds for the volume.
                        if now.sequence == 0 {
                            now.sequence = before.sequence;
                        }
                        break;
                    }
                    Ordering::Equal | Ordering::Greater => break,
                }
            }
        }
        Some(sample)
    }

    /// The sample of `owners` in ascending volume order, `None` when two of them name one volume.
    fn ordered(mut owners: Vec<DeviceCounts>, at_us: u64) -> Option<Self> {
        sort_distinct(&mut owners, |owner| &owner.volume).then_some(Self {
            owners,
            at_us,
            measured: true,
        })
    }

    /// The owners' counts, in ascending volume order.
    pub fn owners(&self) -> &[DeviceCounts] {
        &self.owners
    }

    pub fn at_us(&self) -> u64 {
        self.at_us
    }

    pub fn measured(&self) -> bool {
        self.measured
    }
}

/// The inputs of the five headroom gauges without a procfs source. Each limit is a validated configuration value or
/// `None` when unset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadroomInputs {
    /// The device sample of the same writer boot's previous seal, `None` in the boot's first report; each sample is
    /// `None` when [`DeviceSample::of`] built none.
    pub previous: Option<DeviceSample>,
    pub current: Option<DeviceSample>,
    /// The instance's provisioned operations and bytes per second.
    pub provisioned_iops: Option<NonZeroU64>,
    pub provisioned_bandwidth: Option<NonZeroU64>,
    /// The volumes the host holds attached, spares counted ([`attached`]), and the instance's attachment slots. The
    /// producer counts in `unbound` every attached volume outside the owner bind mappings, an attachment whose
    /// standby never enrolled included, so the gauge counts an attachment from the time it exists until its detach.
    pub attached: Option<u64>,
    pub attachment_slots: Option<NonZeroU64>,
    /// The owner-process roles in use, owned shards plus standby roles, and `host_roles_max`.
    pub roles: Option<u64>,
    pub host_roles_max: Option<NonZeroU64>,
    /// The volumes whose recovery holds a slot ([`recovering`]), and the configured recovery slots.
    pub recovering: Option<u64>,
    pub recovery_slots: Option<NonZeroU64>,
}

impl HeadroomInputs {
    pub const UNAVAILABLE: Self = Self {
        previous: None,
        current: None,
        provisioned_iops: None,
        provisioned_bandwidth: None,
        attached: None,
        attachment_slots: None,
        roles: None,
        host_roles_max: None,
        recovering: None,
        recovery_slots: None,
    };
}

/// `owner_rates` sums the owners' operation and byte deltas from `previous` to `current` separately, saturating each
/// sum at `u64::MAX`, and converts each to a per-second rate rounded down and capped at `u64::MAX`. `owner_rates`
/// returns `None` when either sample is unmeasured: a rate requires counts read for each sample's seal. It also
/// returns `None` when `current` is not later, the samples hold different volumes, an owner's reading is not newer,
/// or an owner's operation or byte count fell: a joined or departed owner's count over the interval is unknown, a
/// reused reading supplies no new measurement, and a counter decrease leaves the interval delta unknown. Each sample
/// holds its volumes once in ascending order, so the samples hold the same volumes exactly when they are equally
/// long and name equal volumes at each position.
fn owner_rates(previous: &DeviceSample, current: &DeviceSample) -> Option<(u64, u64)> {
    if !(previous.measured && current.measured) {
        return None;
    }
    let elapsed = current
        .at_us
        .checked_sub(previous.at_us)
        .filter(|&us| us > 0)?;
    if current.owners.len() != previous.owners.len() {
        return None;
    }
    let (mut ops, mut bytes) = (0u64, 0u64);
    for (before, now) in previous.owners.iter().zip(&current.owners) {
        if now.volume != before.volume || now.sequence <= before.sequence {
            return None;
        }
        ops = ops.saturating_add(now.ops.checked_sub(before.ops)?);
        bytes = bytes.saturating_add(now.bytes.checked_sub(before.bytes)?);
    }
    // A delta whose product with 1_000_000 fits `u64` divides in one machine division; a larger one takes the
    // 128-bit quotient, which a library routine computes. Both round down to the same rate.
    let per_second = |delta: u64| match delta.checked_mul(1_000_000) {
        Some(scaled) => scaled / elapsed,
        None => {
            u64::try_from(u128::from(delta) * 1_000_000 / u128::from(elapsed)).unwrap_or(u64::MAX)
        }
    };
    Some((per_second(ops), per_second(bytes)))
}

/// `used` slots of `limit`, saturating at the limit so an over-committed host reads full; unavailable when either
/// input is missing.
fn slots(used: Option<u64>, limit: Option<NonZeroU64>) -> Gauge {
    used.zip(limit).map_or(Gauge::Unavailable, |(used, limit)| {
        Gauge::known(used.min(limit.get()), limit.get())
    })
}

/// `attached` counts the host's owner bind mappings that record an NVMe controller and adds `unbound`, the attached
/// volumes outside the owner bind mappings, such as spares. `attached` returns `None` if any `mappings` item or
/// `unbound` is `None`, or if two mappings record the same volume, which [`sort_distinct`] finds among the recorded
/// volume names.
pub fn attached<'a>(
    mappings: impl IntoIterator<Item = Option<&'a Mappings>>,
    unbound: Option<u64>,
) -> Option<u64> {
    let mappings = mappings.into_iter();
    let mut volumes = Vec::with_capacity(mappings.size_hint().0);
    for mapping in mappings {
        if let Some(nvme) = &mapping?.nvme {
            volumes.push(nvme.volume.as_str());
        }
    }
    if !sort_distinct(&mut volumes, |volume| *volume) {
        return None;
    }
    (volumes.len() as u64).checked_add(unbound?)
}

/// `recovering` counts the volumes that hold a recovery slot, saturating at `u64::MAX`. Each item pairs a volume's
/// recovery status with a flag that is true while the volume's attach has ticked and reached neither Live nor a
/// terminal end. A volume counts when its last attempt holds a slot ([`RecoveryStatus::holds_slot`]) or its flag is
/// true. `recovering` returns `None` if any item is `None`, a volume whose status or attach state is missing.
pub fn recovering<'a>(
    volumes: impl IntoIterator<Item = Option<(&'a RecoveryStatus, bool)>>,
) -> Option<u64> {
    volumes.into_iter().try_fold(0u64, |sum, volume| {
        volume.map(|(status, attach_before_live)| {
            sum.saturating_add(u64::from(status.holds_slot() || attach_before_live))
        })
    })
}

/// Assigned volumes with no fresh entry from their owner process, of the assigned volumes, 0 of 0 for a host
/// assigned none; `fresh` holds one flag per assigned volume.
pub fn producer_missing(fresh: impl IntoIterator<Item = bool>) -> Members {
    let (missing, assigned) = fresh
        .into_iter()
        .fold((0u64, 0u64), |(missing, assigned), fresh| {
            (
                missing.saturating_add(u64::from(!fresh)),
                assigned.saturating_add(1),
            )
        });
    Members::Known {
        used: missing,
        limit: assigned,
    }
}

/// The sum of the recovery I/O peaks of the owners whose attach built a share, of twice the host share's bytes per
/// interval. One `Gauge::Unavailable` peak makes the aggregate unavailable, and so does a share that
/// [`HostShare::part`] refuses.
pub fn host_recovery_io(peaks: impl IntoIterator<Item = Gauge>, share: HostShare) -> Gauge {
    if share.part(0).is_none() {
        return Gauge::Unavailable;
    }
    let sum = peaks.into_iter().try_fold(0u64, |sum, peak| match peak {
        Gauge::Known { used, .. } => Some(sum.saturating_add(used)),
        Gauge::Unavailable => None,
    });
    slots(sum, NonZeroU64::new(share.bytes.saturating_mul(2)))
}

impl Detector {
    /// The host part's detector fields from `census`: the suspected of the tracked peers, the self-suspicion dwell
    /// left at the last tick, and the nominations since the start.
    pub fn of(census: &WatchCensus) -> Self {
        Self {
            peers: Members::Known {
                used: census.suspected as u64,
                limit: census.tracked as u64,
            },
            self_suspect_us: census.suspect_left,
            nominations: Some(census.nominations),
        }
    }
}

impl Headroom {
    /// The headroom of the `ram` and `cpu_load` readings and the gauges `inputs` give.
    pub fn of(ram: Gauge, cpu_load: Gauge, inputs: &HeadroomInputs) -> Self {
        let i = inputs;
        let (iops, bandwidth) = i
            .previous
            .as_ref()
            .zip(i.current.as_ref())
            .and_then(|(previous, current)| owner_rates(previous, current))
            .unzip();
        Self {
            ram,
            cpu_load,
            iops: slots(iops, i.provisioned_iops),
            bandwidth: slots(bandwidth, i.provisioned_bandwidth),
            attachments: slots(i.attached, i.attachment_slots),
            workers: slots(i.roles, i.host_roles_max),
            recovery: slots(i.recovering, i.recovery_slots),
        }
    }
}

#[cfg(test)]
#[path = "headroom_tests.rs"]
mod tests;
