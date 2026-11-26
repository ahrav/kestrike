//! The fleet's topology: zones of hosts, each host in one placement partition of its zone, and shards, each with a
//! volume of its own in one zone, an owner host and a named standby host of that zone. Under [`Placing::Drawn`],
//! [`Topology::draw`] places the shards by the run's decisions: an owner among the zone's hosts that own the fewest
//! shards, then a standby among the zone's other hosts that stand by for the fewest, outside the owner's partition
//! when such a host exists. Under [`Placing::Small`], [`Placing::Tiny`], [`Placing::Az`] and [`Placing::Trio`] it
//! builds the fixed `small`, `tiny`, `az` and `trio` layouts with no decision.

use crate::failover::arbiter::Partition;
use crate::failover::attachments::InstanceId;
use crate::failover::records::{Host, VolumeId};
use crate::failover::standbys::Zone;
use crate::net::ownership::Shard;

use super::draws::{self, Draws, Refusal, Tag};

/// A fleet's counts: `partitions`, `hosts` and `reconcilers` per zone, `objects` per shard, and how the shards are
/// placed. `cap` limits the number of shards each zone's standby census lists. `roles_max` is the one static bound
/// on a host's roles, owned shards and census entries together: it divides the host's recovery share in a
/// reconciler scenario and sets the zone directory's `host_roles_max`.
/// `share_bytes` is each host's recovery device bytes per share interval (`HostShare::bytes`), which the host's
/// owners divide: [`SHARE_BYTES`](super::SHARE_BYTES) in every layout but the limited one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Shape {
    pub(crate) zones: u16,
    pub(crate) partitions: u32,
    pub(crate) hosts: u32,
    pub(crate) shards: u32,
    pub(crate) objects: u8,
    pub(crate) reconcilers: u8,
    pub(crate) placing: Placing,
    pub(crate) cap: u16,
    pub(crate) roles_max: u32,
    pub(crate) share_bytes: u64,
}

/// How [`Topology::draw`] places the shards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Placing {
    /// Least-loaded owners and standbys by the run's decisions; host `j` of a zone sits in partition
    /// `j % partitions`.
    Drawn,
    /// The `small` layout: one zone of six hosts in the partitions (H0, H1), (H2, H3), (H4) and (H5), and six
    /// shards placed owner to standby s0 H0 to H3, s1 H0 to H3, s2 H0 to H5, s3 H3 to H0, s4 H2 to H5 and
    /// s5 H4 to H1. After the loss of s0's or s3's owner and standby (H0 and H3), or of s5's (H4 and H1), every
    /// surviving host keeps probers in two partitions other than the lost owner's; after the loss of H0 and H5, or
    /// of H2 and H5, H4 keeps probers in one.
    Small,
    /// The `tiny` layout: one zone of four hosts in the partitions (H0), (H1, H2) and (H3), and two shards placed
    /// s0 H0 to H1 and s1 H3 to H2. After a double loss a survivor keeps one prober partition, so no fresh host of
    /// `tiny` gathers a detector quorum.
    Tiny,
    /// The `az` layout: zone 1 holds the `small` layout and zone 2 four hosts and two shards placed as `tiny`, so
    /// `Shape::hosts` counts zone 1's six hosts and zone 2 holds four.
    Az,
    /// The `trio` layout: one zone of eight hosts in the partitions (H0, H1, H2), (H3, H4), (H5, H6) and (H7), and six
    /// shards placed owner to standby s0 H0 to H3, s1 H1 to H5, s2 H4 to H2, s3 H5 to H7, s4 H6 to H4 and s5 H7 to
    /// H3. The first partition is the zone's largest and holds three hosts, so its loss reaches the host agent's
    /// self-suspicion threshold (`host::agent::SELF_SUSPECT`, 3) and stays within the zone loop's host hold, which
    /// counts lost hosts beyond the largest partition. Every shard with a host in it keeps its other host outside it,
    /// and after its loss every survivor keeps probers in two partitions other than the lost one. H2 holds a standby
    /// role alone, so the designation that replaces s2's standby drops it from every record.
    Trio,
}

impl Placing {
    /// The `small` layout's partition of each host, and its placements as owner and standby host indices.
    pub(crate) const SMALL_PARTITIONS: [u32; 6] = [0, 0, 1, 1, 2, 3];
    pub(crate) const SMALL: [(usize, usize); 6] = [(0, 3), (0, 3), (0, 5), (3, 0), (2, 5), (4, 1)];
    pub(crate) const TINY_PARTITIONS: [u32; 4] = [0, 1, 1, 2];
    pub(crate) const TINY: [(usize, usize); 2] = [(0, 1), (3, 2)];
    pub(crate) const TRIO_PARTITIONS: [u32; 8] = [0, 0, 0, 1, 1, 2, 2, 3];
    pub(crate) const TRIO: [(usize, usize); 6] = [(0, 3), (1, 5), (4, 2), (5, 7), (6, 4), (7, 3)];
    /// The hosts of the `trio` layout's largest partition, whose loss the at-threshold partition arms run.
    pub(crate) const TRIO_LOST: [usize; 3] = [0, 1, 2];

    /// The zone, partition, host and shard counts a fixed layout places, or `None` for a drawn one.
    pub(crate) fn counts(self) -> Option<(u16, u32, u32, u32)> {
        match self {
            Self::Drawn => None,
            Self::Small => Some((1, 4, 6, 6)),
            Self::Tiny => Some((1, 3, 4, 2)),
            Self::Az => Some((2, 4, 6, 8)),
            Self::Trio => Some((1, 4, 8, 6)),
        }
    }

    /// The identity's code of the placing.
    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Drawn => 0,
            Self::Small => 1,
            Self::Tiny => 2,
            Self::Az => 3,
            Self::Trio => 4,
        }
    }

    /// The hosts of `zone` under `shape`: `Shape::hosts` in every zone, and in zone 2 of `az` the four of `tiny`.
    fn zone_hosts(self, shape: &Shape, zone: u16) -> u32 {
        match (self, zone) {
            (Self::Az, 2) => Self::TINY_PARTITIONS.len() as u32,
            _ => shape.hosts,
        }
    }

    /// Host `j`'s partition in `zone` of a fixed layout.
    fn partition(self, zone: u16, j: u32, partitions: u32) -> u32 {
        match (self, zone) {
            (Self::Drawn, _) => j % partitions,
            (Self::Small, _) | (Self::Az, 1) => Self::SMALL_PARTITIONS[j as usize],
            (Self::Tiny, _) | (Self::Az, _) => Self::TINY_PARTITIONS[j as usize],
            (Self::Trio, _) => Self::TRIO_PARTITIONS[j as usize],
        }
    }

    /// Shard `i`'s zone, owner and standby in a fixed layout. Zone 2 of `az` places `tiny`'s shards on its own hosts,
    /// which follow zone 1's six.
    fn fixed(self, i: usize) -> (Zone, (usize, usize)) {
        let small = Self::SMALL.len();
        match self {
            Self::Az if i >= small => {
                let (owner, standby) = Self::TINY[i - small];
                (Zone(2), (owner + small, standby + small))
            }
            Self::Tiny => (Zone(1), Self::TINY[i]),
            Self::Trio => (Zone(1), Self::TRIO[i]),
            _ => (Zone(1), Self::SMALL[i]),
        }
    }
}

impl Shape {
    /// The hosts of every zone together.
    pub(crate) fn members(&self) -> u32 {
        let hosts = (1..=self.zones).map(|zone| self.placing.zone_hosts(self, zone));
        hosts.fold(0, u32::saturating_add)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Member {
    pub(crate) host: Host,
    pub(crate) zone: Zone,
    pub(crate) partition: Partition,
    pub(crate) instance: InstanceId,
}

/// `owner` and `standby` index [`Topology::members`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Placement {
    pub(crate) shard: Shard,
    pub(crate) zone: Zone,
    pub(crate) volume: VolumeId,
    pub(crate) owner: usize,
    pub(crate) standby: usize,
}

#[derive(Clone, Copy)]
enum Role {
    Owner,
    /// The standby of the shard the member at this index owns.
    StandbyOf(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Topology {
    pub(crate) members: Vec<Member>,
    pub(crate) placements: Vec<Placement>,
}

impl Topology {
    /// Places every shard of a shape that `Shape::check` accepted.
    ///
    /// # Errors
    ///
    /// A refused decision leaves its shard unplaced.
    pub(super) fn draw(shape: &Shape, draws: &mut Draws) -> Result<Self, Refusal> {
        let mut members = Vec::new();
        for zone in 1..=shape.zones {
            for j in 0..shape.placing.zone_hosts(shape, zone) {
                let value = u64::from(zone) * 1000 + u64::from(j) + 1;
                let partition = shape.placing.partition(zone, j, shape.partitions);
                let host = Host::new(value).expect("a nonzero host");
                members.push(Member {
                    host,
                    zone: Zone(zone),
                    partition: Partition(partition),
                    instance: crate::failover::sim::instance_of_host(host),
                });
            }
        }
        let mut topology = Self {
            members,
            placements: Vec::new(),
        };
        for i in 0..shape.shards {
            let (zone, (owner, standby)) = match shape.placing {
                Placing::Drawn => {
                    let zone = Zone(1 + (i % u32::from(shape.zones)) as u16);
                    let owner = topology.least(zone, Role::Owner, draws)?;
                    (
                        zone,
                        (owner, topology.least(zone, Role::StandbyOf(owner), draws)?),
                    )
                }
                fixed => fixed.fixed(i as usize),
            };
            topology.placements.push(Placement {
                shard: Shard::new(i + 1).expect("a nonzero shard"),
                zone,
                volume: VolumeId::new(&format!("vol-0f{:015x}", i + 1)).expect("a volume ID"),
                owner,
                standby,
            });
        }
        Ok(topology)
    }

    /// The member of `zone` the decision picks among those that hold the fewest placements in `role`. A standby
    /// comes from the hosts other than its owner, and outside the owner's partition when such a host exists.
    fn least(&self, zone: Zone, role: Role, draws: &mut Draws) -> Result<usize, Refusal> {
        let held = |at: usize| {
            (self.placements.iter())
                .filter(|p| match role {
                    Role::Owner => p.owner == at,
                    Role::StandbyOf(_) => p.standby == at,
                })
                .count()
        };
        let (site, owner) = match role {
            Role::Owner => (draws::OWNER, None),
            Role::StandbyOf(owner) => (draws::STANDBY, Some(owner)),
        };
        let mut eligible: Vec<usize> = (0..self.members.len())
            .filter(|&at| self.members[at].zone == zone && Some(at) != owner)
            .collect();
        if let Some(owner) = owner {
            let partition = self.members[owner].partition;
            let apart: Vec<usize> = (eligible.iter().copied())
                .filter(|&at| self.members[at].partition != partition)
                .collect();
            if !apart.is_empty() {
                eligible = apart;
            }
        }
        let fewest = eligible
            .iter()
            .map(|&at| held(at))
            .min()
            .expect("a zone of two hosts");
        eligible.retain(|&at| held(at) == fewest);
        let values: Vec<u64> = (eligible.iter())
            .map(|&at| self.members[at].host.get())
            .collect();
        Ok(eligible[draws.pick(site, Tag::Host, &values)?])
    }

    /// Both owner and standby assignments count toward `member`'s roles.
    pub(crate) fn roles(&self, member: usize) -> u32 {
        (self.placements.iter())
            .filter(|p| p.owner == member || p.standby == member)
            .count() as u32
    }
}
