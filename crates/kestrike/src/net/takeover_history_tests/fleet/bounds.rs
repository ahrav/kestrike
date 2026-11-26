//! [`Shape::check`] and [`requests`] enforce [`LIMITS`] on fleet runs before any draw or allocation.

use super::super::super::owner_tests::OWNER;
use super::topology::{Placing, Shape};

/// The largest fleet a run allocates: `objects` limits the objects per shard, `tenures` the tenures a run serves
/// across its shards, `requests` the GETs drawn for one crash episode, and `roles` the static roles bound a shape
/// names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    pub(crate) zones: u16,
    pub(crate) partitions: u32,
    pub(crate) hosts: u32,
    pub(crate) shards: u32,
    pub(crate) tenures: u32,
    pub(crate) objects: u8,
    pub(crate) reconcilers: u8,
    pub(crate) requests: u32,
    pub(crate) roles: u32,
}

/// `partitions`, `hosts` and `reconcilers` are per-zone limits. `requests` equals the requests the fixture owner
/// admits from one peer, so the owner answers no pressure when every draw of an episode names one shard and round.
pub(crate) const LIMITS: Limits = Limits {
    zones: 2,
    partitions: 7,
    hosts: 16,
    shards: 32,
    tenures: 128,
    objects: 50,
    reconcilers: 2,
    requests: OWNER.peer_requests,
    roles: 64,
};

/// A restart run serves at most two tenures per shard, one from its boot and one from its restart after the
/// crash, and a host scenario one from its boot and one from its takeover, since each script loses a shard's holder
/// once. The shard limit so keeps every checked shape within `LIMITS.tenures`; [`tenures`] refuses the repair
/// scenarios' slot count, which grows with the hosts.
const _: () = assert!(LIMITS.shards * 2 <= LIMITS.tenures);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    Zones(u16),
    Partitions(u32),
    Hosts(u32),
    Shards(u32),
    Objects(u8),
    Reconcilers(u8),
    Requests(u32),
    /// A repair scenario whose tenure slots fall outside `1..=LIMITS.tenures`.
    Tenures(u32),
    /// A fixed layout whose zone, host, partition or shard count differs from the layout's.
    Placing(Placing),
    /// A census cap outside `1..=shards`.
    Cap(u16),
    /// A roles bound outside `1..=LIMITS.roles`.
    RolesMax(u32),
    /// A host share outside `1..=SHARE_BYTES`, the design's share.
    ShareBytes(u64),
}

/// Refuses a tenure count outside `1..=LIMITS.tenures`: the tenure slots a repair scenario allocates, whose count
/// grows with its hosts.
pub(crate) fn tenures(count: u32) -> Result<(), Refused> {
    if !(1..=LIMITS.tenures).contains(&count) {
        return Err(Refused::Tenures(count));
    }
    Ok(())
}

/// Refuses a per-episode request count above `LIMITS.requests`. Zero is valid and draws no GET.
pub(crate) fn requests(count: u32) -> Result<(), Refused> {
    if count > LIMITS.requests {
        return Err(Refused::Requests(count));
    }
    Ok(())
}

impl Shape {
    /// `Shape::check` reports the first invalid `Shape` field in declaration order. Each zone needs at least two
    /// hosts for distinct owner and standby assignments and at most one partition per host. A fixed layout needs
    /// the counts it places, the self-suspicion threshold lies in `2..=hosts`, the census cap in `1..=shards` and the
    /// roles bound in `1..=LIMITS.roles`.
    pub(crate) fn check(&self) -> Result<(), Refused> {
        let within = |count: u64, limit: u64| (1..=limit).contains(&count);
        if !within(u64::from(self.zones), u64::from(LIMITS.zones)) {
            return Err(Refused::Zones(self.zones));
        }
        if !within(u64::from(self.partitions), u64::from(LIMITS.partitions))
            || self.partitions > self.hosts
        {
            return Err(Refused::Partitions(self.partitions));
        }
        if !(2..=LIMITS.hosts).contains(&self.hosts) {
            return Err(Refused::Hosts(self.hosts));
        }
        if !within(u64::from(self.shards), u64::from(LIMITS.shards)) {
            return Err(Refused::Shards(self.shards));
        }
        if !within(u64::from(self.objects), u64::from(LIMITS.objects)) {
            return Err(Refused::Objects(self.objects));
        }
        if !within(u64::from(self.reconcilers), u64::from(LIMITS.reconcilers)) {
            return Err(Refused::Reconcilers(self.reconcilers));
        }
        let counts = (self.zones, self.partitions, self.hosts, self.shards);
        if self.placing.counts().is_some_and(|placed| placed != counts) {
            return Err(Refused::Placing(self.placing));
        }
        if !(1..=self.shards).contains(&u32::from(self.cap)) {
            return Err(Refused::Cap(self.cap));
        }
        if !(1..=LIMITS.roles).contains(&self.roles_max) {
            return Err(Refused::RolesMax(self.roles_max));
        }
        if !(1..=super::SHARE_BYTES).contains(&self.share_bytes) {
            return Err(Refused::ShareBytes(self.share_bytes));
        }
        Ok(())
    }
}
