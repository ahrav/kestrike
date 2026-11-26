//! The zone's fleet directory: a versioned list of hosts, each with its instance, placement and directory state, and
//! of the zone's shards, with the zone hold and the host roles limit, and the derived keys of one projection.
//!
//! - DERIVED-KEYS-ONLY: each projection holds one key of each of its own kinds per listed host. The host projection
//!   ([`HostProjection`]) holds the heartbeat key and the probe key of every listed host, which a host's agent
//!   verifies its peers' heartbeats and probe messages with; the reconciler projection ([`ReconcilerProjection`])
//!   holds the report key of every listed host, which reports are verified with. Each projection refuses a key
//!   tagged with the other's kinds and a key value an earlier key of the same listing holds, and neither type has a
//!   field for a host key. The directory checks tags and values within one listing, not derivation and not key
//!   history: the distribution that builds each [`DerivedKey`] derives it from the listed host's own host key
//!   ([`BeatKey::derive`], [`ProbeKey::derive`], [`ReportKey::derive`]), never gives one host's key to another host
//!   in any version, and hands each holder only its projection. Under that premise a host holds no other host's
//!   report key and cannot seal that host's reports, and the reconciler holds no heartbeat or probe key. The keys
//!   are symmetric, so a projection's holder can seal the messages its own key set authenticates: the reconciler
//!   projection's holder can seal reports of every listed host, those of other zones included, and a host agent can
//!   seal heartbeats and probe messages of every listed host. A projection's `Debug` lists host numbers and prints
//!   no key.
//! - ONE-IDENTITY: a directory lists each host number, each instance and each shard once, and every shard in the
//!   directory's zone. [`Directory::succeeds`] admits a later directory only at a higher version of the same zone
//!   that lists every host the earlier one listed, each with the instance and the zone it named before and a retired
//!   host still retired. Each version lists an instance once, so no earlier host's instance moves to another host
//!   either. A retired host stays listed and retired, so a host number never names a second instance and an instance
//!   never serves a second host number in a chain of admitted versions. Retired hosts and hosts of other zones count
//!   toward [`MAX_HOSTS`], so the bound caps every host number a chain ever lists.
//! - `host_roles_max` is 1 to [`MAX_ENTRIES`]: the most roles one host holds, owned shards and census entries
//!   together, and the owner count a host's recovery share divides over, at most one per host report entry. The
//!   directory checks the range only; a later version may name another value, and an owner keeps the divisor it
//!   attached under.
//!
//! A directory lists the fleet's hosts, those of other zones included, with the keys of each. Every shard it lists
//! is of its own zone. [`Directory::zone_hosts`] and [`Directory::largest_partition`] read only the hosts of the
//! directory's zone; the projection holds the keys of every listed host.

use core::num::NonZeroU32;
use std::collections::{BTreeMap, BTreeSet};

use subtle::ConstantTimeEq;

use crate::failover::arbiter::Partition;
use crate::failover::attachments::InstanceId;
use crate::failover::detect::beat::BeatKey;
use crate::failover::detect::probe::ProbeKey;
use crate::failover::records::{Host, Layout, LayoutRefusal};
use crate::failover::report::{MAX_ENTRIES, ReportKey};
use crate::failover::standbys::{MAX_SLOTS, Zone};
use crate::net::ownership::Shard;

/// The most hosts a directory lists, retired hosts and hosts of other zones included.
pub const MAX_HOSTS: usize = 4096;

/// A deploy color: the hosts a deploy wave restarts together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Color(pub u16);

/// The operator's setting for a host in the fleet's directory: which roles it may hold. A state is no evidence that
/// the host is alive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryState {
    /// The host may take new roles.
    Active,
    /// The host keeps the roles it holds and takes no new one.
    Draining,
    /// The operator retired the host: it stays listed and retired, and a directory retirement is a host loss.
    Retired,
}

/// A host's placement: its zone, its placement partition and its deploy color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placement {
    pub zone: Zone,
    pub partition: Partition,
    pub color: Color,
}

/// One listed host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostEntry {
    pub host: Host,
    pub instance: InstanceId,
    pub placement: Placement,
    pub state: DirectoryState,
}

/// One shard of the zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardEntry {
    pub shard: Shard,
    pub zone: Zone,
    /// The listing reports the layout of the shard's existing volumes. The zone's `ZoneConfig::replacement` is the
    /// layout for replacement volumes.
    pub layout: Layout,
}

/// A key as the directory's distribution carries it, tagged with its kind. The distribution derives it from the
/// host's own host key; the directory reads the tag and the value.
#[derive(Clone, Copy)]
pub enum DerivedKey {
    Heartbeat(BeatKey),
    Probe(ProbeKey),
    Report(ReportKey),
}

/// A directory's contents before [`Directory::new`] checks them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    pub version: u64,
    pub zone: Zone,
    /// The operator's hold on the zone: no new attach, and no replacement step past the correlated hold's write and
    /// the retirement of a displaced volume.
    pub zone_hold: bool,
    pub host_roles_max: u32,
    pub hosts: Vec<HostEntry>,
    pub shards: Vec<ShardEntry>,
}

/// Why [`Directory::new`] refused a listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryRefusal {
    /// More than [`MAX_HOSTS`] hosts, a key list longer than [`MAX_HOSTS`] times the projection's key kinds, or more
    /// than [`MAX_SLOTS`] shards.
    TooMany,
    /// `host_roles_max` is zero or above [`MAX_ENTRIES`].
    RolesMax,
    DuplicateHost(Host),
    /// The host's instance is listed for another host too.
    DuplicateInstance(Host),
    DuplicateShard(Shard),
    /// The shard belongs to another zone than the directory's.
    ForeignShard(Shard),
    /// The shard's layout fails [`Layout::check_floor`].
    Layout(Shard, LayoutRefusal),
    /// The host lacks a key of one of the projection's kinds.
    MissingKey(Host),
    /// The key is tagged with a kind of the other projection.
    ForeignKey(Host),
    /// The host has two keys of one kind.
    DuplicateKey(Host),
    /// The host's key value is also the value of an earlier entry of the key list, of another host or kind.
    SharedKey(Host),
    /// The key names a host the directory does not list.
    UnlistedKey(Host),
}

/// Why [`Directory::succeeds`] refused a later directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuccessionRefusal {
    /// The later directory is of another zone.
    Zone,
    /// The later directory's version is not above the earlier one's.
    Version,
    /// The earlier directory listed the host and the later one does not.
    Departed(Host),
    /// The earlier directory listed the host retired and the later one does not.
    Unretired(Host),
    /// The host names another instance than in the earlier directory.
    Reassigned(Host),
    /// The host names its earlier instance in another zone than in the earlier directory.
    Rezoned(Host),
}

impl DerivedKey {
    fn bytes(&self) -> [u8; 32] {
        match self {
            Self::Heartbeat(key) => key.0,
            Self::Probe(key) => key.0,
            Self::Report(key) => key.0,
        }
    }
}

mod sealed {
    use super::{DerivedKey, DirectoryRefusal, Host};

    /// The permission to build a projection. Only the directory module can make one.
    pub struct Permit(pub(super) ());

    /// The constructor of a projection. Calling it takes a [`Permit`], which only [`super::Directory::new`] makes,
    /// so every projection is one that `Directory::new` built and checked against its listing.
    pub trait Sealed: Sized {
        /// The key kinds the projection holds per listed host.
        const KINDS: usize;

        /// The projection holding `keys`.
        ///
        /// # Errors
        ///
        /// In list order: [`DirectoryRefusal::ForeignKey`] for a key of another projection's kind,
        /// [`DirectoryRefusal::DuplicateKey`] for a host's second key of one kind, and [`DirectoryRefusal::SharedKey`]
        /// for a key value an earlier key holds; then [`DirectoryRefusal::MissingKey`] for the lowest host that holds
        /// a key of one of the projection's kinds and not of another.
        fn project(keys: Vec<(Host, DerivedKey)>, permit: Permit)
        -> Result<Self, DirectoryRefusal>;
    }
}

/// One projection's key set: one key of each of its kinds per listed host. Only [`HostProjection`] and
/// [`ReconcilerProjection`] implement it, and only [`Directory::new`] builds one.
///
/// The trait is in scope through the module's items, so its own methods are callable:
///
/// ```
/// use kestrike::failover::zone_loop::directory::*;
/// fn listed<P: Projection>(keys: &P) -> usize {
///     keys.hosts().count()
/// }
/// ```
///
/// A projection cannot be built by name or through a bound:
///
/// ```compile_fail,E0599
/// use kestrike::failover::zone_loop::directory::*;
/// let _ = HostProjection::project(Vec::new());
/// ```
///
/// ```compile_fail
/// use kestrike::failover::zone_loop::directory::*;
/// fn build<P: Projection>() {
///     let _ = P::project(Vec::new());
/// }
/// ```
pub trait Projection: sealed::Sealed {
    /// The hosts the projection holds a key of, ascending.
    fn hosts(&self) -> impl Iterator<Item = Host>;
}

/// A host agent's projection: every listed host's heartbeat key and probe key. Its `Debug` lists host numbers only.
#[derive(Clone)]
pub struct HostProjection {
    heartbeats: BTreeMap<Host, BeatKey>,
    probes: BTreeMap<Host, ProbeKey>,
}

/// The reconciler's projection: every listed host's report key. Its `Debug` lists host numbers only.
#[derive(Clone)]
pub struct ReconcilerProjection {
    reports: BTreeMap<Host, ReportKey>,
}

/// Checks `keys` in list order: `place` keeps each key or refuses it, then a key value an earlier key holds is
/// [`DirectoryRefusal::SharedKey`].
fn collect_keys(
    keys: Vec<(Host, DerivedKey)>,
    mut place: impl FnMut(Host, DerivedKey) -> Result<(), DirectoryRefusal>,
) -> Result<(), DirectoryRefusal> {
    let mut values = BTreeSet::new();
    for (host, key) in keys {
        let bytes = key.bytes();
        place(host, key)?;
        if !values.insert(bytes) {
            return Err(DirectoryRefusal::SharedKey(host));
        }
    }
    Ok(())
}

/// Keeps `key` as `host`'s key of one kind, refusing a second one.
fn first<K>(held: &mut BTreeMap<Host, K>, host: Host, key: K) -> Result<(), DirectoryRefusal> {
    match held.insert(host, key) {
        None => Ok(()),
        Some(_) => Err(DirectoryRefusal::DuplicateKey(host)),
    }
}

impl sealed::Sealed for HostProjection {
    const KINDS: usize = 2;
    fn project(keys: Vec<(Host, DerivedKey)>, _: sealed::Permit) -> Result<Self, DirectoryRefusal> {
        let (mut heartbeats, mut probes) = (BTreeMap::new(), BTreeMap::new());
        collect_keys(keys, |host, key| match key {
            DerivedKey::Heartbeat(key) => first(&mut heartbeats, host, key),
            DerivedKey::Probe(key) => first(&mut probes, host, key),
            DerivedKey::Report(_) => Err(DirectoryRefusal::ForeignKey(host)),
        })?;
        let unpaired = (heartbeats.keys())
            .filter(|host| !probes.contains_key(host))
            .chain(probes.keys().filter(|host| !heartbeats.contains_key(host)))
            .min();
        match unpaired {
            Some(host) => Err(DirectoryRefusal::MissingKey(*host)),
            None => Ok(Self { heartbeats, probes }),
        }
    }
}

impl Projection for HostProjection {
    fn hosts(&self) -> impl Iterator<Item = Host> {
        self.heartbeats.keys().copied()
    }
}

impl sealed::Sealed for ReconcilerProjection {
    const KINDS: usize = 1;
    fn project(keys: Vec<(Host, DerivedKey)>, _: sealed::Permit) -> Result<Self, DirectoryRefusal> {
        let mut reports = BTreeMap::new();
        collect_keys(keys, |host, key| match key {
            DerivedKey::Report(key) => first(&mut reports, host, key),
            DerivedKey::Heartbeat(_) | DerivedKey::Probe(_) => {
                Err(DirectoryRefusal::ForeignKey(host))
            }
        })?;
        Ok(Self { reports })
    }
}

impl Projection for ReconcilerProjection {
    fn hosts(&self) -> impl Iterator<Item = Host> {
        self.reports.keys().copied()
    }
}

impl HostProjection {
    pub fn heartbeat(&self, host: Host) -> Option<BeatKey> {
        self.heartbeats.get(&host).copied()
    }

    pub fn probe(&self, host: Host) -> Option<ProbeKey> {
        self.probes.get(&host).copied()
    }
}

impl ReconcilerProjection {
    /// The report key of `host`: a lookup in memory that grows nothing on a miss, as `Reader::accept` requires.
    pub fn report(&self, host: Host) -> Option<ReportKey> {
        self.reports.get(&host).copied()
    }

    fn same_key(&self, other: &Self, host: Host) -> bool {
        match (self.reports.get(&host), other.reports.get(&host)) {
            (Some(key), Some(other)) => bool::from(key.0.ct_eq(&other.0)),
            _ => false,
        }
    }
}

impl core::fmt::Debug for HostProjection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_set().entries(self.hosts()).finish()
    }
}

impl core::fmt::Debug for ReconcilerProjection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_set().entries(self.hosts()).finish()
    }
}

/// Refuses the lowest host without a key in `keys`, or the lowest key whose host `hosts` does not list. `hosts` is
/// ascending with no host twice, as [`Directory::new`] leaves it.
fn covered<P: Projection>(hosts: &[HostEntry], keys: &P) -> Result<(), DirectoryRefusal> {
    let mut keyed = keys.hosts();
    for entry in hosts {
        match keyed.next() {
            Some(host) if host == entry.host => {}
            Some(host) if host < entry.host => return Err(DirectoryRefusal::UnlistedKey(host)),
            _ => return Err(DirectoryRefusal::MissingKey(entry.host)),
        }
    }
    match keyed.next() {
        Some(host) => Err(DirectoryRefusal::UnlistedKey(host)),
        None => Ok(()),
    }
}

/// A checked directory with the keys of projection `P`. Hosts and shards are held ascending by number.
#[derive(Debug, Clone)]
pub struct Directory<P> {
    version: u64,
    zone: Zone,
    zone_hold: bool,
    host_roles_max: NonZeroU32,
    hosts: Vec<HostEntry>,
    shards: Vec<ShardEntry>,
    keys: P,
}

impl<P: Projection> Directory<P> {
    /// The directory `listing` states, with the projection of `keys`.
    ///
    /// # Errors
    ///
    /// In order: [`DirectoryRefusal::TooMany`], [`DirectoryRefusal::RolesMax`], a duplicate host, then a duplicate
    /// instance, then for the lowest-numbered failing shard [`DirectoryRefusal::DuplicateShard`],
    /// [`DirectoryRefusal::ForeignShard`] or [`DirectoryRefusal::Layout`], whichever applies first, then in key list
    /// order a foreign, duplicate or shared key, then [`DirectoryRefusal::MissingKey`] for the lowest host that holds
    /// a key of one of the projection's kinds and not of another, then [`DirectoryRefusal::MissingKey`] or
    /// [`DirectoryRefusal::UnlistedKey`] for the lowest host without a key or a key without a host. The key list holds
    /// at most [`MAX_HOSTS`] times the projection's key kinds.
    pub fn new(listing: Listing, keys: Vec<(Host, DerivedKey)>) -> Result<Self, DirectoryRefusal> {
        let Listing {
            version,
            zone,
            zone_hold,
            host_roles_max,
            mut hosts,
            mut shards,
        } = listing;
        if hosts.len() > MAX_HOSTS || keys.len() > MAX_HOSTS * P::KINDS || shards.len() > MAX_SLOTS
        {
            return Err(DirectoryRefusal::TooMany);
        }
        let host_roles_max = NonZeroU32::new(host_roles_max)
            .filter(|max| max.get() as usize <= MAX_ENTRIES)
            .ok_or(DirectoryRefusal::RolesMax)?;
        hosts.sort_by_key(|entry| entry.host);
        if let Some(pair) = hosts.windows(2).find(|pair| pair[0].host == pair[1].host) {
            return Err(DirectoryRefusal::DuplicateHost(pair[0].host));
        }
        let mut instances = BTreeSet::new();
        if let Some(entry) = hosts.iter().find(|entry| !instances.insert(entry.instance)) {
            return Err(DirectoryRefusal::DuplicateInstance(entry.host));
        }
        shards.sort_by_key(|entry| entry.shard);
        // One pass in ascending number, so the lowest shard that fails any of the three checks is the one refused.
        // The sort groups a shard's copies, so `DuplicateShard` takes precedence over either copy's zone or layout
        // refusal.
        for (at, entry) in shards.iter().enumerate() {
            if (shards.get(at + 1)).is_some_and(|next| next.shard == entry.shard) {
                return Err(DirectoryRefusal::DuplicateShard(entry.shard));
            }
            if entry.zone != zone {
                return Err(DirectoryRefusal::ForeignShard(entry.shard));
            }
            (entry.layout.check_floor())
                .map_err(|refusal| DirectoryRefusal::Layout(entry.shard, refusal))?;
        }
        let keys = P::project(keys, sealed::Permit(()))?;
        covered(&hosts, &keys)?;
        Ok(Self {
            version,
            zone,
            zone_hold,
            host_roles_max,
            hosts,
            shards,
            keys,
        })
    }
}

impl<P> Directory<P> {
    /// Admits this directory after `prior`, the directory the caller last admitted. The check compares the two
    /// listings only: a caller's chain holds ONE-IDENTITY across the versions it admitted, and the first directory a
    /// caller holds has no earlier one to be checked against.
    ///
    /// # Errors
    ///
    /// [`SuccessionRefusal::Zone`], then [`SuccessionRefusal::Version`], then for the lowest host of `prior` that
    /// this directory leaves out, returns from retirement, names under another instance or moves to another zone,
    /// [`SuccessionRefusal::Departed`], [`SuccessionRefusal::Unretired`], [`SuccessionRefusal::Reassigned`] or
    /// [`SuccessionRefusal::Rezoned`].
    pub fn succeeds(&self, prior: &Self) -> Result<(), SuccessionRefusal> {
        if self.zone != prior.zone {
            return Err(SuccessionRefusal::Zone);
        }
        if self.version <= prior.version {
            return Err(SuccessionRefusal::Version);
        }
        for old in &prior.hosts {
            let Some(entry) = self.host(old.host) else {
                return Err(SuccessionRefusal::Departed(old.host));
            };
            let retired = DirectoryState::Retired;
            if old.state == retired && entry.state != retired {
                return Err(SuccessionRefusal::Unretired(old.host));
            }
            if entry.instance != old.instance {
                return Err(SuccessionRefusal::Reassigned(old.host));
            }
            if entry.placement.zone != old.placement.zone {
                return Err(SuccessionRefusal::Rezoned(old.host));
            }
        }
        Ok(())
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn zone(&self) -> Zone {
        self.zone
    }

    pub fn zone_hold(&self) -> bool {
        self.zone_hold
    }

    /// The roles one host holds at most, owned shards and census entries together.
    pub fn host_roles_max(&self) -> NonZeroU32 {
        self.host_roles_max
    }

    /// Every listed host, ascending.
    pub fn hosts(&self) -> &[HostEntry] {
        &self.hosts
    }

    pub fn host(&self, host: Host) -> Option<&HostEntry> {
        let at = self.hosts.binary_search_by_key(&host, |entry| entry.host);
        at.ok().map(|at| &self.hosts[at])
    }

    /// The zone's shards, ascending.
    pub fn shards(&self) -> &[ShardEntry] {
        &self.shards
    }

    pub fn keys(&self) -> &P {
        &self.keys
    }

    /// The listed hosts of the directory's zone, retired hosts included, ascending.
    pub fn zone_hosts(&self) -> impl Iterator<Item = &HostEntry> {
        self.hosts
            .iter()
            .filter(|entry| entry.placement.zone == self.zone)
    }

    /// The most hosts of the directory's zone, retired hosts left out, that share one placement partition.
    pub fn largest_partition(&self) -> usize {
        let mut counts = BTreeMap::new();
        let placed = self
            .zone_hosts()
            .filter(|entry| entry.state != DirectoryState::Retired);
        for entry in placed {
            *counts.entry(entry.placement.partition.0).or_insert(0) += 1;
        }
        counts.into_values().max().unwrap_or(0)
    }
}

impl Directory<ReconcilerProjection> {
    /// Whether this directory repeats `held`, report keys included.
    pub fn repeats(&self, held: &Self) -> bool {
        let Self {
            version,
            zone,
            zone_hold,
            host_roles_max,
            hosts,
            shards,
            keys,
        } = self;
        *version == held.version
            && *zone == held.zone
            && *zone_hold == held.zone_hold
            && *host_roles_max == held.host_roles_max
            && *hosts == held.hosts
            && *shards == held.shards
            && hosts
                .iter()
                .all(|entry| keys.same_key(&held.keys, entry.host))
    }

    pub fn rekeyed(&self, prior: &Self) -> Vec<Host> {
        let changed = |entry: &&HostEntry| !self.keys.same_key(&prior.keys, entry.host);
        (prior.hosts.iter())
            .filter(changed)
            .map(|entry| entry.host)
            .collect()
    }
}
