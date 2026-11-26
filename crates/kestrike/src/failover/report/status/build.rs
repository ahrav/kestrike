//! The status builder: a zone loop feeds it one tick's survey rows, the records it read and the reports it holds,
//! through shared borrows, and it returns the tick's [`ZonePart`].
//!
//! - ONE-CLASSIFICATION: a shard's serving class derives from the survey's `ShardState` and the owner's accepted
//!   entry at the shard record's tenure; the builder adds no second state table. The survey's state decides first,
//!   through the one state the survey's ONE-STATE order gives the shard: an unread shard is `Silent`; a record at
//!   `E = 0` is `Fresh`; a retirement request, an impaired volume or an unconfirmed loss is `Blocked`; a replacement
//!   in progress, held or exhausted is `Cold`. Then a lost owner reads `Fresh`; then, while the owner's report is fresh,
//!   a held restart's diagnostic entry in that report (`observe::held_entry`) is `Blocked`, whatever verdict short of
//!   lost the owner has, and otherwise its entry decides: held or parked, a held tenure, or an unloadable metadata
//!   outcome is `Blocked`; serving is `Served`; withdrawn, closed or closing is `Withdrawn`; every other state is
//!   `Recovering`. Every other shard reads `Silent`.
//! - STALE-SERVING: an entry of a fresh report, one whose last advance lies within the fresh window, that reads
//!   serving for a shard at a tenure below the shard record's `(g, 2E)` is stale once per host and shard, and counts
//!   once it has been observed stale for longer than the fresh window, so a predecessor's last report from before a
//!   takeover or a restart ages out before it counts.
//! - Every shard outside the served class takes an exception row, and so does a served shard whose standby is past
//!   its target, so an operator can name each shard with no standby ([`ExceptionRow::admits`]).
//! - The [`Memory`] keeps, per shard with an exception row, the loop time it was first observed in its class (for a
//!   served shard, served and past its target), and per stale host and shard the loop time it was first observed
//!   stale, and drops every entry the tick left out but those of a shard the tick could not read. An exception row's
//!   age and the stale age count from those times.

use std::collections::BTreeMap;

use super::MAX_ROWS;
use super::events::{at, count_one};
use super::part::{
    Budgets, CLASSES, Class, Events, ExceptionRow, Flags, GENERATION_MAX, RECEIPTS, ReceiptCount,
    STANDBYS, Standby, StoreState, ZonePart, closed_at, health_at, need_at, verdict_at,
};
use crate::failover::assignment::hmac;
use crate::failover::bounds::Bounds;
use crate::failover::loss::Phase as ReceiptPhase;
use crate::failover::records::{ATTEMPTS_MAX, EventKind, Host, ShardRecord, VolumeRecord};
use crate::failover::report::{
    Hold, HostReport, MAX_LEN as MAX_REPORT, Members, Metadata, Phase, ReportError, VolumeEntry,
};
use crate::failover::serving::State;
use crate::failover::standbys::{self, Zone};
use crate::failover::zone_loop::directory::DirectoryState;
use crate::failover::zone_loop::evidence::HostEvidence;
use crate::failover::zone_loop::observe::{HostView, ShardRecords, held_entry};
use crate::failover::zone_loop::status::{EnrollPhase, ShardState, ShardStatus, ZoneStatus};
use crate::net::ownership::{ActivatedEpoch, Shard, ShardGeneration};
use crate::storage::store::{Alarm, Tally};

/// A tenure `(g, 2E)`.
type Tenure = (ShardGeneration, ActivatedEpoch);

/// What the loop keeps across ticks for its zone part.
#[derive(Debug, Clone, Default)]
pub struct Memory {
    /// The loop's event counts since it started.
    pub events: Events,
    /// Per host, the digest of the last report the loop refused from it, so an unchanged refused report counts
    /// once.
    refused: BTreeMap<Host, [u8; 32]>,
    since: BTreeMap<Shard, (Class, u64)>,
    /// Per shard the last tick could not read, the class and first-observed time it held when last read.
    held: BTreeMap<Shard, (Class, u64)>,
    /// Per stale host and shard, the lower tenure its fresh report claims serving at and the loop time the claim was
    /// first observed stale.
    stale: BTreeMap<(Shard, Host), (Tenure, u64)>,
}

impl Memory {
    /// Counts a report the loop refused from `host` with `error` once per distinct report: a refused report whose
    /// digest equals the one the memory holds for the host counts nothing. The digest covers the length and every
    /// byte of a delivery of at most the report's `MAX_LEN`, and the length and first `MAX_LEN` bytes of a longer
    /// one, which the reader refuses by its length alone.
    pub(crate) fn refused(&mut self, host: Host, bytes: &[u8], error: ReportError) {
        let length = (bytes.len() as u64).to_be_bytes();
        let held = &bytes[..bytes.len().min(MAX_REPORT)];
        let digest = hmac(&[0; 32], &[REFUSED_DIGEST, &length, held]);
        if self.refused.insert(host, digest) != Some(digest) {
            self.events.refused(error);
        }
    }

    /// Drops the refused digest of `host`, whose report the loop accepted.
    pub(crate) fn accepted(&mut self, host: Host) {
        self.refused.remove(&host);
    }

    /// Keeps the refused digests of the hosts `zone`, ascending, lists only. No directory the loop admits today
    /// reaches the drop, because [`Directory::succeeds`] refuses a directory that drops or rezones a listed host; the
    /// loop calls this on every tick all the same, so the map's bound of one digest per listed host holds without
    /// that rule.
    ///
    /// [`Directory::succeeds`]: crate::failover::zone_loop::directory::Directory::succeeds
    pub(crate) fn track(&mut self, zone: &[Host]) {
        self.refused
            .retain(|host, _| zone.binary_search(host).is_ok());
    }
}

/// The domain of a refused report's digest.
const REFUSED_DIGEST: &[u8] = b"ebs-refused-report";

/// The loop's clock on the tick: the loop time and the zone's fresh window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock {
    pub now_us: u64,
    pub fresh_us: u64,
}

/// One host of the zone as the builder reads it: its verdict and, when its last report advance is within the fresh
/// window, that report.
#[derive(Debug, Clone, Copy)]
struct Seen<'a> {
    verdict: HostEvidence,
    fresh: Option<&'a HostReport>,
}

/// Builds one tick's [`ZonePart`] of one zone.
pub struct Builder<'a> {
    part: ZonePart,
    memory: &'a mut Memory,
    bounds: &'a Bounds,
    clock: Clock,
    hosts: BTreeMap<Host, Seen<'a>>,
    /// Per shard, the hosts whose fresh report holds an entry that reads serving, with the entry's tenure.
    serving: BTreeMap<Shard, Vec<(Host, Tenure)>>,
    since: BTreeMap<Shard, (Class, u64)>,
    held: BTreeMap<Shard, (Class, u64)>,
    stale: BTreeMap<(Shard, Host), (Tenure, u64)>,
    /// [`Builder::carry_stale`] retains stale claims in the memory and leaves the part's stale count unchanged.
    unread_stale: BTreeMap<(Shard, Host), (Tenure, u64)>,
    rows: Vec<ExceptionRow>,
    attempts: Option<u64>,
    generation: Option<u64>,
    /// Recorded pairs and the pair caps summed over the active volumes.
    pairs_used: u64,
    pairs_limit: u64,
}

/// The tenure `(g, 2E)` of `record`, `None` past the activated epochs.
fn tenure(record: &ShardRecord) -> Option<Tenure> {
    let epoch = ActivatedEpoch::new(record.attempts.checked_mul(2)?)?;
    Some((record.generation, epoch))
}

/// The class the owner's accepted entry gives its shard.
fn entry_class(entry: &VolumeEntry) -> Class {
    if matches!(entry.phase, Some(Phase::Held | Phase::Parked))
        || entry.hold == Some(Hold::Held)
        || entry.metadata == Some(Metadata::Unloadable)
    {
        return Class::Blocked;
    }
    match (entry.serving, entry.phase) {
        (Some(State::Serving), _) => Class::Served,
        (Some(State::Withdrawn | State::Closed), _)
        | (None, Some(Phase::Withdrawn | Phase::Closing)) => Class::Withdrawn,
        (None, Some(Phase::Serving)) => Class::Served,
        _ => Class::Recovering,
    }
}

/// The standby state the survey gives `status`. An enrollment that holds no census slot reads `Enrolling` only when
/// the tick's plan admitted its reservation (`reserved`); a withheld one reads by its exposure.
fn standby(status: &ShardStatus, records: Option<&ShardRecords>, reserved: bool) -> Standby {
    if records.is_some_and(|held| held.record.attempts == 0) {
        return Standby::Unneeded;
    }
    match status.state {
        ShardState::Initial => Standby::Unneeded,
        ShardState::Unobserved(_) | ShardState::StandbyUnknown => Standby::Unknown,
        ShardState::Enrolling { phase, .. } if phase != EnrollPhase::Unreserved || reserved => {
            Standby::Enrolling
        }
        _ if status.exposure_us.is_none() => Standby::Named,
        _ if status.overdue => Standby::Past,
        _ => Standby::Within,
    }
}

impl<'a> Builder<'a> {
    /// A builder of `zone`'s part for tick `zone_status.tick` on `clock`, with the survey's zone-wide status, every
    /// host of the zone beside whether its last report advance is older than the fresh window or absent (`silent`),
    /// the store client's `alarm` and `tally`, and the owner's `bounds`, which give the pair cap.
    pub fn new(
        (zone, zone_status): (Zone, &ZoneStatus),
        hosts: impl IntoIterator<Item = (&'a HostView, bool)>,
        memory: &'a mut Memory,
        bounds: &'a Bounds,
        store: (Alarm, &Tally),
        clock: Clock,
    ) -> Self {
        let (complete, holds) = (zone_status.complete, zone_status.holds);
        let flags = Flags {
            reports: complete.reports,
            instances: complete.instances,
            volumes: complete.volumes,
            store: complete.store,
            warm_up: holds.warm_up,
            zone_host: holds.zone_host,
            operator: holds.operator,
            cap_below: zone_status.cap_below.is_some(),
        };
        let census = match zone_status.census {
            Some(len) => Members::Known {
                used: len as u64,
                limit: zone_status.cap.min(standbys::MAX_SLOTS) as u64,
            },
            None => Members::Unavailable,
        };
        let mut counts = [0; super::part::VERDICTS];
        if let Some(verdicts) = &zone_status.verdicts {
            for (verdict, count) in [
                (HostEvidence::Live, verdicts.live),
                (HostEvidence::Lost, verdicts.lost),
                (HostEvidence::Conflict, verdicts.conflict),
                (HostEvidence::Unknown, verdicts.unknown),
            ] {
                counts[verdict_at(verdict)] = u32::try_from(count).unwrap_or(u32::MAX);
            }
        }
        let mut part = ZonePart {
            tick: zone_status.tick,
            flags,
            census,
            store: StoreState::of(store.0, store.1),
            events: memory.events,
            ..ZonePart::blank(zone)
        };
        part.hosts.verdicts = counts;
        part.unnamed_volumes = zone_status.unnamed.map(u64::from);
        let mut builder = Self {
            part,
            memory,
            bounds,
            clock,
            hosts: BTreeMap::new(),
            serving: BTreeMap::new(),
            since: BTreeMap::new(),
            held: BTreeMap::new(),
            stale: BTreeMap::new(),
            unread_stale: BTreeMap::new(),
            rows: Vec::new(),
            attempts: None,
            generation: None,
            pairs_used: 0,
            pairs_limit: 0,
        };
        for (view, silent) in hosts {
            builder.host(view, silent);
        }
        builder
    }

    /// One host of the zone: a host the directory does not retire counts in the silent gauge's population, and a
    /// host whose report is fresh adds its self-suspicion and its serving entries. A host fed twice keeps its
    /// first view.
    fn host(&mut self, view: &'a HostView, silent: bool) {
        let host = view.entry.host;
        if self.hosts.contains_key(&host) {
            return;
        }
        let hosts = &mut self.part.hosts;
        if view.entry.state != DirectoryState::Retired {
            let (used, limit) = match hosts.silent {
                Members::Known { used, limit } => (used, limit),
                Members::Unavailable => (0, 0),
            };
            hosts.silent = Members::Known {
                used: used + u64::from(silent),
                limit: limit + 1,
            };
        }
        let fresh = view.report.as_deref().filter(|_| !silent);
        if let Some(report) = fresh {
            if report
                .host
                .detector
                .self_suspect_us
                .is_some_and(|left| left > 0)
            {
                count_one(&mut hosts.self_suspect);
            }
            for entry in &report.entries {
                if entry.serving == Some(State::Serving)
                    && let Some(held) = entry.tenure
                {
                    self.serving
                        .entry(entry.shard)
                        .or_default()
                        .push((host, held));
                }
            }
        }
        self.hosts.insert(
            host,
            Seen {
                verdict: view.verdict,
                fresh,
            },
        );
    }

    fn verdict(&self, host: Host) -> HostEvidence {
        self.hosts
            .get(&host)
            .map_or(HostEvidence::Unknown, |seen| seen.verdict)
    }

    /// One shard: the survey's `status` row, for a shard the tick read its `records`, and whether the tick's plan
    /// admitted a census reservation for it (`reserved`).
    pub fn shard(&mut self, status: &ShardStatus, records: Option<&ShardRecords>, reserved: bool) {
        let class = self.class(status, records);
        count_one(&mut self.part.classes[at(CLASSES, class)]);
        let standby = standby(status, records, reserved);
        if standby != Standby::Unneeded {
            count_one(&mut self.part.standby[at(STANDBYS, standby)]);
        }
        if let Some(blocker) = status.blocker {
            count_one(&mut self.part.blockers[blocker.position()]);
        }
        let unread = matches!(status.state, ShardState::Unobserved(_));
        let excepted = ExceptionRow::admits(class, standby);
        let since = self.first_observed(status.shard, class, excepted, unread);
        if unread {
            self.carry_stale(status.shard);
        }
        if excepted {
            self.rows.push(ExceptionRow {
                shard: status.shard,
                class,
                standby,
                age_us: self.clock.now_us.saturating_sub(since),
            });
        }
        let Some(records) = records else {
            return;
        };
        let record = &records.record;
        let lost = |host| self.verdict(host) == HostEvidence::Lost;
        if let Some(need) = standbys::need_of(record, &records.active, lost) {
            count_one(&mut self.part.needs[need_at(need)]);
        }
        if let Some(receipt) = records.receipt.as_ref()
            && receipt.request.generation > record.generation
        {
            let phase = match receipt.phase {
                ReceiptPhase::Open => ReceiptCount::Open,
                ReceiptPhase::Issued => ReceiptCount::Issued,
                ReceiptPhase::Created(_) => ReceiptCount::Created,
            };
            count_one(&mut self.part.receipts[at(RECEIPTS, phase)]);
            if receipt.held {
                count_one(&mut self.part.receipts[at(RECEIPTS, ReceiptCount::Held)]);
            }
        }
        count_one(&mut self.part.volumes[health_at(records.judgement.health)]);
        self.attaches(&records.active);
        if status.state == ShardState::Closed
            && let Some(closed) = status.closed
        {
            count_one(&mut self.part.attaches.closed[closed_at(closed)]);
        }
        self.attempts = self.attempts.max(Some(u64::from(record.attempts)));
        self.generation = self.generation.max(Some(record.generation.get()));
        self.stale(record);
    }

    /// The loop time `shard` was first observed in `class`, recorded for the next tick when the shard takes an
    /// exception row (`excepted`). A class the memory holds for the shard, from the last tick or from the last tick
    /// that read it, keeps its time; any other starts now. On a tick that could not read the shard (`unread`), the
    /// class it held when last read is parked, so its age resumes when a later tick reads it in that class; `held`
    /// gains an entry only on such a tick.
    fn first_observed(&mut self, shard: Shard, class: Class, excepted: bool, unread: bool) -> u64 {
        let last = self.memory.since.get(&shard).copied();
        let parked = self.memory.held.get(&shard).copied();
        if unread && let Some(prior) = last.filter(|(was, _)| *was != class).or(parked) {
            self.held.insert(shard, prior);
        }
        let since = [last, parked]
            .into_iter()
            .flatten()
            .find(|(was, _)| *was == class)
            .map_or(self.clock.now_us, |(_, at)| at);
        if excepted {
            self.since.insert(shard, (class, since));
        }
        since
    }

    /// For an unread shard, the builder preserves a stale claim's original `since` when its host view is missing or
    /// a serving claim matches its host and tenure.
    fn carry_stale(&mut self, shard: Shard) {
        let (Some(first), Some(last)) = (Host::new(1), Host::new(u64::MAX)) else {
            return;
        };
        let claims = self.serving.get(&shard).map_or(&[][..], Vec::as_slice);
        for (key, (held, since)) in self.memory.stale.range((shard, first)..=(shard, last)) {
            if !self.hosts.contains_key(&key.1) || claims.contains(&(key.1, *held)) {
                self.unread_stale.insert(*key, (*held, *since));
            }
        }
    }

    /// The shard's class (ONE-CLASSIFICATION): the survey's fixed classes first; then a lost owner reads `Fresh`;
    /// then, while the owner's report is fresh, a held restart's diagnostic entry in it ([`held_entry`]) reads
    /// `Blocked` and otherwise the owner's entry at the record's tenure decides; every other shard reads `Silent`.
    fn class(&self, status: &ShardStatus, records: Option<&ShardRecords>) -> Class {
        if let Some(class) = status.state.class() {
            return class;
        }
        let Some(records) = records else {
            return Class::Silent;
        };
        let owner = records.record.owner;
        let seen = self.hosts.get(&owner);
        if seen.is_some_and(|seen| seen.verdict == HostEvidence::Lost) {
            return Class::Fresh;
        }
        let Some(report) = seen.and_then(|seen| seen.fresh) else {
            return Class::Silent;
        };
        if held_entry(&records.record, &report.entries).is_some() {
            return Class::Blocked;
        }
        let entry = records.entries.iter().find(|(host, _)| *host == owner);
        entry.map_or(Class::Silent, |(_, entry)| entry_class(entry))
    }

    fn attaches(&mut self, volume: &VolumeRecord) {
        let a = &mut self.part.attaches;
        a.live = a.live.saturating_add(volume.live_hosts().count() as u32);
        let ended = |seq| {
            volume
                .event(seq)
                .is_some_and(|event| event.kind == EventKind::Ended)
        };
        let pinned = volume.pairs.iter().filter(|held| ended(held.attach));
        a.ended_paired = a.ended_paired.saturating_add(pinned.count() as u32);
        for host in volume.hosts_with_attach_event() {
            match volume.latest(host) {
                Some((seq, event)) if event.kind == EventKind::Ended => {
                    if volume.pinned(host, seq).is_none() {
                        count_one(&mut a.ended_unpaired);
                    }
                }
                Some((_, event)) if event.kind == EventKind::Gone => count_one(&mut a.gone),
                _ => {}
            }
        }
        self.pairs_used += volume.pairs.len() as u64;
        self.pairs_limit += self.bounds.pair_cap() as u64;
    }

    /// Records each host whose fresh report holds an entry that reads serving for `record`'s shard below its
    /// tenure (STALE-SERVING), once per host and shard, from the time the loop first observed that claimed tenure
    /// stale; a claim at another tenure starts now, and of several claims the oldest stands.
    fn stale(&mut self, record: &ShardRecord) {
        let Some(current) = tenure(record) else {
            return;
        };
        let entries = self
            .serving
            .get(&record.shard)
            .map_or(&[][..], Vec::as_slice);
        for &(host, held) in entries {
            if held >= current {
                continue;
            }
            let key = (record.shard, host);
            let kept = (self.memory.stale.get(&key)).filter(|(claimed, _)| *claimed == held);
            let since = kept.map_or(self.clock.now_us, |(_, since)| *since);
            if self.stale.get(&key).is_none_or(|(_, other)| since < *other) {
                self.stale.insert(key, (held, since));
            }
        }
    }

    /// The tick's part: the exception rows oldest first, then by shard, at most [`MAX_ROWS`] with the rest counted
    /// as omitted, and the stale entries observed stale for longer than the fresh window. The memory keeps this
    /// tick's first-observed times, those of the shards the tick could not read, and drops the rest.
    pub fn finish(mut self) -> ZonePart {
        let mut part = self.part;
        let now_us = self.clock.now_us;
        self.rows
            .sort_by_key(|row| (core::cmp::Reverse(row.age_us), row.shard));
        part.omitted = self.rows.len().saturating_sub(MAX_ROWS) as u32;
        self.rows.truncate(MAX_ROWS);
        part.rows = self.rows;
        let dwelled = (self.stale.values())
            .map(|(_, since)| now_us.saturating_sub(*since))
            .filter(|&age| age > self.clock.fresh_us);
        let (count, oldest) = dwelled.fold((0u32, None), |(count, oldest), age| {
            (count.saturating_add(1), oldest.max(Some(age)))
        });
        part.stale_serving = count;
        part.stale_oldest_us = oldest;
        if self.pairs_limit > 0 {
            part.attaches.pairs = Members::Known {
                used: self.pairs_used,
                limit: self.pairs_limit,
            };
        }
        if let (Some(attempts), Some(generation)) = (self.attempts, self.generation) {
            part.budgets = Budgets {
                attempts: Members::Known {
                    used: attempts,
                    limit: u64::from(ATTEMPTS_MAX),
                },
                generation: Members::Known {
                    used: generation.min(GENERATION_MAX),
                    limit: GENERATION_MAX,
                },
            };
        }
        self.stale.extend(self.unread_stale);
        self.memory.since = self.since;
        self.memory.held = self.held;
        self.memory.stale = self.stale;
        part
    }
}

#[cfg(test)]
#[path = "../status_build_tests.rs"]
mod tests;
