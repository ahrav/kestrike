//! One tick's observation of a zone, with the completeness of each source.
//!
//! - OBSERVE-ORDER: [`ZoneLoop::observe`] reads each zone host's report, the instance listing, the volume listing,
//!   the census `Key::Standbys(zone)`, and then shard by shard the shard record, its active volume's record, its
//!   spare's record when named, and its receipt `Key::Replacement(shard)`, then the record of the volume a
//!   later-generation receipt names when its volume ID differs from the active ID and any spare ID (CENSUS-COVERS
//!   in `failover::standbys`). When a read shard's active volume has an error run on the tick
//!   (`VolumeMemory::erring`), or a read shard holds a receipt of a later generation, the call then reads the
//!   receipt of each shard in `ZoneLoop::issuers` outside the call's shard reads. Last it reads the record of each
//!   listed volume whose health is impaired, lost or unvalued and whose ID is absent from the call's shard records,
//!   in ascending volume ID order, one read per volume. `ZoneLoop::judge` continues with the remaining lookups after
//!   a failure. On any other call that read every shard, `ZoneLoop::count_unnamed` runs last. For
//!   `ZoneView::unnamed`, it reads records for listed impaired or lost volumes missing from both the records already
//!   read and the loop's `uncounted` set.
//!   Each read is its own request, so the observation is advisory: every `Reconciler` step rereads the records its
//!   write depends on.
//! - READ-ONLY: [`ZoneLoop::observe`] issues only read requests to the store.
//! - REPORT-AUTHENTICATED: `report::Reader::accept` verifies each host's report bytes under that host's own report
//!   key from the directory's reconciler projection. A repeat of the host's last accepted report keeps the held
//!   report and its advance stamp. Any other authenticated duplicate counts as an unanswered read, once for each
//!   run of consecutive reads that return its bytes.
//!   [`Observation::dropped`] counts every refusal but a repeat, and the status memory counts each distinct
//!   refused report of a host once, by its kind.
//! - ANSWERED-SILENCE: an unanswered report read, a report that marks a recorded earlier boot as returning, and a
//!   tick that ends at the directory restart the silent window a loss from silence needs ([`tick_evidence`]).
//!   A call more than `LISTING_GAP_TICKS` ticks after the previous call marks every zone host's read unanswered.
//!   `admit` forgets the report stamps of each host `Directory::rekeyed` names, which restarts that host's window.
//! - DIRECTORY-SUCCESSION: a loop admits its first snapshot of the bounds' zone, then a snapshot that repeats the
//!   last admitted one with its report keys or that `Directory::succeeds` admits over it; any other ends the tick
//!   as [`Source::Succession`]. The succession rule spans the ticks of one `ZoneLoop`. When an admitted snapshot
//!   changes a host's report key, the loop starts tracking that host afresh.
//! - HELD-RESTART-MATCH: [`ShardRecords::held`] takes the record owner's diagnostic entry of a restart held after a
//!   bump whose reply is unknown (`report::VolumeEntry::held_restart`) while the owner reads live, for the active
//!   volume at the record's generation and at the record's tenure or one attempt below it, and
//!   [`ShardRecords::entries`] leaves that entry out. The status builder reads the same entry ([`held_entry`]) from
//!   the owner's fresh report for the shard's class. The match reads no record beyond the shard's own reads. After
//!   a later incarnation of the owner bumps, the match stands until the loop holds the owner's first report sealed
//!   after the agent took that incarnation's `Starting` status: one report period and a tick when reports arrive,
//!   and at most the fresh window, past which the owner reads other than live.
//! - A failed census fails every shard and a failed shard read fails that shard, each as [`Source::Store`]. A store
//!   error that withdraws the reconciler's client (`Regression`, `Namespace`, `Log`) makes every later store read of
//!   the loop return `Withdrawn`.
//! - ANSWERED-STORE: [`Observation::answered`] is set when the census read succeeded and each shard read, volume
//!   lookup and issuer receipt reread returned a record, an absence or bytes that do not decode
//!   (`StoreError::Codec`). A shard read that does not decode still fails that shard and clears
//!   [`Completeness::store`]. The loop's warm-up waits for a call with `answered` set, so one stored value that never
//!   decodes leaves the zone's other shards planned; an unanswered read, a withdrawn client and a census that does not
//!   decode hold warm-up.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::failover::attachments::{InstanceId, Unlisted};
use crate::failover::loss::{Health, Phase, Receipt};
use crate::failover::records::{Host, ShardRecord, VolumeId, VolumeRecord, VolumeState};
use crate::failover::report::{HostReport, ReportError, TAG_LEN, VolumeEntry};
use crate::failover::standbys::{ActiveVolume, Census};
use crate::failover::zone_loop::ZoneLoop;
use crate::failover::zone_loop::directory::{
    Directory, HostEntry, ReconcilerProjection, SuccessionRefusal,
};
use crate::failover::zone_loop::evidence::{
    HostEvidence, HostRule, LISTING_GAP_TICKS, ViewRun, VolumeCondition, VolumeJudgement, loss_run,
    tick_evidence,
};
use crate::failover::zone_loop::sources::{
    InstanceSource, ListedVolume, ReportSource, Unreachable, VolumeSource,
};
use crate::net::ownership::{ActivatedEpoch, Shard};
use crate::storage::store::{Key, Read, Store, StoreError, WatermarkLog};

/// The failure that kept an observation from using a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The directory snapshot was unreadable or of another zone.
    Directory,
    /// The refusal of the DIRECTORY-SUCCESSION check against the last admitted snapshot.
    Succession(SuccessionRefusal),
    Store(StoreError),
}

/// Each flag measures source completeness for one tick.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Completeness {
    /// Every zone host's report read answered, as [`HostView::answered`] counts answers.
    pub reports: bool,
    /// The instance listing was whole and named each instance of the zone's hosts in one form.
    pub instances: bool,
    /// The volume listing was whole and named each volume in one form; [`VolumeJudgement::complete`] covers the
    /// volumes a loss decision weighs.
    pub volumes: bool,
    /// The observation read the census, every shard's records, the record of every listed volume
    /// `ZoneLoop::look_up` looked up, every receipt it reread for a shard in `ZoneLoop::issuers` and, on a call that
    /// skips the lookups, every record `ZoneLoop::count_unnamed` read. A failed volume lookup or receipt reread
    /// alone leaves each shard's read status unchanged. A lookup or reread the store answered with bytes that do not
    /// decode counts as read here; [`VolumeJudgement::complete`] carries it. A shard whose own records do not decode
    /// is unread and clears this flag.
    pub store: bool,
}

#[derive(Debug, Clone)]
pub struct HostView {
    pub entry: HostEntry,
    pub verdict: HostEvidence,
    /// `answered` measures the host's report-source completeness for one tick.
    pub answered: bool,
    /// The last report this loop holds for the host under the instance the directory names for it.
    pub report: Option<Arc<HostReport>>,
}

#[derive(Debug, Clone)]
pub struct ShardRecords {
    pub record: ShardRecord,
    pub active: VolumeRecord,
    /// The record of the spare the shard record names.
    pub spare: Option<VolumeRecord>,
    pub receipt: Option<Receipt>,
    pub replacement: Option<VolumeRecord>,
    /// The entries for this shard of the reports held for the zone's hosts, each at the tenure `(g, 2E)` of the shard
    /// record read in the same tick and naming its active volume, a held restart's diagnostic entry excepted.
    pub entries: Vec<(Host, VolumeEntry)>,
    /// HELD-RESTART-MATCH: the diagnostic entry ([`VolumeEntry::held_restart`]) of a restart held after a bump whose
    /// reply is unknown, from the record owner's report when that host reads live, for the shard's active volume, at
    /// the record's generation and at the record's tenure `(g, 2E)` or one attempt below it, `(g, 2E - 2)`, where a
    /// restart that read `E - 1` leaves the record once its bump commits. The match is diagnostic evidence: it shows
    /// no bump committed or uncommitted, and the plan names a blocker from it and orders no step.
    pub held: Option<(Host, VolumeEntry)>,
    /// This shard's own volumes are its active volume and the volume its receipt of a later generation records as
    /// created. `others` and `complete` assess every other volume a read record names before retirement, listed or
    /// not, and every other listed volume whose health reads impaired, lost or unvalued and whose own record shows it
    /// short of retired (`ZoneLoop::judge`). A named volume the complete listing omits has no health value and
    /// leaves `complete` false without adding to `others`. [`VolumeJudgement::complete`] states the other inputs
    /// that leave it false, a listed volume with no record beside an `Issued` receipt among them.
    pub judgement: VolumeJudgement,
}

#[derive(Debug, Clone)]
pub struct ShardView {
    pub shard: Shard,
    /// `None` when the store holds no shard record for the shard.
    pub records: Result<Option<ShardRecords>, Source>,
}

impl ShardView {
    /// A failed read, or an absent shard record under a census slot of `census`. An absent record with no census
    /// slot is a read shard that has not started.
    pub(crate) fn unread(&self, census: &Census) -> bool {
        match &self.records {
            Ok(Some(_)) => false,
            Ok(None) => census.slot(self.shard).is_some(),
            Err(_) => true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ZoneView {
    pub directory: Directory<ReconcilerProjection>,
    /// The hosts of the directory's zone, ascending.
    pub hosts: Vec<HostView>,
    pub volumes: Result<Vec<ListedVolume>, Unlisted>,
    /// An absent census reads as the zone's empty census.
    pub census: Result<Census, Source>,
    /// One view per shard of the directory, ascending.
    pub shards: Vec<ShardView>,
    /// The listed volumes that read impaired or lost, hold a volume record short of retired and are named by no
    /// read shard record or replacement receipt (`ZoneLoop::judge`). `None` when the volume listing, the census, a
    /// shard's records or a volume-record lookup of the call did not read. The call reads only the directory's
    /// shards, so the active volume of a shard the directory omits counts here while it reads impaired or lost.
    pub unnamed: Option<u32>,
}

impl ZoneView {
    /// `active` returns `ActiveVolume::of(&records.record)` when the view holds a successfully read record for
    /// `shard`; otherwise it returns `None`.
    pub(crate) fn active(&self, shard: Shard) -> Option<ActiveVolume> {
        let at = (self.shards.binary_search_by_key(&shard, |held| held.shard)).ok()?;
        let records = self.shards[at].records.as_ref().ok()?.as_ref()?;
        Some(ActiveVolume::of(&records.record))
    }

    /// `listing` returns the attachments of `volume` when at least one row matches, every matching row lists the same
    /// attachments, and each identifier parses as an instance identifier.
    pub(crate) fn listing(&self, volume: VolumeId) -> Option<&[String]> {
        let listed = self.volumes.as_ref().ok()?;
        let mut rows = listed.iter().filter(|row| row.volume == volume);
        let first = rows.next()?;
        let sorted = |ids: &[String]| {
            let mut ids = ids.to_vec();
            ids.sort();
            ids
        };
        let ids = sorted(&first.attachments);
        let agree = rows.all(|row| sorted(&row.attachments) == ids);
        let readable = ids.iter().all(|id| InstanceId::new(id).is_some());
        (agree && readable).then_some(first.attachments.as_slice())
    }
}

#[derive(Debug, Clone)]
pub struct Observation {
    pub complete: Completeness,
    /// The store answered every read of the call: the census read returned a census or its absence, and each read
    /// of a shard's records, each volume-record lookup and each issuer receipt reread returned a record, an absence
    /// or bytes that do not decode (`StoreError::Codec`). A shard whose records do not decode stays unread and
    /// clears [`Completeness::store`]. A census that does not decode, and every other store error, clears this
    /// value too. `ZoneLoop::survey` ends its warm-up on the store source at the first call with this value set.
    /// The record reads of `ZoneLoop::count_unnamed` stay out of this value: the plan reads nothing that count
    /// produces, so a count read the store leaves unanswered clears [`Completeness::store`] alone.
    pub answered: bool,
    pub zone: Result<ZoneView, Source>,
    pub dropped: usize,
}

impl Observation {
    /// The source that left the whole zone unobserved: the directory, or the census.
    pub fn unobserved(&self) -> Option<Source> {
        match &self.zone {
            Err(source) => Some(*source),
            Ok(zone) => zone.census.as_ref().err().copied(),
        }
    }
}

/// A store read for an observation: `Ok(None)` for an absent record, `Err` for any other failure.
fn present<R>(read: Result<Read<R>, StoreError>) -> Result<Option<R>, Source> {
    match read {
        Ok(read) => Ok(Some(read.into_value())),
        Err(StoreError::Absent) => Ok(None),
        Err(error) => Err(Source::Store(error)),
    }
}

/// A volume record short of retirement.
fn live(record: &VolumeRecord) -> bool {
    record.state < VolumeState::Retired
}

/// The outcome of [`ZoneLoop::look_up`]: the volumes to judge beside each shard's own, what leaves the membership
/// of a listed volume unknown, and whether the store answered every volume-record lookup and every issuer receipt
/// reread.
struct Lookup {
    named: BTreeSet<VolumeId>,
    /// The looked-up volumes that read impaired or lost and whose record reads short of retired.
    unnamed: u32,
    /// A looked-up volume has no record in the store.
    recordless: bool,
    /// The store answered a volume-record lookup or an issuer receipt reread with bytes that do not decode.
    undecoded: bool,
    /// The shards whose receipt reads `Issued`, among the call's read shards and the loop's remembered issuers.
    issuers: BTreeSet<Shard>,
    read: bool,
}

impl Lookup {
    fn named<'r>(
        read: impl Iterator<Item = &'r ShardRecords>,
    ) -> (BTreeSet<VolumeId>, BTreeSet<VolumeId>) {
        let roles = |records: &'r ShardRecords| {
            let roles = [Some(&records.active), records.spare.as_ref()];
            roles
                .into_iter()
                .chain([records.replacement.as_ref()])
                .flatten()
        };
        read.flat_map(roles)
            .map(|record| (record.volume, live(record)))
            .fold(
                (BTreeSet::new(), BTreeSet::new()),
                |(mut named, mut settled), (volume, live)| {
                    match live {
                        true => named.insert(volume),
                        false => settled.insert(volume),
                    };
                    (named, settled)
                },
            )
    }

    fn skipped<'r>(read: impl Iterator<Item = &'r ShardRecords>) -> Self {
        Self {
            named: Self::named(read).0,
            unnamed: 0,
            recordless: false,
            undecoded: false,
            issuers: BTreeSet::new(),
            read: true,
        }
    }

    /// Whether the membership of a listed volume is unknown for `records`' shard: a lookup or reread failed or
    /// returned bytes that do not decode, or a looked-up volume has no record while an unresolved create may have
    /// made it as another shard's volume. That create is any other shard's `Issued` receipt, or this shard's own
    /// `Issued` receipt of a generation the shard record already holds. The shard's own `Issued` receipt of a later
    /// generation leaves it known: the volume is then that create's product, one of the shard's own volumes once
    /// recorded, or another workload's.
    fn unknown(&self, records: &ShardRecords) -> bool {
        let shard = records.record.shard;
        let pending = created_generation(&records.record, records.receipt.as_ref());
        let other = |issuer: &Shard| *issuer != shard || !pending;
        !self.read || self.undecoded || (self.recordless && self.issuers.iter().any(other))
    }
}

/// Whether `receipt` is of a generation after `record`'s.
fn created_generation(record: &ShardRecord, receipt: Option<&Receipt>) -> bool {
    receipt.is_some_and(|receipt| receipt.request.generation > record.generation)
}

fn issuable(phase: Phase) -> bool {
    matches!(phase, Phase::Open | Phase::Issued)
}

fn created(record: &ShardRecord, receipt: Option<&Receipt>) -> Option<VolumeId> {
    receipt
        .filter(|receipt| receipt.request.generation > record.generation)
        .and_then(|receipt| receipt.phase.volume())
}

fn tag(bytes: &[u8]) -> Option<[u8; TAG_LEN]> {
    bytes.last_chunk::<TAG_LEN>().copied()
}

fn entries_by_shard(hosts: &[HostView]) -> BTreeMap<Shard, Vec<(Host, &VolumeEntry)>> {
    let mut by_shard: BTreeMap<Shard, Vec<(Host, &VolumeEntry)>> = BTreeMap::new();
    for view in hosts {
        for entry in view.report.iter().flat_map(|report| &report.entries) {
            let held = by_shard.entry(entry.shard).or_default();
            held.push((view.entry.host, entry));
        }
    }
    by_shard
}

#[cfg(test)]
thread_local! {
    /// When true, HELD-RESTART-MATCH takes the record's tenure alone.
    pub(crate) static HELD_AT_RECORD_ONLY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The HELD-RESTART-MATCH of `record` among the shard's report entries `held`: the record owner's diagnostic entry
/// ([`held_entry`]) when `live` holds the owner.
fn held_restart(
    record: &ShardRecord,
    held: &[(Host, &VolumeEntry)],
    live: &BTreeSet<Host>,
) -> Option<(Host, VolumeEntry)> {
    if !live.contains(&record.owner) {
        return None;
    }
    let owners = (held.iter())
        .filter(|(host, _)| *host == record.owner)
        .map(|&(_, entry)| entry);
    held_entry(record, owners).map(|entry| (record.owner, *entry))
}

/// The diagnostic entry of a held restart for `record` among `entries`, the entries of a report of the record's
/// owner: the entry for the shard's active volume at the record's generation whose epoch is the record's `2E` or
/// `2E - 2`. The status builder reads it from the owner's fresh report for the shard's class.
pub(crate) fn held_entry<'e>(
    record: &ShardRecord,
    entries: impl IntoIterator<Item = &'e VolumeEntry>,
) -> Option<&'e VolumeEntry> {
    #[cfg(test)]
    let below = !HELD_AT_RECORD_ONLY.get();
    #[cfg(not(test))]
    let below = true;
    let current = u64::from(record.attempts) * 2;
    let at = |entry: &VolumeEntry| {
        entry.tenure.is_some_and(|(generation, epoch)| {
            let epoch = u64::from(epoch.get());
            generation == record.generation && (epoch == current || (below && epoch + 2 == current))
        })
    };
    entries.into_iter().find(|entry| {
        entry.shard == record.shard
            && entry.volume == record.active
            && entry.held_restart()
            && at(entry)
    })
}

fn one_form(listed: &[ListedVolume]) -> bool {
    let mut forms: BTreeMap<VolumeId, (VolumeCondition, Vec<&str>)> = BTreeMap::new();
    listed.iter().all(|row| {
        let mut attachments: Vec<&str> = row.attachments.iter().map(String::as_str).collect();
        attachments.sort_unstable();
        let form = (row.condition, attachments);
        match forms.get(&row.volume) {
            Some(seen) => *seen == form,
            None => forms.insert(row.volume, form).is_none(),
        }
    })
}

impl<S: Store, L: WatermarkLog> ZoneLoop<S, L> {
    /// The caller supplies its fleet directory snapshot for the tick as `directory`.
    pub fn observe(
        &mut self,
        directory: Result<Directory<ReconcilerProjection>, Unreachable>,
        sources: &mut (impl ReportSource + InstanceSource + VolumeSource),
        now_us: u64,
    ) -> Observation {
        let directory = match self.admit(directory) {
            Ok(directory) => directory,
            Err(source) => {
                self.observed_us = Some(now_us);
                if let Some(held) = &self.directory {
                    for entry in held.zone_hosts() {
                        self.reports.unanswered(entry.host, now_us);
                    }
                    let cleared = self
                        .instances
                        .observe(held, Err(Unlisted), self.ticks, now_us);
                    debug_assert!(cleared.is_err());
                }
                let cleared = self.volumes.observe(Err(Unlisted), self.ticks, now_us);
                debug_assert!(cleared.is_err());
                for run in self.runs.values_mut() {
                    *run = ViewRun::unjudged(run.tick);
                }
                return Observation {
                    complete: Completeness::default(),
                    answered: false,
                    zone: Err(source),
                    dropped: 0,
                };
            }
        };
        self.survey.admit(&directory);
        let floor_us = self.bounds.config().tick_us.div_ceil(2);
        let advanced = (self.counted_us)
            .is_none_or(|counted_us| now_us.saturating_sub(counted_us) >= floor_us);
        if advanced {
            self.ticks = self.ticks.saturating_add(1);
            self.counted_us = Some(now_us);
        }
        let tick = self.ticks;
        let gap_us = (self.bounds.config().tick_us).saturating_mul(LISTING_GAP_TICKS);
        let gapped = (self.observed_us)
            .is_some_and(|observed_us| now_us.saturating_sub(observed_us) > gap_us);
        self.observed_us = Some(now_us);
        let zone = directory.zone();
        self.reports.track(&directory, now_us);
        if gapped {
            for entry in directory.zone_hosts() {
                self.reports.unanswered(entry.host, now_us);
            }
        }
        let (unanswered, dropped) = self.intake(&directory, sources, now_us);
        let instances = sources.instances(zone);
        let listed = instances.as_deref().map_err(|&unlisted| unlisted);
        let instances = (self.instances)
            .observe(&directory, listed, tick, now_us)
            .is_ok();
        let volumes = (sources.volumes(zone))
            .and_then(|listed| one_form(&listed).then_some(listed).ok_or(Unlisted));
        let conditions: Result<Vec<(_, VolumeCondition)>, Unlisted> = (volumes.as_ref())
            .map(|listed| listed.iter().map(|v| (v.volume, v.condition)).collect())
            .map_err(|&unlisted| unlisted);
        let conditions = conditions.as_deref().map_err(|&unlisted| unlisted);
        let usable = self.volumes.observe(conditions, tick, now_us);
        let volumes = volumes.and_then(|listed| usable.map(|()| listed));
        let hosts = self.verdicts(&directory, &unanswered, tick, now_us);
        let census = present(self.reconciler.read_census(zone))
            .map(|held| held.unwrap_or_else(|| Census::empty(zone)));
        let entries = match census {
            Ok(_) => entries_by_shard(&hosts),
            Err(_) => BTreeMap::new(),
        };
        let live: BTreeSet<Host> = (hosts.iter())
            .filter(|view| view.verdict == HostEvidence::Live)
            .map(|view| view.entry.host)
            .collect();
        let mut shards: Vec<ShardView> = (directory.shards().iter())
            .map(|entry| {
                let held = entries.get(&entry.shard).map_or(&[][..], Vec::as_slice);
                ShardView {
                    shard: entry.shard,
                    records: (census.as_ref().map_err(|&source| source))
                        .and_then(|_| self.shard_records(entry.shard, held, &live)),
                }
            })
            .collect();
        let store = census.is_ok() && shards.iter().all(|shard| shard.records.is_ok());
        let answered = |shard: &ShardView| {
            let records = &shard.records;
            matches!(records, Ok(_) | Err(Source::Store(StoreError::Codec(_))))
        };
        let answered = census.is_ok() && shards.iter().all(answered);
        let viewed =
            (census.as_ref()).is_ok_and(|census| shards.iter().all(|shard| !shard.unread(census)));
        let (looked_up, unnamed) = self.judge(&mut shards, viewed, tick, !advanced);
        let unnamed = unnamed.filter(|_| store && volumes.is_ok());
        let counted = unnamed.is_some() || volumes.is_err();
        let complete = Completeness {
            reports: unanswered.is_empty(),
            instances,
            volumes: volumes.is_ok(),
            store: store && looked_up && counted,
        };
        let zone = Ok(ZoneView {
            directory,
            hosts,
            volumes,
            census,
            shards,
            unnamed,
        });
        Observation {
            complete,
            answered: answered && looked_up,
            zone,
            dropped,
        }
    }

    fn admit(
        &mut self,
        directory: Result<Directory<ReconcilerProjection>, Unreachable>,
    ) -> Result<Directory<ReconcilerProjection>, Source> {
        let next = directory.map_err(|Unreachable| Source::Directory)?;
        if next.zone() != self.bounds.config().zone {
            return Err(Source::Directory);
        }
        if let Some(held) = &self.directory {
            if next.repeats(held) {
                return Ok(next);
            }
            next.succeeds(held).map_err(Source::Succession)?;
            for host in next.rekeyed(held) {
                self.reports.forget(host);
                self.tags.remove(&host);
                self.refused.remove(&host);
            }
        }
        self.directory = Some(next.clone());
        Ok(next)
    }

    fn intake(
        &mut self,
        directory: &Directory<ReconcilerProjection>,
        sources: &mut impl ReportSource,
        now_us: u64,
    ) -> (BTreeSet<Host>, usize) {
        let keys = directory.keys();
        let zone: Vec<Host> = directory.zone_hosts().map(|entry| entry.host).collect();
        self.telemetry.track(&zone);
        let (mut unanswered, mut dropped) = (BTreeSet::new(), 0);
        for entry in directory.zone_hosts() {
            let host = entry.host;
            let standing = self.refused.remove(&host);
            let bytes = match sources.latest(host) {
                Ok(Some(bytes)) => bytes,
                Ok(None) => continue,
                Err(Unreachable) => {
                    unanswered.insert(host);
                    continue;
                }
            };
            let own = |writer: Host| keys.report(writer).filter(|_| writer == host);
            let tag = tag(&bytes);
            match self.reader.accept(&bytes, own) {
                Ok(report) => {
                    if let Some(tag) = tag {
                        self.tags.insert(host, tag);
                    }
                    self.telemetry.accepted(host);
                    self.reports.accepted(report, now_us);
                }
                Err(ReportError::Duplicate) if self.tags.get(&host).copied() == tag => {}
                Err(ReportError::Duplicate) => {
                    dropped += 1;
                    if tag.is_none() || standing != tag {
                        unanswered.insert(host);
                    }
                    if let Some(tag) = tag {
                        self.refused.insert(host, tag);
                    }
                }
                Err(error) => {
                    self.telemetry.refused(host, &bytes, error);
                    dropped += 1;
                }
            }
        }
        for &host in &unanswered {
            self.reports.unanswered(host, now_us);
        }
        (unanswered, dropped)
    }

    fn verdicts(
        &self,
        directory: &Directory<ReconcilerProjection>,
        unanswered: &BTreeSet<Host>,
        tick: u64,
        now_us: u64,
    ) -> Vec<HostView> {
        let rule = HostRule::of(&self.bounds);
        let view = |entry: &HostEntry| {
            let host = entry.host;
            let silence = self.reports.silence(host, now_us);
            let answered_us = self.reports.answered_us(host, now_us);
            let instance = self.instances.evidence(host, tick);
            HostView {
                entry: *entry,
                verdict: tick_evidence(&rule, entry.state, silence, answered_us, instance),
                answered: !unanswered.contains(&host),
                report: self.reports.latest(host).cloned(),
            }
        };
        directory.zone_hosts().map(view).collect()
    }

    fn volume(&mut self, id: VolumeId) -> Result<VolumeRecord, Source> {
        let read = self.reconciler.read::<VolumeRecord>(Key::Volume(id));
        read.map(Read::into_value).map_err(Source::Store)
    }

    fn shard_records(
        &mut self,
        shard: Shard,
        held: &[(Host, &VolumeEntry)],
        live: &BTreeSet<Host>,
    ) -> Result<Option<ShardRecords>, Source> {
        let Some(record) = present(self.reconciler.read::<ShardRecord>(Key::Shard(shard)))? else {
            return Ok(None);
        };
        let active = self.volume(record.active)?;
        let spare = record.spare.map(|(id, _)| self.volume(id)).transpose()?;
        let receipt = present(self.reconciler.read::<Receipt>(Key::Replacement(shard)))?;
        let named = |id: &VolumeId| {
            *id == record.active || record.spare.is_some_and(|(spare, _)| spare == *id)
        };
        let pending = created(&record, receipt.as_ref()).filter(|id| !named(id));
        let replacement = pending.map(|id| self.volume(id)).transpose()?;
        let tenure = (record.attempts.checked_mul(2))
            .filter(|&epoch| epoch > 0)
            .and_then(ActivatedEpoch::new)
            .map(|epoch| (record.generation, epoch));
        let entries = (held.iter())
            .filter(|(_, entry)| tenure.is_some() && entry.tenure == tenure)
            .filter(|(_, entry)| entry.volume == record.active && !entry.held_restart())
            .map(|&(host, entry)| (host, *entry))
            .collect();
        let held = held_restart(&record, held, live);
        let judgement = VolumeJudgement {
            health: None,
            others: 0,
            complete: false,
            streak: 0,
            confirmed: false,
        };
        Ok(Some(ShardRecords {
            record,
            active,
            spare,
            receipt,
            replacement,
            entries,
            held,
            judgement,
        }))
    }

    /// Sets `ShardRecords::judgement` for each read shard. The first return value is `true` when every volume-record
    /// lookup and every issuer receipt reread of [`Self::look_up`] read on this call, a call that skips
    /// [`Self::look_up`] included. The second is the count of unnamed volumes ([`ZoneView::unnamed`]), `None` when a
    /// shard went unread or a record read of [`Self::look_up`] or [`Self::count_unnamed`] failed. The count of other
    /// impaired volumes covers every cache volume of the tick's listing that reads impaired or lost
    /// (CORRELATED-HOLD): the volumes the read records name active, spare or as a later-generation receipt's created
    /// replacement, and the volumes [`Self::look_up`] finds.
    /// Each shard's own volumes, its active volume and its receipt's created replacement, stay out of its own
    /// count; the volume records name no shard, so a volume the shard's own create made before its receipt recorded
    /// it counts for that shard as for every other.
    ///
    /// [`Self::look_up`] runs only on a call where a read shard's active volume has an error run on the tick
    /// (`VolumeMemory::erring`), or a read shard holds a receipt of a later generation: the calls whose judgements
    /// can reach a loss decision or a replacement step. A call that skips it gives every shard's run no credit for
    /// its tick, so a run of complete views counts only calls whose count covered the unnamed volumes; such a call
    /// that read every shard obtains the status's count from [`Self::count_unnamed`]. The plan reads nothing that
    /// count produces, so a count read the store leaves unanswered leaves the first return value `true` and the
    /// count `None`; `ZoneLoop::observe` clears [`Completeness::store`] for it and leaves
    /// [`Observation::answered`] set. When an earlier call has the same numbered tick, `repeat` is true; a shard
    /// with no run then starts from an unjudged run of that tick.
    fn judge(
        &mut self,
        shards: &mut [ShardView],
        viewed: bool,
        tick: u64,
        repeat: bool,
    ) -> (bool, Option<u32>) {
        let mut runs: BTreeMap<Shard, ViewRun> = (shards.iter())
            .filter(|shard| !matches!(shard.records, Ok(Some(_))))
            .map(|shard| (shard.shard, ViewRun::unjudged(tick)))
            .collect();
        self.remember_issuers(shards);
        let read = || (shards.iter()).filter_map(|shard| shard.records.as_ref().ok()?.as_ref());
        let needed = read().any(|records| {
            let record = &records.record;
            self.volumes.erring(record.active, tick)
                || created_generation(record, records.receipt.as_ref())
        });
        let (lookup, unnamed) = match needed {
            true => {
                let lookup = self.look_up(read(), tick);
                let unnamed = lookup.read.then_some(lookup.unnamed);
                (lookup, unnamed)
            }
            false => {
                let whole = shards.iter().all(|shard| shard.records.is_ok());
                let unnamed = whole.then(|| self.count_unnamed(read(), tick)).flatten();
                (Lookup::skipped(read()), unnamed)
            }
        };
        let answered = lookup.read;
        let mut read: Vec<&mut ShardRecords> = (shards.iter_mut())
            .filter_map(|shard| shard.records.as_mut().ok()?.as_mut())
            .collect();
        let subjects: Vec<(VolumeId, BTreeSet<VolumeId>)> = (read.iter())
            .map(|records| {
                let record = &records.record;
                let repair = created(record, records.receipt.as_ref());
                let own = [Some(record.active), repair].into_iter().flatten();
                (record.active, own.collect())
            })
            .collect();
        let judged = self.volumes.judge_each(&subjects, &lookup.named, tick);
        let run_length = loss_run(self.bounds.config().loss_ticks);
        for (records, judged) in read.iter_mut().zip(judged) {
            let record = &records.record;
            let complete = judged.complete && viewed && !lookup.unknown(records);
            let lost = judged.health == Some(Health::Lost);
            let prior = (self.runs.get(&record.shard).copied())
                .or_else(|| repeat.then(|| ViewRun::unjudged(tick)));
            let credited = complete && needed;
            let run = ViewRun::next(prior, record.active, tick, credited, lost, run_length);
            runs.insert(record.shard, run);
            records.judgement = VolumeJudgement {
                complete,
                streak: run.views,
                confirmed: run.confirmed,
                ..judged
            };
        }
        self.runs = runs;
        (answered, unnamed)
    }

    /// Counts [`ZoneView::unnamed`] when the caller skips [`Self::look_up`]. It skips record reads for
    /// volumes named by previously read records or listed in `uncounted`. Each other listed volume with impaired or
    /// lost status costs one record read, in ascending volume order. A volume whose lookup returns a retired record
    /// joins `uncounted`, which keeps it while the listing shows it unavailable: a retired record stays retired
    /// (RETIRED-IS-FINAL in `failover::reconcile`), so a retired displaced volume costs one read per stay in the
    /// listing. A volume with no record is read on every call, since `Reconciler::provision` can write its record
    /// later. A record the store answers with bytes that do not decode (`StoreError::Codec`) counts as read and
    /// counts nothing, as in [`Self::look_up`], and is read on every call. The method returns `None` if the store
    /// leaves a read unanswered.
    fn count_unnamed<'r>(
        &mut self,
        read: impl Iterator<Item = &'r ShardRecords>,
        tick: u64,
    ) -> Option<u32> {
        let (named, settled) = Lookup::named(read);
        let unavailable: BTreeSet<VolumeId> = self.volumes.unavailable(tick).collect();
        self.uncounted.retain(|volume| unavailable.contains(volume));
        let mut count = Some(0u32);
        for volume in unavailable {
            let known = named.contains(&volume) || settled.contains(&volume);
            if known || self.uncounted.contains(&volume) || !self.unsound(volume, tick) {
                continue;
            }
            match present(self.reconciler.read::<VolumeRecord>(Key::Volume(volume))) {
                Ok(Some(record)) if live(&record) => count = count.map(|n| n.saturating_add(1)),
                Ok(Some(_)) => {
                    self.uncounted.insert(volume);
                }
                Ok(None) | Err(Source::Store(StoreError::Codec(_))) => {}
                Err(_) => count = None,
            }
        }
        count
    }

    /// Whether tick `tick`'s listing reads `volume` impaired or lost.
    fn unsound(&self, volume: VolumeId, tick: u64) -> bool {
        let health = self.volumes.health(volume, tick);
        matches!(health, Some(Health::Impaired | Health::Lost))
    }

    /// After a shard read, `issuers` holds the shard exactly when its receipt reads `Open` or `Issued`. A shard the
    /// call did not read keeps its prior membership.
    fn remember_issuers(&mut self, shards: &[ShardView]) {
        for shard in shards {
            let Ok(records) = &shard.records else {
                continue;
            };
            let receipt = records
                .as_ref()
                .and_then(|records| records.receipt.as_ref());
            match receipt.is_some_and(|receipt| issuable(receipt.phase)) {
                true => self.issuers.insert(shard.shard),
                false => self.issuers.remove(&shard.shard),
            };
        }
    }

    /// Reads the record of each volume of the tick's listing whose health reads impaired, lost or unvalued and that
    /// no read record names, ascending, one read each; a failed read does not stop the later ones. A volume whose
    /// record reads short of retired joins the named volumes, so a looked-up volume with no status value leaves every
    /// judgement incomplete. A volume a read record shows retired, or whose own record reads retired, counts nothing.
    /// A volume the store holds no record of counts as another workload's volume, except while a receipt reads
    /// `Issued`: its create may have made that volume before writing its record, so the volume's membership is
    /// unknown ([`Lookup::unknown`]) for every shard but the issuer of a later-generation receipt, until the receipt
    /// leaves `Issued`. The receipts are those of the call's read shards and, by one read each, those of the shards
    /// in `issuers` outside the call's read set, delisted shards included. A delisted shard stays in `issuers` while
    /// its receipt reads `Open` or `Issued`. A failed read clears `read` and leaves every shard's membership unknown.
    /// A read the store answered with bytes that do not decode (`StoreError::Codec`) leaves every shard's membership
    /// unknown as well and keeps `read`: the store source of the tick is complete, so the loop's warm-up does not
    /// wait for a record that never decodes, and a receipt that does not decode keeps its shard in `issuers`. A
    /// volume whose record does not decode stays out of the named volumes, as after a failed read, so it counts
    /// nothing beside a loss.
    fn look_up<'r>(
        &mut self,
        read: impl Iterator<Item = &'r ShardRecords> + Clone,
        tick: u64,
    ) -> Lookup {
        let issuing = |records: &&ShardRecords| {
            (records.receipt.as_ref()).is_some_and(|receipt| receipt.phase == Phase::Issued)
        };
        let mut issuers: BTreeSet<Shard> = (read.clone().filter(issuing))
            .map(|records| records.record.shard)
            .collect();
        let seen: BTreeSet<Shard> = read.clone().map(|records| records.record.shard).collect();
        let (mut named, settled) = Lookup::named(read);
        let unnamed: Vec<VolumeId> = (self.volumes.unavailable(tick))
            .filter(|volume| !named.contains(volume) && !settled.contains(volume))
            .collect();
        let (mut recordless, mut undecoded, mut answered) = (false, false, true);
        let mut orphans = 0u32;
        let unavailable: BTreeSet<VolumeId> = self.volumes.unavailable(tick).collect();
        self.uncounted.retain(|volume| unavailable.contains(volume));
        let unseen: Vec<Shard> = self.issuers.difference(&seen).copied().collect();
        for shard in unseen {
            match present(self.reconciler.read::<Receipt>(Key::Replacement(shard))) {
                Ok(Some(receipt)) if receipt.phase == Phase::Issued => {
                    issuers.insert(shard);
                }
                Ok(Some(receipt)) if issuable(receipt.phase) => {}
                Ok(_) => {
                    self.issuers.remove(&shard);
                }
                Err(Source::Store(StoreError::Codec(_))) => undecoded = true,
                Err(_) => answered = false,
            }
        }
        for volume in unnamed {
            match present(self.reconciler.read::<VolumeRecord>(Key::Volume(volume))) {
                Ok(Some(record)) if live(&record) => {
                    named.insert(volume);
                    orphans = orphans.saturating_add(u32::from(self.unsound(volume, tick)));
                }
                Ok(Some(_)) => {
                    self.uncounted.insert(volume);
                }
                Ok(None) => recordless = true,
                Err(Source::Store(StoreError::Codec(_))) => undecoded = true,
                Err(_) => answered = false,
            }
        }
        Lookup {
            named,
            unnamed: orphans,
            recordless,
            undecoded,
            issuers,
            read: answered,
        }
    }
}
