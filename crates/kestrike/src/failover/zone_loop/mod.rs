//! [`ZoneLoop`] uses a `Reconciler` to observe one zone and act on it. It takes validated bounds ([`config`]) and the
//! zone's fleet directory ([`directory`]), reads evidence from its sources ([`sources`]) to form host and volume
//! verdicts ([`evidence`]), reads the zone's store records each tick ([`observe`]), plans the tick's steps
//! ([`plan`]), and carries them out through gated `Reconciler` steps ([`actuate`]), the replacement of a lost active
//! volume among them ([`replace`]). The actuation feeds each step's reservation, attach, reclamation, decision and
//! create results and each `Reconciler` step error to the status's events. Each [`ZoneLoop::tick`] surveys
//! the zone ([`plan`]) and builds the tick's part of the reconciler status from the survey's rows and the records and
//! reports it read (`failover::report::status`). The caller's `now_us` supplies all loop times.
//!
//! REPORTS-CONFER-NO-AUTHORITY: a verdict changes no record. A fresh report the loop accepted makes its host read as
//! live or in conflict on a tick with instance evidence for that host, and vetoes a host-lost verdict from silence.
//! `host_evidence` treats a report as fresh when `silence.advanced` is true and
//! `silence.silent_us <= rule.fresh_us`; a host's first report sets the baseline and leaves `advanced` false.
//! `DirectoryState::Retired` takes precedence over both `silence` and `instance`: `host_evidence` returns `Lost`.
//!
//! In `actuate`, `Lost` verdicts feed the census reservation and release, and an accepted report supplies a
//! candidate's headroom and the era of its attach entry. Store records authorize every write that changes a shard's
//! owner, generation or attempt. In `replace`, the survey's volume judgement starts a replacement receipt, and the
//! flip names the host of the replacement's recorded attach event the shard's owner.
//!
//! Building the status part reads the survey through shared borrows and makes no store request.

use std::collections::BTreeMap;

use crate::failover::reconcile::Reconciler;
use crate::failover::records::Host;
use crate::failover::report::status::{Builder, Clock, Memory as StatusMemory, ZonePart};
use crate::failover::report::{Reader, TAG_LEN};
use crate::failover::zone_loop::config::ZoneBounds;
use crate::failover::zone_loop::directory::{Directory, ReconcilerProjection};
use crate::failover::zone_loop::evidence::{InstanceMemory, ReportMemory, ViewRun, VolumeMemory};
use crate::failover::zone_loop::plan::{Step, Survey};
use crate::failover::zone_loop::sources::{
    InstanceSource, ReportSource, Unreachable, VolumeSource,
};
use crate::net::ownership::Shard;
use crate::storage::store::{Store, Tally, WatermarkLog};

pub mod actuate;
pub mod config;
pub mod directory;
pub mod evidence;
#[cfg(kani)]
mod evidence_kani;
pub mod observe;
pub mod plan;
mod reclaim;
pub mod replace;
pub mod sources;
pub mod status;

/// `ZoneLoop` retains one zone's observations across ticks.
pub struct ZoneLoop<S, L> {
    reconciler: Reconciler<S, L>,
    bounds: ZoneBounds,
    /// The last directory snapshot an observation admitted.
    directory: Option<Directory<ReconcilerProjection>>,
    survey: plan::Memory,
    reader: Reader,
    /// The tag of the last report the reader accepted from each zone host since the host's report key last changed.
    tags: BTreeMap<Host, [u8; TAG_LEN]>,
    /// Each entry identifies a zone host whose latest report read returned an authenticated duplicate distinct from
    /// its last accepted report. The value is the duplicate's tag.
    refused: BTreeMap<Host, [u8; TAG_LEN]>,
    reports: ReportMemory,
    instances: InstanceMemory,
    volumes: VolumeMemory,
    /// Per directory shard of the last admitted call, its run of complete views (`VolumeJudgement::streak` and
    /// `VolumeJudgement::confirmed`). A call whose directory admission fails replaces each run by an unjudged run of
    /// its tick.
    runs: BTreeMap<Shard, ViewRun>,
    /// The shards whose replacement receipt this loop last read as `Open` or `Issued`. The loop retains a shard
    /// after the directory stops listing it. A read removes the shard if its receipt is `Created` or absent, or if
    /// the shard record is absent. While the shard's replacement receipt reads `Issued`, a listed volume with no
    /// record has unknown membership (`Lookup::unknown`).
    issuers: std::collections::BTreeSet<Shard>,
    /// The set tracks listed volumes whose last lookup returned a retired record. Each stays while the listing
    /// shows the volume as unavailable. Counting unnamed volumes skips record reads for volumes in `uncounted`.
    uncounted: std::collections::BTreeSet<crate::failover::records::VolumeId>,
    /// `observe` increments `ticks` once `admit` returns the directory, when `counted_us` is `None` or at least
    /// `tick_us.div_ceil(2)` microseconds before `now_us`, so two calls at one instant share a tick.
    ticks: u64,
    counted_us: Option<u64>,
    observed_us: Option<u64>,
    /// The tick number of the last survey `actuate` admitted.
    actuated: u64,
    requests: actuate::Requests,
    clean: reclaim::Clean,
    /// The loop's last create of each shard's replacement, which spaces its creates.
    creates: replace::Creates,
    /// The volumes each shard's flips displaced, until their retirements settle.
    displaced: replace::Displaced,
    /// The replacement volumes a listing mismatch rejected, until their retirements settle.
    rejected: replace::Rejected,
    sighted: actuate::Sightings,
    /// `displacing` records when a survey of the current run first observed each live, unenrolled entry on a census
    /// slot host that displaces a live named standby. A survey that reads the shard and finds the entry outside that
    /// state ends the run.
    displacing: actuate::Sightings,
    /// `attached` records when each live, unenrolled entry's instance first appears in its volume's attachment
    /// listing during the current run. A readable listing that omits the instance ends the run.
    attached: actuate::Sightings,
    detached: reclaim::Detached,
    tried: actuate::Tried,
    /// What the status builder keeps across ticks.
    telemetry: StatusMemory,
    /// The store client's tally when the loop took it, which the status's outcome counts start from.
    opened: Tally,
}

/// One tick's result: the survey and the tick's part of the reconciler status.
#[derive(Debug, Clone)]
pub struct Tick {
    pub survey: Survey,
    pub part: ZonePart,
}

impl<S: Store, L: WatermarkLog> ZoneLoop<S, L> {
    /// An observation admits the loop's first directory snapshot of the bounds' zone.
    pub fn new(reconciler: Reconciler<S, L>, bounds: ZoneBounds) -> Self {
        let volumes = VolumeMemory::new(&bounds);
        let instances = InstanceMemory::new(&bounds);
        let opened = reconciler.store_state().1;
        Self {
            reconciler,
            bounds,
            directory: None,
            survey: plan::Memory::default(),
            reader: Reader::default(),
            tags: BTreeMap::new(),
            refused: BTreeMap::new(),
            reports: ReportMemory::default(),
            instances,
            ticks: 0,
            counted_us: None,
            observed_us: None,
            volumes,
            runs: BTreeMap::new(),
            issuers: std::collections::BTreeSet::new(),
            uncounted: std::collections::BTreeSet::new(),
            actuated: 0,
            requests: actuate::Requests::new(),
            clean: reclaim::Clean::new(),
            creates: replace::Creates::new(),
            displaced: replace::Displaced::new(),
            rejected: replace::Rejected::new(),
            sighted: actuate::Sightings::new(),
            displacing: actuate::Sightings::new(),
            attached: actuate::Sightings::new(),
            detached: reclaim::Detached::new(),
            tried: actuate::Tried::new(),
            telemetry: StatusMemory::default(),
            opened,
        }
    }

    /// Surveys the zone and builds the tick's status part from the survey's rows, the records and reports the
    /// survey read and the store client's alarm and outcomes; the tick makes the survey's reads only.
    pub fn tick(
        &mut self,
        directory: Result<Directory<ReconcilerProjection>, Unreachable>,
        sources: &mut (impl ReportSource + InstanceSource + VolumeSource),
        now_us: u64,
    ) -> Tick {
        let survey = self.survey(directory, sources, now_us);
        let (alarm, tally) = self.reconciler.store_state();
        let tally = tally.since(&self.opened);
        let zone = self.bounds.config().zone;
        let clock = Clock {
            now_us,
            fresh_us: self.bounds.fresh_us(),
        };
        let view = survey.observation.zone.as_ref().ok();
        let reports = &self.reports;
        let hosts = view.into_iter().flat_map(|view| &view.hosts).map(|host| {
            let silence = reports.silence(host.entry.host, now_us);
            (
                host,
                !silence.advanced || silence.silent_us > clock.fresh_us,
            )
        });
        let mut builder = Builder::new(
            (zone, &survey.status),
            hosts,
            &mut self.telemetry,
            self.bounds.bounds(),
            (alarm, &tally),
            clock,
        );
        let shards = view.map_or(&[][..], |view| &view.shards[..]);
        let reserved: std::collections::BTreeSet<_> = (survey.plan.steps.iter())
            .filter_map(|step| match step {
                Step::Reserve { shard, .. } => Some(*shard),
                _ => None,
            })
            .collect();
        for row in &survey.status.shards {
            let records = (shards
                .binary_search_by_key(&row.shard, |shard| shard.shard)
                .ok())
            .and_then(|at| shards[at].records.as_ref().ok()?.as_ref());
            builder.shard(row, records, reserved.contains(&row.shard));
        }
        let part = builder.finish();
        Tick { survey, part }
    }
}

#[cfg(test)]
#[path = "../zone_loop_tests/mod.rs"]
pub(crate) mod tests;
