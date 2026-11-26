//! The memories retain this process's observations of the zone's hosts and volumes across ticks.
//!
//! - LOST-NEEDS-TWO-CLASSES: [`host_evidence`] returns [`HostEvidence::Lost`] only for a directory retirement,
//!   or for report silence together with control-plane instance evidence: the instance terminated or shutting down,
//!   stopping or stopped for the stopped dwell, its status checks impaired for the impaired dwell, or absent from
//!   consecutive complete listings. Silence alone gives [`HostEvidence::Unknown`], as does a silent host whose
//!   running instance shows no impaired dwell. A nonretired host also reads `Unknown` when the tick lacks instance
//!   evidence for it, fresh report or not. A fresh report beside an instance that is ended, stopping, stopped or
//!   absent gives [`HostEvidence::Conflict`].
//! - Silence is the elapsed loop time since the host's last stamped advance or, before the first advance, since its
//!   baseline: the host's first accepted report, or the start of tracking until one arrives. A host the directory
//!   adds and a host whose first report arrives late each get the whole silent window; a stale first read
//!   postpones a loss by up to one silent window. The loop stamps each advance with its own time at intake.
//! - After the host's first accepted report, an advance is a higher sequence of the host's current boot, a report
//!   of a boot new to the memory's record, or the second higher sequence of a returning boot; the new boot and the
//!   returning boot each become current. A recorded earlier boot becomes the returning boot on a higher sequence,
//!   and that report preserves the current boot and the last stamp. An advance clears the returning mark, and a
//!   higher sequence from another earlier boot moves it. Reports alternating between two recorded boots stamp on
//!   each advance of the current boot. A delayed report of a boot the memory dropped or never recorded stamps once.
//! - The memories track the hosts of the directory's own zone. A host of another zone reads as unknown, or as lost
//!   when the directory retired it.
//! - Every dwell restarts on a contrary observation. A listing that shows the instance in a state other than
//!   stopping or stopped clears its stopped dwell, as does one that shows it stopping after it showed it stopped;
//!   one whose status checks read other than impaired clears its impaired dwell; one that leaves the instance out
//!   clears both and counts an absence; one that lists it clears its absence count. A failed listing, a listing
//!   with two differing rows for one tracked instance, and a listing later than [`LISTING_GAP_TICKS`] ticks of
//!   elapsed time after the previous one clear all three. A dwell spans consecutive complete listings at most
//!   [`LISTING_GAP_TICKS`] ticks apart. While listings keep failing or arrive more than [`LISTING_GAP_TICKS`] ticks
//!   apart, loss based on a dwell or an absence count stays unknown. Retirement establishes loss, and an ended
//!   instance establishes loss when the host meets the silence condition. A directory that names another instance
//!   for the host restarts its dwells and its silence.
//! - Each tick, the caller passes its tick number and loop time to every observation, and reads the memories with
//!   that tick number. A read of a tick without a complete listing finds instance evidence `Unlisted` and volume
//!   health `None`, and a dwell counts up to the tick's listing. A second listing in the same tick applies contrary
//!   observations; only the first complete listing of a tick can increment an absence count or extend an error run.
//! - LOSS-NEEDS-EVIDENCE: [`volume_health`] returns [`Health::Lost`] only after the volume shows `error` for at
//!   least `max(loss_ticks, LOSS_TICKS_MIN)` consecutive complete observations. The run counts the volume's own
//!   observations with a status value; [`VolumeMemory::judge`] checks the other volumes on the tick it judges. A
//!   volume has health `None` under status `insufficient-data`, when a complete listing leaves it out, and under a
//!   failed listing. `judge` reports the zone view incomplete while another named volume has health `None` or the
//!   tick has an incomplete listing. For an isolated loss, the caller defers its decision on an incomplete view, on a
//!   tick with an incomplete record read, and while the shard's [`VolumeJudgement::streak`] is below [`loss_run`].
//!   A loss beside another impaired or lost volume holds once [`VolumeJudgement::confirmed`] is set.
//!   [`VolumeMemory::observe`]
//!   returns `Err(Unlisted)` for a listing with two differing rows for one volume, as it does for a failed listing.
//!
//! The memories hold the hosts and volumes of the last observation. Every time is the caller's `now_us` on one
//! nondecreasing elapsed clock that counts suspended time, such as `CLOCK_BOOTTIME`.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::failover::attachments::{InstanceId, Unlisted};
use crate::failover::loss::Health;
use crate::failover::records::{Host, VolumeId};
use crate::failover::report::{BOOTS, HostReport};
use crate::failover::zone_loop::config::ZoneBounds;
use crate::failover::zone_loop::directory::{Directory, DirectoryState, HostEntry};

/// Dwells and error runs continue across complete listings at most `LISTING_GAP_TICKS` ticks apart.
pub const LISTING_GAP_TICKS: u64 = 2;

/// `volume_health` requires at least `max(loss_ticks, LOSS_TICKS_MIN)` consecutive complete observations of
/// `error` before returning `Health::Lost`.
pub const LOSS_TICKS_MIN: u32 = 2;

/// [`volume_health`] requires `loss_run(loss_ticks)` consecutive complete `error` observations of a volume before
/// returning [`Health::Lost`]. The zone loop requires the same number of consecutive complete views of a shard's
/// active volume: a current run for an isolated loss, and a run that confirmed the loss
/// ([`VolumeJudgement::confirmed`]) for a loss beside another impaired or lost volume.
pub fn loss_run(loss_ticks: u32) -> u32 {
    loss_ticks.max(LOSS_TICKS_MIN)
}

/// An instance's lifecycle state, as the control plane reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceState {
    Pending,
    Running,
    Stopping,
    Stopped,
    ShuttingDown,
    Terminated,
}

/// One status check of an instance, as the control plane reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCheck {
    Ok,
    Impaired,
    InsufficientData,
    Initializing,
    NotApplicable,
}

/// One instance of a zone listing, with its system and instance status checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Instance {
    pub instance: InstanceId,
    pub state: InstanceState,
    pub system_check: StatusCheck,
    pub instance_check: StatusCheck,
}

impl Instance {
    /// `checks` returns impaired if either check is impaired. Otherwise, an ok system check yields the instance
    /// check, and any other system check yields itself.
    pub fn checks(&self) -> StatusCheck {
        match (self.system_check, self.instance_check) {
            (StatusCheck::Impaired, _) | (_, StatusCheck::Impaired) => StatusCheck::Impaired,
            (StatusCheck::Ok, instance) => instance,
            (system, _) => system,
        }
    }
}

/// A volume's lifecycle state, as the control plane's volume listing reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListedVolumeState {
    Creating,
    Available,
    InUse,
    Deleting,
    Deleted,
    Error,
}

/// A volume's status, as the control plane reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeStatus {
    Ok,
    Warning,
    Impaired,
    InsufficientData,
}

/// One volume's state and status in a zone listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeCondition {
    pub state: ListedVolumeState,
    pub status: VolumeStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostEvidence {
    Live,
    Lost,
    Conflict,
    Unknown,
}

/// [`HostRule::of`] derives the windows from validated bounds, under which each is nonzero and `fresh_us` is below
/// `silent_us`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostRule {
    fresh_us: u64,
    silent_us: u64,
    stopped_dwell_us: u64,
    impaired_dwell_us: u64,
    absent_ticks: u32,
}

impl HostRule {
    pub fn of(bounds: &ZoneBounds) -> Self {
        let config = bounds.config();
        Self {
            fresh_us: bounds.fresh_us(),
            silent_us: bounds.silent_us(),
            stopped_dwell_us: config.stopped_dwell_us,
            impaired_dwell_us: config.impaired_dwell_us,
            absent_ticks: config.absent_ticks,
        }
    }

    /// Tests and proofs can supply arbitrary windows, including values outside the validated bounds.
    #[cfg(any(test, kani))]
    pub(crate) fn new(
        fresh_us: u64,
        silent_us: u64,
        stopped_dwell_us: u64,
        impaired_dwell_us: u64,
        absent_ticks: u32,
    ) -> Self {
        Self {
            fresh_us,
            silent_us,
            stopped_dwell_us,
            impaired_dwell_us,
            absent_ticks,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Silence {
    /// This process stamped an advance of the host's reports.
    pub advanced: bool,
    /// `silent_us` measures elapsed time from the baseline until the first stamped advance, then from the most
    /// recent stamped advance.
    pub silent_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceEvidence {
    Unlisted,
    Absent {
        ticks: u32,
    },
    Listed {
        state: InstanceState,
        checks: StatusCheck,
        stopped_us: u64,
        impaired_us: u64,
    },
}

pub fn host_evidence(
    rule: &HostRule,
    state: DirectoryState,
    silence: Silence,
    instance: InstanceEvidence,
) -> HostEvidence {
    if state == DirectoryState::Retired {
        return HostEvidence::Lost;
    }
    let Some(shown) = Shown::of(rule, instance) else {
        return HostEvidence::Unknown;
    };
    if silence.advanced && silence.silent_us <= rule.fresh_us {
        return if shown.contrary {
            HostEvidence::Conflict
        } else {
            HostEvidence::Live
        };
    }
    if silence.silent_us > rule.silent_us && (shown.down || shown.impaired) {
        return HostEvidence::Lost;
    }
    HostEvidence::Unknown
}

/// `instance_down` is true when `instance` shows the host's instance down under `rule`: ended, stopping or stopped
/// for `stopped_dwell_us`, or absent from `absent_ticks` listings in a row. A host whose instance is down answers no
/// new probe; a retired host whose instance runs may still answer one.
pub fn instance_down(rule: &HostRule, instance: InstanceEvidence) -> bool {
    Shown::of(rule, instance).is_some_and(|shown| shown.down)
}

/// `answers_no_probe` is true when the evidence apart from the host's directory state shows that the host answers no
/// new probe: its instance is down ([`instance_down`]), or an active host with this evidence reads `Lost`
/// ([`tick_evidence`]), which adds checks impaired for `impaired_dwell_us` under a report silent past `silent_us`
/// with no unanswered read inside it. A retired host for which this is false may still answer a probe.
pub fn answers_no_probe(
    rule: &HostRule,
    silence: Silence,
    answered_us: u64,
    instance: InstanceEvidence,
) -> bool {
    let active = tick_evidence(rule, DirectoryState::Active, silence, answered_us, instance);
    instance_down(rule, instance) || active == HostEvidence::Lost
}

pub fn tick_evidence(
    rule: &HostRule,
    state: DirectoryState,
    silence: Silence,
    answered_us: u64,
    instance: InstanceEvidence,
) -> HostEvidence {
    match host_evidence(rule, state, silence, instance) {
        HostEvidence::Lost if state != DirectoryState::Retired && answered_us <= rule.silent_us => {
            HostEvidence::Unknown
        }
        verdict => verdict,
    }
}

struct Shown {
    contrary: bool,
    down: bool,
    impaired: bool,
}

impl Shown {
    fn of(rule: &HostRule, instance: InstanceEvidence) -> Option<Self> {
        Some(match instance {
            InstanceEvidence::Unlisted | InstanceEvidence::Absent { ticks: 0 } => return None,
            InstanceEvidence::Absent { ticks } => Self {
                contrary: true,
                down: ticks >= rule.absent_ticks,
                impaired: false,
            },
            InstanceEvidence::Listed {
                state,
                checks,
                stopped_us,
                impaired_us,
            } => {
                let ended = matches!(
                    state,
                    InstanceState::ShuttingDown | InstanceState::Terminated
                );
                Self {
                    contrary: ended || stopping(state),
                    down: ended || (stopping(state) && stopped_us >= rule.stopped_dwell_us),
                    impaired: checks == StatusCheck::Impaired
                        && impaired_us >= rule.impaired_dwell_us,
                }
            }
        })
    }
}

fn stopping(state: InstanceState) -> bool {
    matches!(state, InstanceState::Stopping | InstanceState::Stopped)
}

fn status_ok(status: VolumeStatus) -> Option<bool> {
    match status {
        VolumeStatus::InsufficientData => None,
        VolumeStatus::Ok => Some(true),
        VolumeStatus::Warning | VolumeStatus::Impaired => Some(false),
    }
}

pub fn volume_health(
    condition: Option<VolumeCondition>,
    errors: u32,
    loss_ticks: u32,
) -> Option<Health> {
    let condition = condition?;
    let ok = status_ok(condition.status)?;
    Some(match condition.state {
        ListedVolumeState::Error if errors >= loss_run(loss_ticks) => Health::Lost,
        ListedVolumeState::Available | ListedVolumeState::InUse if ok => Health::Available,
        ListedVolumeState::Available
        | ListedVolumeState::InUse
        | ListedVolumeState::Error
        | ListedVolumeState::Creating
        | ListedVolumeState::Deleting
        | ListedVolumeState::Deleted => Health::Impaired,
    })
}

#[derive(Debug, Clone, Copy)]
struct Sample {
    tick: u64,
    at_us: u64,
}

impl Sample {
    fn continued_by(self, tick: u64, now_us: u64, gap_us: u64) -> bool {
        tick >= self.tick && now_us.saturating_sub(self.at_us) <= gap_us
    }
}

fn listing_gap_us(bounds: &ZoneBounds) -> u64 {
    bounds.config().tick_us.saturating_mul(LISTING_GAP_TICKS)
}

#[derive(Debug, Clone, Default)]
pub struct ReportMemory {
    hosts: BTreeMap<Host, Seen>,
}

#[derive(Debug, Clone)]
struct Seen {
    instance: InstanceId,
    baseline_us: u64,
    // The last boot is current: each higher sequence of it stamps an advance.
    boots: Vec<([u8; 16], u64)>,
    // The recorded earlier boot that most recently sent a higher sequence since the last stamp. Its next higher
    // sequence makes it current and stamps.
    returning: Option<[u8; 16]>,
    latest: Option<Arc<HostReport>>,
    advanced_us: Option<u64>,
    unanswered_us: Option<u64>,
}

impl ReportMemory {
    pub fn track<P>(&mut self, directory: &Directory<P>, now_us: u64) {
        let mut kept = std::mem::take(&mut self.hosts);
        let mut seen = |entry: &HostEntry| {
            let kept = kept.remove(&entry.host);
            let kept = kept.filter(|seen| seen.instance == entry.instance);
            let untracked = || Seen {
                instance: entry.instance,
                baseline_us: now_us,
                boots: Vec::with_capacity(BOOTS),
                returning: None,
                latest: None,
                advanced_us: None,
                unanswered_us: None,
            };
            (entry.host, kept.unwrap_or_else(untracked))
        };
        self.hosts = directory.zone_hosts().map(&mut seen).collect();
    }

    pub fn accepted(&mut self, report: HostReport, now_us: u64) {
        let Some(seen) = self.hosts.get_mut(&report.writer.host) else {
            return;
        };
        Self::advance(seen, &report, now_us);
        if seen.boots.last() == Some(&(report.writer.boot, report.sequence)) {
            seen.latest = Some(Arc::new(report));
        }
    }

    /// The last report recorded for `host` at its current boot's highest sequence.
    pub(crate) fn latest(&self, host: Host) -> Option<&Arc<HostReport>> {
        self.hosts.get(&host)?.latest.as_ref()
    }

    pub fn unanswered(&mut self, host: Host, now_us: u64) {
        if let Some(seen) = self.hosts.get_mut(&host) {
            seen.unanswered_us = Some(now_us);
        }
    }

    pub fn forget(&mut self, host: Host) {
        self.hosts.remove(&host);
    }

    pub fn answered_us(&self, host: Host, now_us: u64) -> u64 {
        let Some(seen) = self.hosts.get(&host) else {
            return 0;
        };
        let since = seen.advanced_us.unwrap_or(seen.baseline_us);
        now_us.saturating_sub(since.max(seen.unanswered_us.unwrap_or(0)))
    }

    fn advance(seen: &mut Seen, report: &HostReport, now_us: u64) {
        let (boot, sequence) = (report.writer.boot, report.sequence);
        let Some((current, earlier)) = seen.boots.split_last_mut() else {
            seen.boots.push((boot, sequence));
            seen.baseline_us = now_us;
            return;
        };
        if current.0 == boot {
            if sequence > current.1 {
                current.1 = sequence;
                seen.returning = None;
                seen.advanced_us = Some(now_us);
            }
            return;
        }
        match earlier.iter().position(|&(earlier, _)| earlier == boot) {
            Some(at) if sequence <= earlier[at].1 => {}
            Some(at) if seen.returning == Some(boot) => {
                seen.boots.remove(at);
                seen.boots.push((boot, sequence));
                seen.returning = None;
                seen.advanced_us = Some(now_us);
            }
            Some(at) => {
                earlier[at].1 = sequence;
                seen.returning = Some(boot);
                seen.unanswered_us = Some(now_us);
            }
            None => {
                if seen.boots.len() == BOOTS {
                    seen.boots.remove(0);
                }
                seen.boots.push((boot, sequence));
                seen.returning = None;
                seen.advanced_us = Some(now_us);
            }
        }
    }

    pub fn silence(&self, host: Host, now_us: u64) -> Silence {
        let Some(seen) = self.hosts.get(&host) else {
            return Silence {
                advanced: false,
                silent_us: 0,
            };
        };
        Silence {
            advanced: seen.advanced_us.is_some(),
            silent_us: now_us.saturating_sub(seen.advanced_us.unwrap_or(seen.baseline_us)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct InstanceMemory {
    gap_us: u64,
    hosts: BTreeMap<Host, (InstanceId, Dwell)>,
    last: Option<Sample>,
    /// The tick of the last complete listing, which a failed listing keeps.
    counted: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
enum Dwell {
    Absent(u32),
    Listed {
        state: InstanceState,
        checks: StatusCheck,
        stopped_since_us: Option<u64>,
        impaired_since_us: Option<u64>,
    },
}

impl Dwell {
    fn next(self, seen: Option<&Instance>, now_us: u64, repeat: bool) -> Self {
        let Some(seen) = seen else {
            return match self {
                Self::Absent(ticks) if repeat => Self::Absent(ticks),
                Self::Listed { .. } if repeat => Self::Absent(0),
                Self::Absent(ticks) => Self::Absent(ticks.saturating_add(1)),
                Self::Listed { .. } => Self::Absent(1),
            };
        };
        let (stopped_before, impaired_before) = match self {
            Self::Listed {
                state,
                stopped_since_us,
                impaired_since_us,
                ..
            } => {
                let restopped =
                    state == InstanceState::Stopped && seen.state == InstanceState::Stopping;
                (stopped_since_us.filter(|_| !restopped), impaired_since_us)
            }
            Self::Absent(_) => (None, None),
        };
        let checks = seen.checks();
        Self::Listed {
            state: seen.state,
            checks,
            stopped_since_us: stopping(seen.state).then(|| stopped_before.unwrap_or(now_us)),
            impaired_since_us: (checks == StatusCheck::Impaired)
                .then(|| impaired_before.unwrap_or(now_us)),
        }
    }
}

impl InstanceMemory {
    pub fn new(bounds: &ZoneBounds) -> Self {
        Self {
            gap_us: listing_gap_us(bounds),
            hosts: BTreeMap::new(),
            last: None,
            counted: None,
        }
    }

    pub fn observe<P>(
        &mut self,
        directory: &Directory<P>,
        listing: Result<&[Instance], Unlisted>,
        tick: u64,
        now_us: u64,
    ) -> Result<(), Unlisted> {
        let Ok(listed) = listing.and_then(|rows| tracked_rows(directory, rows)) else {
            self.hosts.clear();
            self.last = None;
            return Err(Unlisted);
        };
        let last = (self.last).filter(|last| last.continued_by(tick, now_us, self.gap_us));
        let repeat = self.counted == Some(tick);
        let mut kept = std::mem::take(&mut self.hosts);
        if last.is_none() {
            kept.clear();
        }
        let mut next = |entry: &HostEntry| {
            let dwell = (kept.remove(&entry.host))
                .filter(|&(instance, _)| instance == entry.instance)
                .map_or(Dwell::Absent(0), |(_, dwell)| dwell);
            let seen = listed.get(&entry.instance).copied().flatten();
            let dwell = dwell.next(seen.as_ref(), now_us, repeat);
            (entry.host, (entry.instance, dwell))
        };
        self.hosts = directory.zone_hosts().map(&mut next).collect();
        self.last = Some(Sample {
            tick,
            at_us: now_us,
        });
        self.counted = Some(tick);
        Ok(())
    }

    pub fn evidence(&self, host: Host, tick: u64) -> InstanceEvidence {
        let last = self.last.filter(|last| last.tick == tick);
        let (Some((_, dwell)), Some(last)) = (self.hosts.get(&host), last) else {
            return InstanceEvidence::Unlisted;
        };
        let since = |start: Option<u64>| start.map_or(0, |start| last.at_us.saturating_sub(start));
        match *dwell {
            Dwell::Absent(ticks) => InstanceEvidence::Absent { ticks },
            Dwell::Listed {
                state,
                checks,
                stopped_since_us,
                impaired_since_us,
            } => InstanceEvidence::Listed {
                state,
                checks,
                stopped_us: since(stopped_since_us),
                impaired_us: since(impaired_since_us),
            },
        }
    }
}

fn tracked_rows<P>(
    directory: &Directory<P>,
    rows: &[Instance],
) -> Result<BTreeMap<InstanceId, Option<Instance>>, Unlisted> {
    let mut tracked: BTreeMap<InstanceId, Option<Instance>> = directory
        .zone_hosts()
        .map(|entry| (entry.instance, None))
        .collect();
    for row in rows {
        match tracked.get_mut(&row.instance) {
            Some(Some(prior)) if prior != row => return Err(Unlisted),
            Some(slot) => *slot = Some(*row),
            None => {}
        }
    }
    Ok(tracked)
}

#[derive(Debug, Clone)]
pub struct VolumeMemory {
    loss_ticks: u32,
    gap_us: u64,
    volumes: BTreeMap<VolumeId, (VolumeCondition, u32)>,
    last: Option<Sample>,
    /// The tick of the last complete listing, which a failed listing keeps.
    counted: Option<u64>,
}

/// One shard's loss evidence on a tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeJudgement {
    /// The active volume's health.
    pub health: Option<Health>,
    /// The volumes in `named` outside the shard's own that read impaired or lost.
    pub others: usize,
    /// The tick's listing is complete and every volume in `named` outside the shard's own has a health value.
    /// `ZoneLoop::observe` also requires the tick to read the census, every shard's records and the record of every
    /// listed volume it looks up, and to find a shard record for every census slot of a directory shard. A looked-up
    /// volume the store holds no record of leaves a judgement incomplete while a receipt reads `Issued`, until that
    /// receipt leaves `Issued`: for every shard of the zone but the issuer of a later-generation receipt, whose own
    /// create may have made the volume and whose retry of the same token settles it. With no such receipt the volume
    /// adds 0 to `others`. After the directory delists a shard, the loop rereads that shard's receipt while its last
    /// read showed `Open` or `Issued`. A loop whose last read of the shard showed `Created` or no receipt skips the
    /// reread, as does a loop started after the delisting; for such a loop the volume adds 0 to `others`. A
    /// looked-up record or a reread receipt whose stored bytes do not decode leaves every shard's judgement
    /// incomplete on each call that reads it.
    pub complete: bool,
    /// The consecutive numbered ticks, this one included, on which `ZoneLoop::observe` judged this shard `complete`
    /// for its current active volume. A complete judgement on the same tick and active volume as the shard's
    /// previous judgement keeps that judgement's `streak`, so an incomplete judgement earlier on the tick leaves 0.
    /// After an active-volume change, a complete judgement starts at 0 on the previous judgement's tick and at 1 on
    /// a later tick. A call that could not read the shard's records, a call that skipped the lookups, and a call
    /// whose directory admission failed give the tick 0, so a retry on that tick reads 0 and the next tick 1; a shard
    /// first judged on a call that repeats a numbered tick reads 0 as well. [`VolumeMemory::judge`] and
    /// [`VolumeMemory::judge_each`] return 0.
    pub streak: u32,
    /// `ZoneLoop::observe` found the active volume lost on a complete judgement whose `streak` reached
    /// [`loss_run`], and lost on every judgement of the same active volume since, on consecutive ticks. A
    /// confirmation first earned on a tick lasts on that tick only through complete judgements; one carried from the
    /// tick before lasts through the tick. A call that could not judge the shard and a call whose directory admission
    /// failed end it. [`VolumeMemory::judge`] and [`VolumeMemory::judge_each`] return `false`.
    pub confirmed: bool,
}

/// One shard's run of complete views, which `ZoneLoop::observe` carries from one judgement to the next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ViewRun {
    /// The active volume of the last judgement; `None` when the last call could not judge the shard.
    pub(crate) active: Option<VolumeId>,
    /// The observer's tick number of the last call.
    pub(crate) tick: u64,
    /// [`VolumeJudgement::streak`] of the last judgement.
    pub(crate) views: u32,
    /// [`VolumeJudgement::confirmed`] of the last judgement.
    pub(crate) confirmed: bool,
    /// The confirmation the run carried into `tick` from the tick before.
    pub(crate) entered: bool,
}

impl ViewRun {
    pub(crate) fn unjudged(tick: u64) -> Self {
        Self {
            active: None,
            tick,
            views: 0,
            confirmed: false,
            entered: false,
        }
    }

    /// The run after a judgement of `active` on tick `tick`, under the rules of [`VolumeJudgement::streak`] and
    /// [`VolumeJudgement::confirmed`], where `needed` is [`loss_run`] of the zone's bounds.
    pub(crate) fn next(
        prior: Option<Self>,
        active: VolumeId,
        tick: u64,
        complete: bool,
        lost: bool,
        needed: u32,
    ) -> Self {
        let same = prior.filter(|prior| prior.active == Some(active));
        let views = match prior {
            _ if !complete => 0,
            Some(prior) if prior.tick == tick => same.map_or(0, |same| same.views),
            _ => match same {
                Some(same) if same.tick.checked_add(1) == Some(tick) => {
                    same.views.saturating_add(1)
                }
                _ => 1,
            },
        };
        let entered = match same {
            Some(same) if same.tick == tick => same.entered,
            Some(same) if same.tick.checked_add(1) == Some(tick) => same.confirmed,
            _ => false,
        };
        Self {
            active: Some(active),
            tick,
            views,
            confirmed: lost && ((complete && views >= needed) || entered),
            entered,
        }
    }
}

fn impaired(health: Option<Health>) -> bool {
    matches!(health, Some(Health::Impaired | Health::Lost))
}

impl VolumeMemory {
    pub fn new(bounds: &ZoneBounds) -> Self {
        Self {
            loss_ticks: bounds.config().loss_ticks,
            gap_us: listing_gap_us(bounds),
            volumes: BTreeMap::new(),
            last: None,
            counted: None,
        }
    }

    pub fn observe(
        &mut self,
        listing: Result<&[(VolumeId, VolumeCondition)], Unlisted>,
        tick: u64,
        now_us: u64,
    ) -> Result<(), Unlisted> {
        let last = (self.last).filter(|last| last.continued_by(tick, now_us, self.gap_us));
        let repeat = self.counted == Some(tick);
        let mut prior = std::mem::take(&mut self.volumes);
        self.last = None;
        if last.is_none() {
            prior.clear();
        }
        let mut next: BTreeMap<VolumeId, (VolumeCondition, u32)> = BTreeMap::new();
        for &(volume, condition) in listing? {
            match next.entry(volume) {
                Entry::Occupied(seen) if seen.get().0 != condition => return Err(Unlisted),
                Entry::Occupied(_) => {}
                Entry::Vacant(slot) => {
                    slot.insert((condition, error_run(&prior, volume, condition, repeat)));
                }
            }
        }
        self.volumes = next;
        self.last = Some(Sample {
            tick,
            at_us: now_us,
        });
        self.counted = Some(tick);
        Ok(())
    }

    pub fn health(&self, volume: VolumeId, tick: u64) -> Option<Health> {
        let &entry = self.current(tick)?.get(&volume)?;
        self.health_of(entry)
    }

    fn health_of(&self, (condition, errors): (VolumeCondition, u32)) -> Option<Health> {
        volume_health(Some(condition), errors, self.loss_ticks)
    }

    /// Whether `volume` has an error run above zero on tick `tick`'s complete listing. A listing counts the volume
    /// in a run while it shows state `error` with a status value: the first complete listing of a tick adds one to
    /// the run, and a later listing of that tick carries the run the listing before it held for the volume, 0 after
    /// a failed listing. A volume that first shows `error` on such a later listing has run 0 until the next tick's
    /// listing.
    pub fn erring(&self, volume: VolumeId, tick: u64) -> bool {
        let entry = self.current(tick).and_then(|listed| listed.get(&volume));
        entry.is_some_and(|&(_, errors)| errors > 0)
    }

    /// The volumes of tick `tick`'s complete listing whose health is `Some(Health::Impaired)`,
    /// `Some(Health::Lost)` or `None`, ascending. A tick without a complete listing yields none.
    pub fn unavailable(&self, tick: u64) -> impl Iterator<Item = VolumeId> + '_ {
        let listed = self.current(tick).into_iter().flat_map(BTreeMap::iter);
        listed
            .filter(|&(_, &entry)| self.health_of(entry) != Some(Health::Available))
            .map(|(&volume, _)| volume)
    }

    pub fn judge(
        &self,
        volume: VolumeId,
        named: &BTreeSet<VolumeId>,
        tick: u64,
    ) -> VolumeJudgement {
        let own = BTreeSet::from([volume]);
        self.judge_each(&[(volume, own)], named, tick)[0]
    }

    pub fn judge_each(
        &self,
        subjects: &[(VolumeId, BTreeSet<VolumeId>)],
        named: &BTreeSet<VolumeId>,
        tick: u64,
    ) -> Vec<VolumeJudgement> {
        let health: BTreeMap<VolumeId, Option<Health>> = (named.iter())
            .map(|&other| (other, self.health(other, tick)))
            .collect();
        let count = |volumes: &mut dyn Iterator<Item = Option<Health>>| {
            volumes.fold((0, 0), |(impaired_n, missing_n), seen| {
                let missing = usize::from(seen.is_none());
                (
                    impaired_n + usize::from(impaired(seen)),
                    missing_n + missing,
                )
            })
        };
        let (impaired_total, missing_total) = count(&mut health.values().copied());
        let current = self.current(tick).is_some();
        let judged = |(volume, own): &(VolumeId, BTreeSet<VolumeId>)| {
            let mut own_health = own.iter().filter_map(|other| health.get(other).copied());
            let (own_impaired, own_missing) = count(&mut own_health);
            VolumeJudgement {
                health: self.health(*volume, tick),
                others: impaired_total - own_impaired,
                complete: current && missing_total == own_missing,
                streak: 0,
                confirmed: false,
            }
        };
        subjects.iter().map(judged).collect()
    }

    fn current(&self, tick: u64) -> Option<&BTreeMap<VolumeId, (VolumeCondition, u32)>> {
        let last = self.last?;
        (last.tick == tick).then_some(&self.volumes)
    }
}

fn error_run(
    prior: &BTreeMap<VolumeId, (VolumeCondition, u32)>,
    volume: VolumeId,
    condition: VolumeCondition,
    repeat: bool,
) -> u32 {
    if condition.state != ListedVolumeState::Error || status_ok(condition.status).is_none() {
        return 0;
    }
    let before = prior.get(&volume).map_or(0, |&(_, errors)| errors);
    if repeat {
        before
    } else {
        before.saturating_add(1)
    }
}
