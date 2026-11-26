//! The fleet oracles evaluate the store's version history, recovered tenures and settled requests. Each returns
//! `Fail` when the observations violate a rule, `Unrun` when the event that exercises the check never happened,
//! and `Pass` otherwise. `retained` also returns `Inconclusive`, and its doc states the order of its verdicts.

use std::collections::{BTreeMap, BTreeSet};

use crate::failover::records::{Host, ShardRecord};
use crate::net::ownership::Shard;
use crate::oracle::Tenure;
use crate::storage::HostShare;

use super::super::cycles::Verdict;

pub(crate) const TWO_OWNERS: &str = "two hosts own one attempt of a shard";
pub(crate) const TWIN_TENURE: &str = "two hosts activated one tenure";
pub(crate) const REACTIVATED: &str = "one tenure activated twice";
pub(crate) const UNAUTHORIZED: &str =
    "a tenure activated that no record version names for its host";
pub(crate) const NO_ACTIVATION: &str = "no tenure activated";

pub(crate) const GENERATION: &str = "a generation or an active volume changed with no volume lost";
pub(crate) const PROVISIONED: &str =
    "a volume record or a replacement receipt was written with no volume lost";
pub(crate) const FLIP_REQUEST: &str = "a recovery requested a flip with no volume lost";
pub(crate) const HOST_LOSS: &str =
    "a host loss changed a shard's generation or provisioned a volume";
pub(crate) const NO_CRASH: &str = "no crash episode ran";

pub(crate) const UNSERVED: &str =
    "a retained entry was not served its exact bytes at the recovered tenure";
pub(crate) const INCONCLUSIVE: &str = "the history oracle decided nothing";
pub(crate) const ACCOUNT: &str =
    "the history oracle's account of a swept tenure does not hold every object served";
pub(crate) const UNSWEPT: &str = "the retained-set sweep did not run";

pub(crate) const SILENT: &str = "a shard neither serves with a standby nor reports a blocker";
pub(crate) const NO_RECONCILER: &str = "no reconciler runs to settle the fleet";
pub(crate) const LATE: &str = "a recovery passed the settle bound";
pub(crate) const WITHDRAWN: &str = "a tenure that no fault deposed stopped serving";

pub(crate) const ROLES: &str = "a host's roles exceed the owners its recovery share divides over";
pub(crate) const READS: &str = "a host's recovery reads passed twice its share";
pub(crate) const UNCHARGED: &str = "no recovery charged its share";
pub(crate) const UNREFUSED: &str =
    "a recovery load met no share window whose limiter refused a charge";
pub(crate) const NO_LOAD: &str = "no recovery load was judged against its limiter";

pub(crate) const STORE_REQUEST: &str =
    "an untouched shard's records took a store request other than its own record views";
pub(crate) const VIEW_WRITE: &str = "an untouched shard's serving duties wrote its records";
pub(crate) const VIEW_READS: &str = "an untouched shard's reads were other than one volume-record and one shard-record read a view period";
pub(crate) const TENURE_MOVED: &str = "an untouched shard changed its tenure";
pub(crate) const STANDBY_READS: &str = "an untouched shard's standby made more than two record reads or a write in a view period of its wait";
pub(crate) const NO_WAIT: &str =
    "no untouched shard's standby ran a view period of its wait during a recovery";
pub(crate) const REFUSED: &str = "an untouched shard did not serve a request its object's bytes";
pub(crate) const NO_NEIGHBOUR: &str = "no request reached an untouched shard during a recovery";
pub(crate) const NO_WATCH: &str = "a request reached a shard that no watch covers";
pub(crate) const NO_OVERLAP: &str =
    "a request to an untouched shard was not served before the recovering session was active";

fn fail(rule: &'static str, at: impl std::fmt::Display) -> Verdict {
    Verdict::Fail(rule, at.to_string())
}

/// `histories` holds every committed version of each shard's record, oldest first. An activation at `(g, a)` is
/// authorized by a version filed under its shard that names that shard, generation `g`, attempt `a / 2` and its
/// host as owner.
/// This check covers one owner per attempt and per activated tenure. It does not show that the holder's own
/// acknowledged write preceded its activation.
pub(crate) fn one_owner(
    histories: &[(Shard, Vec<ShardRecord>)],
    activations: &[(Shard, Tenure, Host)],
) -> Verdict {
    for (shard, versions) in histories {
        let mut owners: BTreeMap<(u64, u32), BTreeSet<u64>> = BTreeMap::new();
        for record in versions {
            let attempt = (record.generation.get(), record.attempts);
            owners
                .entry(attempt)
                .or_default()
                .insert(record.owner.get());
        }
        if let Some((attempt, _)) = owners.iter().find(|(_, hosts)| hosts.len() > 1) {
            return fail(
                TWO_OWNERS,
                format!("shard {} attempt {attempt:?}", shard.get()),
            );
        }
    }
    let mut hosts: BTreeMap<(u32, u64, u64), u64> = BTreeMap::new();
    for (shard, tenure, host) in activations {
        let at = format!("shard {} tenure {tenure:?}", shard.get());
        let key = (shard.get(), tenure.g, tenure.a);
        if let Some(other) = hosts.insert(key, host.get()) {
            let rule = if other == host.get() {
                REACTIVATED
            } else {
                TWIN_TENURE
            };
            return fail(rule, at);
        }
        let versions = histories.iter().find(|(of, _)| of == shard);
        let named = versions.is_some_and(|(_, versions)| {
            versions.iter().any(|record| {
                record.shard == *shard
                    && record.generation.get() == tenure.g
                    && u64::from(record.attempts) * 2 == tenure.a
                    && record.owner == *host
            })
        });
        if !named {
            return fail(UNAUTHORIZED, at);
        }
    }
    let activated: BTreeSet<u32> = activations.iter().map(|(shard, ..)| shard.get()).collect();
    if histories
        .iter()
        .any(|(shard, _)| !activated.contains(&shard.get()))
    {
        return Verdict::Unrun(NO_ACTIVATION);
    }
    Verdict::Pass
}

/// Counts over the whole run, taken over the shards whose volume the injector did not mark lost: the store's
/// generation flips less the lost shards' generation-changing commits, the commits to any volume-record key after the
/// fleet was seeded less the volumes a lost shard's create step returned, the kept shards' replacement-receipt
/// commits, and the kept shards' flip requests of refused restarts and of tenures' authorities. The store's flip log
/// carries no shard.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Volumes {
    pub(crate) flips: usize,
    pub(crate) volume_writes: usize,
    pub(crate) receipts: usize,
    pub(crate) flip_requests: usize,
}

/// The shards whose volume the injector marked lost, and the shards whose holder's host it lost.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Losses {
    pub(crate) volumes: Vec<u32>,
    pub(crate) hosts: Vec<u32>,
}

/// Fleet oracle F2 over the shards whose volume the injector did not mark lost: `volumes` counts those shards'
/// flips, receipts and flip requests and the volume records no lost shard's create step returned. A generation or
/// active-volume change of a shard whose host was lost fails by [`HOST_LOSS`], and of any other shard by
/// [`GENERATION`].
pub(crate) fn keeps_volume(
    histories: &[(Shard, Vec<ShardRecord>)],
    volumes: Volumes,
    crashes: u32,
    losses: &Losses,
) -> Verdict {
    for (shard, versions) in histories {
        if losses.volumes.contains(&shard.get()) {
            continue;
        }
        let moved = versions.windows(2).any(|pair| {
            pair[0].generation != pair[1].generation || pair[0].active != pair[1].active
        });
        if moved {
            let rule = match losses.hosts.contains(&shard.get()) {
                true => HOST_LOSS,
                false => GENERATION,
            };
            return fail(rule, format!("shard {}", shard.get()));
        }
    }
    if volumes.flips > 0 {
        return fail(GENERATION, format!("{} flips", volumes.flips));
    }
    if volumes.volume_writes + volumes.receipts > 0 {
        let at = format!(
            "{} volume writes, {} receipts",
            volumes.volume_writes, volumes.receipts
        );
        return fail(PROVISIONED, at);
    }
    if volumes.flip_requests > 0 {
        return fail(FLIP_REQUEST, format!("{} requests", volumes.flip_requests));
    }
    if crashes == 0 {
        return Verdict::Unrun(NO_CRASH);
    }
    Verdict::Pass
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Retention {
    pub(crate) shard: Shard,
    /// The tenures of the shard that activated.
    pub(crate) activations: usize,
    /// Each tenure that reached its sweep has one entry, `None` for a skipped sweep. A sweep result counts
    /// requested objects and exact-byte matches.
    pub(crate) sweeps: Vec<Option<(u32, u32)>>,
    pub(crate) judged: Judged,
}

/// The history oracle's judgment of one shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Judged {
    Passed,
    /// The history shows a retained entry that no GET served. A skipped sweep alone produces this rule.
    Unserved(&'static str),
    /// Any other rule the history violated.
    Violated(&'static str),
    Undecided,
}

/// In order: `Unrun` when no tenure swept; `Fail` on the first shard with a sweep that ran short, a violated
/// history rule, or an unserved entry on a shard whose activated tenures all swept; `Unrun` when an activated
/// tenure did not sweep; `Inconclusive` when a history is undecided; `Pass`.
pub(crate) fn retained(shards: &[Retention]) -> Verdict {
    let skipped = |shard: &Retention| {
        shard.sweeps.iter().any(Option::is_none) || shard.sweeps.len() < shard.activations
    };
    if shards.iter().all(|shard| shard.sweeps.is_empty()) {
        return Verdict::Unrun(UNSWEPT);
    }
    for retention in shards {
        let shard = retention.shard.get();
        let mut sweeps = retention.sweeps.iter().flatten();
        if let Some((eligible, served)) = sweeps.find(|(eligible, served)| served < eligible) {
            let at = format!("shard {shard} served {served} of {eligible}");
            return fail(UNSERVED, at);
        }
        match retention.judged {
            Judged::Violated(rule) => return fail(rule, format!("shard {shard}")),
            Judged::Unserved(rule) if !skipped(retention) => {
                return fail(rule, format!("shard {shard}"));
            }
            Judged::Unserved(_) | Judged::Passed | Judged::Undecided => {}
        }
    }
    if shards.iter().any(skipped) {
        return Verdict::Unrun(UNSWEPT);
    }
    if shards.iter().any(|shard| shard.judged == Judged::Undecided) {
        return Verdict::Inconclusive(INCONCLUSIVE);
    }
    Verdict::Pass
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Settle {
    pub(crate) shard: Shard,
    /// Whether, when the run ends, a tenure at the record's `(g, E)` holds the shard with its authority `Serving`
    /// inside its Report window, its owner `Live`, its client session active and the client's route bound to it.
    pub(crate) serving: bool,
    pub(crate) standby: bool,
    /// The blockers the shard's last recovery reported.
    pub(crate) blockers: usize,
    /// The tenures that opened a client session and that the fleet's own close ended with an authority other than
    /// `Serving`. A tenure that `serve::teardown` ended at a `Rerun` or a `Deposed` exit is judged by that exit
    /// (`hosts::unscripted_exit`, the first rule of `Report::credit`) and is counted in no shard's withdrawals.
    pub(crate) withdrawals: usize,
    pub(crate) rounds: Vec<u64>,
}

fn withdrawn(settle: &Settle) -> Option<Verdict> {
    let at = || {
        format!(
            "shard {} {} tenures",
            settle.shard.get(),
            settle.withdrawals
        )
    };
    (settle.withdrawals > 0).then(|| fail(WITHDRAWN, at()))
}

/// The settle verdict of a run with no reconciler: the withdrawn rule alone is judged, and a run that keeps it
/// reads `Unrun`.
pub(crate) fn unsettled(shards: &[Settle]) -> Verdict {
    let failed = shards.iter().find_map(withdrawn);
    failed.unwrap_or(Verdict::Unrun(NO_RECONCILER))
}

pub(crate) fn settles(shards: &[Settle], bound: u64, crashes: u32) -> Verdict {
    for settle in shards {
        if let Some(failed) = withdrawn(settle) {
            return failed;
        }
        if !(settle.serving && settle.standby) && settle.blockers == 0 {
            return fail(SILENT, format!("shard {}", settle.shard.get()));
        }
        if let Some(rounds) = settle.rounds.iter().find(|&&rounds| rounds > bound) {
            let at = format!("shard {} took {rounds} rounds", settle.shard.get());
            return fail(LATE, at);
        }
    }
    if crashes == 0 {
        return Verdict::Unrun(NO_CRASH);
    }
    Verdict::Pass
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostUse {
    pub(crate) host: Host,
    pub(crate) roles: u32,
    pub(crate) shares: Vec<HostShare>,
    /// The sum, over the shards the host owns, of the largest peak window bytes any recovery of the shard reported.
    pub(crate) peak_bytes: u64,
}

pub(crate) fn within_share(hosts: &[HostUse]) -> Verdict {
    for HostUse {
        host,
        roles,
        shares,
        peak_bytes,
    } in hosts
    {
        if let Some(share) = shares.iter().find(|share| share.owners < *roles) {
            let at = format!("host {} roles {roles} owners {}", host.get(), share.owners);
            return fail(ROLES, at);
        }
        if let Some(share) = shares
            .iter()
            .find(|share| *peak_bytes > share.bytes.saturating_mul(2))
        {
            let at = format!("host {} read {peak_bytes} of {}", host.get(), share.bytes);
            return fail(READS, at);
        }
    }
    if hosts.iter().all(|host| host.peak_bytes == 0) {
        return Verdict::Unrun(UNCHARGED);
    }
    Verdict::Pass
}

/// Judges recovery loads that a scenario sizes above their owner's part of the host share: each reports a share
/// window in which its limiter refused a charge. A load whose limiter admitted every charge fails by `UNREFUSED`,
/// and an empty list is `Unrun`.
pub(crate) fn meets_limiter(loads: &[super::Recovered]) -> Verdict {
    if let Some(load) = loads.iter().find(|load| load.saturated == 0) {
        let (host, share) = (load.host.get(), load.share);
        let at = format!("host {host} share {} over {}", share.bytes, share.owners);
        return fail(UNREFUSED, at);
    }
    if loads.is_empty() {
        return Verdict::Unrun(NO_LOAD);
    }
    Verdict::Pass
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Watched {
    pub(crate) shard: Shard,
    /// Whether the shard's records took a store request other than its own serving duties' since another shard's
    /// crash, and whether its record's
    /// `(g, E)` and owner or its client's route differ from their values at that crash or its authority stopped
    /// serving. Both are sampled once that shard's recovery ended and its GETs drained.
    pub(crate) requested: bool,
    pub(crate) moved: bool,
    /// What the shard's own serving duties did on its records over the same interval.
    pub(crate) views: Views,
    /// The view periods of the shard's standby wait over the same interval, the most reads one of them made, and the
    /// writes they made together; `None` in a run with no hosts.
    pub(crate) waits: Option<Waits>,
}

/// A standby wait's view periods over an interval, judged period by period: their count, the most reads one period
/// made, and the writes of all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Waits {
    pub(crate) periods: u64,
    pub(crate) most_reads: u64,
    pub(crate) writes: u64,
}

impl Waits {
    /// The summary of the periods `waits` lists as their reads and writes.
    pub(crate) fn of(waits: &[(u64, u64)]) -> Self {
        Self {
            periods: waits.len() as u64,
            most_reads: waits.iter().map(|&(reads, _)| reads).max().unwrap_or(0),
            writes: waits.iter().map(|&(_, writes)| writes).sum(),
        }
    }
}

/// What a shard's serving duties did on its records over `rounds` fleet rounds: the reads of its volume record, of
/// its shard record and of any other of its records, and the writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Views {
    pub(crate) volume: u64,
    pub(crate) shard: u64,
    pub(crate) other: u64,
    pub(crate) writes: u64,
    pub(crate) rounds: u64,
}

impl Views {
    /// The most record views the duties submit over the interval: one each view period begun in it. The sample and
    /// the watch each come before the duty turns of their round, so the interval holds the duty turns of `rounds`
    /// rounds of a tenure stepped once a round, and views at least [`VIEW_ROUNDS`] rounds apart number at most
    /// `ceil(rounds / VIEW_ROUNDS)` there.
    pub(crate) fn bound(&self) -> u64 {
        self.rounds.div_ceil(VIEW_ROUNDS)
    }

    /// The fewest record views the duties submit over the interval: one each whole view period in it. A tenure
    /// stepped once a round submits a view every [`VIEW_ROUNDS`] duty turns, so `rounds` turns hold at least
    /// `floor(rounds / VIEW_ROUNDS)` of them.
    pub(crate) fn due(&self) -> u64 {
        self.rounds / VIEW_ROUNDS
    }

    /// Whether the reads are the interval's record views, judged on per-key totals: as many volume-record reads as
    /// shard-record reads, from [`Views::due`] to [`Views::bound`] of each, and no read of another of the shard's
    /// records. The totals attribute no read to a view, a tenure or a round.
    pub(crate) fn exact(&self) -> bool {
        let views = self.due()..=self.bound();
        self.other == 0 && self.volume == self.shard && views.contains(&self.shard)
    }
}

/// The fleet rounds of the duties' view period.
pub(crate) const VIEW_ROUNDS: u64 = super::DUTY_VIEW_US / super::super::ROUND_US;

/// `requests` holds each GET sent to a serving shard during another shard's recovery and whether the client
/// received the object's exact bytes on a route that admitted every frame. `overlapped` counts those served
/// between the crash and the recovering tenure's active session or blocker.
pub(crate) fn untouched(
    watched: &[Watched],
    requests: &[(Shard, bool)],
    overlapped: usize,
) -> Verdict {
    if let Some((shard, _)) = requests.iter().find(|(_, served)| !served) {
        return fail(REFUSED, format!("shard {}", shard.get()));
    }
    for watch in watched {
        if watch.requested {
            return fail(STORE_REQUEST, format!("shard {}", watch.shard.get()));
        }
        let views = watch.views;
        if views.writes > 0 {
            let at = format!("shard {} {} writes", watch.shard.get(), views.writes);
            return fail(VIEW_WRITE, at);
        }
        if !views.exact() {
            let (shard, rounds) = (watch.shard.get(), views.rounds);
            let (volume, record, other) = (views.volume, views.shard, views.other);
            let at = format!(
                "shard {shard} reads volume {volume} shard {record} other {other} over {rounds} rounds"
            );
            return fail(VIEW_READS, at);
        }
        if watch.moved {
            return fail(TENURE_MOVED, format!("shard {}", watch.shard.get()));
        }
        if let Some(waits) = watch.waits
            && (waits.most_reads > 2 || waits.writes > 0)
        {
            let (reads, writes) = (waits.most_reads, waits.writes);
            let at = format!("shard {} reads {reads} writes {writes}", watch.shard.get());
            return fail(STANDBY_READS, at);
        }
    }
    if requests.is_empty() {
        return Verdict::Unrun(NO_NEIGHBOUR);
    }
    // A run with hosts needs one view period of a watched standby's wait to judge the standby's bound.
    let hosted = watched.iter().any(|watch| watch.waits.is_some());
    let waited = (watched.iter()).any(|watch| watch.waits.is_some_and(|waits| waits.periods > 0));
    if hosted && !waited {
        return Verdict::Unrun(NO_WAIT);
    }
    let covered = |shard: &Shard| watched.iter().any(|watch| watch.shard == *shard);
    if !requests.iter().all(|(shard, _)| covered(shard)) {
        return Verdict::Unrun(NO_WATCH);
    }
    if overlapped < requests.len() {
        return Verdict::Unrun(NO_OVERLAP);
    }
    Verdict::Pass
}

pub(crate) const OVER_CAP: &str = "a zone's census lists more shards than its cap";
pub(crate) const UNCOVERED: &str = "a shard record names a designated standby with no census entry";
pub(crate) const NO_RESERVATION: &str = "witness reservations missing";
pub(crate) const NO_COVERAGE: &str = "witness boot-coverage missing";

/// Fleet oracle F4 over every committed census version's entry count in every zone, each zone's `cap`, and the
/// reconcilers' log: the first shard record found naming a standby with no census entry after a commit, and the
/// reservations made. A run reads `Unrun` unless, in each of its `zones` zones, the census once covered every live
/// named standby.
pub(crate) fn census(
    versions: &[usize],
    (cap, zones): (usize, u16),
    log: &super::reconcile::ReconLog,
) -> Verdict {
    if let Some((at, len)) = versions.iter().enumerate().find(|(_, len)| **len > cap) {
        return fail(OVER_CAP, format!("version {} lists {len} of {cap}", at + 1));
    }
    if let Some((shard, round)) = log.uncovered {
        return fail(UNCOVERED, format!("shard {shard} at round {round}"));
    }
    if log.reservations == 0 {
        return Verdict::Unrun(NO_RESERVATION);
    }
    if (1..=zones).any(|zone| !log.covered.contains(&zone)) {
        return Verdict::Unrun(NO_COVERAGE);
    }
    Verdict::Pass
}

/// One shard's state when the run ended: whether it serves with a standby, and the blocker it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Settled {
    pub(crate) shard: Shard,
    pub(crate) served: bool,
    pub(crate) blocker: Option<crate::failover::zone_loop::status::Blocker>,
}

impl Settled {
    /// A served shard carries no blocker or `VolumeImpaired`, and an unserved shard carries a blocker.
    pub(crate) fn settled(&self) -> bool {
        match self.served {
            true => self.blocker.is_none_or(serves_on),
            false => self.blocker.is_some(),
        }
    }
}

/// `VolumeImpaired` is the one blocker a serving shard carries: the reconciler retained the impaired volume, and
/// the tenure on it serves on.
fn serves_on(blocker: crate::failover::zone_loop::status::Blocker) -> bool {
    blocker == crate::failover::zone_loop::status::Blocker::VolumeImpaired
}

/// The volume-side blockers a later restart's or takeover's hold leaves carried, `VolumeImpaired` and
/// `CorrelatedHold`.
fn standing(blocker: crate::failover::zone_loop::status::Blocker) -> bool {
    use crate::failover::zone_loop::status::Blocker;
    matches!(blocker, Blocker::VolumeImpaired | Blocker::CorrelatedHold)
}

pub(crate) const UNSETTLED: &str = "a shard reached neither a serving owner with an enrolled standby nor a named blocker within the settle bound";
pub(crate) const UNBACKED: &str = "a blocker was recorded with no typed refusal behind it";
pub(crate) const STALE_BLOCKER: &str =
    "a shard that serves with an enrolled standby carries a blocker";
pub(crate) const NO_SETTLE: &str = "witness settle-started missing";

/// Fleet oracle F5. Every shard ends served with a standby or carrying a blocker, never both except a served
/// shard's `VolumeImpaired`, and the last time every shard did so came within
/// [`REPAIR_SETTLE_ROUNDS`](super::reconcile::REPAIR_SETTLE_ROUNDS) of the settle phase's start, a bound that is a
/// hypothesis. Every blocker the log entered follows a refusal of its shard that `reconcile::backs` matches. An
/// unserved shard's final blocker is the last one its log entered, or, for `VolumeImpaired` and `CorrelatedHold`,
/// the last of those two its log entered, since a later hold leaves either carried. A run whose settle phase never
/// started reads `Unrun`.
///
/// Each logged blocker names a distinct earlier refusal for the same shard.
/// `reconcile::backs` matches the blocker to that refusal.
pub(crate) fn settled(shards: &[Settled], log: &super::reconcile::ReconLog) -> Verdict {
    let bound = super::reconcile::REPAIR_SETTLE_ROUNDS;
    let Some(phase) = log.settle else {
        return Verdict::Unrun(NO_SETTLE);
    };
    if let Some(shard) = shards.iter().find(|s| !s.served && s.blocker.is_none()) {
        return fail(UNSETTLED, format!("shard {}", shard.shard.get()));
    }
    if let Some(stale) =
        (shards.iter()).find(|s| s.served && s.blocker.is_some_and(|b| !serves_on(b)))
    {
        let at = format!("shard {} {:?}", stale.shard.get(), stale.blocker);
        return fail(STALE_BLOCKER, at);
    }
    match phase.turns {
        Some(turns) if turns <= bound => {}
        Some(turns) => {
            return fail(
                UNSETTLED,
                format!("every shard settled after {turns} rounds"),
            );
        }
        None => {
            return fail(
                UNSETTLED,
                format!("every shard settled only past {bound} rounds"),
            );
        }
    }
    for (entry, (seq, shard, blocker, refusal)) in log.blockers.iter().enumerate() {
        let named = (log.refusals.iter()).find(|(at, _, _)| Some(*at) == *refusal);
        let backed = named.is_some_and(|(at, of, refused)| {
            at < seq && of == shard && super::reconcile::backs(*blocker, refused)
        });
        let shared = (log.blockers[..entry].iter()).any(|(.., earlier)| earlier == refusal);
        if !backed || shared {
            return fail(UNBACKED, format!("shard {shard} {blocker:?}"));
        }
    }
    for settled in shards.iter().filter(|s| !s.served) {
        let shard = settled.shard.get();
        let kept = settled.blocker.is_some_and(standing);
        let entered = (log.blockers.iter())
            .rev()
            .filter(|(_, of, ..)| *of == shard);
        let last = entered
            .map(|(_, _, blocker, _)| *blocker)
            .find(|&b| !kept || standing(b));
        if last != settled.blocker {
            let at = format!("shard {shard} {:?}", settled.blocker);
            return fail(UNBACKED, at);
        }
    }
    Verdict::Pass
}

pub(crate) const FENCE_ORDER: &str =
    "a tenure admitted an operation before its last coverage fence commit";
pub(crate) const NO_ADMISSION: &str = "no tenure admitted an operation";

/// The kind of a tenure's first admitted operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admitted {
    /// A GET the tenure answered with its object's bytes.
    Hit,
    /// A FILL the tenure published.
    Fill,
    /// An INVALIDATE the tenure acknowledged.
    Invalidate,
}

/// A tenure's first admitted operation, with the commit count of each coverage page of its shard read when the
/// fleet submitted the operation to the tenure, which is at or before its admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Admission {
    pub(crate) shard: Shard,
    pub(crate) tenure: Tenure,
    pub(crate) admitted: Admitted,
    pub(crate) pages: Vec<usize>,
}

/// A shard with, for each of its coverage pages, the fence of every committed version, oldest first.
pub(crate) type PageFences = (Shard, Vec<Vec<u64>>);

/// The position, counted from one, of `tenure`'s fence commit on each page of `pages`: the first version that carries
/// the tenure's session. `None` for a page no version of which carries it. A fence write that committed with an
/// unknown reply and its confirming write both carry the session, and the first one is taken; the fleet's zone
/// scenarios arm no store fault, so each page holds one fence write per tenure.
pub(crate) fn fence_commits(pages: &[Vec<u64>], tenure: Tenure) -> Vec<Option<usize>> {
    let session = (tenure.g << 32) | tenure.a;
    let commit = |versions: &Vec<u64>| {
        let first = versions.iter().position(|&fence| fence == session);
        first.map(|at| at + 1)
    };
    pages.iter().map(commit).collect()
}

/// The fence-before-admission check (acknowledged coverage precedes a successor tenure's admission): for each
/// admission, every coverage page of the shard holds the tenure's fence commit at a position within the page's
/// commit count at the operation's submission, so the tenure's last fence commit precedes the admission of its first
/// hit, acknowledged FILL or acknowledged INVALIDATE. A run with no admission reads `Unrun`.
pub(crate) fn fenced_before_admission(fences: &[PageFences], admissions: &[Admission]) -> Verdict {
    for admission in admissions {
        let at = format!(
            "shard {} tenure {:?} {:?}",
            admission.shard.get(),
            admission.tenure,
            admission.admitted
        );
        let Some((_, pages)) = fences.iter().find(|(shard, _)| *shard == admission.shard) else {
            return fail(FENCE_ORDER, at);
        };
        let commits = fence_commits(pages, admission.tenure);
        let fenced = commits.len() == admission.pages.len()
            && (commits.iter().zip(&admission.pages))
                .all(|(commit, count)| commit.is_some_and(|commit| commit <= *count));
        if !fenced {
            return fail(FENCE_ORDER, at);
        }
    }
    if admissions.is_empty() {
        return Verdict::Unrun(NO_ADMISSION);
    }
    Verdict::Pass
}

pub(crate) const ALARM_SET: &str = "the fired alarm rows differ from the scenario's expected set";
pub(crate) const ALARM_UNREAD: &str = "the alarm oracle's reader refused a sealed report or status";
pub(crate) const ALARM_UNSEALED: &str = "a report or status writer refused a due record, or a status writer an early one its scenario does not script";
pub(crate) const ALARM_NOT_JUDGED: &str = "the scenario states no expected alarm set";
pub(crate) const ALARM_PLANTED: &str = "a planted run's alarm set is not judged";
pub(crate) const ALARM_INCOMPLETE: &str = "a scenario's alarm set was not judged";
