//! The host detector of one observer, the standby: one table over every peer the shard records name as owner or
//! standby, the heartbeat admission that feeds it, the indirect probe record of each suspect, and the nominations it
//! publishes for the shard records that name this observer as standby, each naming the record's `(g, owner, E)`.
//!
//! Invariants:
//!
//! - ADMIT-BEFORE-STATE: a heartbeat changes detector state only after it decodes at [`beat::VERSION`], names a host
//!   the table tracks, verifies under that host's key for this observer and falls inside the host's replay window:
//!   the current boot with a sequence above the highest admitted one, a boot whose stamp is above every stamp admitted
//!   from the host, or any other boot once the current boot is suspected and the heartbeat acknowledges one of the
//!   observer's last `D` heartbeats of this observer boot, which a recording cannot carry. A peer with no
//!   current boot, such as every peer of a new `Watch` and a host tracked again after leaving the records, admits
//!   any authenticated boot, so the replay floor lasts as long as this table remembers the peer. A refused
//!   heartbeat, probe reply, sync or tick leaves every table, counter and deadline as it was; a refused sync rewrites
//!   only its `seen` and `roster` scratch.
//! - NAMED-TARGET: a nomination names a shard the last sync listed with this observer as standby, the `(g, owner, E)`
//!   of that record and the owner's observation generation. A sync that adds or changes a target of an owner, or
//!   moves a tracked peer to another partition, opens a newer generation for that peer, which clears its suspicion
//!   and restarts its new-peer and holder grace, so evidence gathered before the change cannot nominate.
//! - INDIRECT-QUORUM: every suspected peer is probed. A suspect is nominated only on DEAD votes of its current probe
//!   cycle, each dated by the window its request was issued in and counted for `rounds` windows plus the jitter,
//!   from at least `k >= 2` distinct partitions other than the
//!   suspect's, each prober's partition taken from the last sync's placement. An ALIVE vote of the cycle vetoes at
//!   once, in any round and in the judging window: it ends the cycle, so the owner's published targets lapse, and it
//!   keeps the peer out of the suspect count until a DEAD vote of a later cycle arrives or a window reads ALIVE. An UNKNOWN vote holds the prober's place without counting, so the quorum waits
//!   for DEAD answers. A cycle that spends every round without a quorum reads UNKNOWN for one window and probing
//!   restarts; a cycle that reached a quorum holds its round, so probing continues and a veto still applies.
//! - FRESH-EVIDENCE: an unobserved window close, at a late tick or one after an observer pause, ends the peer's
//!   probe cycle, and a nomination needs an observed close less than two windows old.
//! - ONCE-PER-CYCLE: each target is published at most once per probe cycle that reached a quorum, and
//!   [`Watch::revalidate`] accepts a nomination only while that cycle holds and the arbiter still accepts its votes.
//! - SELF-SUSPICION: when at least `self_suspect` peers hold a suspicion, no veto, no fresh declared reading and
//!   no recovery from a declared hold at one tick, the observer suspects itself for the arbiter's dwell, publishes
//!   no nomination, refuses revalidation and reports the repair demand. A fresh declared reading rests on an
//!   authenticated heartbeat that arrived, so it is no evidence that the observer is cut off. A peer recovers from
//!   a declared hold ([`Peer::recovers`](super::Peer::recovers)) from the healthy heartbeat with progress that ends
//!   its declaration, through the gray suspicion that heartbeat leaves, for as long as every observed window
//!   progresses; a window without progress and an unobserved close count the peer again. Hosts that leave their
//!   holds together therefore raise no repair demand while each makes progress. The arbiter's own self-suspicion on
//!   an empty vote list never arises here, because a peer with no DEAD vote is not judged.
//! - DECLARED-FRESH: a peer's declared reading counts, in its local evidence, in [`Watch::liveness`] and so in the
//!   reading a prober answers with, only from the window close that read it until a heartbeat that reports the
//!   peer healthy is admitted; the declared reading then reads gray. The SELF-SUSPICION count uses the fresh
//!   declaration from the close before an exhausted probe cycle's UNKNOWN mask.
//! - DECLARED-BRAKE: while the declarations of at least `self_suspect` peers stand, every declared suspicion and
//!   declared vote reads gray to the arbiter, so a correlated declaration nominates only with a second observer
//!   class, and silent peers still nominate. A peer's declaration stands from its first declared reading until a
//!   heartbeat that reports the peer healthy is admitted, except while `D` or more consecutive windows have passed
//!   with no heartbeat from the peer.
//! - DETECTION-CARRIES-NO-SAFETY: the detector publishes values only; it issues no device command and no store
//!   request. The takeover compare-and-swap on the shard record decides, so every timing input here changes only
//!   when a nomination appears.
//! - BOUNDED: the table holds at most the AZ host maximum of peers and placements, at most `shards` targets, at most
//!   [`MAX_PROBERS`] probe votes per peer, `D` sent-heartbeat stamps and at most `per_tick` nominations per tick, all
//!   reserved at construction. Ticks start the nomination pass at a rotating peer, so one owner's targets cannot hold
//!   the budget every tick.
//!
//! Every time is in microseconds on the observer's suspend-aware elapsed clock, the serving table's clock.
//!
//! Caller contract: tick at each [`Watch::deadline`], and admit a heartbeat received after a deadline only after the
//! tick for that deadline. A tick more than `h + jitter` after the previous tick is an observer pause for each
//! window open at the previous tick.

use super::beat::{self, BeatError, BeatKey};
use super::{
    DetectBounds, DetectRefusal, Detector, Failure, Liveness, ObservationGeneration, Peer,
    PeerSlot, Suspicion,
};
use crate::failover::arbiter::{
    self, ArbiterBounds, Clock, Decline, FlipNomination, Nomination, Observation, ObserverClass,
    Partition, Vote,
};
use crate::failover::records::{Host, ShardRecord};
use crate::failover::retire::Target;
use crate::failover::serving::Event;
use crate::net::ownership::Shard;

/// The most probe votes one suspect keeps, one per prober.
pub const MAX_PROBERS: usize = 8;

/// The detector's validated inputs.
#[derive(Debug, Clone, Copy)]
pub struct WatchBounds {
    pub detect: DetectBounds,
    /// The arbiter's bounds; their window equals the detector's.
    pub arbiter: ArbiterBounds,
    /// The most shard records one sync lists.
    pub shards: usize,
    /// The most nominations one tick publishes.
    pub per_tick: usize,
    /// The simultaneous suspects that make the observer suspect itself, from 2 to the AZ host maximum, and the
    /// standing declarations that brake nominations on declared evidence (DECLARED-BRAKE). Automatic recovery of
    /// every shard of a failed placement partition needs a value above the largest partition's host count.
    pub self_suspect: usize,
}

impl WatchBounds {
    /// Checks both cores' bounds, equal windows, a quorum of at most [`MAX_PROBERS`], fewer than `u32::MAX` probe
    /// rounds, positive `shards` and `per_tick`, and `self_suspect` in `2..=detect.hosts`.
    /// The vote lifetime `h * rounds + jitter` must fit `u64`, because `Watch::reach` computes it unchecked.
    pub fn validate(self) -> Result<Self, WatchRefusal> {
        self.detect.validate().map_err(WatchRefusal::Detect)?;
        self.arbiter.validate().map_err(WatchRefusal::Arbiter)?;
        let lifetime = self
            .detect
            .h
            .checked_mul(u64::from(self.arbiter.rounds))
            .and_then(|v| v.checked_add(self.detect.jitter));
        if self.arbiter.h != self.detect.h
            || self.arbiter.k > MAX_PROBERS
            || self.arbiter.rounds == u32::MAX
            || lifetime.is_none()
            || self.shards == 0
            || self.per_tick == 0
            || !(2..=self.detect.hosts).contains(&self.self_suspect)
        {
            return Err(WatchRefusal::Bounds);
        }
        Ok(self)
    }
}

/// Why the detector refused an input. Each refusal leaves the detector unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchRefusal {
    Detect(DetectRefusal),
    Arbiter(Decline),
    /// The arbiter's window differs from the detector's, a count bound is out of range, or the vote lifetime
    /// overflows the clock.
    Bounds,
    Allocation,
    /// A sync lists more than `shards` records.
    Shards,
    /// A sync lists one shard twice, or one host twice in its placement.
    Duplicate,
    /// The placement lists more hosts than the AZ host maximum, or a named peer has no placement partition.
    Placement,
    /// `now` precedes a peer's last window close, the last tick or the last sent heartbeat, or a deadline from `now`
    /// overflows.
    Time,
    Beat(BeatError),
    /// The heartbeat falls outside the sender's replay window.
    Replay,
    /// The probe reply names an untracked suspect, another observation generation or probe cycle, a round not open,
    /// or an earlier round or issuance than the prober's recorded vote or the cycle's evicted votes; or a sent
    /// heartbeat's sequence is not above the last one.
    Stale,
    /// The prober has no placement, is the observer or the suspect, sits in the suspect's partition, or the
    /// suspect's vote record is full.
    Prober,
}

/// An indirect prober's reading of a suspect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reading {
    Alive,
    Dead(Failure),
    Unknown,
}

/// One probe the caller sends through probers outside the suspect's partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeRequest {
    pub suspect: Host,
    pub partition: Partition,
    pub generation: ObservationGeneration,
    /// The suspect's probe cycle in this `Watch`. A veto, an exhausted cycle, an unobserved close, a reading of
    /// ALIVE or UNKNOWN, a new boot, a retrack and a prober leaving or moving in the placement each start a new one.
    pub cycle: u64,
    pub round: u32,
    /// The window close the request was issued at, which dates the vote it returns.
    pub issued: u64,
}

/// A prober's answer to a [`ProbeRequest`]. The caller authenticates the whole reply as the named prober's and binds
/// it to a request this `Watch` issued, and attributes the prober's observer class; [`Watch::probe`] checks the
/// request's lifecycle and the prober's placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeReply {
    pub request: ProbeRequest,
    pub prober: Host,
    pub class: ObserverClass,
    pub reading: Reading,
}

/// A nomination of `shard`'s record `(g, owner, E)`, decided under the owner's observation `generation`. The caller
/// keeps it and passes it to [`Watch::revalidate`], which mints a [`Revalidated`] witness only while it accepts the
/// nomination; `failover::takeover::Takeover::nominated` builds the standby's takeover from that witness until the
/// witness expires. Any
/// refusal can be temporary, a lapsed or withdrawn vote included, while the cycle holds; the caller drops the
/// nomination once a sync stops listing its target or the owner's generation moves past it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nominated {
    pub shard: Shard,
    pub generation: ObservationGeneration,
    pub nomination: FlipNomination,
}

/// The witness that [`Watch::revalidate`] accepted a nomination of `target` for `shard`: a plain value that can cross
/// to the owner process, valid while `now < until_us` on the observer's `CLOCK_BOOTTIME`. It only starts the
/// takeover sequence, whose step 1 and compare-and-swap decide (DETECTION-CARRIES-NO-SAFETY). A witness stays
/// valid until `until_us` whatever the detector decides after its mint; the owner process passes on only a witness
/// its own host's detector minted in the current boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revalidated {
    pub shard: Shard,
    pub target: Target,
    pub until_us: u64,
}

/// The observer suspects itself until `until`, with `suspects` peers suspected at the tick that reported it; a
/// vetoed peer, a peer with a fresh declared reading and a peer recovering from a declared hold are not counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepairDemand {
    pub suspects: usize,
    pub until: u64,
}

/// A peer's probe lifecycle. `Open(r)` collects round `r`; `Open(rounds + 1)` judges the last round's votes, takes
/// no replies and reads UNKNOWN at its close. `Held(r)` has reached a quorum and keeps probing. `Vetoed(n)` waits
/// `n` windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Open(u32),
    Held(u32),
    Vetoed(u32),
}

const NO_VOTE: Vote = Vote {
    partition: Partition(0),
    class: ObserverClass(0),
    round: 0,
    reading: Liveness::Unknown,
};

#[derive(Debug)]
struct Watched {
    host: Host,
    partition: Partition,
    slot: PeerSlot,
    /// The current boot's nonce and stamp.
    boot: Option<([u8; 16], u64)>,
    /// The highest boot stamp admitted for this host. Admitting a lower stamp preserves the floor.
    stamp_floor: u64,
    /// The observation generation the last admitted heartbeat arrived in and its latest receipt time in that
    /// generation. A track, a retrack and a reboot each open a newer generation, and the heartbeat that establishes
    /// a reboot arrives in the generation it opens.
    heard: Option<(ObservationGeneration, u64)>,
    liveness: Liveness,
    phase: Phase,
    cycle: u64,
    /// `probers[i]` cast `votes[i]`, DEAD or UNKNOWN, on the request issued at `issued[i]`, for `i < count`.
    probers: [Option<Host>; MAX_PROBERS],
    votes: [Vote; MAX_PROBERS],
    issued: [u64; MAX_PROBERS],
    count: usize,
    /// The latest issuance among votes evicted from this cycle; a prober with no vote replies to no earlier one.
    floor: Option<u64>,
    /// An ALIVE vote arrived and no DEAD vote of a later cycle has.
    vetoed: bool,
    /// The last observed window close.
    observed_at: u64,
    /// Healthy heartbeats of this boot sent with no outstanding work; each counts as progress.
    idle: u64,
    /// Set by `sync` for a peer whose evidence the sync invalidates.
    changed: bool,
}

impl Watched {
    fn restart(&mut self, phase: Phase) {
        self.count = 0;
        self.floor = None;
        self.cycle += 1;
        self.phase = phase;
    }

    fn open_round(&self, rounds: u32) -> Option<u32> {
        match self.phase {
            Phase::Open(r) if r <= rounds => Some(r),
            Phase::Held(r) => Some(r.min(rounds)),
            Phase::Idle | Phase::Open(_) | Phase::Vetoed(_) => None,
        }
    }

    fn probing(&self) -> bool {
        matches!(self.phase, Phase::Open(_) | Phase::Held(_))
    }
}

/// The inputs of one judgment of a peer's evidence: the time, the observer's clock and own health, and whether the
/// brake on correlated declarations holds.
#[derive(Debug, Clone, Copy)]
struct Judged {
    now: u64,
    clock: Clock,
    healthy: bool,
    braked: bool,
}

#[derive(Debug, Clone, Copy)]
struct StandbyTarget {
    shard: Shard,
    target: Target,
    /// The owner's probe cycle this target was published in.
    published: Option<u64>,
}

/// The observer's host detector.
pub struct Watch {
    own: Host,
    /// The observer's boot nonce, which a peer's acknowledgment names.
    boot: [u8; 16],
    bounds: WatchBounds,
    detector: Detector,
    peers: Vec<Watched>,
    placement: Vec<(Host, Partition)>,
    targets: Vec<StandbyTarget>,
    scratch: Vec<StandbyTarget>,
    outbox: Vec<Nominated>,
    /// `seen` keeps `sync` duplicate checks within reserved storage.
    seen: Vec<u64>,
    /// The hosts other than this observer that the records of the sync under way name, in first-appearance order,
    /// each with its placement partition.
    roster: Vec<(Host, Partition)>,
    /// The sequence and send time of the observer's last `D` heartbeats, oldest first.
    sent: Vec<(u64, u64)>,
    generation: u64,
    last_tick: Option<u64>,
    cursor: usize,
    peer_read_at: Option<u64>,
    suspect_until: Option<u64>,
    /// The nominations the observer published since it started, saturating at `u64::MAX`; nothing reads it but
    /// [`Watch::census`].
    nominations: u64,
}

/// What a [`Watch`] holds about its peers, for the host report's detector fields: the tracked peers, the peers
/// that hold a suspicion, no ALIVE veto, no fresh declared reading and no recovery from a declared hold, which the
/// SELF-SUSPICION rule counts, the self-suspicion dwell left at the last tick (the repair demand's deadline less
/// that tick's time, 0 when the tick returned no demand, `None` before the first tick), and the nominations it
/// published since it started, which counts from the writer's boot while the producer keeps one `Watch` per boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchCensus {
    pub tracked: usize,
    pub suspected: usize,
    pub suspect_left: Option<u64>,
    pub nominations: u64,
}

fn reserve<T>(n: usize) -> Result<Vec<T>, WatchRefusal> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| WatchRefusal::Allocation)?;
    Ok(v)
}

fn peer_of(detector: &Detector, slot: PeerSlot) -> &Peer {
    // Invariant: every `Watched` holds the handle of a tracked detector slot until `sync` untracks it.
    detector.peer(slot).expect("watched peers stay tracked")
}

fn partition_of(placement: &[(Host, Partition)], h: Host) -> Option<Partition> {
    placement.iter().find(|(p, _)| *p == h).map(|&(_, p)| p)
}

/// `seen` must have capacity for every key, which keeps the duplicate check within reserved storage.
fn repeats(seen: &mut Vec<u64>, keys: impl Iterator<Item = u64>) -> bool {
    seen.clear();
    seen.extend(keys);
    seen.sort_unstable();
    seen.windows(2).any(|w| w[0] == w[1])
}

impl Watch {
    /// The detector of observer `own` in its boot `boot`, with every table reserved at its bound.
    ///
    /// # Errors
    ///
    /// `Beat(BeatError::Field)` for an all-zero `boot`: a heartbeat's `ack_boot` is all zero when its sender received
    /// nothing, so a zero observer boot would read that heartbeat as an acknowledgment.
    pub fn new(own: Host, boot: [u8; 16], bounds: WatchBounds) -> Result<Self, WatchRefusal> {
        if boot == [0; 16] {
            return Err(WatchRefusal::Beat(BeatError::Field));
        }
        let bounds = bounds.validate()?;
        Ok(Self {
            own,
            boot,
            detector: Detector::new(bounds.detect).map_err(WatchRefusal::Detect)?,
            peers: reserve(bounds.detect.hosts)?,
            placement: reserve(bounds.detect.hosts)?,
            targets: reserve(bounds.shards)?,
            scratch: reserve(bounds.shards)?,
            outbox: reserve(bounds.per_tick)?,
            seen: reserve(bounds.shards.max(bounds.detect.hosts))?,
            roster: reserve(bounds.detect.hosts)?,
            sent: reserve(bounds.detect.d as usize)?,
            bounds,
            generation: 0,
            last_tick: None,
            cursor: 0,
            peer_read_at: None,
            suspect_until: None,
            nominations: 0,
        })
    }

    fn next(&mut self) -> ObservationGeneration {
        self.generation += 1;
        ObservationGeneration(self.generation)
    }

    /// Two windows, which `DetectBounds::validate` keeps representable through `d * h`.
    fn horizon(&self) -> u64 {
        self.bounds.detect.h * 2
    }

    /// Whether every deadline a time `now` can later need, the two-window horizon and the self-suspicion dwell, fits.
    fn fits(&self, now: u64) -> bool {
        now.checked_add(self.horizon().max(self.bounds.arbiter.dwell))
            .is_some()
    }

    /// Records that the observer sent its heartbeat `sequence` at `at`, at or before its first transmission, which a
    /// peer acknowledges in later heartbeats. Sequences rise within the observer's boot.
    ///
    /// # Errors
    ///
    /// `Stale` for a sequence at or below the last one and `Time` for a time before the last one, each with no
    /// change.
    pub fn sent(&mut self, sequence: u64, at: u64) -> Result<(), WatchRefusal> {
        if let Some(&(last, last_at)) = self.sent.last() {
            if sequence <= last {
                return Err(WatchRefusal::Stale);
            }
            if at < last_at {
                return Err(WatchRefusal::Time);
            }
        }
        if self.sent.len() == self.bounds.detect.d as usize {
            self.sent.remove(0);
        }
        self.sent.push((sequence, at));
        Ok(())
    }

    /// The send time of the observer heartbeat `header` acknowledges, when it is one of the last `D` of this boot
    /// and was sent at or before `now`.
    fn acked(&self, header: &beat::Header, now: u64) -> Option<u64> {
        (header.ack_boot == self.boot)
            .then(|| self.sent.iter().find(|(s, _)| *s == header.ack))
            .flatten()
            .map(|&(_, at)| at)
            .filter(|&at| at <= now)
    }

    /// A refused `sync` preserves detector state.
    fn check(
        &mut self,
        records: &[ShardRecord],
        placement: &[(Host, Partition)],
        now: u64,
    ) -> Result<(), WatchRefusal> {
        if records.len() > self.bounds.shards {
            return Err(WatchRefusal::Shards);
        }
        if placement.len() > self.bounds.detect.hosts {
            return Err(WatchRefusal::Placement);
        }
        let shards = records.iter().map(|r| u64::from(r.shard.get()));
        let hosts = placement.iter().map(|(h, _)| h.get());
        if repeats(&mut self.seen, shards) || repeats(&mut self.seen, hosts) {
            return Err(WatchRefusal::Duplicate);
        }
        let own = self.own;
        self.roster.clear();
        let named = records.iter().flat_map(|r| [Some(r.owner), r.standby]);
        // `memo` keeps, per residue of a host key, the roster place last found for it. A place that holds another
        // host or no entry, after a collision or before the first sighting, falls back to the search, latest
        // entries first.
        let mut memo = [0; 256];
        for h in named.flatten().filter(|h| *h != own) {
            let at = &mut memo[h.get() as usize % 256];
            if self.roster.get(*at).is_some_and(|(n, _)| *n == h) {
                continue;
            }
            let found = self.roster.iter().rposition(|(n, _)| *n == h);
            *at = found.unwrap_or(self.roster.len());
            if found.is_none() {
                let partition = partition_of(placement, h).ok_or(WatchRefusal::Placement)?;
                self.roster.push((h, partition));
            }
        }
        if !self.fits(now)
            || self.last_tick.is_some_and(|t| now < t)
            || self
                .peers
                .iter()
                .any(|p| now < peer_of(&self.detector, p.slot).window_at())
        {
            return Err(WatchRefusal::Time);
        }
        Ok(())
    }

    /// Tracks exactly the hosts other than this observer that `records` name as owner or standby, each in the
    /// partition `placement` names, keeps `placement` for prober attribution, and keeps as targets the records that
    /// name this observer as standby. A tracked owner that gains or changes a target, or a tracked peer that changes
    /// partition, opens a newer observation generation, which clears its suspicion and restarts its grace; a peer
    /// holding a vote whose prober moved or left the placement starts a new probe cycle; a new peer starts in
    /// new-peer grace at `now`.
    ///
    /// # Errors
    ///
    /// `Shards`, `Placement` for the placement's length, `Duplicate`, `Placement` for a named peer, then `Time`, each
    /// leaving every field but the `seen` and `roster` scratch as it was.
    pub fn sync(
        &mut self,
        records: &[ShardRecord],
        placement: &[(Host, Partition)],
        now: u64,
    ) -> Result<(), WatchRefusal> {
        self.check(records, placement, now)?;
        let own = self.own;
        let (detector, roster) = (&mut self.detector, &self.roster);
        self.peers.retain(|p| {
            let keep = roster.iter().any(|(h, _)| *h == p.host);
            if !keep {
                detector.untrack(p.slot);
            }
            keep
        });
        for p in &mut self.peers {
            let moved = p.probers[..p.count]
                .iter()
                .zip(&p.votes)
                .any(|(h, v)| h.and_then(|h| partition_of(placement, h)) != Some(v.partition));
            if moved {
                p.restart(Phase::Idle);
            }
        }
        self.placement.clear();
        self.placement.extend_from_slice(placement);
        self.scratch.clear();
        for r in records.iter().filter(|r| r.standby == Some(own)) {
            let target = Target::of(r);
            let kept = self
                .targets
                .iter()
                .find(|t| t.shard == r.shard && t.target == target);
            self.scratch.push(StandbyTarget {
                shard: r.shard,
                target,
                published: kept.and_then(|t| t.published),
            });
            if kept.is_none()
                && let Some(p) = self.peers.iter_mut().find(|p| p.host == r.owner)
            {
                p.changed = true;
            }
        }
        std::mem::swap(&mut self.targets, &mut self.scratch);
        for i in 0..self.roster.len() {
            let (h, partition) = self.roster[i];
            if let Some(p) = self.peers.iter_mut().find(|p| p.host == h) {
                p.changed |= p.partition != partition;
                p.partition = partition;
                continue;
            }
            let generation = self.next();
            // Invariant: every named host has one of the unique placement entries, at most the AZ host maximum, so
            // untracking left a slot for it, and a u64 incarnation counter raised once per track cannot run out.
            let slot = self
                .detector
                .track(generation, now)
                .expect("check bounded the named hosts");
            self.peers.push(Watched {
                host: h,
                partition,
                slot,
                boot: None,
                stamp_floor: 0,
                heard: None,
                liveness: Liveness::Alive,
                phase: Phase::Idle,
                cycle: 0,
                probers: [None; MAX_PROBERS],
                votes: [NO_VOTE; MAX_PROBERS],
                issued: [0; MAX_PROBERS],
                count: 0,
                floor: None,
                vetoed: false,
                observed_at: now,
                idle: 0,
                changed: false,
            });
        }
        for i in 0..self.peers.len() {
            if !std::mem::take(&mut self.peers[i].changed) {
                continue;
            }
            let generation = self.next();
            let p = &mut self.peers[i];
            // Invariant: `check` put `now` at or after every window close, and `next` is newer than every generation
            // issued, so the retrack cannot refuse.
            self.detector
                .retrack(p.slot, generation, now)
                .expect("watched peers stay tracked")
                .expect("check bounded the time and the generation is newer");
            p.liveness = Liveness::Alive;
            p.vetoed = false;
            p.restart(Phase::Idle);
        }
        Ok(())
    }

    /// Admits one heartbeat received at `now`. `key` returns the heartbeat key of a tracked sender. A heartbeat whose
    /// acknowledgment names one of the observer's last `D` heartbeats of this boot, sent at `s`, feeds the read-age
    /// export with `s` minus each reported age, the earliest time the sender's read can have happened. The first
    /// progress sample of a boot or of a newly tracked peer sets the baseline and counts as progress. After it, a
    /// heartbeat from a sender reporting itself unhealthy, or with outstanding work and flat counters, adds a
    /// stalled window, and `D` stalled windows outside new-peer grace read as a gray failure; a healthy sender with no
    /// outstanding work makes progress. `D` observed windows that admitted a heartbeat, with every heartbeat admitted
    /// since the last healthy one reporting the sender unhealthy, read as a declared failure instead; a window with
    /// no heartbeat keeps that count.
    ///
    /// # Errors
    ///
    /// `Beat` when decoding or authentication fails, including `BeatError::Sender` for a host the table does not
    /// track, `Replay` outside the replay window, and `Time` when a new boot arrives before the peer's last window
    /// close or too near the clock's end. `now` is a receipt time and may precede the last tick: a new boot is
    /// admitted from the peer's last window close on, and the current boot at any time.
    pub fn heartbeat(
        &mut self,
        bytes: &[u8],
        key: impl FnOnce(Host) -> Option<BeatKey>,
        now: u64,
    ) -> Result<(), WatchRefusal> {
        let peers = &self.peers;
        let mut found = None;
        let (header, entries) = beat::decode(bytes, self.own, |h| {
            found = peers.iter().position(|p| p.host == h);
            found.and_then(|_| key(h))
        })
        .map_err(WatchRefusal::Beat)?;
        let i = found.expect("decode admits only tracked senders");
        self.observe(i, header, entries, now)
    }

    /// [`Watch::heartbeat`] for a caller whose `key` holds keys of hosts the table may not track. The codec decodes
    /// and authenticates the bytes under `key` first, then the table looks the sender up, so the bytes take one
    /// HMAC pass and the caller reads the admitted header.
    ///
    /// # Errors
    ///
    /// `Beat` with the codec's refusal under `key`, then `Beat` with `BeatError::Sender` for a sender the table does
    /// not track, then `Replay` and `Time` as [`Watch::heartbeat`] returns them.
    pub(crate) fn admit(
        &mut self,
        bytes: &[u8],
        key: impl FnOnce(Host) -> Option<BeatKey>,
        now: u64,
    ) -> Result<beat::Header, WatchRefusal> {
        let (header, entries) = beat::decode(bytes, self.own, key).map_err(WatchRefusal::Beat)?;
        let tracked = self.peers.iter().position(|p| p.host == header.host);
        let i = tracked.ok_or(WatchRefusal::Beat(beat::BeatError::Sender))?;
        self.observe(i, header, entries, now)?;
        Ok(header)
    }

    /// Applies the authenticated heartbeat `header` and `entries` of the tracked peer at `i`, received at `now`.
    fn observe(
        &mut self,
        i: usize,
        header: beat::Header,
        entries: impl Iterator<Item = beat::Entry>,
        now: u64,
    ) -> Result<(), WatchRefusal> {
        let boot = (header.boot, header.booted_at_us);
        let acked = self.acked(&header, now);
        let p = &self.peers[i];
        let peer = peer_of(&self.detector, p.slot);
        let reboot = match p.boot {
            None => false,
            Some(current) if current == boot => {
                if peer.sequence().is_some_and(|s| header.sequence <= s) {
                    return Err(WatchRefusal::Replay);
                }
                false
            }
            Some(_) => {
                if header.booted_at_us <= p.stamp_floor
                    && (peer.suspicion().is_none() || acked.is_none())
                {
                    return Err(WatchRefusal::Replay);
                }
                true
            }
        };
        if reboot {
            if !self.fits(now) {
                return Err(WatchRefusal::Time);
            }
            let generation = ObservationGeneration(self.generation + 1);
            self.detector
                .reboot(p.slot, generation, now)
                .expect("watched peers stay tracked")
                .map_err(|_| WatchRefusal::Time)?;
            // The generation advances only after the reboot accepted it, so a refusal leaves the counter unchanged.
            self.generation += 1;
        }
        let p = &mut self.peers[i];
        if reboot {
            p.liveness = Liveness::Alive;
            p.idle = 0;
            p.vetoed = false;
            p.restart(Phase::Idle);
        }
        p.boot = Some(boot);
        p.stamp_floor = p.stamp_floor.max(header.booted_at_us);
        let generation = peer_of(&self.detector, p.slot).generation();
        // A receipt time may precede an earlier heartbeat's, and the later of the two dates the evidence.
        let at = match p.heard {
            Some((heard, at)) if heard == generation => at.max(now),
            _ => now,
        };
        p.heard = Some((generation, at));
        if header.healthy && header.pending == 0 {
            p.idle = p.idle.saturating_add(1);
        }
        let progress = if header.healthy {
            header
                .io
                .saturating_add(header.completions)
                .saturating_add(p.idle)
        } else {
            0
        };
        self.detector
            .heartbeat(p.slot, header.sequence, progress, header.healthy)
            .expect("watched peers stay tracked");
        if let Some(sent_at) = acked {
            // The least reported age gives the latest read; when it exceeds the send time, every age does.
            let least = entries.filter_map(|e| e.read_age_us).min();
            let read = least.and_then(|age| sent_at.checked_sub(age));
            self.peer_read_at = self.peer_read_at.max(read);
        }
        Ok(())
    }

    /// Records one indirect probe reply received at `now`. ALIVE of the cycle vetoes at once, in any round and in the
    /// judging window. DEAD and UNKNOWN replace the prober's vote of an earlier or equal round and issuance. A prober
    /// with no vote takes a free place, then the place of a vote that no longer counts (UNKNOWN or lapsed DEAD), then,
    /// for DEAD from a partition no counting vote covers, the place of a counting vote whose partition another
    /// counting vote repeats, preferring one whose observer class stays represented.
    /// Otherwise, a DEAD vote from an unrepresented observer class replaces a counting vote whose class another
    /// counting vote carries, provided the replacement preserves or increases the number of distinct counting
    /// partitions. Both replacements of another prober's counting vote need a reply whose own vote counts: a DEAD
    /// reply whose `issued` is more than the vote lifetime before `now` takes only a free place or the place of a
    /// vote that no longer counts.
    ///
    /// # Errors
    ///
    /// See [`WatchRefusal`] for the causes of `Stale` and `Prober`. A DEAD or UNKNOWN reply's `issued` must be at or
    /// before the suspect's last window close, because [`Watch::probes`] dates each request by that close; a later
    /// one is `Stale`.
    pub fn probe(&mut self, reply: ProbeReply, now: u64) -> Result<(), WatchRefusal> {
        let limit = MAX_PROBERS.min(self.bounds.arbiter.hosts);
        let rounds = self.bounds.arbiter.rounds;
        let reach = self.reach();
        let request = reply.request;
        let i = self
            .peers
            .iter()
            .position(|p| p.host == request.suspect)
            .ok_or(WatchRefusal::Stale)?;
        let peer = peer_of(&self.detector, self.peers[i].slot);
        let (generation, closed) = (peer.generation(), peer.window_at());
        let p = &mut self.peers[i];
        if request.generation != generation || request.cycle != p.cycle || !p.probing() {
            return Err(WatchRefusal::Stale);
        }
        let partition = partition_of(&self.placement, reply.prober).ok_or(WatchRefusal::Prober)?;
        if reply.prober == self.own || reply.prober == p.host || partition == p.partition {
            return Err(WatchRefusal::Prober);
        }
        let failure = match reply.reading {
            Reading::Alive => {
                p.restart(Phase::Vetoed(rounds));
                p.vetoed = true;
                return Ok(());
            }
            Reading::Unknown => None,
            Reading::Dead(failure) => Some(failure),
        };
        let open = p
            .open_round(rounds)
            .is_some_and(|r| (1..=r).contains(&request.round));
        if !open || request.issued > closed {
            return Err(WatchRefusal::Stale);
        }
        let at = p.probers[..p.count]
            .iter()
            .position(|h| *h == Some(reply.prober));
        let below = match at {
            Some(at) => p.votes[at].round > request.round || p.issued[at] > request.issued,
            None => p.floor.is_some_and(|f| request.issued < f),
        };
        if below {
            return Err(WatchRefusal::Stale);
        }
        let counts = |j: usize| {
            matches!(p.votes[j].reading, Liveness::Dead(_))
                && p.issued[j].saturating_add(reach) >= now
        };
        let at = match at {
            Some(at) => at,
            None if p.count < limit => p.count,
            None => {
                let stale = (0..p.count).find(|&j| !counts(j));
                let uncovered =
                    (0..p.count).all(|j| !counts(j) || p.votes[j].partition != partition);
                let repeated = |j: usize| {
                    counts(j)
                        && (0..p.count).any(|o| {
                            o != j && counts(o) && p.votes[o].partition == p.votes[j].partition
                        })
                };
                let class_kept = |j: usize| {
                    reply.class == p.votes[j].class
                        || (0..p.count)
                            .any(|o| o != j && counts(o) && p.votes[o].class == p.votes[j].class)
                };
                let replaceable = (0..p.count).filter(|&j| repeated(j));
                let crowded = replaceable
                    .clone()
                    .find(|&j| class_kept(j))
                    .or_else(|| replaceable.clone().next());
                let new_class =
                    || (0..p.count).all(|j| !counts(j) || p.votes[j].class != reply.class);
                // When every vote counts, replacing a `spare` vote preserves class coverage and maintains at least
                // as many distinct counting partitions.
                let spare = |j: usize| {
                    class_kept(j) && (uncovered || repeated(j) || p.votes[j].partition == partition)
                };
                // `class_kept` and `spare` credit the record with the reply's own class and partition, which holds
                // only for a reply whose vote counts: a DEAD one issued at most the vote lifetime before `now`.
                let fresh = failure.is_some() && request.issued.saturating_add(reach) >= now;
                match (stale, crowded) {
                    (Some(j), _) => j,
                    (None, Some(j)) if fresh && uncovered => j,
                    (None, _) if fresh && new_class() => (0..p.count)
                        .find(|&j| spare(j))
                        .ok_or(WatchRefusal::Prober)?,
                    _ => return Err(WatchRefusal::Prober),
                }
            }
        };
        if at < p.count && p.probers[at] != Some(reply.prober) {
            p.floor = p.floor.max(Some(p.issued[at]));
        }
        p.count = p.count.max(at + 1);
        p.probers[at] = Some(reply.prober);
        p.issued[at] = request.issued;
        p.votes[at] = Vote {
            partition,
            class: reply.class,
            round: request.round,
            reading: failure.map_or(Liveness::Unknown, |failure| {
                Liveness::Dead(Suspicion {
                    generation,
                    failure,
                    since: request.issued,
                })
            }),
        };
        if failure.is_some() {
            p.vetoed = false;
        }
        Ok(())
    }

    /// How long a DEAD vote counts after its request was issued: the probe rounds plus the tick jitter.
    /// `WatchBounds::validate` keeps the sum representable.
    pub(crate) fn reach(&self) -> u64 {
        let (d, a) = (&self.bounds.detect, &self.bounds.arbiter);
        d.h * u64::from(a.rounds) + d.jitter
    }

    /// Closes every window due at `now` and publishes the nominations the evidence supports, at most `per_tick`.
    /// A window closes unobserved, at `now`, when `now` is at least one window past its end or an observer pause
    /// preceded it. `healthy` is the observer's own health. Returns the repair demand while the observer suspects
    /// itself, when the tick publishes nothing.
    ///
    /// # Errors
    ///
    /// `Time` when `now` precedes the last tick or a deadline from `now` overflows; the table is unchanged.
    pub fn tick(
        &mut self,
        now: u64,
        clock: Clock,
        healthy: bool,
    ) -> Result<Option<RepairDemand>, WatchRefusal> {
        let h = self.bounds.detect.h;
        let rounds = self.bounds.arbiter.rounds;
        if self.last_tick.is_some_and(|t| now < t) || !self.fits(now) {
            return Err(WatchRefusal::Time);
        }
        let limit = h + self.bounds.detect.jitter;
        let last = self.last_tick.replace(now);
        self.outbox.clear();
        for p in &mut self.peers {
            let opened = peer_of(&self.detector, p.slot).window_at();
            let due = opened + h;
            if now < due {
                continue;
            }
            // The observer ran at the last tick and at the call that opened this window, so a pause spans the
            // window only when the later of the two is more than `h + jitter` before this tick.
            let paused = last.is_some_and(|t| now - t.max(opened) > limit);
            let observed = !paused && now < due + h;
            // Invariant: the close is exactly one window after the last one when observed and at least one window
            // after it otherwise, under bounds `new` validated, so it cannot refuse.
            let (at, spent) = (
                if observed { due } else { now },
                p.phase == Phase::Open(rounds + 1),
            );
            let closed = self.detector.window(p.slot, at, observed, spent);
            p.liveness = closed
                .expect("watched peers stay tracked")
                .expect("due windows close");
            if observed {
                p.observed_at = due;
            }
            match p.liveness {
                Liveness::Dead(_) => {}
                reading => {
                    p.vetoed &= reading != Liveness::Alive;
                    if p.phase != Phase::Idle {
                        p.restart(Phase::Idle);
                    }
                    continue;
                }
            }
            if !observed {
                p.restart(Phase::Open(1));
                continue;
            }
            match p.phase {
                Phase::Idle | Phase::Vetoed(1) => p.restart(Phase::Open(1)),
                Phase::Open(r) => p.phase = Phase::Open(r + 1),
                Phase::Held(_) => {}
                Phase::Vetoed(n) => p.phase = Phase::Vetoed(n - 1),
            }
        }
        let suspects = self.suspected();
        if suspects >= self.bounds.self_suspect {
            // Invariant: `fits(now)` above covers the dwell.
            self.suspect_until = Some(now + self.bounds.arbiter.dwell);
        }
        if let Some(until) = self.suspect_until.filter(|&u| now < u) {
            return Ok(Some(RepairDemand { suspects, until }));
        }
        let n = self.peers.len();
        let at = Judged {
            now,
            clock,
            healthy,
            braked: self.braked(),
        };
        for k in 0..n {
            self.decide((self.cursor + k) % n, at);
        }
        self.cursor = (self.cursor + 1) % n.max(1);
        Ok(None)
    }

    /// The peer's local reading under DECLARED-FRESH: a declared reading reads gray once a heartbeat admitted since
    /// its close reported the peer healthy.
    fn evidence(&self, p: &Watched) -> Liveness {
        match p.liveness {
            Liveness::Dead(s) if s.failure == Failure::Declared && !self.declares(p) => {
                Liveness::Dead(Suspicion {
                    failure: Failure::Gray,
                    ..s
                })
            }
            reading => reading,
        }
    }

    fn declares(&self, p: &Watched) -> bool {
        peer_of(&self.detector, p.slot).declares()
    }

    /// Whether DECLARED-BRAKE holds: the declarations of at least `self_suspect` peers stand.
    fn braked(&self) -> bool {
        let stands =
            |p: &&Watched| peer_of(&self.detector, p.slot).stands_declared(&self.bounds.detect);
        let braked = self.peers.iter().filter(stands).count() >= self.bounds.self_suspect;
        #[cfg(test)]
        let braked = braked && !super::tests::plant("unbraked");
        braked
    }

    /// The arbiter's verdict on `p`'s evidence for `target`.
    fn nomination(
        &self,
        p: &Watched,
        target: Target,
        at: Judged,
    ) -> Result<FlipNomination, Decline> {
        let Judged {
            now,
            clock,
            healthy,
            braked,
        } = at;
        let Liveness::Dead(mut suspicion) = self.evidence(p) else {
            return Err(Decline::StaleSuspicion);
        };
        let brake = |failure: Failure| match failure {
            Failure::Declared if braked => Failure::Gray,
            failure => failure,
        };
        suspicion.failure = brake(suspicion.failure);
        if now
            .checked_sub(p.observed_at)
            .is_none_or(|age| age >= self.horizon())
        {
            return Err(Decline::StaleSuspicion);
        }
        let reach = self.reach();
        let mut votes = [NO_VOTE; MAX_PROBERS];
        let mut counted = 0;
        for j in 0..p.count {
            if let Liveness::Dead(s) = p.votes[j].reading
                && p.issued[j].saturating_add(reach) >= now
            {
                votes[counted] = Vote {
                    reading: Liveness::Dead(Suspicion {
                        failure: brake(s.failure),
                        ..s
                    }),
                    ..p.votes[j]
                };
                counted += 1;
            }
        }
        if counted == 0 {
            return Err(Decline::Quorum);
        }
        let peer = peer_of(&self.detector, p.slot);
        arbiter::nominate(
            &self.bounds.arbiter,
            &Nomination {
                now,
                observer_healthy: healthy,
                observation: Observation {
                    generation: peer.generation(),
                    target,
                },
                suspicion,
                // The observation opened at or after the holder's tenure began, so the holder grace runs at least as
                // long as the arbiter requires.
                holder_since: peer.tracked_since(),
                votes: &votes[..counted],
                clock,
            },
        )
    }

    /// Moves peer `i` to `Held` when its votes reach a quorum, then publishes its targets not yet published in the
    /// cycle while the outbox has room.
    fn decide(&mut self, i: usize, at: Judged) {
        let p = &self.peers[i];
        if !p.probing() {
            return;
        }
        let host = p.host;
        let Some(first) = self.targets.iter().find(|t| t.target.owner == host) else {
            return;
        };
        if let Phase::Open(r) = p.phase {
            let quorum = self.nomination(p, first.target, at);
            let Ok(_) = quorum else { return };
            self.peers[i].phase = Phase::Held(r);
        }
        let p = &self.peers[i];
        let generation = peer_of(&self.detector, p.slot).generation();
        for j in 0..self.targets.len() {
            let t = self.targets[j];
            if t.target.owner != host || t.published == Some(p.cycle) {
                continue;
            }
            if self.outbox.len() == self.bounds.per_tick {
                return;
            }
            let Ok(nomination) = self.nomination(p, t.target, at) else {
                return;
            };
            self.outbox.push(Nominated {
                shard: t.shard,
                generation,
                nomination,
            });
            self.nominations = self.nominations.saturating_add(1);
            self.targets[j].published = Some(p.cycle);
        }
    }

    /// The placement of the last accepted sync, which [`Watch::probe`] reads each prober's partition from.
    pub fn placement(&self) -> &[(Host, Partition)] {
        &self.placement
    }

    /// The nominations the last tick published.
    pub fn published(&self) -> &[Nominated] {
        &self.outbox
    }

    /// The peers that hold a suspicion, no ALIVE veto, no fresh declared reading and no recovery from a declared
    /// hold, the count SELF-SUSPICION compares with `self_suspect`.
    fn suspected(&self) -> usize {
        self.peers
            .iter()
            .filter(|p| {
                let peer = peer_of(&self.detector, p.slot);
                let (declares, recovers) = (peer.declares(), peer.recovers());
                #[cfg(test)]
                let declares = declares && !super::tests::plant("declared-counts");
                #[cfg(test)]
                let recovers = recovers && !super::tests::plant("recovering-counts");
                !p.vetoed && peer.suspicion().is_some() && !declares && !recovers
            })
            .count()
    }

    /// The detector's census through a shared borrow; reading it changes no nomination.
    pub fn census(&self) -> WatchCensus {
        WatchCensus {
            tracked: self.peers.len(),
            suspected: self.suspected(),
            suspect_left: self.last_tick.map(|tick| {
                self.suspect_until
                    .map_or(0, |until| until.saturating_sub(tick))
            }),
            nominations: self.nominations,
        }
    }

    /// The probes the caller sends for this window: one per suspect with an open round, issued at its last window
    /// close.
    pub fn probes(&self) -> impl Iterator<Item = ProbeRequest> + '_ {
        let rounds = self.bounds.arbiter.rounds;
        self.peers.iter().filter_map(move |p| {
            Some(ProbeRequest {
                round: p.open_round(rounds)?,
                suspect: p.host,
                partition: p.partition,
                generation: peer_of(&self.detector, p.slot).generation(),
                cycle: p.cycle,
                issued: peer_of(&self.detector, p.slot).window_at(),
            })
        })
    }

    /// Whether `n` still holds at `now` under the observer's `clock` and own `healthy` state: the observer's last
    /// self-suspicion deadline has passed both `now` and the last tick, the last sync lists `n`'s shard with `n`'s
    /// `(g, owner, E)` published in the owner's current cycle, that cycle holds a quorum under `n`'s observation
    /// generation, and the arbiter still accepts the cycle's counting votes after an observed close less than two
    /// windows old. The witness it returns expires one detector window after `now`. Its lifetime is shorter than the
    /// two-window evidence horizon, and it runs from the mint: a witness minted late in the horizon outlasts the
    /// evidence it was minted on by up to one window. The caller passes it to
    /// `failover::takeover::Takeover::nominated` to start the takeover.
    pub fn revalidate(
        &self,
        n: &Nominated,
        now: u64,
        clock: Clock,
        healthy: bool,
    ) -> Option<Revalidated> {
        let target = n.nomination.target;
        let last = self.last_tick.unwrap_or(0);
        let at = || Judged {
            now,
            clock,
            healthy,
            braked: self.braked(),
        };
        let holds = self.suspect_until.is_none_or(|u| now >= u && last >= u)
            && self.peers.iter().any(|p| {
                p.host == target.owner
                    && matches!(p.phase, Phase::Held(_))
                    && self.targets.iter().any(|t| {
                        t.shard == n.shard && t.target == target && t.published == Some(p.cycle)
                    })
                    && peer_of(&self.detector, p.slot).generation() == n.generation
                    && self.nomination(p, target, at()) == Ok(n.nomination)
            });
        holds.then(|| Revalidated {
            shard: n.shard,
            target,
            until_us: now.saturating_add(self.bounds.detect.h),
        })
    }

    /// The latest peer read time in the AZ: the greatest send time of an acknowledged observer heartbeat minus a
    /// reported read age, over the admitted heartbeats whose acknowledgment names one of the observer's last `D`
    /// heartbeats, or `None` when none has; an age above that send time contributes nothing.
    pub fn peer_read_at(&self) -> Option<u64> {
        self.peer_read_at
    }

    /// The serving table's peer withhold input for [`Watch::peer_read_at`].
    pub fn peer_event(&self) -> Event {
        Event::Peer {
            read_at: self.peer_read_at,
        }
    }

    /// The earliest time a peer's window falls due, `None` with no peer tracked; the caller ticks at it.
    pub fn deadline(&self) -> Option<u64> {
        self.peers
            .iter()
            .map(|p| peer_of(&self.detector, p.slot).window_at() + self.bounds.detect.h)
            .min()
    }

    /// The reading of `host`'s last window close, with exhaustion read as UNKNOWN and a declared reading read gray
    /// once a heartbeat admitted since that close reported the host healthy (DECLARED-FRESH); an indirect ALIVE veto
    /// leaves it. A track, a retrack and a reboot each set it to ALIVE until the peer's next window close.
    pub fn liveness(&self, host: Host) -> Option<Liveness> {
        self.peers
            .iter()
            .find(|p| p.host == host)
            .map(|p| self.evidence(p))
    }

    /// Whether an ALIVE reading of `host` rests on a recent heartbeat at `now`: the detector admitted one in the
    /// peer's current observation generation at most `h + jitter` before `now` and less than `D·h - tau - jitter`
    /// before it, and the peer's counters hold fewer than `D` consecutive empty windows and fewer than `D` stalled
    /// windows. The age is this observer's elapsed time since the receipt, so the answer depends on no window
    /// boundary.
    ///
    /// An observer that suspects a silent `host` has closed `D` empty windows, so `host`'s last heartbeat reached it
    /// at least `D·h` earlier by its clock. Where that heartbeat reached this observer at most `jitter` later and
    /// the two clocks differ by at most `tau` over that span, it is at least `D·h - tau - jitter` old here, and
    /// `hears` is false. Heartbeats that arrive at most `h + jitter` apart keep `hears` true between arrivals where
    /// `2·jitter + tau < (D - 1)·h`; under bounds with a larger jitter or clock error the second limit reads false
    /// for the rest of such a gap.
    pub fn hears(&self, host: Host, now: u64) -> bool {
        let b = &self.bounds.detect;
        // Invariant: `new` validated `d * h > tau + jitter + h`, so neither term overflows and the second is at least
        // `h`.
        let limit = (b.h + b.jitter).min(u64::from(b.d) * b.h - b.tau - b.jitter - 1);
        self.peers.iter().find(|p| p.host == host).is_some_and(|p| {
            let peer = peer_of(&self.detector, p.slot);
            let recent = p.heard.is_some_and(|(generation, at)| {
                generation == peer.generation() && now.saturating_sub(at) <= limit
            });
            recent && !peer.failing(b)
        })
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> String {
        let peers: Vec<_> = self
            .peers
            .iter()
            .map(|p| (p, peer_of(&self.detector, p.slot)))
            .collect();
        format!(
            "{peers:?} {:?} {:?} {:?} {:?} {} {:?} {} {:?} {:?} {}",
            self.placement,
            self.targets,
            self.outbox,
            self.sent,
            self.generation,
            self.last_tick,
            self.cursor,
            self.peer_read_at,
            self.suspect_until,
            self.nominations
        )
    }
}
