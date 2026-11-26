//! The host agent's core: one turn over the host detector [`Watch`] that admits heartbeats, syncs the records,
//! ticks the detector, sends heartbeats once per detector window, exchanges indirect probe messages with other
//! hosts' agents, seals one host report per report period and addresses each revalidated nomination to the local
//! process whose last status shows it standing by for the shard.
//!
//! Invariants:
//!
//! - DETECTION-CARRIES-NO-SAFETY: [`Agent::turn`] takes values and returns values. The agent issues nominations,
//!   and the takeover performs the shard record's compare-and-swap that decides an ownership change.
//! - NAMED-STANDBY: the agent keeps each nomination the detector published until a sync stops listing its target,
//!   and sends a [`Nominate`](Inbound::Nominate) for it at most once per detector window, each time with a fresh
//!   witness from [`Watch::revalidate`] that expires one window after its mint.
//! - SELF-SUSPICION: [`Watch::revalidate`] refuses while the observer suspects itself, so the agent sends a
//!   nomination only outside self-suspicion and returns the tick's repair demand during it.
//! - HOST-HEALTH: the heartbeat's health bit is false only while the last synced record of a shard names this host
//!   as owner and a standby on another host, and the process for the record's active volume reports a hold, remains
//!   silent past the restart grace after a status other than parked or closing, or has no status in the agent's
//!   table for longer than the restart grace since the first sync in the role's current run of consecutive mentions.
//!   A status of the role's volume that the table holds from before that run ends the last check, and the hold and
//!   silence rules judge it by its phase and its receipt time.
//!   The bit is host-wide, so every shard this host owns whose record names a standby on another host moves with it.
//!   Peers read a false bit in the detector's onset count of windows as a declared failure (DECLARED-FRESH in
//!   `failover::detect::host`), which the arbiter nominates on the ordinary quorum while every counted vote reads
//!   silent or declared and the declarations of fewer than [`SELF_SUSPECT`] hosts stand at the standby's detector
//!   (DECLARED-BRAKE), the threshold that also starts its self-suspicion; so a held owner's standby takes it over on
//!   host probes, which all vote in [`PROBER_CLASS`]. A healthy bit with stalled counters reads as a gray failure,
//!   which still needs votes of a second observer class, so host probes alone do not nominate it.
//! - MONOTONE-PROGRESS: the heartbeat's device and request counts are the host's totals since the agent started,
//!   each status adding its increase over the last one of the same process and tenure, so a tenure that restarts
//!   its counts or a status that goes stale lowers neither. The agent keeps that last status's counts per volume
//!   for as long as it runs, so a process whose status row a sync dropped adds only its increase when it publishes
//!   again.
//! - PROBE-OUTSIDE-PARTITION: the agent sends each request of [`Watch::probes`] once, sealed under its probe key with
//!   its boot nonce, to at most [`MAX_PROBERS`] hosts of the last sync's placement outside the suspect's partition
//!   that hold a probe key, one per partition before a second of any, the order within and across partitions
//!   rotating with each request about that suspect and with this host's number. Heartbeats go to every placed host,
//!   which includes every host the records name, so a prober that tracks the suspect hears it. After the turn's tick
//!   the agent answers an authenticated request about a host its detector tracks with the reading
//!   [`Watch::liveness`] holds, echoing the request's boot nonce; while it suspects itself or reads itself unhealthy
//!   a DEAD reading answers UNKNOWN. It suspects itself from a tick that returns a repair demand until a tick that
//!   returns none, which is a tick at or after the demand's deadline. An ALIVE reading answers UNKNOWN unless
//!   [`Watch::hears`] holds at the turn's time: the detector admitted a heartbeat in the suspect's current
//!   observation generation at most `h + jitter` and less than `D·h - tau - jitter` earlier, and fewer than `D`
//!   stalled windows stand. The reading a track or a retrack starts with therefore vetoes nothing at the observer,
//!   and neither does the reading of a prober whose windows trail the observer's or that paused: a silent suspect's
//!   last heartbeat, received here at most `jitter` after the observer received it, is at least
//!   `D·h - tau - jitter` old by this host's clock when the observer's first request can be answered. A suspect that sends heartbeats with stalled counters reads
//!   ALIVE here until `D` stalled windows, so a trailing prober still vetoes a gray suspicion's cycle.
//! - PROBE-REPLY-BOUND: a reply reaches [`Watch::probe`] only after it verifies under its prober's probe key and
//!   matches every field of a request the agent sent to that prober in its current boot and holds no answer to,
//!   with [`PROBER_CLASS`] as its observer class. Each sent request takes one answer per prober and is kept for one
//!   window past the time a DEAD vote on it stops counting, which covers the judging window, so a late ALIVE veto
//!   still reaches the detector, which judges the reply's cycle and round. The turn drops expired bindings before it
//!   reads any reply. After an accepted sync moves or removes a prober, its bindings pass only an ALIVE reply, so
//!   a DEAD or UNKNOWN reading counts only in the partition where the probe was requested. [`Watch::probe`] takes
//!   that ALIVE veto while the last sync places the prober outside the suspect's partition and refuses it otherwise.
//! - REPORT-PER-PERIOD: the agent seals a schema-3 report through its [`Writer`] at the first turn and at each turn
//!   once the writer's period has passed, with one entry per fresh status that carries a report entry naming its
//!   own volume, shard and tenure, so a host whose processes send no such fresh entry seals an empty report. The
//!   entries of the last sync's roles come first and a report holds [`MAX_ENTRIES`], so the entry of a role the
//!   sync no longer lists takes a place only when every listed role's entry has one.
//!   Parking ends the tenure. The agent seals a parked status's entry when the entry names the status's volume and
//!   shard. A waiting process's `Standby` status carries no tenure, and the agent seals its entry when the status
//!   and the entry hold no tenure and the entry names the status's volume and shard with no serving state and the
//!   role `Standby` or `Unrecorded`; such an entry counts toward no owned role in the producer-missing gauge, and a
//!   `Standby` status gives no heartbeat entry. The producer-missing gauge counts the owned roles of the last
//!   accepted sync with no sealed entry of a phase other than `Standby`, and reads unavailable before the first
//!   accepted sync. A seal the writer refuses reports its [`SealError`] in
//!   [`Outputs::seal_refused`], and the next turn tries again. [`Outputs::deliver`] hands the sealed bytes to a [`ReportSink`]
//!   unchanged.
//! - REPORTS-CONFER-NO-AUTHORITY: the agent holds no store client and no device handle. A report, a probe reading
//!   and a heartbeat change the detector's evidence and the values the agent returns.

use std::collections::BTreeMap;

use super::duties::STATUS_US;
use super::gate::HostGate;
use super::link::{Inbound, Status};
use crate::failover::arbiter::{Clock, ObserverClass, Partition};
use crate::failover::detect::Liveness;
use crate::failover::detect::beat::{self, BeatKey, Entry, Header};
use crate::failover::detect::host::{
    MAX_PROBERS, Nominated, ProbeReply, ProbeRequest, Reading, RepairDemand, Watch, WatchBounds,
    WatchRefusal,
};
use crate::failover::detect::probe::{self, Keyed, Message, ProbeError, ProbeKey};
use crate::failover::records::{self, Host, ShardRecord, VolumeId};
use crate::failover::report::{
    BuildIdentity, Detector, Ended, Gauge, Headroom, Health, HostState, MAX_ENTRIES, Members,
    Phase, RecordedRole, SealError, VolumeEntry, Writer, producer_missing,
};
use crate::failover::retire::Target;
use crate::failover::zone_loop::directory::{HostProjection, Projection};
use crate::net::ownership::{ActivatedEpoch, Shard, ShardGeneration, VolumeState};

/// The restart grace, 60 s.
pub const RESTART_GRACE_US: u64 = 60_000_000;
/// The status staleness bound, three status periods.
pub const STALE_US: u64 = 3 * STATUS_US;
/// The detector's self-suspicion threshold, 3.
pub const SELF_SUSPECT: usize = 3;
/// The observer class of every indirect prober's vote. The directory names no class per host, so every host
/// agent's reading is one class of evidence: a silent or declared suspicion nominates on these votes while every
/// counted vote reads silent or declared and the observer's brake on correlated declarations does not hold, and a
/// gray suspicion, which the arbiter nominates only on votes of two classes, stays unnominated by host probes alone.
pub const PROBER_CLASS: ObserverClass = ObserverClass(1);

/// The agent's keys: its own heartbeat and probe keys, which seal what it sends, and each peer's, which verify what
/// it receives.
pub struct Keys {
    pub own: BeatKey,
    pub probe: ProbeKey,
    pub peers: Vec<(Host, BeatKey)>,
    pub probers: Vec<(Host, ProbeKey)>,
}

impl Keys {
    /// The keys of `own`, derived from its `host_key`, with the heartbeat and probe keys of every other host
    /// `projection` holds.
    pub fn of(own: Host, host_key: &[u8; 32], projection: &HostProjection) -> Self {
        let others = || projection.hosts().filter(move |host| *host != own);
        Self {
            own: BeatKey::derive(host_key),
            probe: ProbeKey::derive(host_key),
            peers: others()
                .filter_map(|host| Some((host, projection.heartbeat(host)?)))
                .collect(),
            probers: others()
                .filter_map(|host| Some((host, projection.probe(host)?)))
                .collect(),
        }
    }
}

/// The report's host gauges the caller samples off the agent: `headroom` from `Headroom::sample` and `recovery_io`
/// from `report::host_recovery_io`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostSample {
    pub headroom: Headroom,
    pub recovery_io: Gauge,
}

impl HostSample {
    pub const UNAVAILABLE: Self = Self {
        headroom: Headroom {
            ram: Gauge::Unavailable,
            cpu_load: Gauge::Unavailable,
            iops: Gauge::Unavailable,
            bandwidth: Gauge::Unavailable,
            attachments: Gauge::Unavailable,
            workers: Gauge::Unavailable,
            recovery: Gauge::Unavailable,
        },
        recovery_io: Gauge::Unavailable,
    };
}

/// The seam that carries a sealed host report to its transport. The transport keeps the latest report of each
/// host.
pub trait ReportSink {
    fn deliver(&mut self, report: &[u8]);
}

/// The records and placement a caller read, for [`Watch::sync`].
#[derive(Debug, Clone, Copy)]
pub struct Synced<'a> {
    pub records: &'a [ShardRecord],
    pub placement: &'a [(Host, Partition)],
}

#[derive(Debug, Clone, Copy)]
pub struct Inputs<'a> {
    /// Every status the local processes published since the previous turn. A heartbeat counts each status's ages
    /// from the previous turn's time. A status withheld for more turns reports a read age below its true age.
    pub statuses: &'a [Status],
    pub heartbeats: &'a [&'a [u8]],
    pub probes: &'a [&'a [u8]],
    pub sync: Option<Synced<'a>>,
    pub clock: Clock,
    /// The wall clock in microseconds since the Unix epoch, which stamps a sealed report.
    pub wall_us: u64,
    pub host: HostSample,
}

impl Inputs<'_> {
    pub const NONE: Inputs<'static> = Inputs {
        statuses: &[],
        heartbeats: &[],
        probes: &[],
        sync: None,
        clock: Clock::Untrusted,
        wall_us: 0,
        host: HostSample::UNAVAILABLE,
    };
}

/// What one turn returns. The caller delivers each message to the process of its volume and retries a delivery
/// the inbox refused.
#[derive(Debug, Default)]
pub struct Outputs {
    pub heartbeats: Vec<(Host, Vec<u8>)>,
    /// The probe requests and replies the turn sealed, each for the host it names.
    pub probes: Vec<(Host, [u8; probe::LEN])>,
    pub messages: Vec<(VolumeId, Inbound)>,
    /// The report the turn sealed, which [`Outputs::deliver`] hands to a [`ReportSink`].
    pub report: Option<Vec<u8>>,
    pub repair: Option<RepairDemand>,
    pub refused: Vec<WatchRefusal>,
    /// The probe messages the turn refused, one per refused message.
    pub probes_refused: Vec<ProbeError>,
    /// Why the writer sealed no report at a turn that reached its due time.
    pub seal_refused: Option<SealError>,
    /// The earliest later time the agent has work at, when one exists.
    pub deadline: Option<u64>,
}

impl Outputs {
    /// Hands the turn's sealed report, when it sealed one, to `sink` as the writer sealed it.
    pub fn deliver(&self, sink: &mut impl ReportSink) {
        if let Some(report) = &self.report {
            sink.deliver(report);
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Received {
    status: Status,
    at: u64,
    /// The process published the status after the agent's previous turn. This field records that turn's timestamp,
    /// or zero on the agent's first turn.
    published_after: u64,
}

impl Received {
    /// A status is fresh for [`STALE_US`] after its arrival.
    fn fresh_at(&self, now: u64) -> bool {
        now.saturating_sub(self.at) <= STALE_US
    }
}

#[derive(Debug, Clone, Copy)]
struct Kept {
    nominated: Nominated,
    sent_at: Option<u64>,
}

/// The counts of the last status of a volume's process that added to the progress totals.
#[derive(Debug, Clone, Copy)]
struct Baseline {
    volume: VolumeId,
    pid: u32,
    tenure: Option<(ShardGeneration, ActivatedEpoch)>,
    io: u64,
    completions: u64,
}

/// A serving process's volume, process id and tenure.
type Peered = (VolumeId, u32, Option<(ShardGeneration, ActivatedEpoch)>);

#[derive(Debug, Clone, Copy)]
struct Acked {
    host: Host,
    boot: [u8; 16],
    sequence: u64,
}

/// The agent's [`Keys`] as its turns use them: the heartbeat keys as given and the probe keys prepared once, each
/// list in host order.
struct Prepared {
    own: BeatKey,
    probe: Keyed,
    peers: Vec<(Host, BeatKey)>,
    probers: Vec<(Host, Keyed)>,
}

pub struct Agent {
    own: Host,
    boot: [u8; 16],
    booted_at_us: u64,
    h: u64,
    watch: Watch,
    keys: Prepared,
    statuses: Vec<Received>,
    /// The time of the last turn, and zero before the first.
    turned_at: u64,
    /// The shards, each with its record's active volume, that the last sync lists with this host owner and a
    /// standby on another host.
    standby_named: Vec<(Shard, VolumeId)>,
    /// Each entry pairs a `standby_named` role awaiting status with the timestamp of the first sync in its current
    /// run of consecutive mentions.
    unreported: Vec<(Shard, VolumeId, u64)>,
    /// The shards, each with its record's active volume, that the last sync lists with this host owner or standby.
    roles: Vec<(Shard, VolumeId)>,
    /// The shards, each with its record's active volume, that the last sync lists with this host owner.
    /// `None` before the first accepted sync.
    owned: Option<Vec<(Shard, VolumeId)>>,
    /// The other hosts the last sync's records name, in host order.
    roster: Vec<Host>,
    /// The last heartbeat admitted from each host of the roster, in host order.
    acked: Vec<Acked>,
    sequence: u64,
    beat_at: u64,
    kept: Vec<Kept>,
    /// Device commands and answered requests the host's processes completed since this agent started, summed
    /// from each status's increase over the last one of the same process and tenure.
    progress: (u64, u64),
    /// One baseline per volume whose process reported to this agent, replaced by a later process or tenure of the
    /// volume and kept while the agent runs.
    baselines: Vec<Baseline>,
    peer_read_at: Option<u64>,
    /// The fresh serving processes sent the current peer read time, each by its volume, process id and tenure, so a
    /// process that restarts on the same volume, or a process that opens another tenure, is sent it again.
    peered: Vec<Peered>,
    /// The storage [`Agent::peer`] lists a turn's serving processes in before the list becomes `peered`.
    serving: Vec<Peered>,
    /// Each suspect's last sent request paired with its request count. The count rotates prober selection for that
    /// suspect. A sync retains entries for hosts named in its records.
    asked: BTreeMap<Host, (ProbeRequest, u64)>,
    /// The sent requests with the prober each went to, and whether an accepted sync has since moved or removed
    /// that prober.
    outstanding: Vec<(ProbeRequest, Host, bool)>,
    /// Whether the last tick returned a repair demand. Self-suspicion lasts until a tick at or after the demand's
    /// deadline returns none, the rule [`Watch::revalidate`] applies to a nomination.
    suspecting: bool,
    writer: Writer,
    build: BuildIdentity,
}

impl Agent {
    /// `new` builds the detector with the self-suspicion threshold [`SELF_SUSPECT`] in place of `watch`'s. `boot` is a
    /// nonce drawn fresh at each agent start, and `booted_at_us` the host's wall clock at that start in microseconds
    /// since the Unix epoch, which peers order this host's boots by. `writer` seals the host's reports at the zone's
    /// report period, and `build` is the build identity every report carries.
    ///
    /// # Errors
    ///
    /// `new` returns [`WatchRefusal::Duplicate`] for a key list that names a host twice, then the refusal of
    /// [`Watch::new`].
    pub fn new(
        _gate: &HostGate,
        (own, boot, booted_at_us): (Host, [u8; 16], u64),
        watch: WatchBounds,
        mut keys: Keys,
        (writer, build): (Writer, BuildIdentity),
    ) -> Result<Self, WatchRefusal> {
        keys.peers.sort_unstable_by_key(|(host, _)| *host);
        keys.probers.sort_unstable_by_key(|(host, _)| *host);
        let peers_twice = keys.peers.windows(2).any(|pair| pair[0].0 == pair[1].0);
        let probers_twice = keys.probers.windows(2).any(|pair| pair[0].0 == pair[1].0);
        if peers_twice || probers_twice {
            return Err(WatchRefusal::Duplicate);
        }
        let bounds = WatchBounds {
            self_suspect: SELF_SUSPECT,
            ..watch
        };
        Ok(Self {
            own,
            boot,
            booted_at_us,
            h: bounds.detect.h,
            watch: Watch::new(own, boot, bounds)?,
            keys: Prepared {
                own: keys.own,
                peers: keys.peers,
                probe: keys.probe.keyed(),
                probers: (keys.probers.iter())
                    .map(|(host, key)| (*host, key.keyed()))
                    .collect(),
            },
            statuses: Vec::new(),
            turned_at: 0,
            standby_named: Vec::new(),
            unreported: Vec::new(),
            roles: Vec::new(),
            owned: None,
            roster: Vec::new(),
            acked: Vec::new(),
            sequence: 0,
            beat_at: 0,
            kept: Vec::new(),
            progress: (0, 0),
            baselines: Vec::new(),
            peer_read_at: None,
            peered: Vec::new(),
            serving: Vec::new(),
            asked: BTreeMap::new(),
            outstanding: Vec::new(),
            suspecting: false,
            writer,
            build,
        })
    }

    pub fn watch(&self) -> &Watch {
        &self.watch
    }

    /// `turn` receives `now` and all other inputs as values and returns every heartbeat and message in its outputs.
    /// `now` is microseconds on the host's suspend-aware elapsed clock (`CLOCK_BOOTTIME`), the clock its owner
    /// processes read, and never decreases across turns.
    /// A due tick runs before the turn's heartbeats are admitted, as the detector's caller contract asks.
    pub fn turn(&mut self, now: u64, inputs: Inputs<'_>) -> Outputs {
        let mut out = Outputs::default();
        self.receive(inputs.statuses, now);
        self.turned_at = now;
        if let Some(sync) = inputs.sync
            && let Err(refusal) = self.sync(sync, now)
        {
            out.refused.push(refusal);
        }
        let kept_for = self.watch.reach().saturating_add(self.h);
        (self.outstanding).retain(|(sent, _, _)| sent.issued.saturating_add(kept_for) >= now);
        let asked: Vec<(Host, [u8; 16], ProbeRequest)> = (inputs.probes.iter())
            .filter_map(|bytes| self.received_probe(bytes, now, &mut out))
            .collect();
        let healthy = self.healthy(now);
        if self
            .watch
            .deadline()
            .is_some_and(|deadline| deadline <= now)
        {
            match self.watch.tick(now, inputs.clock, healthy) {
                Ok(repair) => {
                    self.suspecting = repair.is_some();
                    out.repair = repair;
                }
                Err(refusal) => out.refused.push(refusal),
            }
            self.keep();
        }
        for bytes in inputs.heartbeats {
            if let Err(refusal) = self.admit(bytes, now) {
                out.refused.push(refusal);
            }
        }
        for (requester, boot, request) in asked {
            self.answer((requester, boot), request, now, healthy, &mut out);
        }
        self.nominate(now, inputs.clock, healthy, &mut out.messages);
        if now >= self.beat_at {
            self.beat(now, healthy, &mut out);
        }
        self.request(&mut out.probes);
        self.peer(now, &mut out.messages);
        if now >= self.writer.due_at() {
            self.seal(now, &inputs, healthy, &mut out);
        }
        let h = self.h;
        let resend = (self.kept.iter())
            .filter_map(|kept| kept.sent_at.map(|at| at.saturating_add(h)))
            .filter(|&at| at > now)
            .min();
        let report_at = Some(self.writer.due_at()).filter(|&at| at > now);
        out.deadline = [self.watch.deadline(), Some(self.beat_at), resend, report_at]
            .into_iter()
            .flatten()
            .min();
        out
    }

    fn probe_key(&self, host: Host) -> Option<Keyed> {
        let probers = &self.keys.probers;
        let at = probers.binary_search_by_key(&host, |(prober, _)| *prober);
        at.ok().map(|at| probers[at].1)
    }

    /// Decodes one received probe message, passes a bound reply to the detector and returns a request to answer.
    fn received_probe(
        &mut self,
        bytes: &[u8],
        now: u64,
        out: &mut Outputs,
    ) -> Option<(Host, [u8; 16], ProbeRequest)> {
        let decoded = probe::open(bytes, self.own, |host| self.probe_key(host));
        let (prober, boot, request, reading) = match decoded {
            Err(refusal) => {
                out.probes_refused.push(refusal);
                return None;
            }
            Ok((requester, boot, Message::Request(request))) => {
                return Some((requester, boot, request));
            }
            Ok((prober, boot, Message::Reply { request, reading })) => {
                (prober, boot, request, reading)
            }
        };
        let sent = (self.outstanding.iter())
            .position(|&(sent, to, _)| boot == self.boot && (sent, to) == (request, prober));
        let bound = sent.map(|at| self.outstanding.swap_remove(at));
        #[cfg(test)]
        let bound = bound.or_else(|| tests::unbound().then_some((request, prober, false)));
        // After a prober moves, its binding passes only ALIVE. The detector uses the prober's placement at the last
        // sync, so it would attribute DEAD or UNKNOWN to the wrong partition.
        let counts =
            |&(_, _, moved): &(ProbeRequest, Host, bool)| !moved || reading == Reading::Alive;
        if !bound.as_ref().is_some_and(counts) {
            out.probes_refused.push(ProbeError::Unrequested);
            return None;
        }
        let reply = ProbeReply {
            request,
            prober,
            class: PROBER_CLASS,
            reading,
        };
        if let Err(refusal) = self.watch.probe(reply, now) {
            out.refused.push(refusal);
        }
        None
    }

    /// Answers `requester`'s request, echoing the boot nonce it carried, with the detector's reading of its suspect.
    /// While this host suspects itself or reads itself unhealthy a DEAD reading answers UNKNOWN, so a degraded
    /// observer lends no DEAD vote and still relays an ALIVE one. It suspects itself from a tick that returns a
    /// repair demand until a tick that returns none. An ALIVE reading that rests on no recent heartbeat at `now`
    /// ([`Watch::hears`]) answers UNKNOWN.
    fn answer(
        &mut self,
        (requester, boot): (Host, [u8; 16]),
        request: ProbeRequest,
        now: u64,
        healthy: bool,
        out: &mut Outputs,
    ) {
        let Some(liveness) = self.watch.liveness(request.suspect) else {
            return out.probes_refused.push(ProbeError::Untracked);
        };
        let degraded = !healthy || self.suspecting;
        let reading = match reading(liveness) {
            Reading::Dead(_) if degraded => Reading::Unknown,
            Reading::Alive if !self.watch.hears(request.suspect, now) => Reading::Unknown,
            reading => reading,
        };
        let reply = Message::Reply { request, reading };
        let bytes = probe::seal(&reply, boot, self.own, requester, &self.keys.probe);
        out.probes.push((requester, bytes));
    }

    /// The hosts `request` goes to under PROBE-OUTSIDE-PARTITION: each candidate ranks by its place among its
    /// partition's candidates, then by its partition's place in the order of first appearance, and the first
    /// [`MAX_PROBERS`] candidates in that ranking receive the request. `turn` is the number of requests sent about
    /// the suspect so far plus this host's number. The partition window moves by [`MAX_PROBERS`] each request, and
    /// once it has covered every partition the host place within each partition moves by one. A count per suspect
    /// makes the successive requests about one suspect cover every partition while the detector probes several
    /// suspects in one window.
    fn probers(&self, request: &ProbeRequest, turn: u64) -> Vec<Host> {
        let candidates: Vec<(Host, Partition)> = (self.watch.placement().iter())
            .filter(|&&(host, partition)| {
                host != self.own
                    && host != request.suspect
                    && partition != request.partition
                    && self.probe_key(host).is_some()
            })
            .copied()
            .collect();
        let mut partitions: BTreeMap<u32, (usize, usize)> = BTreeMap::new();
        for &(_, partition) in &candidates {
            let order = partitions.len();
            partitions.entry(partition.0).or_insert((order, 0)).1 += 1;
        }
        let sweep = partitions.len().div_ceil(MAX_PROBERS).max(1) as u64;
        let window = (turn % sweep) as usize * MAX_PROBERS;
        let lead = turn / sweep;
        let rotated =
            |at: usize, by: u64, len: usize| (at + len - (by % len as u64) as usize) % len;
        let mut seen = BTreeMap::new();
        let mut ranked: Vec<(usize, usize, Host)> = (candidates.iter())
            .map(|&(host, partition)| {
                let (order, size) = partitions[&partition.0];
                let at = seen.entry(partition.0).or_insert(0);
                let rank = rotated(*at, lead, size);
                *at += 1;
                (rank, rotated(order, window as u64, partitions.len()), host)
            })
            .collect();
        ranked.sort_unstable();
        ranked.truncate(MAX_PROBERS);
        ranked.into_iter().map(|(_, _, host)| host).collect()
    }

    fn request(&mut self, probes: &mut Vec<(Host, [u8; probe::LEN])>) {
        let current: Vec<ProbeRequest> = self.watch.probes().collect();
        for request in current {
            let sent = self.asked.get(&request.suspect).copied();
            if sent.is_some_and(|(last, _)| last == request) {
                continue;
            }
            let count = sent.map_or(0, |(_, count)| count);
            let turn = count.wrapping_add(self.own.get());
            for prober in self.probers(&request, turn) {
                let message = Message::Request(request);
                probes.push((
                    prober,
                    probe::seal(&message, self.boot, self.own, prober, &self.keys.probe),
                ));
                self.outstanding.push((request, prober, false));
            }
            (self.asked).insert(request.suspect, (request, count.wrapping_add(1)));
        }
    }

    fn seal(&mut self, now: u64, inputs: &Inputs<'_>, healthy: bool, out: &mut Outputs) {
        // The roles of the last sync come first, so a status the sync kept for an unlisted role takes a place only
        // after every listed one has its own.
        let listed = |status: &&Status| self.roles.contains(&(status.shard, status.volume));
        let entries: Vec<VolumeEntry> = (self.fresh(now).filter(listed))
            .chain(self.fresh(now).filter(|status| !listed(status)))
            .filter_map(|status| {
                let entry = Self::own_entry(status)?;
                Some(VolumeEntry {
                    phase: Some(status.phase),
                    ended: status.ended,
                    ..entry
                })
            })
            .take(MAX_ENTRIES)
            .collect();
        // A waiting process's entry produces no owned role's entry.
        let produced = (self.owned.as_ref()).map(|owned| {
            producer_missing(owned.iter().map(|&(shard, volume)| {
                (entries.iter()).any(|entry| {
                    (entry.shard, entry.volume) == (shard, volume)
                        && entry.phase != Some(Phase::Standby)
                })
            }))
        });
        let host = HostState {
            build: self.build,
            headroom: inputs.host.headroom,
            health: Some(if healthy {
                Health::Healthy
            } else {
                Health::Unhealthy
            }),
            detector: Detector::of(&self.watch.census()),
            producer_missing: produced.unwrap_or(Members::Unavailable),
            recovery_io: inputs.host.recovery_io,
        };
        match self.writer.seal(&host, &entries, inputs.wall_us, now) {
            Ok(report) => out.report = Some(report),
            Err(refusal) => out.seal_refused = Some(refusal),
        }
    }

    /// A parked `status` with `tenure == None` can accept an entry with `Some` tenure when volume and shard match.
    /// All other statuses require matching tenure as well. A `Standby` status and its entry also hold no tenure, and
    /// the entry no serving state and the role `Standby` or `Unrecorded`, so a waiting process's entry never reads as
    /// an owner's.
    fn own_entry(status: &Status) -> Option<VolumeEntry> {
        let entry = status.entry?;
        let tenure = match status.tenure {
            Some(tenure) => entry.tenure == Some(tenure),
            None => status.phase == Phase::Parked || entry.tenure.is_none(),
        };
        let waiting = status.phase != Phase::Standby
            || (status.tenure.is_none()
                && entry.tenure.is_none()
                && entry.serving.is_none()
                && matches!(
                    entry.role,
                    Some(RecordedRole::Standby | RecordedRole::Unrecorded)
                ));
        let own = tenure && waiting && (entry.volume, entry.shard) == (status.volume, status.shard);
        own.then_some(entry)
    }

    fn receive(&mut self, statuses: &[Status], now: u64) {
        for status in statuses {
            let received = Received {
                status: *status,
                at: now,
                published_after: self.turned_at,
            };
            let baseline = (self.baselines.iter_mut()).find(|kept| kept.volume == status.volume);
            let previous = baseline.as_deref().copied();
            // A status of an earlier tenure than the volume's baseline, or a same-tenure sample whose counts fell, is
            // a replay or a reordering: it changes neither the row, the baseline nor the progress totals.
            let earlier = previous.is_some_and(|last| {
                matches!((last.tenure, status.tenure), (Some(kept), Some(new)) if new < kept)
            });
            let same =
                previous.filter(|last| last.pid == status.pid && last.tenure == status.tenure);
            let fell = same
                .is_some_and(|last| status.io < last.io || status.completions < last.completions);
            if earlier || fell {
                continue;
            }
            // A status without a tenure counts no tenure's progress, so it leaves the baseline and the totals to the
            // last tenure's status: a replay of that status then reads as the same sample.
            let tenured = status.tenure.is_some();
            let (io, completions) = same.map_or((0, 0), |last| (last.io, last.completions));
            if tenured {
                self.progress.0 = (self.progress.0).saturating_add(status.io - io);
                self.progress.1 =
                    (self.progress.1).saturating_add(status.completions - completions);
                let next = Baseline {
                    volume: status.volume,
                    pid: status.pid,
                    tenure: status.tenure,
                    io: status.io,
                    completions: status.completions,
                };
                match baseline {
                    Some(baseline) => *baseline = next,
                    None => self.baselines.push(next),
                }
            }
            match (self.statuses.iter_mut()).find(|kept| kept.status.volume == status.volume) {
                Some(kept) => *kept = received,
                None => self.statuses.push(received),
            }
            let role = (status.shard, status.volume);
            (self.unreported).retain(|&(shard, volume, _)| (shard, volume) != role);
        }
    }

    fn sync(&mut self, sync: Synced<'_>, now: u64) -> Result<(), WatchRefusal> {
        // Only a sent request reads its prober's partition before the sync.
        let before = match self.outstanding.is_empty() {
            true => Vec::new(),
            false => self.watch.placement().to_vec(),
        };
        self.watch.sync(sync.records, sync.placement, now)?;
        let partition = |placement: &[(Host, Partition)], prober: Host| {
            (placement.iter())
                .find(|(host, _)| *host == prober)
                .map(|(_, p)| *p)
        };
        let after = self.watch.placement();
        for (_, prober, moved) in &mut self.outstanding {
            let stayed =
                partition(&before, *prober).is_some_and(|p| partition(after, *prober) == Some(p));
            *moved |= !stayed;
        }
        let own = self.own;
        let role = |r: &ShardRecord| (r.shard, r.active);
        self.standby_named.clear();
        let named = |r: &&ShardRecord| r.owner == own && r.standby.is_some_and(|s| s != own);
        (self.standby_named).extend(sync.records.iter().filter(named).map(role));
        self.roles.clear();
        let held = |r: &&ShardRecord| r.owner == own || r.standby == Some(own);
        (self.roles).extend(sync.records.iter().filter(held).map(role));
        let mut owned = self.owned.take().unwrap_or_default();
        owned.clear();
        owned.extend(sync.records.iter().filter(|r| r.owner == own).map(role));
        self.owned = Some(owned);
        // A status of a role the records no longer list stays for the restart grace, so the fresh-status readers keep
        // the entry of a process that still runs.
        let roles = &self.roles;
        self.statuses.retain(|kept| {
            roles.contains(&(kept.status.shard, kept.status.volume))
                || now.saturating_sub(kept.at) <= RESTART_GRACE_US
        });
        // A standby-named role that stays named and unreported keeps its original `since`, so repeated syncs
        // preserve its grace deadline.
        let (before, statuses) = (std::mem::take(&mut self.unreported), &self.statuses);
        let reported =
            |role| (statuses.iter()).any(|kept| (kept.status.shard, kept.status.volume) == role);
        self.unreported = (self.standby_named.iter())
            .filter(|&&role| !reported(role))
            .map(|&(shard, volume)| {
                let since = (before.iter())
                    .find(|&&(s, v, _)| (s, v) == (shard, volume))
                    .map_or(now, |&(.., since)| since);
                (shard, volume, since)
            })
            .collect();
        // Consecutive records often name one owner and standby pair, so a host equal to one of the last two listed
        // is skipped before the sort removes the other repeats.
        self.roster.clear();
        let named = sync.records.iter().flat_map(|r| [Some(r.owner), r.standby]);
        for host in named.flatten().filter(|host| *host != own) {
            if !self
                .roster
                .iter()
                .rev()
                .take(2)
                .any(|listed| *listed == host)
            {
                self.roster.push(host);
            }
        }
        self.roster.sort_unstable();
        self.roster.dedup();
        let roster = &self.roster;
        (self.acked).retain(|acked| roster.binary_search(&acked.host).is_ok());
        (self.asked).retain(|suspect, _| roster.binary_search(suspect).is_ok());
        let targets: Vec<(Shard, Target)> = match self.kept.is_empty() {
            true => Vec::new(),
            false => (sync.records.iter())
                .filter(|r| r.standby == Some(own))
                .map(|r| (r.shard, Target::of(r)))
                .collect(),
        };
        self.kept.retain(|kept| {
            let n = kept.nominated;
            targets.contains(&(n.shard, n.nomination.target))
        });
        Ok(())
    }

    /// Admits one heartbeat through [`Watch::admit`], which authenticates it once under the agent's keys, and records
    /// the sender's boot and sequence for the acknowledgment of the next heartbeat to it.
    fn admit(&mut self, bytes: &[u8], now: u64) -> Result<(), WatchRefusal> {
        let peers = &self.keys.peers;
        let key = |host: Host| {
            let at = peers.binary_search_by_key(&host, |(peer, _)| *peer);
            at.ok().map(|at| peers[at].1)
        };
        let header = self.watch.admit(bytes, key, now)?;
        let acked = Acked {
            host: header.host,
            boot: header.boot,
            sequence: header.sequence,
        };
        match self
            .acked
            .binary_search_by_key(&header.host, |kept| kept.host)
        {
            Ok(at) => self.acked[at] = acked,
            Err(at) => self.acked.insert(at, acked),
        }
        Ok(())
    }

    fn fresh(&self, now: u64) -> impl Iterator<Item = &Status> + '_ {
        (self.statuses.iter())
            .filter(move |kept| kept.fresh_at(now))
            .map(|kept| &kept.status)
    }

    /// The host health bit at `now` under HOST-HEALTH. A process holds while its status shows `Held`, or shows the
    /// `Held` exit of its last incarnation and no serving tenure, and it is silent once its last status, other than
    /// a parked or closing one, is older than [`RESTART_GRACE_US`].
    pub fn healthy(&self, now: u64) -> bool {
        // A process that died before its first status reached the agent leaves its role unreported.
        let unreported = (self.unreported.iter())
            .any(|&(.., since)| now.saturating_sub(since) > RESTART_GRACE_US);
        !unreported
            && !self.statuses.iter().any(|kept| {
                let status = &kept.status;
                let held = status.phase == Phase::Held
                    || (status.ended == Some(Ended::Held) && status.phase != Phase::Serving);
                let silent = now.saturating_sub(kept.at) > RESTART_GRACE_US
                    && !matches!(status.phase, Phase::Parked | Phase::Closing);
                (held || silent) && (self.standby_named).contains(&(status.shard, status.volume))
            })
    }

    fn keep(&mut self) {
        #[cfg(test)]
        if tests::published_only() {
            self.kept.clear();
        }
        for nominated in self.watch.published() {
            let same = |kept: &Kept| {
                kept.nominated.shard == nominated.shard
                    && kept.nominated.nomination.target == nominated.nomination.target
            };
            match self.kept.iter_mut().find(|kept| same(kept)) {
                Some(kept) => kept.nominated = *nominated,
                None => self.kept.push(Kept {
                    nominated: *nominated,
                    sent_at: None,
                }),
            }
        }
    }

    fn nominate(
        &mut self,
        now: u64,
        clock: Clock,
        healthy: bool,
        messages: &mut Vec<(VolumeId, Inbound)>,
    ) {
        let h = self.h;
        let (watch, statuses, roles) = (&self.watch, &self.statuses, &self.roles);
        for kept in &mut self.kept {
            if kept.sent_at.is_some_and(|at| now < at.saturating_add(h)) {
                continue;
            }
            let revalidated = watch.revalidate(&kept.nominated, now, clock, healthy);
            #[cfg(test)]
            let revalidated = revalidated.or_else(|| {
                tests::unrevalidated().then(|| crate::failover::detect::host::Revalidated {
                    shard: kept.nominated.shard,
                    target: kept.nominated.nomination.target,
                    until_us: now.saturating_add(h),
                })
            });
            let Some(witness) = revalidated else {
                continue;
            };
            let standby = statuses.iter().find(|received| {
                received.fresh_at(now)
                    && received.status.shard == witness.shard
                    && roles.contains(&(witness.shard, received.status.volume))
                    && received.status.phase == Phase::Standby
            });
            if let Some(received) = standby {
                messages.push((received.status.volume, Inbound::Nominate(witness)));
                kept.sent_at = Some(now);
            }
        }
    }

    /// The heartbeat entry of `received` at `now`, when it holds an activated tenure. The entry's Report and read
    /// ages grow by the time since [`Received::published_after`]. That span covers the status's wait for the agent's
    /// turn and its time in the agent's table, so each age is at least the status's age plus the time since its
    /// publication.
    fn entry(&self, received: &Received, now: u64) -> Option<Entry> {
        let status = &received.status;
        let waited = now.saturating_sub(received.published_after);
        if status.phase == Phase::Standby {
            return None;
        }
        let (generation, epoch) = status.tenure.filter(|(_, a)| a.is_activated())?;
        // A tenure is retired when its own entry reads its volume from Retired on, or when the last sync names
        // another volume active for a shard this host still holds a role on.
        let displaced = (self.roles.iter())
            .any(|&(shard, volume)| shard == status.shard && volume != status.volume);
        let retired = displaced
            || (Self::own_entry(status))
                .and_then(|entry| entry.volume_state)
                .is_some_and(|state| state >= records::VolumeState::Retired);
        Some(Entry {
            shard: status.shard,
            generation,
            epoch,
            volume: if retired {
                VolumeState::Retired
            } else {
                VolumeState::Active
            },
            report_age_us: (status.report_age_us)
                .map_or(u64::MAX, |age| age.saturating_add(waited)),
            read_age_us: status.read_age_us.map(|age| age.saturating_add(waited)),
        })
    }

    fn beat(&mut self, now: u64, healthy: bool, out: &mut Outputs) {
        let mut entries: Vec<_> = (self.statuses.iter())
            .filter(|received| received.fresh_at(now))
            .filter_map(|received| self.entry(received, now))
            .collect();
        entries.truncate(beat::MAX_ENTRIES);
        let pending =
            (self.fresh(now)).fold(0_u64, |sum, status| sum.saturating_add(status.pending));
        let (io, completions) = self.progress;
        self.sequence += 1;
        let mut bytes = [0; beat::MAX_LEN];
        let own = self.own;
        // The placement holds every host the records name, since a sync refuses a named peer without a placement.
        let placement = self.watch.placement();
        out.heartbeats.reserve(placement.len());
        for &(peer, _) in placement.iter().filter(|(host, _)| *host != own) {
            let acked = self.acked.binary_search_by_key(&peer, |acked| acked.host);
            let acked = acked.ok().map(|at| &self.acked[at]);
            let header = Header {
                host: self.own,
                boot: self.boot,
                booted_at_us: self.booted_at_us,
                sequence: self.sequence,
                ack: acked.map_or(0, |acked| acked.sequence),
                io,
                completions,
                pending,
                ack_boot: acked.map_or([0; 16], |acked| acked.boot),
                healthy,
            };
            match beat::encode(&header, &entries, peer, &self.keys.own, &mut bytes) {
                Ok(len) => out.heartbeats.push((peer, bytes[..len].to_vec())),
                Err(refusal) => out.refused.push(WatchRefusal::Beat(refusal)),
            }
        }
        if let Err(refusal) = self.watch.sent(self.sequence, now) {
            out.refused.push(refusal);
        }
        self.beat_at = now.saturating_add(self.h);
    }

    /// Sends the detector's peer read time to each fresh serving process not yet sent it, and to every one when the
    /// read time changes. A process is its status's volume, process id and tenure, and the agent remembers only the
    /// processes whose fresh status shows them serving.
    fn peer(&mut self, now: u64, messages: &mut Vec<(VolumeId, Inbound)>) {
        let read_at = self.watch.peer_read_at();
        if read_at != self.peer_read_at {
            self.peer_read_at = read_at;
            self.peered.clear();
        }
        if read_at.is_none() {
            return;
        }
        let mut serving = std::mem::take(&mut self.serving);
        serving.clear();
        let fresh = (self.statuses.iter()).filter(|kept| kept.fresh_at(now));
        serving.extend(
            fresh
                .filter(|kept| kept.status.phase == Phase::Serving)
                .map(|kept| (kept.status.volume, kept.status.pid, kept.status.tenure)),
        );
        for &(volume, ..) in serving
            .iter()
            .filter(|process| !self.peered.contains(process))
        {
            messages.push((volume, Inbound::Peer { read_at }));
        }
        self.serving = std::mem::replace(&mut self.peered, serving);
    }
}

/// The reply reading of a detector's liveness reading.
fn reading(liveness: Liveness) -> Reading {
    match liveness {
        Liveness::Alive => Reading::Alive,
        Liveness::Dead(suspicion) => Reading::Dead(suspicion.failure),
        Liveness::Unknown => Reading::Unknown,
    }
}

#[cfg(test)]
#[path = "agent_tests.rs"]
pub(crate) mod tests;
