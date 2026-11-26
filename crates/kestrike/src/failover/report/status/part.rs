//! One availability zone's part of the reconciler status: the per-tick counts a zone loop's survey gives, the
//! events the loop has counted since it started, and the exception rows of the shards outside the served class and
//! of the served shards with no standby past their target.
//!
//! - CLOSED-LABELS: every count array is indexed by a closed table: a label table of this module, or an exhaustive
//!   match over a survey type (`Blocker`, `Need`, `HostEvidence`, `Closed`), so a new variant of one of those types
//!   compiles only with a position. A shard is a field of its row.
//! - Each per-tick count holds the value the builder aggregated for the tick; each [`Events`] count rises from zero
//!   when the loop starts and saturates at `u32::MAX`.

use crate::failover::loss::Health;
use crate::failover::report::Members;
use crate::failover::standbys::{Closed, Need, Zone};
use crate::failover::zone_loop::evidence::HostEvidence;
use crate::failover::zone_loop::status::Blocker;
use crate::net::ownership::Shard;

labels! {
    /// A shard's serving class, as an operator reads it.
    Class, pub CLASSES, [
        /// The owner's entry at the shard record's tenure reads serving.
        Served,
        /// The owner's entry reads a recovery in progress, or a serving state short of serving.
        Recovering,
        /// The owner's entry reads withdrawn or closed.
        Withdrawn,
        /// The owner's entry reads held, parked, a held tenure or an unloadable metadata outcome, the owner's fresh
        /// report holds a held restart's diagnostic entry, or the survey finds a retirement request, an impaired volume
        /// or an unconfirmed loss.
        Blocked,
        /// The loop holds no owner entry at the record's tenure and no held restart's entry from a fresh report, or
        /// could not read the shard.
        Silent,
        /// The active volume is lost: a replacement runs, is held or has no generation left.
        Cold,
        /// The shard awaits a host that has not served it: its record stands at `E = 0`, or its owner is lost.
        Fresh,
    ]
}

labels! {
    /// A shard's standby state in an exception row.
    Standby, pub STANDBYS, [
        /// The record names a standby whose host reads live.
        Named,
        /// An enrollment holds the shard's census slot, or the tick's plan admitted its reservation. Either
        /// condition applies regardless of exposure relative to the standby target.
        Enrolling,
        /// The shard has had no live named standby for at most the zone's standby target.
        Within,
        /// The shard has had no live named standby for longer than the zone's standby target.
        Past,
        /// The survey could not judge the standby: the shard is unread or its named standby's host reads unknown.
        Unknown,
        /// The shard needs no standby yet: its record stands at `E = 0` or is absent.
        Unneeded,
    ]
}

labels! {
    /// A replacement receipt of a later generation than the shard record's, by phase, and held.
    ReceiptCount, pub RECEIPTS, [Open, Issued, Created, Held]
}

labels! {
    /// The kind of a host report the loop refused: one label per [`ReportError`](crate::failover::report::ReportError) but `Duplicate`, which a repeated
    /// delivery returns, and `Foreign`, an accepted report of a writer outside the zone.
    Refused, pub REFUSED, [Length, Magic, Schema, Writer, Tag, Flag, Field, Foreign]
}

labels! {
    /// A census reservation step's result: the census written or already holding the slot, or the population's
    /// refusal.
    Reservation, pub RESERVATIONS, [Reserved, Headroom, Full, Taken, Ineligible, Closed]
}

labels! {
    /// A standby enrollment's refusal, one label per variant of [`StandbyRefusal`](crate::failover::reconcile::StandbyRefusal).
    Enrollment, pub ENROLLMENTS, [Records, Tenure, Persist, Binding, Enrollment, Write]
}

labels! {
    /// A loss decision that acts: a replacement, a hold, or a hold at the last generation.
    Decided, pub DECISIONS, [Provision, Hold, Exhausted]
}

labels! {
    /// A reconciler step's error, one label per variant of [`ReconcileError`](crate::failover::reconcile::ReconcileError).
    StepError, pub STEP_ERRORS, [
        Store, Conflict, Stale, Retry, Named, Unclean, Layout, Population, Held, Exhausted, Create,
    ]
}

labels! {
    /// A provider create's result.
    Create, pub CREATES, [Created, Unknown, Failed]
}

labels! {
    /// An attach step's result: the attach event recorded, the attach requested, the request refused for good, or
    /// its outcome unknown.
    AttachOutcome, pub ATTACHES, [Recorded, Requested, Failed, Unknown]
}

labels! {
    /// An attachment reclamation step's result.
    Reclaim, pub RECLAIMS, [
        /// The attach entry was recorded ended.
        Ended,
        /// The attach entry was recorded ended while the shard record named its host standby.
        EndedNamed,
        /// The step refused: the entry's host is the shard's owner.
        RefusedOwner,
        /// The step refused: the entry's host is the shard's named standby.
        RefusedStandby,
        /// The detach of the ended entry's attachment was requested.
        DetachRequested,
        /// The detach request's outcome is unknown.
        DetachUnknown,
        /// The ended entry was recorded gone.
        Gone,
        /// The gone entry left the record.
        Removed,
    ]
}

labels! {
    /// The reconciler store client's watermark alarm, one label per variant of [`Alarm`](crate::storage::store::Alarm).
    StoreAlarm, pub STORE_ALARMS, [Clear, Regression, Checkpoint, Log, Namespace]
}

/// The highest generation a replacement can activate, the limit of the generation budget.
pub const GENERATION_MAX: u64 = u32::MAX as u64 - 1;

/// The survey blockers, one count slot each.
pub const BLOCKERS: usize = Blocker::COUNT;
/// The needs, one count slot each.
pub const NEEDS: usize = 2;
/// The host verdicts, one count slot each.
pub const VERDICTS: usize = 4;
/// The volume health judgements and the unjudged slot.
pub const HEALTHS: usize = 4;
/// The [`Closed`] bounds, one count slot each.
pub const CLOSED: usize = 5;
/// The store outcomes: unknown, unavailable, refused, log.
pub const OUTCOMES: usize = 4;

/// The positions `0..N` in order, which each index function binds one per variant, so a new variant compiles only
/// beside a longer count array.
pub const fn positions<const N: usize>() -> [usize; N] {
    let mut out = [0; N];
    let mut at = 0;
    while at < N {
        out[at] = at;
        at += 1;
    }
    out
}

/// The position of `need`: `Standby`, then `Fresh`.
pub fn need_at(need: Need) -> usize {
    let [standby, fresh] = positions::<NEEDS>();
    match need {
        Need::Standby => standby,
        Need::Fresh => fresh,
    }
}

/// The position of `verdict`: `Live`, `Lost`, `Conflict`, `Unknown`.
pub fn verdict_at(verdict: HostEvidence) -> usize {
    let [live, lost, conflict, unknown] = positions::<VERDICTS>();
    match verdict {
        HostEvidence::Live => live,
        HostEvidence::Lost => lost,
        HostEvidence::Conflict => conflict,
        HostEvidence::Unknown => unknown,
    }
}

/// The position of a volume's health: `Available`, `Impaired`, `Lost`, then unjudged.
pub fn health_at(health: Option<Health>) -> usize {
    let [available, impaired, lost, unjudged] = positions::<HEALTHS>();
    match health {
        Some(Health::Available) => available,
        Some(Health::Impaired) => impaired,
        Some(Health::Lost) => lost,
        None => unjudged,
    }
}

/// The position of `closed`: `LiveCap`, `EntryCap`, `PairCap`, `OwnEntry`, `KeyTaken`.
pub fn closed_at(closed: Closed) -> usize {
    let [live_cap, entry_cap, pair_cap, own_entry, key_taken] = positions::<CLOSED>();
    match closed {
        Closed::LiveCap => live_cap,
        Closed::EntryCap => entry_cap,
        Closed::PairCap => pair_cap,
        Closed::OwnEntry => own_entry,
        Closed::KeyTaken => key_taken,
    }
}

/// The flags of a zone part: the completeness of each source on the tick, the survey's holds, and whether the
/// configured census cap sits below the zone's shard count.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags {
    pub reports: bool,
    pub instances: bool,
    pub volumes: bool,
    pub store: bool,
    pub warm_up: bool,
    pub zone_host: bool,
    pub operator: bool,
    pub cap_below: bool,
}

/// The attach slots of the zone's active volumes, read from their records, and the survey's closed shards by cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attaches {
    /// Live attach entries.
    pub live: u32,
    /// Ended entries a recorded pair still pins.
    pub ended_paired: u32,
    /// Hosts whose latest entry is ended with no recorded pair pinning it: an end awaiting its detach.
    pub ended_unpaired: u32,
    /// Hosts whose latest entry is gone.
    pub gone: u32,
    /// Recorded pairs, of the pair cap summed over the volumes.
    pub pairs: Members,
    /// Shards in the survey's `Closed` state by the [`Closed`] bound of their survey row, which names the bound of the
    /// one host the plan judged (`zone_loop::plan::ShardPlan::closed`). A closed row with no bound counts in no cell,
    /// so in a status the survey builds the cells sum to at most the shards under `Blocker::AttachClosed`.
    pub closed: [u32; CLOSED],
}

/// The zone's hosts as this tick's verdicts and reports show them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hosts {
    /// Hosts by verdict, in [`verdict_at`] order.
    pub verdicts: [u32; VERDICTS],
    /// Hosts the directory does not retire whose last report advance is older than the fresh window, or that have
    /// none, of those hosts.
    pub silent: Members,
    /// Hosts with a fresh report whose detector holds a self-suspicion dwell.
    pub self_suspect: u32,
}

/// The highest attempt counter and generation among the zone's shard records, each of its largest value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budgets {
    /// The highest `E`, of `ATTEMPTS_MAX`.
    pub attempts: Members,
    /// The highest generation, of `2^32 - 2`, the last generation a replacement can activate. The codec refuses a
    /// value above the limit, so a producer reports a record past that generation as the limit.
    pub generation: Members,
}

/// The reconciler store client's alarm and the outcome counts since the zone loop took the client. The counts
/// saturate at `u32::MAX` and appear in this order: unknown, unavailable, refused, log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreState {
    pub alarm: StoreAlarm,
    pub outcomes: [u32; OUTCOMES],
}

/// What the loop counted since it started: refused reports and each step result it fed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Events {
    pub refused: [u32; REFUSED.len()],
    pub reservations: [u32; RESERVATIONS.len()],
    pub enrollments: [u32; ENROLLMENTS.len()],
    pub decisions: [u32; DECISIONS.len()],
    pub errors: [u32; STEP_ERRORS.len()],
    pub creates: [u32; CREATES.len()],
    pub attaches: [u32; ATTACHES.len()],
    pub reclaims: [u32; RECLAIMS.len()],
}

/// One shard outside the served class, or one served shard with no standby past its target: its class, its standby
/// state and the time since the loop first observed it in that class and, for a served shard, past its target, on
/// the loop's clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExceptionRow {
    pub shard: Shard,
    pub class: Class,
    pub standby: Standby,
    pub age_us: u64,
}

impl ExceptionRow {
    /// Whether a shard in `class` with `standby` takes an exception row: every shard outside the served class, and a
    /// served shard whose standby is [`Standby::Past`].
    pub fn admits(class: Class, standby: Standby) -> bool {
        class != Class::Served || standby == Standby::Past
    }
}

/// One zone's part of a status: the tick's counts, the loop's [`Events`], and at most [`super::MAX_ROWS`] exception
/// rows, oldest first, with the count of rows left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZonePart {
    pub zone: Zone,
    /// The loop's tick count since it started.
    pub tick: u64,
    pub flags: Flags,
    /// Shards by serving class, in [`CLASSES`] order.
    pub classes: [u32; CLASSES.len()],
    /// Entries of fresh reports that read serving at a tenure below the shard record's and have been observed stale
    /// for longer than the fresh window.
    pub stale_serving: u32,
    /// The longest time any counted entry has been observed stale, `None` without one.
    pub stale_oldest_us: Option<u64>,
    /// Shards by standby state, in [`STANDBYS`] order, `Unneeded` left out.
    pub standby: [u32; STANDBYS.len() - 1],
    /// Shards by need, in [`need_at`] order.
    pub needs: [u32; NEEDS],
    /// Shards by survey blocker, in [`Blocker::position`] order.
    pub blockers: [u32; BLOCKERS],
    /// The census length beside the configured cap, which a cap lowered below a census already written leaves below
    /// the length; unavailable when the census was unread.
    pub census: Members,
    pub attaches: Attaches,
    /// Receipts of a later generation than their shard record's, in [`RECEIPTS`] order.
    pub receipts: [u32; RECEIPTS.len()],
    /// Active volumes by health, in [`health_at`] order.
    pub volumes: [u32; HEALTHS],
    /// The listed volumes that read impaired or lost, hold a volume record short of retired and are named by no
    /// shard record or replacement receipt the tick read: a displaced volume whose retirement no process finished
    /// reads here. `None` on a tick whose volume listing, census, shard records or volume-record lookups were
    /// incomplete. The tick reads only the directory's shards, so the active volume of a shard the directory omits
    /// counts here too while it reads impaired or lost.
    pub unnamed_volumes: Option<u64>,
    pub hosts: Hosts,
    pub budgets: Budgets,
    pub store: StoreState,
    pub events: Events,
    /// Shards the rows leave out among those [`ExceptionRow::admits`] names.
    pub omitted: u32,
    pub rows: Vec<ExceptionRow>,
}

impl ZonePart {
    /// The part of `zone` at tick 0 with every flag clear, every count zero, every gauge unavailable, the store
    /// alarm clear and no row.
    pub fn blank(zone: Zone) -> Self {
        Self {
            zone,
            tick: 0,
            flags: Flags::default(),
            classes: [0; CLASSES.len()],
            stale_serving: 0,
            stale_oldest_us: None,
            standby: [0; STANDBYS.len() - 1],
            needs: [0; NEEDS],
            blockers: [0; BLOCKERS],
            census: Members::Unavailable,
            attaches: Attaches {
                live: 0,
                ended_paired: 0,
                ended_unpaired: 0,
                gone: 0,
                pairs: Members::Unavailable,
                closed: [0; CLOSED],
            },
            receipts: [0; RECEIPTS.len()],
            volumes: [0; HEALTHS],
            unnamed_volumes: None,
            hosts: Hosts {
                verdicts: [0; VERDICTS],
                silent: Members::Unavailable,
                self_suspect: 0,
            },
            budgets: Budgets {
                attempts: Members::Unavailable,
                generation: Members::Unavailable,
            },
            store: StoreState {
                alarm: StoreAlarm::Clear,
                outcomes: [0; OUTCOMES],
            },
            events: Events::default(),
            omitted: 0,
            rows: Vec::new(),
        }
    }
}
