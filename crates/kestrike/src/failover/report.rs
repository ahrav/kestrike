//! The host report: one authenticated, bounded value per period carrying what a host observes about each volume it
//! holds, its headroom and the build it runs, for the reconciler and the monitors. The report is an observation:
//! every recovery and serving decision rests on the store records and the device.
//!
//! The body uses big-endian values at fixed offsets behind a 4-byte magic and a 2-byte schema
//! version, a decoder that accepts exactly the encodings its encoder produces, and errors that name the first
//! failed check. A 48-byte header (`HRPT`, schema, writer host, boot nonce, sequence, seal time, entry count, a zero
//! byte) precedes the host part, one [`ENTRY_LEN`]-byte entry per volume in [`VolumeEntry::encode`]'s format, and a
//! 32-byte tag.
//!
//! [`SCHEMA`] 3 fixes the layout, the label tables, the unavailable encodings, the decoder's field rules and the
//! units, rate windows and counter reset points below. A production build's first sealed report freezes them. After
//! that, a change to any of them, an appended label included, uses a new schema. The
//! operator contract, `failover/report/contract.json`, pins the layout, each field's unit and reset identity, the
//! label tables, the unavailable encodings, the fields schema 3 leaves out and sealed fixtures, a schema-2 report
//! among them:
//!
//! - `sealed_at_us` is the writer's wall-clock reading in microseconds since the Unix epoch at the seal, or the
//!   boot's previous stamp when the clock has stepped back below it, so a boot's stamps rise with its sequence. It
//!   is best-effort wall time: a consumer uses it to estimate a report's staleness, and a stepped clock skews it.
//!   The stamp also orders a host's boots at a [`Reader`]: when the reader keeps [`BOOTS`] boots of the host, a new
//!   boot's reports drop until its clock passes the lowest kept stamp, so a backward step can delay the next boot.
//!   The writer paces its period on a separate elapsed clock. Every other time is a duration in microseconds that
//!   the producer computes when it builds the entry or samples the host; sealing refreshes no value.
//! - `ram` is bytes in use, `MemTotal - MemAvailable`, of `MemTotal`. `cpu_load` is the one-minute load average in
//!   hundredths, of 100 per online CPU, saturating at the limit, so `used == limit` reads a load at or above the
//!   online CPU count; the load average counts runnable tasks and tasks in uninterruptible I/O wait, so a storage
//!   stall raises it with no CPU in use. `iops` is operations per second and `bandwidth` bytes per second, each
//!   averaged over the interval since the same writer boot's previous seal and summed over the host's owners, of
//!   the provisioned rate; each is unavailable in a boot's first report and when the owner set changed between the
//!   two seals, an owner's count fell, or at either seal an owner's reading is missing, failed or no newer than the
//!   reading at the seal before it. The producer measures that interval on the writer's elapsed clock.
//!   `attachments` (spares counted), `workers` and `recovery` count slots.
//! - Each pressure gauge counts the entries of one bounded resource in use, of its bound, when the producer builds
//!   the entry: `frontier` the delta blocks the last accepted shard record's replay still requires, of the own
//!   volume's delta region and saturating at it, `ancestry` the retained ancestry suffixes of that record, `quarantine` the checkpoint
//!   slots a tenure's possibly-named set holds quarantined or names for an unsettled Publish, of its layout's slots,
//!   and `full` how many of the ancestry, the delta history and the owner's recovery I/O share stand at their bound,
//!   of those three; the share is at its bound when its current window refused a charge. The frontier and full
//!   gauges read the recorded history, and an owner whose shard record names another volume active reports them
//!   unavailable, since that record's history lies on the active volume's region.
//! - An entry's counts restart from zero with each tenure `(g, a)` of its shard, which NoEpochReuse makes unique
//!   within the shard; the recovery attempt count and the detector's nomination count restart under a new
//!   `WriterId::boot`. The contract's `resets` map names each count's reset identity, and its `reset_identities`
//!   map gives the report fields that key each identity.
//! - `report_age_us` is the authority's Report age on its serving clock. `checkpoint_age_us` counts from this owner
//!   tenure's first read of a shard record naming the checkpoint, on the owner's turn clock, and restarts with each
//!   tenure, so a monitor compares checkpoint identity across reports for the checkpoint's age across tenures.
//! - `own_records` is the own host ID's record count among the rows the authority inspected in the last Report it
//!   evaluated, absent when that Report gave no count. The inspected rows stop at the registrant bound, so a count
//!   above one is a lower bound, and a count of one also covers one row under a wrong key.
//! - The recovery part's times count on the owner's turn clock from the first tick of the tenure's attach, each
//!   read at the observation that recorded its milestone, and its gauges and counts are the contract's units: each
//!   holds the value when the producer builds the entry. The host part's detector fields read the detector when the
//!   producer samples it.
//! - The volume, shard, tenure and operation identity are fields. A monitor aggregates by the labels: role, state
//!   and cause.
//!
//! Invariants owned here:
//!
//! - REPORT-AUTHENTICATED: the tag is HMAC-SHA256 under the writer's [`ReportKey`] over a 16-byte domain label and
//!   the body, which the `sha256` submodule computes. [`ReportKey::derive`] computes that key from the host key
//!   under a label of its own, so a verifier holds a key that authenticates reports only. [`Reader::accept`] reads only the magic, the schema, the
//!   entry count and the writer before the tag verifies in constant time.
//! - REPORT-BOUNDED: a report holds at most [`MAX_ENTRIES`] entries, one per volume, and is exactly
//!   `306 + 509·n` bytes, at most [`MAX_LEN`]. `MAX_ENTRIES` is 128, the largest instance attachment limit, so one
//!   report covers every volume a host can hold; `MAX_LEN` is 65,458 bytes, within 65,536 bytes and one sixth of the
//!   store's item limit, as compile-time assertions check. A [`Writer`]
//!   seals at most one report per period. A [`Reader`] keeps up to [`BOOTS`] high-waters for each host its key
//!   lookup names, so its state grows with the hosts it has accepted over its lifetime. The key lookup receives the
//!   header's host before the tag verifies, and [`Reader::accept`] requires it to be a bounded local lookup that
//!   grows nothing on a miss. Each delivered report then costs the reader one key lookup and one HMAC over at most
//!   `MAX_LEN` bytes, and the transport that carries reports bounds their arrival rate.
//! - CLOSED-LABELS: every label is a byte that selects from a closed table, code 0 naming an absent or unavailable
//!   value, and the decoder refuses any other byte. The conversions from the owner's withdrawal and refusal causes
//!   match exhaustively over their top-level variants, so a new top-level cause compiles only with a label or an
//!   aggregation into one; the registrant, metadata and store-class conversions match the same way. `Report` and
//!   `Admission` aggregate their inner causes, and the recorded-holder hold, the no-holder hold and a lapsed
//!   deferral's withdrawal read `recorded-holder`, `unheld` and `unverified` with no flip request. A hold after a deposing status keeps `conflict` or
//!   `preempt-aborted` with no flip request, which a pending STATUS-REJUDGE and a status withdrawal followed by a
//!   successor observation (`SupersededRequestsNoFlip`) also show; the entry's [`Hold`] label tells them apart. The
//!   retained refusal need not explain the current withdrawal. The serving and load-refusal lists also form
//!   exhaustive matches, so compilation fails when one omits a variant. An exhaustive match gives each exit status
//!   its position, so a new status compiles only with a position, and a compile-time check holds each status the
//!   exit table lists at its position. The volume-state and readiness tables come from the record and readiness
//!   modules. The encoder maps a value outside its table to code 255, which the decoder refuses. Every other field
//!   encodes without loss, so an encoding the decoder accepts decodes to the value encoded, and [`Writer::seal`]
//!   refuses with [`SealError::Field`] exactly the encodings the decoder refuses, which keeps their bytes off the
//!   wire.
//! - NO-KEY-MATERIAL: a report holds no key, reservation key, host attachment identifier, request identifier or
//!   instance identifier, and the writer's `Debug` omits its key. The volume name and the exit's operation identity
//!   are fields, never labels.
//! - NO-INVENTED-VALUES: a field the producer has no source for is [`Gauge::Unavailable`],
//!   [`Enumeration::Unavailable`], [`Watermark::Unavailable`] or `None`, and no report type implements `Default`.
//! - WRITER-SEQUENCE: a writer is a fleet host and a boot nonce, its sequence rises by one per sealed report from
//!   1, and its seal time stamps are nondecreasing. A reader drops a report at or below the highest sequence it
//!   accepted from that writer. The reader keeps up to [`BOOTS`] boots per host, each with the highest seal time it
//!   accepted from that boot. When [`BOOTS`] boots are kept, the reader accepts a report of another boot whose seal
//!   time exceeds the lowest kept seal time, and that lowest boot leaves. Every accepted report's boot is kept with
//!   its sequence, and the lowest kept seal time is nondecreasing and at or above every seal time accepted from a
//!   boot that left, so every report of that boot sealed at or before them drops, a report of it that passes
//!   carries a higher sequence than any the reader accepted, and a replay of any accepted report drops. The same
//!   rule delays a host's next boot after a backward wall-clock step: when the reader keeps [`BOOTS`] boots stamped
//!   under the earlier, higher clock, the new boot's reports drop until the clock passes the lowest of those stamps.
//! - REPORTS-CONFER-NO-AUTHORITY: this module holds no store client, device handle or serving machine. Producing an
//!   entry reads the owner through a shared borrow. No write that changes a shard's owner, generation or tenure
//!   derives from a report, and no device write does. A report may select a candidate and its headroom and veto a
//!   host-lost verdict from silence. A host is lost only on a directory retirement, or on report silence together
//!   with control-plane instance evidence (`failover::zone_loop::evidence::host_evidence`).
//!   The reconciler's standby census reservation (`failover::reconcile::Reconciler::reserve`) takes its candidate
//!   host and headroom from a report its caller accepted and bounds in age, and that reservation names no owner or
//!   standby.

use core::num::{NonZeroU64, NonZeroU128};
use std::collections::BTreeMap;
use std::path::Path;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::entropy::{EntropyError, nonce_from, os_entropy};
use crate::failover::assignment::hmac;
use crate::failover::evidence::NotSole;
use crate::failover::records::{
    self, CHECKPOINT, CodecError, Host, NamedCheckpoint, Reader as Bytes, STATES, ShardRecord,
    VOLUME, VolumeId, VolumeState, index,
};
use crate::failover::retire::Stale;
use crate::failover::serving::{self, Cause, Deposing};
use crate::net::ownership::{ActivatedEpoch, Shard, ShardGeneration};
use crate::storage::store::StoreError;
use crate::storage::{AuthorityRefusal, AuthorityReport, LoadRefusal, MetadataOutcome, Readiness};

mod headroom;
mod observed;
mod recovery;
pub use headroom::{
    DeviceCounts, DeviceSample, HeadroomInputs, attached, host_recovery_io, producer_missing,
    recovering,
};
pub use observed::{Observed, read_defects};
pub use recovery::{RecoveryRefusal, RecoveryStatus};

/// The body version this module encodes and the only one its reader accepts.
pub const SCHEMA: u16 = 3;
/// The most entries one report holds.
pub const MAX_ENTRIES: usize = 128;
/// One entry, in wire order: the authority part, then the recovery part.
pub const ENTRY_LEN: usize = AUTHORITY_LEN + RECOVERY_LEN;
/// Volume, shard, role, `(g, a)`, the volume-state, serving, flags, withdrawal, refusal, enumeration and watermark
/// bytes, the flagged Report age (9), the flagged own-record count (5), the flagged checkpoint, the flagged
/// checkpoint age and capture counts (3 × 9), the exit code and operation (17) and four pressure gauges.
const AUTHORITY_LEN: usize =
    VOLUME + 4 + 1 + 8 + 7 + 9 + 5 + (1 + CHECKPOINT) + 3 * 9 + (1 + 16) + 4 * GAUGE;
/// Twelve label bytes, the second flags byte, the flagged attempt count (5) and age (9), five flagged recovery
/// times, the retention account, the suffix backlog gauge and flagged lag, the recovery I/O gauge and flagged
/// saturated windows, the attach gauge, four flagged store outcome counts, the two coverage gauges, the
/// invalidation gauge and the flagged read-defect and served counts.
const RECOVERY_LEN: usize =
    12 + 1 + 5 + 9 + 5 * 9 + RETENTION + 2 * (GAUGE + 9) + GAUGE + 4 * 9 + 3 * GAUGE + 2 * 9;
/// A flag byte, the first-damage label, three 8-byte entry and unit counts, four 4-byte unit and suffix counts and
/// four 8-byte suffix and slot counts.
const RETENTION: usize = 2 + 3 * 8 + 4 * 4 + 4 * 8;
/// Magic (4), schema (2), writer host (8), boot (16), sequence (8), seal time (8), entry count (1), zero byte (1).
const HEADER_LEN: usize = 48;
/// The era (4), the flagged digest (33), seven headroom gauges, the health label, the detector's peer gauge and
/// two flagged values, the producer gauge and the host recovery I/O gauge.
const HOST_LEN: usize = 4 + 33 + 7 * GAUGE + 1 + GAUGE + 2 * 9 + 2 * GAUGE;
pub(crate) const TAG_LEN: usize = 32;
/// A flag byte, `used` (8) and `limit` (8).
const GAUGE: usize = 17;
/// The length of a report holding [`MAX_ENTRIES`] entries.
pub const MAX_LEN: usize = report_len(MAX_ENTRIES);
/// The boots per host a [`Reader`] keeps a high-water for.
pub const BOOTS: usize = 4;
const MAGIC: &[u8; 4] = b"HRPT";
const DOMAIN: &[u8; 16] = b"ebs-host-report1";
const KEY_DOMAIN: &[u8] = b"ebs-host-report-key";

/// The length of a report holding `entries` entries.
const fn report_len(entries: usize) -> usize {
    HEADER_LEN + HOST_LEN + entries * ENTRY_LEN + TAG_LEN
}

const _: () =
    assert!(AUTHORITY_LEN == 189 && ENTRY_LEN == 509 && HOST_LEN == 226 && MAX_LEN == 65_458);
const _: () = assert!(
    MAX_LEN <= 65_536
        && MAX_LEN <= crate::storage::store::ITEM_LIMIT / 6
        && MAX_ENTRIES <= u8::MAX as usize
);

/// The key that authenticates one host's reports. It has no `Debug`, so no format string prints it.
#[derive(Clone, Copy)]
pub struct ReportKey(pub [u8; 32]);

impl ReportKey {
    /// The report key of `host_key` authenticates host reports in a separate HMAC domain.
    pub fn derive(host_key: &[u8; 32]) -> Self {
        Self(hmac(host_key, &[KEY_DOMAIN]))
    }
}

/// A report's writer: the fleet host and the nonzero nonce its writer drew at start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterId {
    pub host: Host,
    pub boot: [u8; 16],
}

/// One decoded report: its writer metadata, the host part and one entry per volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostReport {
    pub writer: WriterId,
    pub sequence: u64,
    /// The writer's wall-clock stamp in microseconds since the Unix epoch at the seal, or the boot's previous stamp
    /// when the wall clock fell below it, so stamps are nondecreasing within a boot.
    pub sealed_at_us: u64,
    pub host: HostState,
    pub entries: Vec<VolumeEntry>,
}

/// The host part: the build the host runs, its headroom, its heartbeat health bit, its detector census, its
/// producer health and its recovery I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostState {
    pub build: BuildIdentity,
    pub headroom: Headroom,
    /// The host-wide health bit the host's heartbeat carries, `None` without a source.
    pub health: Option<Health>,
    pub detector: Detector,
    /// Assigned volumes with no fresh entry from their owner process, of the assigned volumes; a host assigned no
    /// volume reads 0 of 0.
    pub producer_missing: Members,
    /// The sum of [`RecoveryIo::peak`] bytes over the owners whose attach built a recovery I/O share, of twice the
    /// host share's bytes per interval; an owner with no share adds nothing. The limit saturates at `u64::MAX` and
    /// the sum at the limit, so `used == limit` reads a sum at or above the limit. The owners' peaks come from share
    /// windows that need not overlap. Unavailable when a share-holding owner's peak is unavailable or its owner has
    /// no fresh entry, and when the host share gives an owner no usable part: a zero interval, no owners, more than
    /// 128 owners, or bytes per owner below one delta block.
    pub recovery_io: Gauge,
}

/// What the host's failure detector holds about its peers when the producer samples it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Detector {
    /// The peers that hold a suspicion, no ALIVE veto, no fresh declared reading and no recovery from a declared
    /// hold, which the detector's self-suspicion rule counts, of the peers it tracks; a detector tracking no peer
    /// reads 0 of 0.
    pub peers: Members,
    /// The self-suspicion dwell left at the detector's last successful tick, from that tick's repair demand, on its
    /// elapsed clock; 0 when that tick returned no repair demand.
    pub self_suspect_us: Option<u64>,
    /// Nominations the detector published since the writer's boot.
    pub nominations: Option<u64>,
}

/// The binary era this build records in attachment events, [`records::ERA`], and the SHA-256 of its executable,
/// `None` when the executable could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildIdentity {
    pub era: u32,
    pub digest: Option<[u8; 32]>,
}

/// Host headroom; the module documentation states each gauge's unit and window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Headroom {
    pub ram: Gauge,
    /// The one-minute load average, counting runnable tasks and tasks in uninterruptible I/O wait, saturating at
    /// the online CPU count.
    pub cpu_load: Gauge,
    pub iops: Gauge,
    pub bandwidth: Gauge,
    /// Attachment slots, spares counted.
    pub attachments: Gauge,
    pub workers: Gauge,
    pub recovery: Gauge,
}

/// A reading of a bounded resource. The codec carries a known gauge only with `used` at most `limit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gauge {
    Unavailable,
    Known { used: u64, limit: NonZeroU64 },
}

/// A count of a population's members, of the population's size, which can be empty. The codec carries a known reading
/// only with `used` at most `limit`, so a known empty population reads 0 of 0. The status codec treats `used` and
/// `limit` as independent values in its census and pair gauges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Members {
    Unavailable,
    Known { used: u64, limit: u64 },
}

/// Defines a closed label enum and its code table, which lists every variant in code order.
macro_rules! labels {
    ($(#[$meta:meta])* $name:ident, $vis:vis $table:ident, [$($(#[$doc:meta])* $variant:ident),+ $(,)?]) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $($(#[$doc])* $variant,)+
        }

        /// Every value of the label, in code order.
        $vis const $table: &[$name] = &[$($name::$variant),+];
    };
}

labels! {
    /// The role the last accepted shard record and the last own-volume read give the host for the volume. Owner
    /// and replacement rank first and need only the shard record; the others need an own-volume read.
    RecordedRole, ROLES, [
        /// The shard record names the volume active and the host its owner.
        Owner,
        /// The shard record names the volume active under another owner, and the volume record lists a registrant
        /// pair of the host. A deposed owner's pair on the same volume reads as standby until a fence drops it. The
        /// role reports enrollment: the shard record's named standby, which alone holds takeover authority, and any
        /// other enrolled host both read as standby.
        Standby,
        /// The shard record names the volume and host as its spare.
        Replacement,
        /// The records give the host none of the roles above.
        Unrecorded,
    ]
}

labels! {
    /// The serving machine's withdrawal cause, as a label. The recorded-holder and no-holder holds and the
    /// unverified registrant have labels of their own beside `Report`, which aggregates every other Report-triggered
    /// cause.
    Withdrawal, WITHDRAWALS, [
        Report, RecordedHolder, Unheld, Conflict, PreemptAborted, ForceDetach, Attachment, Modification,
        RestartCheck, ActivationRecord, Exhausted, Planned, Flipped, NewerFence, LaterTenure, Regression,
        /// LAPSE-UNVERIFIED: a lapsed deferral withdrew the tenure with no flip request, and the owner's poll
        /// judges the registrant against a later volume-record read.
        Unverified,
    ]
}

labels! {
    /// The authority's last refusal cause, as a label.
    Refusal, REFUSALS, [
        Admission, ReportMalformed, ReportTimeout, ForeignLower, ForeignEqual, ForeignHigher,
        Conflict, PreemptAborted, OwnHostId, Clock, Boundary,
    ]
}

labels! {
    /// The attachment enumeration's result against the desired state, as `failover::attachments::check` judges a
    /// control-plane listing; `Foreign` and `Duplicate` are the results that retire a volume. Code 0 is
    /// `Unavailable`; this table has no separate absent code.
    Enumeration, ENUMERATIONS, [
        /// The producer has no enumeration result.
        Unavailable,
        /// The listing holds the own instance once, each admitted peer at most once, and no other record.
        Matches,
        /// The listing holds no record of the own instance and none outside the admitted set.
        Missing,
        /// A listed record names an instance outside the admitted set, or an instance the listing client could not
        /// read.
        Foreign,
        /// The own instance or an admitted peer is listed more than once.
        Duplicate,
        /// The control plane returned no listing.
        Unlisted,
    ]
}

labels! {
    /// The store client's watermark alarm, which keeps the first cause that withdrew the client. Code 0 is
    /// `Unavailable`; this table has no separate absent code.
    Watermark, WATERMARKS, [
        /// The producer has no watermark source.
        Unavailable,
        /// No alarm is raised.
        Clear,
        /// A read returned a version below the mark, a tracked value below the mark, or the mark's version with
        /// another value; a record whose mark is held was absent or failed to decode at or below the marked
        /// version; or a write committed at or below the held version or at a version other than the one it names.
        Regression,
        /// The log failed to record a raised watermark.
        Log,
        /// A shard record named no checkpoint, an older one or another one with the adopted checkpoint's identity at
        /// the adopted checkpoint's generation.
        Checkpoint,
        /// A record named another store instance than the store's.
        Namespace,
    ]
}

labels! {
    /// The last evaluated Report's registrants, judged against the own pair and the volume record's pairs.
    Registrants, REGISTRANTS, [
        /// The own pair holds and is the only registrant.
        Sole,
        /// The own pair holds and every other registrant is a recorded pair.
        Recorded,
        Excess, Unreadable, ReservationType, DuplicateOwnRecord, ForeignHolder, ForeignRegistrant, NotHolder,
        /// Another registrant is a recorded pair that pins no live attach, or an admitted unrecorded pair under the key
        /// of a spent entry number no live attach holds, as the authority's `RegistrantJudgment::Ended` reads it.
        EndedRegistrant,
    ]
}

labels! {
    /// The serving machine's hold on the last evaluated Report.
    Hold, HOLDS, [
        /// The Report holds the tenure in no way.
        Clear,
        /// The Report shows a recorded pair of another attachment holding or nobody holding, and the tenure holds
        /// with no flip request.
        Held,
        /// A deposing status awaits its rejudge.
        Pending,
        /// A successor observation superseded a status withdrawal, which requests no flip.
        Superseded,
    ]
}

labels! {
    /// The attach's metadata outcome, one label per top-level variant of [`MetadataOutcome`].
    Metadata, METADATA, [
        Bootstrapping, Unformatted, Open, SlotUnreadable, Unsupported, FormatMismatch, TiedRoots, StaleSession,
        Unfenced, EntropyUnavailable, MetadataFailed, Collided, Unloadable,
    ]
}

labels! {
    /// The sequence the last recovery attempt ran: a same-host restart, a takeover, a fresh first acquisition, or
    /// a restart that took the lineage arm after its own bump, which reached its fencing boundary through the arm or
    /// refused at one of the arm's device commands.
    RecoveryKind, KINDS, [Restart, Takeover, Fresh, Lineage]
}

labels! {
    /// Where the last recovery attempt stands.
    RecoveryOutcome, OUTCOMES, [Running, Completed, Refused]
}

labels! {
    /// The check that refused the last recovery attempt: one label per top-level check variant of the restart, the
    /// takeover and the fresh first acquisition, a variant name the sequences share reading as one label. The
    /// restart's `Lineage` refusals read `RecordedHolder`, the hold they share with a recorded holder.
    RecoveryCheck, CHECKS, [
        Records, Deposed, RecordedHolder, Unheld, Fresh, Volume, Exhausted, SuffixOnly, Local, Driver, Ready,
        HostId, FirstReport, NotHolding, Unobserved, Bump, Preempt, SecondReport, NotSole, Coverage, Stale,
        Restart, Predecessor, TakeOver, Unparsed, Holder, Register, SecondUnparsed, Superseded, Origin, Persist,
        EnrollWrite, EnrollRefused, Acquire, Report, Hold, Write, Read, Activation, Confirm, Named, Fencing,
        Fence, UnresolvedPage, Release, Retention,
    ]
}

labels! {
    /// The step after a refused recovery attempt, as the attempt's own sequence names it: a flip request, a hold
    /// with the volume retained, a same-host restart, or a stop. The owner process's exit after the refusal is a
    /// separate classification, the entry's [`Ended`] label, which parks or deposes some refusals whose sequence
    /// holds or restarts.
    RecoveryNext, NEXTS, [Flip, Hold, Restart, Stop]
}

labels! {
    /// The class of a store error, one label per variant of [`StoreError`].
    StoreClass, STORE_CLASSES, [
        Unavailable, Refused, Unknown, Absent, Codec, Successor, Flip, Stale, AttemptsExhausted, Regression,
        Withdrawn, Namespace, Log,
    ]
}

labels! {
    /// The owner process's phase.
    Phase, PHASES, [Starting, Recovering, Held, Standby, Serving, Withdrawn, Closing, Parked]
}

labels! {
    /// The kind of the one exit that ended the owner process's last incarnation.
    Ended, ENDINGS, [Stopped, Rerun, Held, Deposed, Retire, Refused, Retired, Fault]
}

labels! {
    /// The kind of a checkpoint slot's first damage, which outranks the rest: a unit's record header, its chunk
    /// checksum, its content, unit 0's unit count, or a unit the device could not read.
    Damage, DAMAGES, [Header, Chunk, Content, Units, Unread]
}

labels! {
    /// The host-wide health bit a heartbeat carries.
    Health, HEALTH, [Healthy, Unhealthy]
}

/// Capture refusals and abandonments in the entry's tenure, each `None` without a counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Captures {
    pub refused: Option<u64>,
    pub abandoned: Option<u64>,
}

/// Recovery-history pressure: the required delta history, the retained ancestry, the unresolved checkpoint slots in
/// `quarantine`, which [`Pressure::unresolved`] supplies, and the history resources at their bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pressure {
    pub frontier: Gauge,
    pub ancestry: Gauge,
    pub quarantine: Gauge,
    pub full: Gauge,
}

/// The resources `full` counts: the ancestry chain, the delta history and the recovery I/O share.
const HISTORY_RESOURCES: u64 = 3;

impl Pressure {
    /// The pressure of `record` over the delta region of `layout` and of the owner's recovery I/O share, which is
    /// full when its window open at the report refused a charge. `layout` is the own volume's recorded layout, and a
    /// producer passes `None` unless `record` names the own volume active, since the record's history lies on the
    /// active volume's region. A required history at or past a region of `J` blocks reads `frontier` as `J` of `J`
    /// and counts as at bound in `full`; a layout with no delta region holds no history, so `frontier` reads
    /// `Unavailable` and `full` counts the delta history as at bound. `full` is known only with both a record and a
    /// layout, so without them it reads `Unavailable` and carries no reading of the share.
    pub fn recorded(
        record: Option<&ShardRecord>,
        layout: Option<&records::Layout>,
        share_full: bool,
    ) -> Self {
        let chain = record.map(|record| record.ancestry.as_slice().len() as u64);
        let ancestry = chain.map_or(Gauge::Unavailable, |used| {
            Gauge::known(used, records::MAX_CHAIN as u64)
        });
        let history = record
            .zip(layout)
            .map(|(record, layout)| crate::storage::checkpoint::required_history(record, layout));
        let frontier = history.map_or(Gauge::Unavailable, |(used, limit)| {
            Gauge::known(used.min(limit), limit)
        });
        let full = match (chain, history) {
            (Some(chain), Some((used, limit))) => {
                let at_bound = u64::from(chain >= records::MAX_CHAIN as u64)
                    + u64::from(used >= limit)
                    + u64::from(share_full);
                Gauge::known(at_bound, HISTORY_RESOURCES)
            }
            _ => Gauge::Unavailable,
        };
        Self {
            frontier,
            ancestry,
            quarantine: Gauge::Unavailable,
            full,
        }
    }

    /// The `quarantine` gauge of a tenure's possibly-named set: the checkpoint slots that are quarantined or possibly
    /// named by a Publish whose outcome no success settled, of the layout's slots.
    pub fn unresolved(possible: &crate::storage::checkpoint::PossiblyNamed) -> Gauge {
        let (used, limit) = possible.unresolved();
        Gauge::known(used, limit)
    }
}

/// The nonzero, opaque identity of one owner-requested exit. Identities carry no order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitOperation(NonZeroU128);

impl ExitOperation {
    pub fn new(bytes: [u8; 16]) -> Option<Self> {
        NonZeroU128::new(u128::from_be_bytes(bytes)).map(Self)
    }

    pub fn bytes(self) -> [u8; 16] {
        self.0.get().to_be_bytes()
    }
}

/// Why an exit request ends in a restart: its retirement admission refused it, it requested a planned restart, or
/// its transfer write was refused or ended with an unknown outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restart {
    /// The report label `restarting-deadline`, which the report contract keeps and no code sets: a planned exit whose
    /// deadline passes before its withdrawal resumes with [`Resume::Deadline`].
    Deadline,
    Refused(Stale),
    /// A requested restart or an owner-raised roll.
    Planned,
    TransferRefused,
    TransferUnknown,
}

/// Why a planned exit resumed in place before its withdrawal: its deadline passed, its cut was not published and
/// certified, no standby was named, or a store request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resume {
    Deadline,
    /// The exit requires a ready cut.
    Cut,
    /// The exit requires the record to name its standby.
    Standby,
    /// A failed store request, a record that names another shard or tenure, or an attempt counter without room for
    /// the exit's bumps.
    Store,
}

/// What the owner did with an exit request: received it, stops admission in stages, withdrew, waits for a successor
/// tenure, exited once a successor tenure exists and its authority is withdrawn or closed, resumed in place before
/// its withdrawal, or restarts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    Received,
    Draining,
    Withdrawn,
    Waiting,
    Exited,
    Resumed(Resume),
    Restarting(Restart),
}

/// The last exit request the producer tracks and its status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exit {
    pub operation: ExitOperation,
    pub status: ExitStatus,
}

/// One volume the host holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeEntry {
    pub volume: VolumeId,
    pub shard: Shard,
    /// `None` without an accepted shard record, and without an own-volume read when the shard record names neither
    /// the owner nor the replacement role.
    pub role: Option<RecordedRole>,
    /// The `(g, a)` of the tenure's session.
    pub tenure: Option<(ShardGeneration, ActivatedEpoch)>,
    /// The state of the volume's last read record.
    pub volume_state: Option<VolumeState>,
    /// The serving state when the producer builds the entry. Without it the three flags are unavailable, and the
    /// codec carries them only as false.
    pub serving: Option<serving::State>,
    /// Readiness is withheld; bit 0 of the flags byte.
    pub withheld: bool,
    /// Recovery readiness holds an integrity fault; bit 1. The owner producer writes false on every entry, since no
    /// readiness state records an integrity fault; the codec carries a true value under a serving state, and only false
    /// without one.
    pub quarantine: bool,
    /// The serving machine holds a flip request; bit 2.
    pub flip: bool,
    pub withdrawal: Option<Withdrawal>,
    pub refusal: Option<Refusal>,
    pub enumeration: Enumeration,
    pub watermark: Watermark,
    pub report_age_us: Option<u64>,
    /// The own host ID's record count among the inspected rows of the last evaluated Report, `None` without a count.
    pub own_records: Option<u32>,
    /// The checkpoint the shard record names.
    pub checkpoint: Option<NamedCheckpoint>,
    /// The time since this owner tenure first read a shard record naming `checkpoint`, on the owner's turn clock,
    /// present only with `checkpoint` and absent when the clock reads before that first read; each tenure restarts
    /// it.
    pub checkpoint_age_us: Option<u64>,
    pub captures: Captures,
    /// The last exit request the producer tracks, `None` when it tracks none, either because it has received no
    /// request or because it has no exit source.
    pub exit: Option<Exit>,
    pub pressure: Pressure,
    /// The last evaluated Report's registrant judgment.
    pub registrants: Option<Registrants>,
    /// The serving machine's hold on the last evaluated Report.
    pub hold: Option<Hold>,
    /// The volume's readiness word.
    pub readiness: Option<Readiness>,
    /// The attach's metadata outcome.
    pub metadata: Option<Metadata>,
    /// The warm load's refusal.
    pub load_refusal: Option<LoadRefusal>,
    pub recovery: Recovery,
    /// The owner process's phase.
    pub phase: Option<Phase>,
    /// The exit that ended the owner process's last incarnation.
    pub ended: Option<Ended>,
    /// The shard record names the host its standby on the volume it names active; bit 0 of the second flags byte.
    /// Each of the four flags of that byte is `None` without a source, and its bit plus 4 marks it known.
    pub named: Option<bool>,
    /// The tenure stands at a bound that asks for a planned same-host restart; bit 1.
    pub roll_due: Option<bool>,
    /// A planned same-host restart runs; bit 2.
    pub roll_active: Option<bool>,
    /// The tenure's suffix asks for a checkpoint publication; bit 3.
    pub publication_due: Option<bool>,
    pub times: RecoveryTimes,
    /// The warm load's retention account, `None` until the load commits or ends `Unloadable`, `Collided` or
    /// `MetadataFailed` after its stage recorded the decoded load's account, and fixed for the tenure after; a load
    /// refused before its stage, awaiting its commit or stopped there reads `None`.
    pub retention: Option<Retention>,
    pub suffix: Backlog,
    pub recovery_io: RecoveryIo,
    /// Live attachments the volume record lists, of the attachments a volume admits.
    pub attaches: Gauge,
    pub store: StoreOutcomes,
    pub coverage: Coverage,
    /// Held INVALIDATEs awaiting their coverage write, of the hold bound.
    pub invalidations: Gauge,
    /// Reads of the tenure whose terminal outcome was a header or chunk mismatch, a key mismatch of the first extent
    /// excepted, which the owner answers missing.
    pub read_defects: Option<u64>,
    /// Reads of the tenure that completed.
    pub served: Option<u64>,
}

/// The last recovery attempt's status. `kind` is present whenever a field other than `attempts` is, and `check`,
/// `next` and `store` appear only with an outcome of `Refused` or `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recovery {
    pub kind: Option<RecoveryKind>,
    pub outcome: Option<RecoveryOutcome>,
    /// The check that refused the attempt.
    pub check: Option<RecoveryCheck>,
    pub next: Option<RecoveryNext>,
    /// The class of the store error the refusing check carries.
    pub store: Option<StoreClass>,
    /// Recovery attempts since the writer's boot.
    pub attempts: Option<u32>,
    /// The time since the attempt started, on the owner's turn clock, when the producer builds the entry.
    pub age_us: Option<u64>,
}

/// When the tenure's attach reached each recovery milestone, in microseconds on the owner's turn clock from the
/// attach's first tick. Each time is the turn-clock value of the owner's last turn when the recorder recorded the
/// milestone, so an observation between turns, a replay step or a close, carries the last turn's time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryTimes {
    /// The first observation at which the readiness word left `Detached` and `Loading`, whether the load completed,
    /// withheld or closed.
    pub loaded_us: Option<u64>,
    /// The observation at which the readiness word reached `Live`.
    pub live_us: Option<u64>,
    /// The observation after the first read that ended complete at `Live`.
    pub first_hit_us: Option<u64>,
    /// The `live_us` time of an attach that reached `Live` over restored bindings, absent when it restored none.
    pub retained_us: Option<u64>,
    /// The observation after the first payload write submitted at `Live`.
    pub fill_us: Option<u64>,
}

/// What a warm load kept and lost: the entry counts and the units by loss cause of the slot and its suffixes, with
/// the slot's first damage as a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    pub first_damage: Option<Damage>,
    /// Entries installed at the commit, and entries the conversion omitted.
    pub installed: u64,
    pub omitted: u64,
    /// Units the warm bootstrap's allocator holds restored.
    pub held_units: u64,
    /// Slot units that failed a check, and slot units the device could not read.
    pub failed_units: u32,
    pub unread_units: u32,
    /// Suffixes whose first hole is damage, and suffixes whose first hole ends their unflushed tail.
    pub suffix_damage: u32,
    pub suffix_tails: u32,
    /// Suffix inserts behind their suffix's first hole, and the replay's unread markers: the LSNs whose read failed,
    /// the region end of each suffix recorded longer than its region, and the first LSN a replay that refused its
    /// limits leaves unread.
    pub suffix_dropped: u64,
    pub suffix_unread: u64,
    /// Slot entries a suffix entry superseded, and slot entries withheld for an unadmitted session.
    pub slot_superseded: u64,
    pub slot_withheld: u64,
}

/// The tenure's suffix blocks that are not yet durable, the open block included, of the suffix queue's bound, and
/// the time since the first record appended to the oldest of them, on the suffix log's clock in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backlog {
    pub blocks: Gauge,
    pub flush_lag_us: Option<u64>,
}

/// The owner's recovery I/O share since the attach that built it: the most bytes charged in one share window, the
/// open window included, of the share's part plus its bucket capacity, saturating at `u64::MAX`, and the windows
/// that refused a charge, each counted once. A share window opens, on the owner's turn clock in microseconds, at the
/// first charge offered one share interval or more after the previous window opened. A recovery read or a
/// checkpoint-unit command the device turns away at its submit leaves the window's bytes. A suffix block counts
/// each time the suffix log hands it out for writing and stays counted when the device turns away or fails that
/// write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryIo {
    pub peak: Gauge,
    pub saturated: Option<u64>,
}

/// The tenure's final store results by error class: `unknown` the writes whose outcome is unknown, `unavailable`
/// the reads that returned no value, `refused` the writes the store reported not committed, and `log` the results
/// whose watermark log write failed. Each result after watermark settlement counts once, a batch counting each
/// element and the batch itself nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreOutcomes {
    pub unknown: Option<u64>,
    pub unavailable: Option<u64>,
    pub refused: Option<u64>,
    pub log: Option<u64>,
}

/// The shard's coverage pages as the tenure last knows them, from the values its acknowledged writes or its reads set:
/// the saturated pages of the page count, and the bytes of the largest page of the page capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Coverage {
    pub saturated: Gauge,
    pub largest: Gauge,
}

impl Recovery {
    pub const UNAVAILABLE: Self = Self {
        kind: None,
        outcome: None,
        check: None,
        next: None,
        store: None,
        attempts: None,
        age_us: None,
    };
}

impl RecoveryTimes {
    pub const UNAVAILABLE: Self = Self {
        loaded_us: None,
        live_us: None,
        first_hit_us: None,
        retained_us: None,
        fill_us: None,
    };
}

impl Backlog {
    pub const UNAVAILABLE: Self = Self {
        blocks: Gauge::Unavailable,
        flush_lag_us: None,
    };
}

impl RecoveryIo {
    pub const UNAVAILABLE: Self = Self {
        peak: Gauge::Unavailable,
        saturated: None,
    };
}

impl StoreOutcomes {
    pub const UNAVAILABLE: Self = Self {
        unknown: None,
        unavailable: None,
        refused: None,
        log: None,
    };
}

impl Coverage {
    pub const UNAVAILABLE: Self = Self {
        saturated: Gauge::Unavailable,
        largest: Gauge::Unavailable,
    };
}

impl Detector {
    pub const UNAVAILABLE: Self = Self {
        peers: Members::Unavailable,
        self_suspect_us: None,
        nominations: None,
    };
}

/// The first check a host report or a reconciler status failed. `status::StatusReader::accept` lists the status
/// conditions behind each variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportError {
    /// The length is outside the bounds, or differs from the entry count's layout.
    Length,
    Magic,
    /// A schema mismatch stops decoding at the schema field.
    Schema {
        found: u16,
    },
    /// A zero writer host or boot, or a host without a key.
    Writer,
    Tag,
    /// A flag or label byte outside its table, or nonzero bytes of an absent part.
    Flag,
    /// A present value that breaks its field's rule in the `unavailable` section of
    /// `failover/report/contract.json`, or two entries that name one volume.
    Field,
    /// The sequence is at or below the writer's accepted high-water, or [`BOOTS`] boots of the host are kept, the
    /// report's boot is not among them and its seal time is at or below the lowest kept seal time.
    Duplicate,
}

/// A failed report or status seal preserves the writer's state. `status::StatusWriter::seal` lists the status
/// conditions for each variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// The pacing clock is earlier than the writer's next due time.
    Early,
    /// More than [`MAX_ENTRIES`] entries in a report.
    Entries,
    /// The sequence has no successor, or the next due time does not fit.
    Exhausted,
    /// The decoder refuses the encoding with this error.
    Field(ReportError),
}

impl From<CodecError> for ReportError {
    fn from(error: CodecError) -> Self {
        match error {
            CodecError::Length => Self::Length,
            CodecError::Magic => Self::Magic,
            CodecError::Flag | CodecError::Version => Self::Flag,
            CodecError::Field | CodecError::Checksum => Self::Field,
        }
    }
}

impl From<Cause> for Withdrawal {
    fn from(cause: Cause) -> Self {
        match cause {
            Cause::Report(_) => Self::Report,
            Cause::RecordedHolder => Self::RecordedHolder,
            Cause::Unheld => Self::Unheld,
            Cause::Unverified => Self::Unverified,
            Cause::Status(Deposing::Conflict) => Self::Conflict,
            Cause::Status(Deposing::PreemptAborted) => Self::PreemptAborted,
            Cause::ForceDetach => Self::ForceDetach,
            Cause::Attachment => Self::Attachment,
            Cause::Modification => Self::Modification,
            Cause::RestartCheck => Self::RestartCheck,
            Cause::ActivationRecord => Self::ActivationRecord,
            Cause::Exhausted => Self::Exhausted,
            Cause::Planned => Self::Planned,
            Cause::Flipped => Self::Flipped,
            Cause::NewerFence { .. } => Self::NewerFence,
            Cause::LaterTenure => Self::LaterTenure,
            Cause::Regression => Self::Regression,
        }
    }
}

impl From<AuthorityRefusal> for Refusal {
    fn from(refusal: AuthorityRefusal) -> Self {
        match refusal {
            AuthorityRefusal::Admission(_) => Self::Admission,
            AuthorityRefusal::ReportMalformed => Self::ReportMalformed,
            AuthorityRefusal::ReportTimeout => Self::ReportTimeout,
            AuthorityRefusal::ForeignLower => Self::ForeignLower,
            AuthorityRefusal::ForeignEqual => Self::ForeignEqual,
            AuthorityRefusal::ForeignHigher => Self::ForeignHigher,
            AuthorityRefusal::Conflict => Self::Conflict,
            AuthorityRefusal::PreemptAborted => Self::PreemptAborted,
            AuthorityRefusal::OwnHostId => Self::OwnHostId,
            AuthorityRefusal::Clock => Self::Clock,
            AuthorityRefusal::Boundary => Self::Boundary,
        }
    }
}

impl From<NotSole> for Registrants {
    fn from(refusal: NotSole) -> Self {
        match refusal {
            NotSole::Excess => Self::Excess,
            NotSole::Unreadable => Self::Unreadable,
            NotSole::ReservationType => Self::ReservationType,
            NotSole::DuplicateOwnRecord => Self::DuplicateOwnRecord,
            NotSole::ForeignHolder => Self::ForeignHolder,
            NotSole::ForeignRegistrant => Self::ForeignRegistrant,
            NotSole::NotHolder => Self::NotHolder,
        }
    }
}

impl From<&MetadataOutcome> for Metadata {
    fn from(outcome: &MetadataOutcome) -> Self {
        match outcome {
            MetadataOutcome::Bootstrapping => Self::Bootstrapping,
            MetadataOutcome::Unformatted => Self::Unformatted,
            MetadataOutcome::Open => Self::Open,
            MetadataOutcome::SlotUnreadable { .. } => Self::SlotUnreadable,
            MetadataOutcome::Unsupported { .. } => Self::Unsupported,
            MetadataOutcome::FormatMismatch => Self::FormatMismatch,
            MetadataOutcome::TiedRoots => Self::TiedRoots,
            MetadataOutcome::StaleSession => Self::StaleSession,
            MetadataOutcome::Unfenced(_) => Self::Unfenced,
            MetadataOutcome::EntropyUnavailable => Self::EntropyUnavailable,
            MetadataOutcome::MetadataFailed => Self::MetadataFailed,
            MetadataOutcome::Collided => Self::Collided,
            MetadataOutcome::Unloadable(_) => Self::Unloadable,
        }
    }
}

impl From<&StoreError> for StoreClass {
    fn from(error: &StoreError) -> Self {
        match error {
            StoreError::Unavailable => Self::Unavailable,
            StoreError::Refused(_) => Self::Refused,
            StoreError::Unknown => Self::Unknown,
            StoreError::Absent => Self::Absent,
            StoreError::Codec(_) => Self::Codec,
            StoreError::Successor(_) => Self::Successor,
            StoreError::Flip(_) => Self::Flip,
            StoreError::Stale(_) => Self::Stale,
            StoreError::AttemptsExhausted => Self::AttemptsExhausted,
            StoreError::Regression(_) => Self::Regression,
            StoreError::Withdrawn => Self::Withdrawn,
            StoreError::Namespace => Self::Namespace,
            StoreError::Log => Self::Log,
        }
    }
}

impl Gauge {
    /// The gauge of `used` out of `limit`, or `Unavailable` when `limit` is zero or below `used`.
    pub fn known(used: u64, limit: u64) -> Self {
        match NonZeroU64::new(if used <= limit { limit } else { 0 }) {
            Some(limit) => Self::Known { used, limit },
            None => Self::Unavailable,
        }
    }
}

impl Headroom {
    /// Samples `ram` as `MemTotal - MemAvailable` bytes of `MemTotal` and `cpu_load` as the one-minute load average
    /// over the online CPUs, saturating at the CPU count, each `Unavailable` when its source does not parse, the
    /// load is not finite and nonnegative, or the online list is not ascending and disjoint, and takes the other
    /// five gauges from `inputs` ([`Headroom::of`]). The sources are procfs and sysfs files, so a caller samples off
    /// the owner thread.
    pub fn sample(inputs: &HeadroomInputs) -> Self {
        let read = |path| crate::bind::Host::read(Path::new(path));
        let cpu_load = read("/proc/loadavg")
            .zip(read("/sys/devices/system/cpu/online"))
            .map_or(Gauge::Unavailable, |(load, online)| {
                cpu_load(&load, &online)
            });
        let ram = read("/proc/meminfo").map_or(Gauge::Unavailable, |info| ram(&info));
        Self::of(ram, cpu_load, inputs)
    }
}

/// Bytes in use, `MemTotal - MemAvailable`, out of `MemTotal`.
fn ram(meminfo: &str) -> Gauge {
    let kib = |name: &str| {
        meminfo.lines().find_map(|line| {
            let value = line.strip_prefix(name)?.strip_prefix(':')?;
            value
                .trim()
                .strip_suffix("kB")?
                .trim()
                .parse::<u64>()
                .ok()?
                .checked_mul(1024)
        })
    };
    match (kib("MemTotal"), kib("MemAvailable")) {
        (Some(total), Some(available)) if available <= total => {
            Gauge::known(total - available, total)
        }
        _ => Gauge::Unavailable,
    }
}

/// The one-minute load average out of the online CPUs, both in hundredths; a load above the CPU count reads as
/// the full limit, and an online list that does not parse, or whose ranges overlap or descend, reads as
/// `Unavailable`.
fn cpu_load(loadavg: &str, online: &str) -> Gauge {
    let cpus = online
        .trim()
        .split(',')
        .try_fold((0u64, 0), |(count, next), range| {
            let (low, high) = range.split_once('-').unwrap_or((range, range));
            let (low, high) = (low.parse::<u64>().ok()?, high.parse::<u64>().ok()?);
            let count = count.checked_add(high.checked_sub(low)?.checked_add(1)?)?;
            (low >= next).then_some((count, high.checked_add(1)?))
        });
    let load = loadavg
        .split_whitespace()
        .next()
        .and_then(|load| load.parse::<f64>().ok());
    match (cpus.and_then(|(cpus, _)| cpus.checked_mul(100)), load) {
        (Some(limit), Some(load)) if load.is_finite() && load >= 0.0 => {
            Gauge::known(((load * 100.0).round() as u64).min(limit), limit)
        }
        _ => Gauge::Unavailable,
    }
}

impl BuildIdentity {
    /// The running build: [`records::ERA`] and the SHA-256 of `/proc/self/exe`. Each call reads the whole
    /// executable; callers should cache the result for the process lifetime.
    pub fn running() -> Self {
        let mut hash = Sha256::new();
        let read =
            crate::bind::Host::stream(Path::new("/proc/self/exe"), |chunk| hash.update(chunk));
        Self {
            era: records::ERA,
            digest: read.map(|()| hash.finalize().into()),
        }
    }
}

/// The exhaustive match guarantees that `$table` includes every variant of `$name`.
macro_rules! listed {
    ($table:ident, $name:ident, [$($variant:ident),+ $(,)?]) => {
        const $table: &[$name] = &[$($name::$variant),+];
        const _: fn($name) = |value| match value {
            $($name::$variant)|+ => {}
        };
    };
}

type ServingState = serving::State;

listed! {
    SERVING, ServingState, [PreBoundary, Recovering, Serving, Withdrawn, Closed]
}
const EXITS: &[ExitStatus] = &[
    ExitStatus::Received,
    ExitStatus::Draining,
    ExitStatus::Withdrawn,
    ExitStatus::Waiting,
    ExitStatus::Exited,
    ExitStatus::Resumed(Resume::Deadline),
    ExitStatus::Resumed(Resume::Cut),
    ExitStatus::Resumed(Resume::Standby),
    ExitStatus::Resumed(Resume::Store),
    ExitStatus::Restarting(Restart::Deadline),
    ExitStatus::Restarting(Restart::Refused(Stale::Target)),
    ExitStatus::Restarting(Restart::Refused(Stale::Volume)),
    ExitStatus::Restarting(Restart::Planned),
    ExitStatus::Restarting(Restart::TransferRefused),
    ExitStatus::Restarting(Restart::TransferUnknown),
];
/// The position of `status` in [`EXITS`]. The match names every status with no wildcard arm, so a new status, a
/// nested one included, compiles only once it has a position, and the assertion below holds each listed status at
/// its position.
const fn exit_at(status: ExitStatus) -> usize {
    match status {
        ExitStatus::Received => 0,
        ExitStatus::Draining => 1,
        ExitStatus::Withdrawn => 2,
        ExitStatus::Waiting => 3,
        ExitStatus::Exited => 4,
        ExitStatus::Resumed(Resume::Deadline) => 5,
        ExitStatus::Resumed(Resume::Cut) => 6,
        ExitStatus::Resumed(Resume::Standby) => 7,
        ExitStatus::Resumed(Resume::Store) => 8,
        ExitStatus::Restarting(Restart::Deadline) => 9,
        ExitStatus::Restarting(Restart::Refused(Stale::Target)) => 10,
        ExitStatus::Restarting(Restart::Refused(Stale::Volume)) => 11,
        ExitStatus::Restarting(Restart::Planned) => 12,
        ExitStatus::Restarting(Restart::TransferRefused) => 13,
        ExitStatus::Restarting(Restart::TransferUnknown) => 14,
    }
}

const _: () = {
    let mut at = 0;
    while at < EXITS.len() {
        assert!(
            exit_at(EXITS[at]) == at,
            "EXITS lists each status at its position"
        );
        at += 1;
    }
};

const READINESS: &[Readiness] = &Readiness::ALL_STATES;

listed! {
    LOAD_REFUSALS, LoadRefusal, [
        Limits, Memory, Bounds, Key, Slot, Overlap, Units, Entries, StaleWrite, Unreadable, Unrestorable,
    ]
}

/// The code of an optional label: 0 for `None`, else one past its position in `table`, or 255, which no table
/// reaches, for a value `table` lacks.
fn code<T: PartialEq>(table: &[T], value: Option<&T>) -> u8 {
    let at = value.map(|value| table.iter().position(|listed| listed == value));
    at.map_or(0, |at| at.map_or(u8::MAX, |at| at as u8 + 1))
}

/// Writes the fields of `N` bytes in wire order. Every method is inlined into its encoder, where each field's
/// offset is a constant.
struct Wire<'a, const N: usize> {
    bytes: &'a mut [u8; N],
    /// The offset of the next field.
    at: usize,
}

impl<const N: usize> Wire<'_, N> {
    #[inline(always)]
    fn put<const M: usize>(&mut self, bytes: [u8; M]) {
        self.bytes[self.at..self.at + M].copy_from_slice(&bytes);
        self.at += M;
    }

    #[inline(always)]
    fn u8(&mut self, value: u8) {
        self.put([value]);
    }

    #[inline(always)]
    fn u32(&mut self, value: u32) {
        self.put(value.to_be_bytes());
    }

    #[inline(always)]
    fn u64(&mut self, value: u64) {
        self.put(value.to_be_bytes());
    }

    /// The code byte of an optional label, as [`code`] gives it.
    #[inline(always)]
    fn label<T: PartialEq>(&mut self, table: &[T], value: Option<T>) {
        self.u8(code(table, value.as_ref()));
    }

    /// A flag byte and `value`, or zero bytes for `None`.
    #[inline(always)]
    fn count(&mut self, value: Option<u64>) {
        self.u8(u8::from(value.is_some()));
        self.u64(value.unwrap_or(0));
    }

    /// A flag byte and `value`, or zero bytes for `None`.
    #[inline(always)]
    fn count32(&mut self, value: Option<u32>) {
        self.u8(u8::from(value.is_some()));
        self.u32(value.unwrap_or(0));
    }

    /// A flag byte, `used` and `limit`, or zero bytes for an unavailable gauge.
    #[inline(always)]
    fn gauge(&mut self, gauge: Gauge) {
        let (flag, used, limit) = match gauge {
            Gauge::Unavailable => (0, 0, 0),
            Gauge::Known { used, limit } => (1, used, limit.get()),
        };
        self.u8(flag);
        self.u64(used);
        self.u64(limit);
    }

    /// A flag byte, `used` and `limit`, or zero bytes for an unavailable count.
    #[inline(always)]
    fn members(&mut self, members: Members) {
        let (flag, used, limit) = match members {
            Members::Unavailable => (0, 0, 0),
            Members::Known { used, limit } => (1, used, limit),
        };
        self.u8(flag);
        self.u64(used);
        self.u64(limit);
    }
}

/// The entry count in the header of `bytes`, which hold that many entries and `trailer` more bytes.
fn layout(bytes: &[u8], trailer: usize) -> Result<usize, ReportError> {
    let count = usize::from(*bytes.get(HEADER_LEN - 2).ok_or(ReportError::Length)?);
    (count <= MAX_ENTRIES && bytes.len() == report_len(count) - TAG_LEN + trailer)
        .then_some(count)
        .ok_or(ReportError::Length)
}

impl VolumeEntry {
    /// The entry's fixed encoding in a schema-[`SCHEMA`] report, returned only when [`VolumeEntry::decode`] accepts
    /// it. The bytes carry no schema, so a sender that carries an entry outside a report names `SCHEMA` beside it.
    ///
    /// # Errors
    ///
    /// [`ReportError::Field`] or [`ReportError::Flag`], the error [`VolumeEntry::decode`] returns for the bytes.
    pub fn encode(&self) -> Result<[u8; ENTRY_LEN], ReportError> {
        let bytes = entry_bytes(self);
        Self::decode(&bytes).map(|_| bytes)
    }

    /// Decodes one entry of a schema-[`SCHEMA`] report; it accepts every encoding [`VolumeEntry::encode`] returns.
    /// The bytes carry no schema: inside a report its header names it, and a receiver of an entry in another message
    /// decodes it only when that message's version selects this `SCHEMA`.
    ///
    /// # Errors
    ///
    /// [`ReportError::Field`] or [`ReportError::Flag`] for the first failing check in wire order, as
    /// [`Reader::accept`] reports it for an entry of a report.
    #[inline(always)]
    pub fn decode(bytes: &[u8; ENTRY_LEN]) -> Result<Self, ReportError> {
        let mut entry = take_identity(bytes)?;
        take_fields(bytes, &mut entry)?;
        Ok(entry)
    }
}

/// The bytes of entry `e`.
fn entry_bytes(e: &VolumeEntry) -> [u8; ENTRY_LEN] {
    let mut out = [0; ENTRY_LEN];
    put_entry(e, &mut out);
    out
}

/// Writes the bytes of entry `e` over `out`, every byte of it.
#[inline(always)]
fn put_entry(e: &VolumeEntry, out: &mut [u8; ENTRY_LEN]) {
    let mut w = Wire { bytes: out, at: 0 };
    w.put(e.volume.field());
    w.u32(e.shard.get());
    w.label(ROLES, e.role);
    let (g, a) = e.tenure.map_or((0, 0), |(g, a)| (g.get() as u32, a.get()));
    w.u32(g);
    w.u32(a);
    w.label(&STATES, e.volume_state);
    w.label(SERVING, e.serving);
    w.u8(u8::from(e.withheld) | u8::from(e.quarantine) << 1 | u8::from(e.flip) << 2);
    w.label(WITHDRAWALS, e.withdrawal);
    w.label(REFUSALS, e.refusal);
    w.u8(index(ENUMERATIONS, &e.enumeration));
    w.u8(index(WATERMARKS, &e.watermark));
    w.count(e.report_age_us);
    w.count32(e.own_records);
    let ck = e.checkpoint.unwrap_or_default();
    w.u8(u8::from(e.checkpoint.is_some()));
    w.u32(ck.slot);
    w.u64(ck.session);
    w.u32(ck.capture);
    w.u32(ck.units);
    w.count(e.checkpoint_age_us);
    w.count(e.captures.refused);
    w.count(e.captures.abandoned);
    w.label(EXITS, e.exit.map(|exit| exit.status));
    w.put(e.exit.map_or([0; 16], |exit| exit.operation.bytes()));
    let p = e.pressure;
    for gauge in [p.frontier, p.ancestry, p.quarantine, p.full] {
        w.gauge(gauge);
    }
    let r = e.recovery;
    w.label(REGISTRANTS, e.registrants);
    w.label(HOLDS, e.hold);
    w.label(READINESS, e.readiness);
    w.label(METADATA, e.metadata);
    w.label(LOAD_REFUSALS, e.load_refusal);
    w.label(KINDS, r.kind);
    w.label(OUTCOMES, r.outcome);
    w.label(CHECKS, r.check);
    w.label(NEXTS, r.next);
    w.label(STORE_CLASSES, r.store);
    w.label(PHASES, e.phase);
    w.label(ENDINGS, e.ended);
    w.u8(known_flags([
        e.named,
        e.roll_due,
        e.roll_active,
        e.publication_due,
    ]));
    w.count32(r.attempts);
    w.count(r.age_us);
    let t = e.times;
    for time in [
        t.loaded_us,
        t.live_us,
        t.first_hit_us,
        t.retained_us,
        t.fill_us,
    ] {
        w.count(time);
    }
    w.put(retention_bytes(e.retention.as_ref()));
    w.gauge(e.suffix.blocks);
    w.count(e.suffix.flush_lag_us);
    w.gauge(e.recovery_io.peak);
    w.count(e.recovery_io.saturated);
    w.gauge(e.attaches);
    let s = e.store;
    for count in [s.unknown, s.unavailable, s.refused, s.log] {
        w.count(count);
    }
    for gauge in [e.coverage.saturated, e.coverage.largest, e.invalidations] {
        w.gauge(gauge);
    }
    w.count(e.read_defects);
    w.count(e.served);
    debug_assert!(w.at == ENTRY_LEN, "the fields cover the entry");
}

/// For `Some(value)` at index `i`, bit `i` stores `value` and bit `i + 4` marks the flag as known. `None` encodes both
/// bits as zero.
fn known_flags(flags: [Option<bool>; 4]) -> u8 {
    let bit = |(at, flag): (usize, Option<bool>)| {
        flag.map_or(0, |value| 1 << (at + 4) | u8::from(value) << at)
    };
    flags
        .into_iter()
        .enumerate()
        .map(bit)
        .fold(0, |byte, bit| byte | bit)
}

/// `Some(r)` starts with byte `1`, followed by the `first_damage` code and the big-endian counts; `None` is
/// [`RETENTION`] zero bytes.
#[inline(always)]
fn retention_bytes(retention: Option<&Retention>) -> [u8; RETENTION] {
    let mut out = [0; RETENTION];
    let Some(r) = retention else {
        return out;
    };
    let mut w = Wire {
        bytes: &mut out,
        at: 0,
    };
    w.u8(1);
    w.label(DAMAGES, r.first_damage);
    for count in [r.installed, r.omitted, r.held_units] {
        w.u64(count);
    }
    for count in [
        r.failed_units,
        r.unread_units,
        r.suffix_damage,
        r.suffix_tails,
    ] {
        w.u32(count);
    }
    for count in [
        r.suffix_dropped,
        r.suffix_unread,
        r.slot_superseded,
        r.slot_withheld,
    ] {
        w.u64(count);
    }
    debug_assert!(w.at == RETENTION, "the fields cover the account");
    out
}

/// `Err(ReportError::Flag)` unless `valid`.
#[inline(always)]
fn flag(valid: bool) -> Result<(), ReportError> {
    if valid {
        Ok(())
    } else {
        Err(ReportError::Flag)
    }
}

/// `Err(ReportError::Field)` unless `valid`.
#[inline(always)]
fn field(valid: bool) -> Result<(), ReportError> {
    if valid {
        Ok(())
    } else {
        Err(ReportError::Field)
    }
}

/// `value` after its flag byte `present`, `None` for a clear flag. A flag other than 0 and 1, or a clear flag with a
/// nonzero value, refuses.
#[inline(always)]
fn flagged<T: Default + PartialEq>(present: u8, value: T) -> Result<Option<T>, ReportError> {
    flag((present == 1) | ((present == 0) & (value == T::default())))?;
    Ok((present == 1).then_some(value))
}

/// What a decoder does with the entries of a body.
trait Entries {
    /// Decodes the entry `bytes`.
    ///
    /// # Errors
    ///
    /// The entry's first failing check in wire order.
    fn take(&mut self, bytes: &[u8; ENTRY_LEN]) -> Result<(), ReportError>;
}

/// Keeps every entry, in order. An entry whose fields refuse stays, partly decoded, as the last one.
impl Entries for Vec<VolumeEntry> {
    #[inline(always)]
    fn take(&mut self, bytes: &[u8; ENTRY_LEN]) -> Result<(), ReportError> {
        let at = self.len();
        self.push(take_identity(bytes)?);
        take_fields(bytes, &mut self[at])
    }
}

/// Checks each entry and keeps none: a writer's check of the body it encoded.
struct Discard;

impl Entries for Discard {
    #[inline(always)]
    fn take(&mut self, bytes: &[u8; ENTRY_LEN]) -> Result<(), ReportError> {
        VolumeEntry::decode(bytes).map(drop)
    }
}

/// Decodes a body that [`Reader::accept`] authenticated.
///
/// # Errors
///
/// The first failing check in layout order.
fn decode_body(body: &[u8]) -> Result<HostReport, ReportError> {
    let mut entries = Vec::with_capacity(MAX_ENTRIES.min(body.len() / ENTRY_LEN));
    let report = decode(body, &mut entries)?;
    Ok(HostReport { entries, ..report })
}

/// The bytes of a body between its writer and its first entry: the sequence, the seal time, the entry count, the
/// zero byte and the host part.
const SEALED_LEN: usize = HEADER_LEN + HOST_LEN - WRITER_END;
/// The end of the writer in a body: the magic, the schema, the host and the boot.
const WRITER_END: usize = 4 + 2 + 8 + 16;

/// Decodes a body, passing each entry to `entries` in order; the report it returns holds no entries.
///
/// # Errors
///
/// The first failing check in layout order.
fn decode(body: &[u8], entries: &mut impl Entries) -> Result<HostReport, ReportError> {
    layout(body, 0)?;
    let mut r = Bytes::open(body, MAGIC, SCHEMA)?;
    let writer = take_writer(&mut r)?;
    // The layout check fixed the bytes after the writer at the rest of the header, the host part and the header's
    // entry count of entries.
    let (sealed, rest) =
        r.0.split_first_chunk::<SEALED_LEN>()
            .ok_or(ReportError::Length)?;
    let report = take_host(writer, sealed)?;
    take_entries(rest.as_chunks().0, entries)?;
    Ok(report)
}

/// The report of `writer` whose sequence, seal time and host part are in `sealed`, with no entries.
///
/// # Errors
///
/// The first failing check in layout order.
fn take_host(writer: WriterId, sealed: &[u8; SEALED_LEN]) -> Result<HostReport, ReportError> {
    let mut f = Fields {
        bytes: sealed,
        at: 0,
    };
    let sequence = f.u64();
    field(sequence >= 1)?;
    let sealed_at_us = f.u64();
    let [_, zero] = f.bytes();
    flag(zero == 0)?;
    let build = BuildIdentity {
        era: f.u32(),
        digest: flagged(f.u8(), f.bytes())?,
    };
    let headroom = Headroom {
        ram: f.gauge()?,
        cpu_load: f.gauge()?,
        iops: f.gauge()?,
        bandwidth: f.gauge()?,
        attachments: f.gauge()?,
        workers: f.gauge()?,
        recovery: f.gauge()?,
    };
    let health = f.label(HEALTH)?;
    let detector = Detector {
        peers: f.members()?,
        self_suspect_us: f.count()?,
        nominations: f.count()?,
    };
    let producer_missing = f.members()?;
    let recovery_io = f.gauge()?;
    debug_assert!(f.at == SEALED_LEN, "the fields cover the host part");
    Ok(HostReport {
        writer,
        sequence,
        sealed_at_us,
        host: HostState {
            build,
            headroom,
            health,
            detector,
            producer_missing,
            recovery_io,
        },
        entries: Vec::new(),
    })
}

/// Decodes the entries `chunks` of one body in order, passing each to `entries`. The loop is its own function, so
/// its registers hold one entry's fields and none of the host part.
///
/// # Errors
///
/// The first failing check in layout order; an entry that names the volume of an earlier one refuses after its own
/// fields.
#[inline(never)]
fn take_entries(chunks: &[[u8; ENTRY_LEN]], entries: &mut impl Entries) -> Result<(), ReportError> {
    let mut slots = [0; 8 * MAX_ENTRIES];
    for at in 0..chunks.len() {
        entries.take(&chunks[at])?;
        if !first_volume(&mut slots, chunks, at) {
            return Err(ReportError::Field);
        }
    }
    Ok(())
}

/// Records the volume field of `entries[at]` in `slots`, or returns false when an earlier entry holds the same
/// field. `slots` is an open-addressing table of the fields of every entry before `at`, each slot 0 or one past the
/// position of the entry stored there; `at` is below [`MAX_ENTRIES`], so at most an eighth of the slots fill and a
/// probe sequence always reaches an empty slot. A decoded volume field is canonical, so two entries name one volume
/// exactly when their fields are equal.
#[inline(always)]
fn first_volume(slots: &mut [u8; 8 * MAX_ENTRIES], entries: &[[u8; ENTRY_LEN]], at: usize) -> bool {
    let field = &entries[at][..VOLUME];
    let word = |from: usize| u64::from_le_bytes(field_at(field, from));
    let mixed = (word(0) ^ word(7).rotate_left(21) ^ word(VOLUME - 8).rotate_left(42))
        .wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut slot = (mixed >> 54) as usize;
    while let Some(seen) = usize::from(slots[slot]).checked_sub(1) {
        if entries[seen][..VOLUME] == *field {
            return false;
        }
        slot = (slot + 1) % slots.len();
    }
    slots[slot] = at as u8 + 1;
    true
}

/// The writer after the schema: a nonzero host and a nonzero boot.
fn take_writer(r: &mut Bytes<'_>) -> Result<WriterId, ReportError> {
    let (host, boot) = (Host::new(r.u64()?), r.take()?);
    host.filter(|_| boot != [0; 16])
        .map(|host| WriterId { host, boot })
        .ok_or(ReportError::Writer)
}

/// The `N` bytes of `bytes` from `at`.
#[inline(always)]
pub(crate) fn field_at<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    let mut field = [0; N];
    field.copy_from_slice(&bytes[at..at + N]);
    field
}

#[inline(always)]
pub(crate) fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(field_at(bytes, at))
}

#[inline(always)]
pub(crate) fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(field_at(bytes, at))
}

/// Writes `bytes` over `out` from `at`.
#[inline(always)]
pub(crate) fn put(out: &mut [u8], at: usize, bytes: &[u8]) {
    out[at..at + bytes.len()].copy_from_slice(bytes);
}

/// Reads the fields of `N` bytes in wire order and refuses at a field's first failing check. Every method is
/// inlined into its decoder, where each field's offset is a constant.
struct Fields<'a, const N: usize> {
    bytes: &'a [u8; N],
    /// The offset of the next field.
    at: usize,
}

impl<const N: usize> Fields<'_, N> {
    /// The offset of the next field, `len` bytes long.
    #[inline(always)]
    fn next(&mut self, len: usize) -> usize {
        let at = self.at;
        self.at += len;
        at
    }

    #[inline(always)]
    fn u8(&mut self) -> u8 {
        self.bytes[self.next(1)]
    }

    #[inline(always)]
    fn u32(&mut self) -> u32 {
        u32_at(self.bytes, self.next(4))
    }

    #[inline(always)]
    fn u64(&mut self) -> u64 {
        u64_at(self.bytes, self.next(8))
    }

    #[inline(always)]
    fn bytes<const M: usize>(&mut self) -> [u8; M] {
        field_at(self.bytes, self.next(M))
    }

    /// The optional label of a code byte: `None` for 0, else the value one before the code in `table`. A code past
    /// the table refuses.
    #[inline(always)]
    fn label<T: Copy>(&mut self, table: &[T]) -> Result<Option<T>, ReportError> {
        let at = usize::from(self.u8());
        flag(at <= table.len())?;
        Ok(at.checked_sub(1).map(|at| table[at]))
    }

    /// The label of a code byte of a table without an absent code. A code past the table refuses.
    #[inline(always)]
    fn pick<T: Copy>(&mut self, table: &[T]) -> Result<T, ReportError> {
        let at = usize::from(self.u8());
        flag(at < table.len())?;
        Ok(table[at])
    }

    /// A flag byte and a 64-bit value, as [`flagged`] reads them.
    #[inline(always)]
    fn count(&mut self) -> Result<Option<u64>, ReportError> {
        flagged(self.u8(), self.u64())
    }

    /// A gauge: a flag byte, `used` and `limit`. A flag other than 0 and 1, or a clear flag with a nonzero value,
    /// refuses as a flag, and a set flag refuses as a field when `used` exceeds `limit` or `limit` is zero.
    #[inline(always)]
    fn gauge(&mut self) -> Result<Gauge, ReportError> {
        let (flag_byte, used, limit) = (self.u8(), self.u64(), self.u64());
        let present = flag_byte == 1;
        flag(present | ((flag_byte == 0) & ((used | limit) == 0)))?;
        let gauge = Gauge::known(used, if present { limit } else { 0 });
        field(!present | (gauge != Gauge::Unavailable))?;
        Ok(gauge)
    }

    /// A member count: a flag byte, `used` and `limit`. A flag other than 0 and 1, or a clear flag with a nonzero
    /// value, refuses as a flag, and a set flag refuses as a field when `used` exceeds `limit`.
    #[inline(always)]
    fn members(&mut self) -> Result<Members, ReportError> {
        let (flag_byte, used, limit) = (self.u8(), self.u64(), self.u64());
        let present = flag_byte == 1;
        flag(present | ((flag_byte == 0) & ((used | limit) == 0)))?;
        field(!present | (used <= limit))?;
        Ok(match present {
            true => Members::Known { used, limit },
            false => Members::Unavailable,
        })
    }
}

/// The entry that `e` names by its volume and shard, with every other field absent or unavailable until
/// [`take_fields`] decodes it.
#[inline(always)]
fn take_identity(e: &[u8; ENTRY_LEN]) -> Result<VolumeEntry, ReportError> {
    let field = e
        .first_chunk()
        .expect("an entry begins with its volume field");
    let volume = VolumeId::from_field(field).ok_or(ReportError::Field)?;
    let shard = Shard::new(u32_at(e, VOLUME)).ok_or(ReportError::Field)?;
    Ok(VolumeEntry {
        volume,
        shard,
        role: None,
        tenure: None,
        volume_state: None,
        serving: None,
        withheld: false,
        quarantine: false,
        flip: false,
        withdrawal: None,
        refusal: None,
        enumeration: Enumeration::Unavailable,
        watermark: Watermark::Unavailable,
        report_age_us: None,
        own_records: None,
        checkpoint: None,
        checkpoint_age_us: None,
        captures: Captures {
            refused: None,
            abandoned: None,
        },
        exit: None,
        pressure: Pressure {
            frontier: Gauge::Unavailable,
            ancestry: Gauge::Unavailable,
            quarantine: Gauge::Unavailable,
            full: Gauge::Unavailable,
        },
        registrants: None,
        hold: None,
        readiness: None,
        metadata: None,
        load_refusal: None,
        recovery: Recovery::UNAVAILABLE,
        phase: None,
        ended: None,
        named: None,
        roll_due: None,
        roll_active: None,
        publication_due: None,
        times: RecoveryTimes::UNAVAILABLE,
        retention: None,
        suffix: Backlog::UNAVAILABLE,
        recovery_io: RecoveryIo::UNAVAILABLE,
        attaches: Gauge::Unavailable,
        store: StoreOutcomes::UNAVAILABLE,
        coverage: Coverage::UNAVAILABLE,
        invalidations: Gauge::Unavailable,
        read_defects: None,
        served: None,
    })
}

/// Decodes the fields of the entry `e` after its volume and shard into `out`, checking them in wire order. Each
/// field is written into `out` once its bytes are read, the recovery status once its last part is, and a refusal
/// returns at the first failing check, which leaves the fields after it as they were.
#[inline(always)]
fn take_fields(e: &[u8; ENTRY_LEN], out: &mut VolumeEntry) -> Result<(), ReportError> {
    let mut f = Fields {
        bytes: e,
        at: VOLUME + 4,
    };
    out.role = f.label(ROLES)?;
    let (g, a) = (f.u32(), f.u32());
    let tenure = ShardGeneration::new(g.into()).zip(ActivatedEpoch::new(a));
    out.tenure = tenure;
    field(tenure.is_some() | ((g, a) == (0, 0)))?;
    out.volume_state = f.label(&STATES)?;
    let serving = f.label(SERVING)?;
    out.serving = serving;
    let flags = f.u8();
    flag((flags >> 3 == 0) & (serving.is_some() | (flags == 0)))?;
    out.withheld = flags & 1 != 0;
    out.quarantine = flags & 2 != 0;
    out.flip = flags & 4 != 0;
    out.withdrawal = f.label(WITHDRAWALS)?;
    out.refusal = f.label(REFUSALS)?;
    out.enumeration = f.pick(ENUMERATIONS)?;
    out.watermark = f.pick(WATERMARKS)?;
    out.report_age_us = f.count()?;
    out.own_records = flagged(f.u8(), f.u32())?;
    let present = f.u8();
    let listed = NamedCheckpoint {
        slot: f.u32(),
        session: f.u64(),
        capture: f.u32(),
        units: f.u32(),
    };
    let checkpoint = flagged(present, listed)?;
    out.checkpoint = checkpoint;
    let age = f.count()?;
    out.checkpoint_age_us = age;
    field(checkpoint.is_some() | age.is_none())?;
    out.captures = Captures {
        refused: f.count()?,
        abandoned: f.count()?,
    };
    let status = f.label(EXITS)?;
    let operation: [u8; 16] = f.bytes();
    flag(status.is_some() | (operation == [0; 16]))?;
    let exit = status
        .zip(ExitOperation::new(operation))
        .map(|(status, operation)| Exit { operation, status });
    out.exit = exit;
    field(status.is_none() | exit.is_some())?;
    let pressure = Pressure {
        frontier: f.gauge()?,
        ancestry: f.gauge()?,
        quarantine: f.gauge()?,
        full: f.gauge()?,
    };
    out.pressure = pressure;
    field(match pressure.full {
        Gauge::Known { limit, .. } => limit.get() == HISTORY_RESOURCES,
        Gauge::Unavailable => true,
    })?;
    out.registrants = f.label(REGISTRANTS)?;
    out.hold = f.label(HOLDS)?;
    out.readiness = f.label(READINESS)?;
    out.metadata = f.label(METADATA)?;
    out.load_refusal = f.label(LOAD_REFUSALS)?;
    let kind = f.label(KINDS)?;
    let outcome = f.label(OUTCOMES)?;
    let check = f.label(CHECKS)?;
    let next = f.label(NEXTS)?;
    let store = f.label(STORE_CLASSES)?;
    let refusing = matches!(outcome, None | Some(RecoveryOutcome::Refused));
    field(refusing | ((check, next, store) == (None, None, None)))?;
    field(store.is_none() | check.is_some())?;
    out.phase = f.label(PHASES)?;
    out.ended = f.label(ENDINGS)?;
    let more = f.u8();
    let (values, known) = (more & 0x0F, more >> 4);
    flag(values & !known == 0)?;
    let known_flag = |bit: u8| (known >> bit & 1 == 1).then_some(values >> bit & 1 == 1);
    out.named = known_flag(0);
    out.roll_due = known_flag(1);
    out.roll_active = known_flag(2);
    out.publication_due = known_flag(3);
    let attempts = flagged(f.u8(), f.u32())?;
    let age_us = f.count()?;
    let unlabelled = (outcome, check, next, store) == (None, None, None, None);
    field(kind.is_some() | (unlabelled & age_us.is_none()))?;
    out.recovery = Recovery {
        kind,
        outcome,
        check,
        next,
        store,
        attempts,
        age_us,
    };
    let times = RecoveryTimes {
        loaded_us: f.count()?,
        live_us: f.count()?,
        first_hit_us: f.count()?,
        retained_us: f.count()?,
        fill_us: f.count()?,
    };
    let ordered =
        |early: Option<u64>, later: Option<u64>| early.zip(later).is_none_or(|(a, b)| a <= b);
    out.times = times;
    let live = times.live_us.or(times.retained_us);
    field(
        ordered(times.loaded_us, live)
            & ordered(live, times.first_hit_us)
            & ordered(live, times.fill_us)
            & (times.live_us.zip(times.retained_us))
                .is_none_or(|(live, retained)| live == retained),
    )?;
    out.retention = take_retention(&f.bytes())?;
    let suffix = Backlog {
        blocks: f.gauge()?,
        flush_lag_us: f.count()?,
    };
    let empty = matches!(suffix.blocks, Gauge::Known { used: 0, .. });
    out.suffix = suffix;
    field(!empty | suffix.flush_lag_us.is_none_or(|lag| lag == 0))?;
    out.recovery_io = RecoveryIo {
        peak: f.gauge()?,
        saturated: f.count()?,
    };
    out.attaches = f.gauge()?;
    out.store = StoreOutcomes {
        unknown: f.count()?,
        unavailable: f.count()?,
        refused: f.count()?,
        log: f.count()?,
    };
    out.coverage = Coverage {
        saturated: f.gauge()?,
        largest: f.gauge()?,
    };
    out.invalidations = f.gauge()?;
    out.read_defects = f.count()?;
    out.served = f.count()?;
    debug_assert!(f.at == ENTRY_LEN, "the fields cover the entry");
    Ok(())
}

/// The retention account in `bytes`. An absent account uses the all-zero encoding. A present account's first damage
/// matches its unit counts: no damage with no failed or unread unit, `Unread` with unread units and no failed one,
/// `Header`, `Chunk` and `Units` with a failed unit, and `Content` with any counts.
#[inline(always)]
fn take_retention(bytes: &[u8; RETENTION]) -> Result<Option<Retention>, ReportError> {
    let mut f = Fields { bytes, at: 0 };
    let present = f.u8();
    flag(present == 1 || (present == 0 && bytes[1..] == [0; RETENTION - 1]))?;
    let first_damage = f.label(DAMAGES)?;
    let (installed, omitted, held_units) = (f.u64(), f.u64(), f.u64());
    let (failed_units, unread_units) = (f.u32(), f.u32());
    field(match first_damage {
        None => (failed_units | unread_units) == 0,
        Some(Damage::Content) => true,
        Some(Damage::Unread) => (failed_units == 0) & (unread_units != 0),
        Some(Damage::Header | Damage::Chunk | Damage::Units) => failed_units != 0,
    })?;
    let retention = Retention {
        first_damage,
        installed,
        omitted,
        held_units,
        failed_units,
        unread_units,
        suffix_damage: f.u32(),
        suffix_tails: f.u32(),
        suffix_dropped: f.u64(),
        suffix_unread: f.u64(),
        slot_superseded: f.u64(),
        slot_withheld: f.u64(),
    };
    debug_assert!(f.at == RETENTION, "the fields cover the account");
    Ok((present == 1).then_some(retention))
}

/// The sequence and pacing of one writer's sealed records, and the header and tag they share: a magic, a schema, the
/// writer host and boot, the sequence, the seal time, a part count and a zero byte, then the body, then the tag over
/// a 16-byte domain label and every byte before it (WRITER-SEQUENCE).
#[derive(Debug)]
pub(crate) struct Envelope {
    id: WriterId,
    period_us: NonZeroU64,
    next: u64,
    next_due: u64,
    /// The highest seal time stamped so far.
    sealed_at_us: u64,
}

/// The header values of the record an [`Envelope`] seals next, and the state it advances to after the seal.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Slot {
    sequence: u64,
    sealed_at_us: u64,
    next_due: u64,
}

impl Envelope {
    /// An envelope for `id` that seals its first record with sequence 1.
    pub(crate) fn new(id: WriterId, period_us: NonZeroU64) -> Self {
        Self {
            id,
            period_us,
            next: 1,
            next_due: 0,
            sealed_at_us: 0,
        }
    }

    /// The slot of the next record, sealed at `sealed_at_us` on the wall clock and `elapsed_us` on the pacing clock,
    /// when the record `fits` its writer's bounds; the stamp is the higher of `sealed_at_us` and the previous stamp.
    ///
    /// # Errors
    ///
    /// `slot` checks the pacing deadline ([`SealError::Early`]), then `fits` ([`SealError::Entries`]), then
    /// sequence and deadline overflow ([`SealError::Exhausted`]).
    pub(crate) fn slot(
        &self,
        fits: bool,
        sealed_at_us: u64,
        elapsed_us: u64,
    ) -> Result<Slot, SealError> {
        if elapsed_us < self.next_due {
            return Err(SealError::Early);
        }
        if !fits {
            return Err(SealError::Entries);
        }
        self.next.checked_add(1).ok_or(SealError::Exhausted)?;
        let next_due = elapsed_us
            .checked_add(self.period_us.get())
            .ok_or(SealError::Exhausted)?;
        Ok(Slot {
            sequence: self.next,
            sealed_at_us: sealed_at_us.max(self.sealed_at_us),
            next_due,
        })
    }

    /// The [`HEADER_LEN`] header bytes of the record in `slot` under `magic` and `schema`, with `parts` parts.
    pub(crate) fn header(
        &self,
        magic: &[u8; 4],
        schema: u16,
        slot: Slot,
        parts: usize,
    ) -> [u8; HEADER_LEN] {
        let mut header = [0; HEADER_LEN];
        let mut w = Wire {
            bytes: &mut header,
            at: 0,
        };
        w.put(*magic);
        w.put(schema.to_be_bytes());
        w.u64(self.id.host.get());
        w.put(self.id.boot);
        w.u64(slot.sequence);
        w.u64(slot.sealed_at_us);
        w.put([parts as u8, 0]);
        debug_assert!(w.at == HEADER_LEN, "the fields cover the header");
        header
    }

    /// Appends the tag under `key` and `domain` to `body`, the record of `slot`, and advances the sequence, the next
    /// due time and the stamp. The caller checks the body with its decoder first, so a refused body advances nothing.
    pub(crate) fn close(
        &mut self,
        key: &[u8; 32],
        domain: &[u8; 16],
        mut body: Vec<u8>,
        slot: Slot,
    ) -> Vec<u8> {
        let tag = sha256::tag(key, domain, &body);
        body.extend_from_slice(&tag);
        self.next = slot.sequence + 1;
        self.next_due = slot.next_due;
        self.sealed_at_us = slot.sealed_at_us;
        body
    }
}

/// Seals one host's reports under its report key, at most one per period, with sequences from 1.
pub struct Writer {
    key: ReportKey,
    envelope: Envelope,
}

impl core::fmt::Debug for Writer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Writer")
            .field("envelope", &self.envelope)
            .finish_non_exhaustive()
    }
}

impl Writer {
    /// A writer for `host` under the report key derived from `host_key` and a boot nonce drawn from the operating
    /// system.
    ///
    /// # Errors
    ///
    /// The draw's error.
    pub fn new(
        host: Host,
        host_key: &[u8; 32],
        period_us: NonZeroU64,
    ) -> Result<Self, EntropyError> {
        let boot = nonce_from(os_entropy)?;
        Ok(Self {
            key: ReportKey::derive(host_key),
            envelope: Envelope::new(WriterId { host, boot }, period_us),
        })
    }

    pub fn due_at(&self) -> u64 {
        self.envelope.next_due
    }

    /// The body of this writer's report of `host` and `entries` in `slot`: every byte before the tag, in a buffer
    /// with room for the tag.
    fn encode(&self, host: &HostState, entries: &[VolumeEntry], slot: Slot) -> Vec<u8> {
        let len = report_len(entries.len());
        let mut out = Vec::with_capacity(len);
        out.extend_from_slice(&self.envelope.header(MAGIC, SCHEMA, slot, entries.len()));
        out.resize(len - TAG_LEN, 0);
        let (head, rest) = out
            .split_first_chunk_mut::<{ HEADER_LEN + HOST_LEN }>()
            .expect("a body holds its header and host part");
        let mut w = Wire {
            bytes: head,
            at: HEADER_LEN,
        };
        w.u32(host.build.era);
        w.u8(u8::from(host.build.digest.is_some()));
        w.put(host.build.digest.unwrap_or([0; 32]));
        let h = host.headroom;
        for gauge in [
            h.ram,
            h.cpu_load,
            h.iops,
            h.bandwidth,
            h.attachments,
            h.workers,
            h.recovery,
        ] {
            w.gauge(gauge);
        }
        let d = host.detector;
        w.label(HEALTH, host.health);
        w.members(d.peers);
        w.count(d.self_suspect_us);
        w.count(d.nominations);
        w.members(host.producer_missing);
        w.gauge(host.recovery_io);
        debug_assert!(
            w.at == HEADER_LEN + HOST_LEN,
            "the fields cover the host part"
        );
        // The buffer holds one entry's bytes for each entry after the host part.
        for (bytes, entry) in rest.as_chunks_mut().0.iter_mut().zip(entries) {
            put_entry(entry, bytes);
        }
        out
    }

    /// Seals the next report of `host` and `entries`, then advances the sequence and the next due time.
    /// `sealed_at_us` is wall-clock microseconds since the Unix epoch and only stamps the report; the stamp is the
    /// higher of it and the previous stamp, so a boot's stamps rise with its sequence. `elapsed_us` is a
    /// nondecreasing elapsed clock, such as `CLOCK_BOOTTIME`, and paces the period, so a wall-clock step moves no
    /// seal.
    ///
    /// # Errors
    ///
    /// [`SealError::Early`] before [`SealError::Entries`] before [`SealError::Exhausted`] before
    /// [`SealError::Field`], which names the decoder's refusal of the encoding.
    pub fn seal(
        &mut self,
        host: &HostState,
        entries: &[VolumeEntry],
        sealed_at_us: u64,
        elapsed_us: u64,
    ) -> Result<Vec<u8>, SealError> {
        let fits = entries.len() <= MAX_ENTRIES;
        let slot = (self.envelope).slot(fits, sealed_at_us, elapsed_us)?;
        let bytes = self.encode(host, entries, slot);
        // A label its table lacks encodes to code 255, which the decoder refuses, and every other field encodes
        // without loss, so a body the decoder accepts decodes to the report it encodes.
        decode(&bytes, &mut Discard).map_err(SealError::Field)?;
        Ok(self.envelope.close(&self.key.0, DOMAIN, bytes, slot))
    }
}

/// Accepts reports, keeping for each host up to [`BOOTS`] boots with their sequence and seal-time high-waters.
#[derive(Debug, Default)]
pub struct Reader {
    seen: BTreeMap<Host, Vec<KeptBoot>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeptBoot {
    boot: [u8; 16],
    /// The highest sequence accepted from the boot.
    sequence: u64,
    /// The highest seal time accepted from the boot.
    sealed_at_us: u64,
}

impl Reader {
    /// Authenticates and decodes `bytes` under the report key `key` returns for the writer's host, and records the
    /// sequence. `key` receives the unauthenticated header host, so it must be a bounded local lookup that makes no
    /// remote call and grows no state on a miss. The reader's state changes only on an accepted report.
    ///
    /// # Errors
    ///
    /// In order: [`ReportError::Length`] under 6 bytes, [`ReportError::Magic`], [`ReportError::Schema`] before any
    /// later field is read, [`ReportError::Length`] for a count or length outside the layout, which bounds a
    /// report at [`MAX_LEN`], [`ReportError::Writer`], [`ReportError::Tag`], the body's flag and field checks in
    /// layout order, then [`ReportError::Duplicate`].
    pub fn accept(
        &mut self,
        bytes: &[u8],
        key: impl FnOnce(Host) -> Option<ReportKey>,
    ) -> Result<HostReport, ReportError> {
        let layout = |bytes: &[u8]| layout(bytes, TAG_LEN).map(drop);
        let key = |host| key(host).map(|key| key.0);
        let body = authenticated(bytes, (MAGIC, SCHEMA, DOMAIN), layout, key)?;
        let report = decode_body(body)?;
        admit(
            &mut self.seen,
            report.writer,
            report.sequence,
            report.sealed_at_us,
        )?;
        Ok(report)
    }
}

/// The body of `bytes` once its tag verifies: the checks every sealed record's reader makes before it reads a field
/// past the writer (REPORT-AUTHENTICATED). It reads the magic, the schema and the length `layout` checks, then the
/// writer, whose host `key` maps to the record's key, and verifies the tag under that key and `domain` in constant
/// time.
///
/// # Errors
///
/// In order: [`ReportError::Length`] under 6 bytes, [`ReportError::Magic`], [`ReportError::Schema`] before any later
/// field is read, the error `layout` returns, [`ReportError::Length`] under the header and the tag,
/// [`ReportError::Writer`] for a zero writer or a host without a key, and [`ReportError::Tag`].
pub(crate) fn authenticated<'a>(
    bytes: &'a [u8],
    (magic, schema, domain): (&[u8; 4], u16, &[u8; 16]),
    layout: impl FnOnce(&[u8]) -> Result<(), ReportError>,
    key: impl FnOnce(Host) -> Option<[u8; 32]>,
) -> Result<&'a [u8], ReportError> {
    if bytes.len() < 6 {
        return Err(ReportError::Length);
    }
    if &bytes[..4] != magic {
        return Err(ReportError::Magic);
    }
    let found = u16::from_be_bytes([bytes[4], bytes[5]]);
    if found != schema {
        return Err(ReportError::Schema { found });
    }
    layout(bytes)?;
    if bytes.len() < HEADER_LEN + TAG_LEN {
        return Err(ReportError::Length);
    }
    let (body, tag) = bytes.split_at(bytes.len() - TAG_LEN);
    let writer = take_writer(&mut Bytes(&body[6..]))?;
    let key = key(writer.host).ok_or(ReportError::Writer)?;
    if !bool::from(sha256::tag(&key, domain, body).ct_eq(tag)) {
        return Err(ReportError::Tag);
    }
    Ok(body)
}

/// Records an authenticated record of `writer` with `sequence` and `sealed_at_us` in `seen`, the boots a reader keeps
/// per host (WRITER-SEQUENCE); `seen` changes only when the record is admitted.
///
/// # Errors
///
/// [`ReportError::Duplicate`] when the sequence is at or below the boot's high-water, or when [`BOOTS`] boots of the
/// host are kept, the record's boot is not among them and its seal time is at or below the lowest kept seal time.
pub(crate) fn admit(
    seen: &mut BTreeMap<Host, Vec<KeptBoot>>,
    writer: WriterId,
    sequence: u64,
    sealed_at_us: u64,
) -> Result<(), ReportError> {
    let boots = seen.entry(writer.host).or_default();
    let at = boots.iter().position(|kept| kept.boot == writer.boot);
    let oldest = boots
        .iter()
        .enumerate()
        .min_by_key(|(_, kept)| kept.sealed_at_us)
        .filter(|_| boots.len() == BOOTS)
        .map(|(at, kept)| (at, kept.sealed_at_us));
    let duplicate = match at {
        Some(at) => boots[at].sequence >= sequence,
        None => oldest.is_some_and(|(_, sealed)| sealed_at_us <= sealed),
    };
    if duplicate {
        return Err(ReportError::Duplicate);
    }
    let arrived = KeptBoot {
        boot: writer.boot,
        sequence,
        sealed_at_us,
    };
    match (at, oldest) {
        (Some(at), _) => {
            let kept = &mut boots[at];
            kept.sealed_at_us = kept.sealed_at_us.max(sealed_at_us);
            kept.sequence = sequence;
        }
        (None, None) => boots.push(arrived),
        (None, Some((oldest, _))) => boots[oldest] = arrived,
    }
    Ok(())
}

/// Follows the last owner-requested exit of one shard's owner host by its operation identity. Its status is an
/// observation of what the owner did and admits nothing. The request's deadline belongs to the owner's planned
/// exit: the owner resumes at it before the withdrawal and records the resume through [`ExitTracker::resumed`].
#[derive(Debug, Clone, Copy)]
pub struct ExitTracker {
    shard: Shard,
    host: Host,
    /// The request, and the shard generation and attempt counter `E` it was received at.
    last: Option<(Exit, (ShardGeneration, u32))>,
}

impl ExitTracker {
    /// A tracker of the exit requests `host` receives as the owner of `shard`.
    pub fn new(shard: Shard, host: Host) -> Self {
        Self {
            shard,
            host,
            last: None,
        }
    }

    /// Records `operation` as received at the authority's tenure `(g, a)`, with `E = a / 2`; a repeat of the last operation changes
    /// nothing, and another operation replaces it, so a redelivered earlier request replaces a later one.
    pub fn received(&mut self, operation: ExitOperation, authority: &AuthorityReport) {
        if self
            .last
            .is_none_or(|(exit, ..)| exit.operation != operation)
        {
            let exit = Exit {
                operation,
                status: ExitStatus::Received,
            };
            let (g, a) = authority.tenure;
            self.last = Some((exit, (g, a.get() / 2)));
        }
    }

    /// Records that retirement admission refused `operation`, while it is the last request and not ended.
    pub fn refused(&mut self, operation: ExitOperation, stale: Stale) {
        if let Some((exit, ..)) = self
            .last
            .as_mut()
            .filter(|(exit, ..)| exit.operation == operation && !ended(exit))
        {
            exit.status = ExitStatus::Restarting(Restart::Refused(stale));
        }
    }

    /// Records that the owner entered a drain stage for the tracked request, while it is received or draining.
    pub fn draining(&mut self) {
        self.before_withdrawal(ExitStatus::Draining);
    }

    /// Records that the owner resumed in place for `reason`, while the tracked request is received or draining.
    pub fn resumed(&mut self, reason: Resume) {
        self.before_withdrawal(ExitStatus::Resumed(reason));
    }

    /// Records that the tracked request restarts once for `reason`, while it has not ended.
    pub fn restarting(&mut self, reason: Restart) {
        if let Some((exit, ..)) = (self.last.as_mut()).filter(|(exit, ..)| !ended(exit)) {
            exit.status = ExitStatus::Restarting(reason);
        }
    }

    /// Records that the authority withdrew or closed while the tracked request is received or draining.
    pub fn withdrawn(&mut self) {
        self.before_withdrawal(ExitStatus::Withdrawn);
    }

    fn before_withdrawal(&mut self, status: ExitStatus) {
        if let Some((exit, ..)) = (self.last.as_mut()).filter(|(exit, ..)| pending(exit.status)) {
            exit.status = status;
        }
    }

    /// The first matching rule determines an active request's status: a successor record exits it under a withdrawn
    /// or closed authority; a withdrawn or closed authority withdraws a received or draining request; and a record
    /// for the tracked shard at the receipt's generation under the host sets a withdrawn request waiting. Every
    /// other observation preserves the status, however long after the receipt it arrives: an authority that is
    /// neither withdrawn nor closed preserves a received or draining request, and a withdrawn or waiting request
    /// stays until a successor record exits it or [`ExitTracker::restarting`] or [`ExitTracker::refused`] restarts
    /// it.
    pub fn observe(&mut self, authority: &AuthorityReport, shard: Option<&ShardRecord>) {
        self.observe_with(authority, shard, false);
    }

    /// [`ExitTracker::observe`] while the owner's planned transfer is outstanding or committed: every record of the
    /// tracked shard at a later `(g, E)` than the receipt's is a successor, whatever host it names, and only a record
    /// at the receipt's `(g, owner, E)` sets a withdrawn request waiting.
    pub fn observe_handoff(&mut self, authority: &AuthorityReport, shard: Option<&ShardRecord>) {
        self.observe_with(authority, shard, true);
    }

    fn observe_with(
        &mut self,
        authority: &AuthorityReport,
        shard: Option<&ShardRecord>,
        handoff: bool,
    ) {
        let Some((exit, (generation, attempts))) =
            self.last.as_mut().filter(|(exit, ..)| !ended(exit))
        else {
            return;
        };
        let read = shard.filter(|record| record.shard == self.shard);
        // Under a handoff every later `(g, E)` supersedes the withdrawn tenure, a same-host restart's included, and
        // only the receipt's own tenure sets the request waiting.
        let successor = read.is_some_and(|record| {
            record.generation > *generation
                || (record.generation == *generation
                    && record.attempts > *attempts
                    && (handoff || record.owner != self.host))
        });
        let at_receipt = read.is_some_and(|r| {
            (r.generation, r.owner) == (*generation, self.host)
                && (!handoff || r.attempts == *attempts)
        });
        let withdrawn = matches!(
            authority.state,
            serving::State::Withdrawn | serving::State::Closed
        );
        exit.status = match exit.status {
            _ if successor && withdrawn => ExitStatus::Exited,
            status if withdrawn && pending(status) => ExitStatus::Withdrawn,
            ExitStatus::Withdrawn if at_receipt => ExitStatus::Waiting,
            status => status,
        };
    }

    pub fn last(&self) -> Option<Exit> {
        self.last.map(|(exit, ..)| exit)
    }
}

/// Whether the request precedes the withdrawal: received, or draining in place.
fn pending(status: ExitStatus) -> bool {
    matches!(status, ExitStatus::Received | ExitStatus::Draining)
}

/// Whether the request ended: it exited, resumed in place or restarts.
fn ended(exit: &Exit) -> bool {
    matches!(
        exit.status,
        ExitStatus::Exited | ExitStatus::Resumed(_) | ExitStatus::Restarting(_)
    )
}

#[cfg(test)]
pub(crate) mod alarm_tests;
mod sha256;
#[cfg(test)]
mod sha256_tests;
pub mod status;
#[cfg(test)]
pub(crate) mod tests;
