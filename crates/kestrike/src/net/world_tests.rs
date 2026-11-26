//! The turn controller driving the production owner, a PUT-capable client
//! and a GET client over the simulated disk and links, and, in a two-owner
//! plan, a peer owner of the same configuration with its own two clients
//! (see the `peer` module). Every owner poll, client poll, disk execute,
//! post and admission, disk service call, NIC return, held update delivery
//! and workload action is one selected event,
//! and each action is proposable only under its precondition and only when
//! the profile declares its kind. Upload actions are [`PutAction`]
//! descriptors in the PUT domain, NIC returns are link release events, and
//! the rest are workload events.
//!
//! World time is in microseconds; the links run on their own turn clock of
//! 100 microseconds, and a datagram reaches its receiver at that receiver's
//! selected poll once it falls due. The owner is due when its maintenance
//! rest ends, or at once while maintenance has more work, and a client when
//! its next deadline falls due; either is also runnable while due datagrams
//! wait for it, an owner only while it is open, and the owner while
//! completions wait for a pick or its links hold reclaimable transmit
//! references. The storage platform is shared by the owner and the storage
//! actions: each turn re-arms it with the turn's projection, one nanosecond
//! tick per nanosecond of world time from tick one, so every sample a turn
//! consumes is that turn's.
//!
//! Held updates cover session changes and keyring replacement: each is held
//! until its own selected delivery event, whose result is that event's
//! outcome. The index key pair, the owner's and both clients' boot nonces,
//! every rekey's nonce and every link fault are draws from the run's
//! chooser. A withheld transmit reference becomes returnable at its own
//! selected event, and its sender's next poll returns it.
//!
//! The world judges a GET whose outcome its read action collects, by the
//! bytes the GET handed its client against the contents the registry holds
//! for its key, and a complete read of the upload's key by whether the
//! owner's index has bound that key: [`misread`] names the rules. A
//! stopped boundary, and the end of a run that finishes, judge a
//! publication its outcome action collected against the client's report.
//! A scripted history that collects a GET's or an upload's outcome through
//! its own step judges that outcome itself.

use crate::index::ShardIndex;
use crate::sim::action::{ActionKind, Profile};
use std::cell::RefCell;
use std::rc::Rc;

use crate::sim::choice::{CANDIDATE_LEN, Candidate, Chooser, Domain, EventKind, PutAction, Site};
use crate::sim::entropy::{DrawRefusal, draw, key_pair, key_pair_site, nonce, nonce_site};
use crate::sim::recovery::{Record as RecoveryRecord, Recovery};
use crate::sim::trace::Event;
use crate::sim::turn::{Defect, End, Hook, Limits, Report, World, run_hooked};
use crate::storage::device::sim::Stage;
use crate::storage::owner_fixture::{Commit, TestPlatform, last_sample, samples_taken, set_clock};
use crate::storage::{
    AllocationId, Decision, ExtentLease, Registration, RetireOutcome, SlotIndex, Storage,
    WorkBudget, WritableFill,
};

use super::audit::{Audit, Class, Reason, Record, Verdict};
use super::auth::KeyEntry;
use super::client::SessionState;
use super::fetch::{FragmentLease, Outcome};
use super::frame::Kind;
use super::geometry::FRAGMENT_LEN;
use super::link::{Draws, Faults, LinkLimits, TxRelease, UNBOUNDED};
use super::observe::{Failure, FirstFailure, Lenses, Observer, Registry, boundary, conserved};
use super::owner::{MAINTAIN_REST_US, OwnerConfig, OwnerRekeyError};
use super::owner_tests::{OWNER, PRINCIPALS, TestOwner, key, payload};
use super::put_tests::{Drawn, Scene, Successor, scene_relaunching};
use super::requests::RequestId;
use super::rules::{Capture, Chain, Effect, MANIFEST, Rule, Selector};
use super::session::RekeyError;
use super::upload::UploadOutcome;
use crate::oracle::Label;

mod boundary;

pub(crate) mod branch;

pub(crate) mod long_run;

mod parked;

pub(crate) mod bundle;

pub(crate) mod campaign_fuzz;
pub(crate) mod catalog;
pub(crate) mod cluster;
mod peer;
mod recovery;
mod relation;
mod relaunch;
pub(crate) mod session;

pub(crate) mod replay;

pub(crate) mod schedule;

pub(crate) mod histories;

pub(crate) mod narrate;

pub(crate) mod suffix;

/// Bytes of the object the world uploads and fills: three fragments, the
/// last short.
const OBJECT_LEN: u32 = 3 * FRAGMENT_LEN - 100;

/// The controller's selection site.
const SITE: Site = Site {
    domain: Domain::Workload,
    actor: 0,
    site: 1,
};

/// The owner's and the two clients' actor numbers at their nonce sites.
const ACTORS: [u16; 3] = [1, 2, 3];
/// The storage's actor number at its key pair site.
const INDEX: u16 = 4;
/// The two links' actor numbers at their fault sites.
const LINKS: [u16; 2] = [5, 6];
/// A two-owner scene's peer owner's and its two clients' actor numbers at
/// their nonce sites.
const PEER_ACTORS: [u16; 3] = [7, 8, 9];
/// The peer storage's actor number at its key pair site.
const PEER_INDEX: u16 = 10;
/// The peer's two links' actor numbers at their fault sites.
const PEER_LINKS: [u16; 2] = [11, 12];
/// The device index of the peer device's audit records, past every index
/// an incarnation of the scripted owner takes.
const PEER_AUDIT_DEVICE: u16 = u16::MAX;

const OWNER_POLL: u8 = 1;
const CLIENT_POLL: u8 = 2;
const SERVICE: u8 = 3;
const DELIVER: u8 = 4;
/// The event code of a scripted history's next step.
const SCRIPT: u8 = 5;
const PEER_OWNER_POLL: u8 = 6;
const PEER_CLIENT_POLL: u8 = 7;
const PEER_SERVICE: u8 = 8;
/// Workload action codes follow the controller's own events.
const ACTION: u8 = 16;
const _: () = assert!(PEER_SERVICE < ACTION);

/// The upload's key, as its descriptors name it.
const PUT_KEY: u8 = 6;
/// The local object's key.
const LOCAL_KEY: u8 = 7;
/// A key no object is published under.
const STRANGER: u8 = 11;

/// The disk's ready sets, in stage order.
const STAGES: [Stage; 3] = [Stage::Execute, Stage::Post, Stage::Admit];

/// World microseconds per link turn.
const LINK_TURN_US: u64 = 100;

/// How long one deferral holds the supplier.
const DEFER_US: u64 = 5_000;

const TTL_MS: u32 = 60_000;
const WAIT_US: u64 = 200_000;

/// Storage deadlines are whole seconds; the local object lives to the next
/// one after its publication.
const SECOND_US: u64 = 1_000_000;
/// Fills one pressure action holds.
const PRESSURE: u8 = 3;

/// Outcome codes are read with their kind, so codes of different kinds
/// share values. An action the system refused; it waits for another event.
const REFUSED: u64 = 0;
/// An action that took effect, where nothing finer is recorded.
const APPLIED: u64 = 1;
/// A session change or rekey enqueued as a held update.
const HELD: u64 = 1;
/// A session change delivered.
const DELIVERED: u64 = 2;
/// A rekey delivered and applied.
const REKEYED: u64 = 3;
/// A rekey delivered and refused busy, a request being live.
const REKEY_BUSY: u64 = 4;
/// A rekey delivered and refused otherwise.
const REKEY_REFUSED: u64 = 5;
/// A rekey delivered and refused because the chooser refused its nonce
/// draw.
const REKEY_CUT: u64 = 6;
/// A rekey delivered and refused because its nonce drew all zeros.
const REKEY_ZERO: u64 = 7;
/// A pressure release, plus the fills it dropped.
const PRESSURE_RELEASED: u64 = 100;

/// The storage tick `now_us` projects to.
fn ticks(now_us: u64) -> u64 {
    1 + now_us * 1_000
}

/// An upload outcome as a recorded code, none of them `REFUSED`.
fn upload_code(outcome: UploadOutcome) -> u64 {
    match outcome {
        UploadOutcome::Published => 1,
        UploadOutcome::Failed(_) => 2,
        UploadOutcome::NotStarted => 3,
        UploadOutcome::Unknown => 4,
    }
}

/// A held update, applied only at its own delivery event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Update {
    Session(usize),
    Rekey,
}

/// The rule a decided GET of `key` breaks by the `bytes` it handed its
/// client, judged against the contents `registry` holds for the key: a
/// complete read of a key with no content or of a key the owner's index
/// never bound, a complete read of bytes that are no one content's body, a
/// read that failed after handing out bytes that start no content's body,
/// or a read that ended `Missing`, refused under pressure or failed before
/// any byte, and handed out bytes.
///
/// The registry holds an upload's content from its invocation, so `bound`
/// carries the publication: whether the world has seen the owner's index
/// bind `key`, as [`Mixed::bound`] records for the upload's key. The
/// evidence is of the key and stays once seen, so a complete read of a
/// version the owner removed, or of a later version of a key bound
/// before, breaks no rule here.
fn misread(
    registry: &Registry,
    key: &[u8; 32],
    bound: bool,
    outcome: Outcome,
    bytes: &[u8],
) -> Option<Failure> {
    use crate::oracle::Obligation;
    let (obligation, rule) = match outcome {
        Outcome::Complete if !registry.knows(key) || !bound => (
            Obligation::History,
            "a hit of a version no linearized fill published",
        ),
        Outcome::Complete if !registry.serves(key, bytes) => (
            Obligation::Bytes,
            "a complete read returned bytes other than the label's content",
        ),
        Outcome::Incomplete(_) if !registry.starts(key, bytes) => (
            Obligation::Contain,
            "a failed read exposed bytes outside the verified prefix",
        ),
        Outcome::Missing | Outcome::Pressure(_) | Outcome::Failed(_) if !bytes.is_empty() => {
            (Obligation::Contain, "a refused read exposed bytes")
        }
        _ => return None,
    };
    Some(Failure::Violation(obligation, rule))
}

#[derive(Debug)]
struct Get {
    id: RequestId,
    /// The key the GET reads, and the bytes an exact read returns.
    wanted: ([u8; 32], Vec<u8>),
    /// The turn that issued it.
    issued: usize,
    bytes: Vec<u8>,
    outcome: Option<Outcome>,
    cancelled: bool,
}

/// One GET the world collected: its client, key, the turns that issued
/// and decided it, its outcome and whether it returned exactly the bytes
/// its key's content holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Decided {
    client: usize,
    key: [u8; 32],
    issued: usize,
    decided: usize,
    outcome: Outcome,
    exact: bool,
}

/// Turns after a held update's delivery within which each [`Episode`] it
/// opens must settle; an episode still open past them fails the run with a
/// Progress violation.
const EPISODE_TURNS: usize = 1_000;

/// Logical microseconds after a held update's delivery within which each
/// [`Episode`] it opens must settle: the deadline of the GET that settles
/// it, [`WAIT_US`], plus one owner maintenance rest.
const EPISODE_US: u64 = WAIT_US + super::owner::MAINTAIN_REST_US;

/// The window from one witnessed held-update delivery to the GET that
/// settles it for one client. A rekey opens one episode per client and a
/// session change one for its client. `turn` and `at_us` are the
/// delivery's turn and logical time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Episode {
    kind: ActionKind,
    /// The delivery's recorded outcome.
    outcome: u64,
    client: usize,
    turn: usize,
    at_us: u64,
    /// The owner's key epoch and the client's session epoch before the
    /// delivery.
    before: (u32, Option<u64>),
    /// The settling GET, and whether the endpoints then showed the update
    /// as [`Episode::shown`] decides.
    settled: Option<(Decided, bool)>,
}

impl Episode {
    /// The first GET in `decided` this episode's client issued after the
    /// delivery turn. The issue turn alone selects it, whenever the GET
    /// decided.
    fn settled_by(&self, decided: &[Decided]) -> Option<Decided> {
        decided
            .iter()
            .find(|got| got.client == self.client && got.issued > self.turn)
            .copied()
    }

    /// Whether the episode missed its bound. An unsettled episode is past
    /// the bound at turn `turns` or time `now`; a settled one is judged by
    /// the turn its GET decided, and the time bound applies only while it
    /// is unsettled: GETs decide only in [`World::apply`], and
    /// [`World::advance`] scans at every clock move before any event runs
    /// at the new time. `turns` must be at least the delivery turn.
    fn stalled(&self, turns: usize, now: u64) -> bool {
        match self.settled {
            Some((got, _)) => got.decided - self.turn > EPISODE_TURNS,
            None => turns - self.turn > EPISODE_TURNS || now > self.at_us + EPISODE_US,
        }
    }

    /// Whether the endpoints show this episode's update, given the owner's
    /// `key_epoch`, the client's `session` epoch and the owner's `held`
    /// epoch for the client's session. An applied rekey shows as the key
    /// epoch one past its value before delivery, and a busy one as the key
    /// epoch unchanged. A session change shows as a client session epoch
    /// that differs from its value before delivery and equals `held`.
    fn shown(&self, key_epoch: u32, session: Option<u64>, held: Option<u64>) -> bool {
        match (self.kind, self.outcome) {
            (ActionKind::Rekey, REKEYED) => key_epoch == self.before.0 + 1,
            (ActionKind::Rekey, _) => key_epoch == self.before.0,
            _ => session.is_some() && session != self.before.1 && session == held,
        }
    }

    /// Whether the episode settled with its endpoints showing the update.
    /// An applied rekey leaves every client holding its pre-rekey keys, so
    /// its read ends before any byte; a busy rekey leaves the ring and the
    /// sessions as they were, so any terminal heals it; a session change
    /// heals only at a `Complete`, exact read in the new session.
    fn healed(&self) -> bool {
        self.settled.is_some_and(|(got, shown)| {
            shown
                && match (self.kind, self.outcome) {
                    (ActionKind::Rekey, REKEYED) => {
                        !matches!(got.outcome, Outcome::Complete | Outcome::Incomplete(_))
                    }
                    (ActionKind::Rekey, _) => true,
                    _ => got.outcome == Outcome::Complete && got.exact,
                }
        })
    }
}

#[derive(Debug)]
struct Put {
    id: RequestId,
    attempt: u16,
    /// The client's active session epoch at invocation.
    session: Option<u64>,
    prepared: bool,
    supplied: Vec<bool>,
    deferrals: u32,
    deferred_until: u64,
    cancelled: bool,
    outcome: Option<UploadOutcome>,
    retired: bool,
}

/// Something a read or an acquisition handed out, held until a selected
/// release drops it.
enum Held<'s, 'm> {
    Fragment(FragmentLease<'m>),
    Extent(ExtentLease<'s, TestPlatform>),
}

/// The local object's progress.
enum Local<'s, 'm> {
    Unfilled,
    Filling {
        fill: Box<WritableFill<'s, 'm, TestPlatform>>,
        received: usize,
    },
    Published {
        expires_us: u64,
    },
}

/// Fills a pressure action holds.
enum Pressure<'s, 'm> {
    Idle,
    Holding(Vec<WritableFill<'s, 'm, TestPlatform>>),
    Released,
}

/// A failure a scenario plants on purpose, for the reducer to minimize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Plant {
    None,
    /// Once the uploading client collects its publication, a payload byte of
    /// the record changes on the device, which the next stopped boundary
    /// judges.
    PublishedByte,
    /// An outcome collection that finds every fragment acknowledged and no
    /// result claims publication, which the next stopped boundary judges,
    /// or the end of a run that finishes before one.
    AckAsSuccess,
    /// Once the goal holds, a payload byte of the published record changes
    /// on the device, so a settled run's media differs from its pair's.
    SettledByte,
    /// Once the uploading client collects its publication, the world
    /// panics, a failure the reducer keeps by the panic's location and
    /// payload.
    Panic,
    /// Once the uploading client collects its publication, a debug
    /// assertion fails, so the world panics in a build that keeps debug
    /// assertions and runs on to its goal in a build that drops them.
    DebugAssertion,
    /// Once a held update opens an episode for client 1, the GET client,
    /// the world stops offering that client's Read turns, so its episode
    /// stays unsettled while client 0's requests run on.
    StalledHeal,
    /// A GET that decides `Complete` hands its client a first byte other
    /// than the one the owner sent.
    ChangedRead,
    /// A GET that decides `Missing` hands its client the resident object's
    /// bytes as a complete read.
    UnpublishedHit,
    /// A GET that decides `Missing` hands its client one byte.
    ExposedMiss,
    /// An upload whose outcome the client reports as `Unknown` is collected
    /// as published, which the next stopped boundary judges, or the end of
    /// a run that finishes before one.
    UnknownAsSuccess,
    /// A GET of the upload's key that decides `Missing` while no applied
    /// event has left the key bound in the owner's index hands its client
    /// the upload's object as a complete read.
    StagedHit,
    /// Once the uploading client collects its publication, one payload unit
    /// is reserved from the owner's extent allocator and recorded in no
    /// slot, which the conservation rule judges at the end of that turn.
    LeakedUnit,
    /// An upload the client reports `Failed(Status::Contended)` is
    /// collected as published, which the next stopped boundary judges, or
    /// the end of a run that finishes before one.
    ContendedAsSuccess,
    /// The first owner poll with a datagram due toward the owner arms its
    /// multiplexer's swallow, so that multiplexer's next receive that fills
    /// a slot drops the last lease it filled and reports one fewer, which
    /// the datagram accounts check judges at the next stopped boundary or
    /// the run's end.
    Uncounted,
    /// As [`Plant::Uncounted`], on the multiplexer of a two-owner plan's
    /// peer owner, armed at the peer's first poll with a datagram due
    /// toward it.
    UncountedPeer,
}

/// The storage a run's owner serves from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Geometry {
    /// 128 units, eight slots, 8 KiB chunks.
    Fixture,
    /// 256 units, sixteen slots, 16 KiB chunks.
    Scaled,
    /// Two slots with insufficient units for the workload after accounting
    /// for the owner's structural floor and reserve.
    Cramped,
    /// The fixture's units, slots and chunks, over a storage whose recovery
    /// limits admit a warm attach, from
    /// [`storage_warm_as`](crate::storage::owner_fixture::storage_warm_as).
    /// `mixed_run` installs each successor's own drawn key pair, or the
    /// colliding hasher under `plan.collide`, so a warm load routes each
    /// restored key by the successor's fingerprint of it.
    Warm,
    /// An object with [`SEQUENCED_METADATA`] metadata bytes and one body
    /// byte spans two extents.
    Sequenced,
    /// The fixture's units, slots and chunks, over simulated devices whose
    /// persistence unit is 16384 bytes, the fixture's largest transfer.
    WideUnit,
    /// [`Geometry::Fixture`]'s storage with a read share of one command.
    OneReadCommand,
    /// [`Geometry::Fixture`]'s storage with three fill records, which give
    /// the scene six receive-write buffers.
    ThreeFills,
}

/// The metadata cap of [`Geometry::Sequenced`]: one extent's payload.
const SEQUENCED_METADATA: usize = crate::storage::EXTENT_PAYLOAD as usize;

impl Geometry {
    /// The storage's units and slots, and its record chunk length.
    fn shape(self) -> (crate::storage::owner_fixture::Shape, u32) {
        use crate::storage::owner_fixture::{CHUNK_LEN, FIXTURE, Shape};
        let shape = |units, slots| Shape { units, slots };
        match self {
            Self::Fixture
            | Self::Warm
            | Self::WideUnit
            | Self::OneReadCommand
            | Self::ThreeFills => (FIXTURE, CHUNK_LEN),
            Self::Scaled => (shape(256, 16), 2 * CHUNK_LEN),
            Self::Cramped => (shape(52, 2), CHUNK_LEN),
            Self::Sequenced => (shape(512, 8), CHUNK_LEN),
        }
    }

    fn storage(self) -> Storage<TestPlatform> {
        use crate::storage::owner_fixture::{
            CHUNK_LEN, sequence_storage_shaped, storage_filling, storage_reading_one_command,
            storage_shaped_as, storage_warm_as,
        };
        let (shape, chunk_len) = self.shape();
        match self {
            Self::Fixture | Self::Scaled | Self::Cramped | Self::WideUnit => {
                storage_shaped_as(shape, chunk_len)
            }
            Self::Warm => storage_warm_as(shape, chunk_len),
            Self::Sequenced => {
                assert_eq!(chunk_len, CHUNK_LEN, "the sequence storage's chunk length");
                sequence_storage_shaped(SEQUENCED_METADATA, shape)
            }
            Self::OneReadCommand => storage_reading_one_command(shape, chunk_len),
            // `storage_filling` builds over the fixture's shape and chunk length.
            Self::ThreeFills => storage_filling(4, 3),
        }
    }
}

/// What a scenario asks of its run. The counts are budgets the run spends.
#[derive(Debug, Clone, Copy)]
struct Plan {
    gets: [u32; 2],
    puts: u32,
    retries: u32,
    /// Source bytes the clients hold at once, which admission holds against
    /// the manifest's `source_bytes`.
    source_bytes: u32,
    sessions: u32,
    rekeys: u32,
    invalidations: u32,
    /// Deferrals the supplier makes before it supplies; `u32::MAX` never
    /// supplies.
    withhold: u32,
    /// The GET client reads the key only once the upload published it.
    read_after_publish: bool,
    /// The GET client reads the key only once the supplier deferred.
    read_during_stall: bool,
    /// The GET client reads the object resident since setup, not the
    /// upload's key.
    read_resident: bool,
    /// The rekey is proposed only while the GET client's request is live
    /// and undecided in the client.
    rekey_during_get: bool,
    /// The links withhold every transmit reference until a selected NIC
    /// return event.
    withheld_tx: bool,
    /// Every datagram toward the owner on the uploading client's link is
    /// lost, so its upload's outcome is unknown.
    lose_upload: bool,
    /// The owner's polls run no storage maintenance, so expiry and eviction
    /// happen only as selected actions.
    manual_maintenance: bool,
    /// Cancels are proposed only once the client decided the request, so
    /// every cancel runs against a decided request and earns no credit.
    cancel_after_decision: bool,
    /// Both links lose, duplicate, reorder and delay traffic, return
    /// transmit references after drawn delays, and run a tapped rule that
    /// delays GET DATA.
    link_faults: bool,
    /// The uploading client's next send fails with no origin the harness
    /// can name.
    unattributed: bool,
    /// The GET client's link takes no datagram longer than a header, so the
    /// owner's DATA toward it is refused as oversize.
    short_link: bool,
    /// The production outcomes the scenario provokes on purpose, which judge
    /// as modeled.
    declared: &'static [Reason],
    /// A payload byte of the resident object is changed on the device before
    /// the run.
    corrupt_resident: bool,
    /// The run must report the first failure the scenario provokes at a
    /// stopped boundary; `None` requires every boundary to pass.
    observed: Option<&'static Failure>,
    /// Both links' copied-byte and retained-transmit bounds.
    link: LinkLimits,
    /// The uploading client's link drops every upload RESULT toward it.
    drop_result: bool,
    plant: Plant,
    /// Datagrams one owner poll receives and sends at most, the owner's own
    /// when `None`.
    batch: Option<u32>,
    geometry: Geometry,
    /// Turns the run keeps taking once its goal holds.
    drain: u32,
    /// Live records one peer may hold at the owner, the owner's own share
    /// when `None`.
    share: Option<u32>,
    /// The uploading client's GETs read the resident object and are
    /// proposed only while its upload is prepared and undecided.
    get_during_upload: bool,
    /// Bytes of the object the run uploads and fills.
    object_len: u32,
    /// The GET client reads a key no object was published under.
    read_stranger: bool,
    /// Each witnessed held-update delivery opens an [`Episode`] per client
    /// it affects, which a GET that client issues afterward must settle
    /// within [`EPISODE_TURNS`] and [`EPISODE_US`]. The world proposes GETs
    /// once every planned held update is delivered.
    episodes: bool,
    /// The index hashes the stranger key to the resident object's word, so
    /// the two share a fingerprint.
    collide: bool,
    /// The upload begins only once the local object published, and
    /// pressure reserves only once no extent lease is held, the local
    /// object is no longer bound and no retired extent waits to return, so
    /// the reservations meet the hole it left.
    fragmenting: bool,
    /// The uploading client's link drops every PUT BEGIN toward the owner
    /// under a tapped rule.
    drop_begin: bool,
    /// Write commands the owner's PUT core may submit in one turn, the
    /// owner's own value when `None`.
    put_commands: Option<usize>,
    /// The uploading client's link drops the first upload RESULT toward it
    /// under a tapped rule, so the client learns its outcome from a later
    /// RESULT in the same session.
    drop_first_result: bool,
    /// A composed history's steps, each proposed in order once ready.
    script: &'static [Step],
    /// The marks a composed history's steps must set.
    witnesses: &'static [&'static str],
    /// The marks a composed history's run must set before `fail` records
    /// its violation.
    premise: &'static [&'static str],
    /// The world the plan runs: the mixed single-owner world, a recovery
    /// run, or a cluster run whose operations come from its shape.
    world: WorldKind,
    /// The owner's follower caps, its own when `None`.
    follow: Option<super::parked::FollowConfig>,
    /// With `get_during_upload`, the uploading client's GETs read the
    /// upload's key, joining its fill, instead of the resident object.
    upload_reads: bool,
    /// The upload's cancel and the GET client's session changes are
    /// proposed only while the owner holds a GET parked behind the upload.
    while_parked: bool,
    /// Owner relaunches a composed history's script runs, each over a
    /// later incarnation the run builds before it starts.
    relaunches: u32,
    /// A second owner of the same configuration runs beside the scripted
    /// one over its own storage, device, links and clients.
    peer_owner: bool,
    /// The storage's chaos points are armed for the turn loop, at the odds
    /// the catalog sets.
    chaos: bool,
    /// Source slots client 1 holds, so a composed history uploads from it.
    second_sources: u32,
}

/// One step of a composed history: its name, whether it may run now, and
/// its action, whose result is the turn's outcome.
#[derive(Clone, Copy)]
struct Step {
    name: &'static str,
    ready: fn(&Mixed<'_, '_, '_>, u64) -> bool,
    run: fn(&mut Mixed<'_, '_, '_>, u64) -> u64,
}

impl std::fmt::Debug for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name)
    }
}

const QUIET: Plan = Plan {
    gets: [0, 0],
    puts: 0,
    retries: 0,
    source_bytes: OBJECT_LEN,
    sessions: 0,
    rekeys: 0,
    invalidations: 0,
    withhold: 0,
    read_after_publish: false,
    read_during_stall: false,
    read_resident: false,
    rekey_during_get: false,
    withheld_tx: false,
    lose_upload: false,
    manual_maintenance: false,
    cancel_after_decision: false,
    link_faults: false,
    unattributed: false,
    short_link: false,
    declared: &[],
    corrupt_resident: false,
    observed: None,
    link: UNBOUNDED,
    drop_result: false,
    plant: Plant::None,
    batch: None,
    geometry: Geometry::Fixture,
    drain: 0,
    share: None,
    get_during_upload: false,
    object_len: OBJECT_LEN,
    read_stranger: false,
    episodes: false,
    collide: false,
    fragmenting: false,
    drop_begin: false,
    put_commands: None,
    drop_first_result: false,
    script: &[],
    witnesses: &[],
    premise: &[],
    world: WorldKind::Mixed,
    follow: None,
    upload_reads: false,
    while_parked: false,
    relaunches: 0,
    peer_owner: false,
    chaos: false,
    second_sources: 0,
};

/// The world a [`Plan`] runs.
#[derive(Debug, Clone, Copy)]
enum WorldKind {
    /// One owner and its clients under the plan's operation budgets.
    Mixed,
    /// A recovery run of this kind.
    Recovery(Recovery),
    /// A cluster run of this shape, which sets its own operations, so the
    /// plan's operation budgets stay unused.
    Cluster(&'static cluster::Shape),
}

impl Plan {
    /// When the plan's links return a delivered datagram's device
    /// references: after a drawn delay under link faults, at a selected
    /// release when withheld, and otherwise at delivery.
    fn tx_release(&self) -> TxRelease {
        if self.link_faults {
            TxRelease::Delayed(3)
        } else if self.withheld_tx {
            TxRelease::Withheld
        } else {
            TxRelease::AtDelivery
        }
    }

    fn recovery(&self) -> Option<Recovery> {
        match self.world {
            WorldKind::Recovery(recovery) => Some(recovery),
            WorldKind::Mixed | WorldKind::Cluster(_) => None,
        }
    }

    /// The plan plants a wrong behavior its run must fail on.
    fn control(&self) -> bool {
        self.plant != Plant::None || self.corrupt_resident
    }

    /// A link loses, delays or withholds traffic, refuses an oversize
    /// datagram or an unattributed send, or drops a result. The link's
    /// copy and retention bounds are fixed inputs the manifest sets.
    fn faulted(&self) -> bool {
        self.link_faults
            || self.lose_upload
            || self.withheld_tx
            || self.short_link
            || self.unattributed
            || self.drop_result
            || self.drop_first_result
    }

    fn owner_batch(&self) -> u32 {
        self.batch.unwrap_or(OWNER.batch)
    }

    /// Every budget is spent: each planned GET, upload, retry, session
    /// change, rekey and invalidation was issued.
    fn spent(&self) -> bool {
        self.gets == [0, 0]
            && self.puts == 0
            && self.retries == 0
            && self.sessions == 0
            && self.rekeys == 0
            && self.invalidations == 0
    }

    /// The world's `config` record begins with the plan's record: the
    /// counts little-endian, the flags one byte each with the resident
    /// corruption flag last, the declared reasons' count and canonical
    /// codes, the observed failure's canonical code or a zero, the link
    /// bounds little-endian, the result-dropping flag, the plant's code, a
    /// batch presence byte and the batch little-endian or a zero, the
    /// geometry's code, the drain little-endian, a share presence byte and
    /// the share little-endian or a zero, the GET-during-upload flag, the
    /// object length little-endian, the stranger-read, colliding,
    /// fragmenting and BEGIN-dropping flags, a PUT command presence byte
    /// and the command count little-endian or a zero, the
    /// first-result-dropping flag, the healed-episodes flag, each script
    /// step's name length and bytes, and, for a plan with its own follower
    /// caps, upload-key reads or faults proposed while parked, a 0xF0 byte,
    /// the upload-reads and while-parked flags and the four follower caps
    /// little-endian, and, for a plan that arms the chaos points, a 0xF1
    /// byte. `source_bytes`, an admission
    /// bound, stays out, and so do `witnesses`, `premise`, `relaunches`,
    /// `peer_owner` and `second_sources`, which follow from the script.
    fn record(&self) -> Vec<u8> {
        let counts = [
            self.gets[0],
            self.gets[1],
            self.puts,
            self.retries,
            self.sessions,
            self.rekeys,
            self.invalidations,
            self.withhold,
        ];
        let flags = [
            self.read_after_publish,
            self.read_during_stall,
            self.read_resident,
            self.rekey_during_get,
            self.withheld_tx,
            self.lose_upload,
            self.manual_maintenance,
            self.cancel_after_decision,
            self.link_faults,
            self.unattributed,
            self.short_link,
            self.corrupt_resident,
        ];
        let mut out: Vec<u8> = counts
            .iter()
            .flat_map(|count| count.to_le_bytes())
            .collect();
        out.extend(flags.map(u8::from));
        out.extend((self.declared.len() as u32).to_le_bytes());
        for &reason in self.declared {
            out.extend(bundle::reason_code(reason));
        }
        match self.observed {
            Some(failure) => out.extend(bundle::failure_code(failure)),
            None => out.push(0),
        }
        for bound in [self.link.copy_bytes, self.link.tx_slots] {
            out.extend((bound as u64).to_le_bytes());
        }
        out.push(u8::from(self.drop_result));
        out.push(self.plant as u8);
        out.push(u8::from(self.batch.is_some()));
        out.extend(self.batch.unwrap_or(0).to_le_bytes());
        out.push(self.geometry as u8);
        out.extend(self.drain.to_le_bytes());
        out.push(u8::from(self.share.is_some()));
        out.extend(self.share.unwrap_or(0).to_le_bytes());
        out.push(u8::from(self.get_during_upload));
        out.extend(self.object_len.to_le_bytes());
        out.extend(
            [
                self.read_stranger,
                self.collide,
                self.fragmenting,
                self.drop_begin,
            ]
            .map(u8::from),
        );
        out.push(u8::from(self.put_commands.is_some()));
        out.extend((self.put_commands.unwrap_or(0) as u64).to_le_bytes());
        out.push(u8::from(self.drop_first_result));
        out.push(u8::from(self.episodes));
        for step in self.script {
            out.push(step.name.len() as u8);
            out.extend(step.name.as_bytes());
        }
        // A plan that keeps the owner's follower caps and reads the
        // resident object during an upload records nothing more, so the
        // records of earlier plans stay as they were.
        if self.follow.is_some() || self.upload_reads || self.while_parked {
            out.push(0xF0);
            out.push(u8::from(self.upload_reads));
            out.push(u8::from(self.while_parked));
            let follow = self.follow.unwrap_or(OWNER.follow);
            for value in [
                follow.followers,
                follow.fill_followers,
                follow.peer_followers,
                follow.wake,
            ] {
                out.extend(value.to_le_bytes());
            }
        }
        if self.chaos {
            out.push(0xF1);
        }
        out
    }
}

/// One owner-side turn's clock: the turn's time, the samples it consumed
/// and the platform's last sample after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Clock {
    now: u64,
    /// The sample the turn armed: its time's tick, or the tick a history
    /// holds the clock at.
    projection: u64,
    taken: usize,
    last: Option<u64>,
}

/// One executed action: its turn, kind and outcome code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Act {
    turn: usize,
    kind: ActionKind,
    outcome: u64,
}

/// Owner and client state after a turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seen {
    epoch: u32,
    states: [SessionState; 2],
    sessions: [Option<u64>; 2],
    /// Each client's GET is live and its outcome undecided in the client.
    pending: [bool; 2],
    /// The upload is live and its outcome undecided in the client.
    uploading: bool,
    /// The owner's live requests, active and draining.
    live: u32,
    /// The owner's fingerprint false positives.
    false_positives: u64,
    /// The uploading client's source slots holding a fragment.
    sources: usize,
    /// The upload's receipt base and grant.
    receipt: Option<(u32, u32)>,
    /// Transmit references each link withholds.
    withheld: [usize; 2],
    /// PUT BEGINs the uploading client's link dropped under a rule.
    begins: usize,
    /// How many of the newest datagrams in flight, one per direction of each
    /// link, parse as frames, and the parse errors of the rest.
    frames: (usize, [Option<super::frame::FrameError>; 4]),
    /// The storage's raw byte partition, when its ledger reads.
    raw: Option<crate::storage::RawPartition>,
    /// The owner's PUT write commands submitted and its consume passes
    /// that waited for a write command.
    writes: (u64, u64),
    /// The live upload's attempt and the fill serial its receipt names,
    /// zero before the owner admitted it.
    upload: Option<(u16, u64)>,
    /// The uploading client's source slots a device holds.
    device_held: usize,
    /// The slot and incarnation the upload's key is bound to, when bound.
    binding: Option<(u32, u32)>,
    /// Write completions the device delivered.
    written: usize,
    /// Transmit references each link retains, withheld or delayed.
    nic: [usize; 2],
    /// The most bytes one direction of a link holds copied in flight.
    copied: usize,
    /// Captures each link's rule chain kept.
    captured: [usize; 2],
    /// Records each link's audit kept.
    audited: [usize; 2],
    /// Uploads the clients hold admitted and not yet released.
    uploads: usize,
    /// Bytes the clients' source slots hold.
    source_bytes: usize,
    /// GETs the owner holds parked behind a fill.
    parked: u32,
    /// GET duplicates the owner's transfer core took so far.
    duplicates: u64,
}

impl Mixed<'_, '_, '_> {
    /// The owner turn's limits, asserted after every owner poll, as
    /// [`check_turn_limits`] states them under the plan's batch and wake
    /// allowance.
    fn check_turn_limits(
        &self,
        before: &super::owner::OwnerReport,
        after: &super::owner::OwnerReport,
    ) {
        let wake = self.plan.follow.unwrap_or(OWNER.follow).wake;
        check_turn_limits(
            &self.scene.owner,
            (before, after),
            u64::from(self.plan.owner_batch()),
            wake,
        );
    }
}

/// Asserts the owner turn's limits between the reports `before` and
/// `after` one poll: one receive batch, one storage tick, one maintenance
/// call, at most `batch` sends and `wake` wake visits, and the parked GETs
/// within the request census.
fn check_turn_limits(
    owner: &TestOwner<'_, '_, '_>,
    (before, after): (&super::owner::OwnerReport, &super::owner::OwnerReport),
    batch: u64,
    wake: u32,
) {
    let (receives, ticks) = owner.turn_stages();
    assert!(
        receives <= 1 && ticks <= 1,
        "{receives} receive batches, {ticks} storage ticks"
    );
    let calls = after.maintained + after.maintenance_refused
        - before.maintained
        - before.maintenance_refused;
    assert!(calls <= 1, "{calls} maintenance calls in one turn");
    let sent = after.sent + after.failed - before.sent - before.failed;
    assert!(
        sent <= batch,
        "{sent} frames sent above the batch of {batch}"
    );
    assert!(
        owner.wake_visits() <= wake,
        "{} wake visits above {wake}",
        owner.wake_visits()
    );
    if let Err(census) = owner.check_parked_census() {
        panic!("the parked GETs left the request census: {census}");
    }
}

/// Polls `scene`'s owner at `now`. Returns the reports before and after the
/// poll, the time its next maintenance poll is due and the poll's outcome
/// code. Maintenance that ran with more work, or was refused, tries again on
/// the next poll; one that rests waits out its rest.
fn poll_owner(
    scene: &mut Scene<'_, '_>,
    now: u64,
) -> (
    super::owner::OwnerReport,
    super::owner::OwnerReport,
    u64,
    u64,
) {
    let before = scene.owner.report();
    scene.owner.poll(now);
    let report = scene.owner.report();
    let tried = report.maintained > before.maintained
        || report.maintenance_refused > before.maintenance_refused;
    let due = match scene.owner.maintain_rest_until_us() {
        Some(until) => until,
        None if tried => now,
        None => now + MAINTAIN_REST_US,
    };
    let outcome = report.received ^ report.sent.rotate_left(21) ^ report.maintained.rotate_left(42);
    (before, report, due, outcome)
}

/// A closed owner skips receiving, so waiting datagrams make the owner
/// runnable only while `open`.
fn owner_ready(scene: &Scene<'_, '_>, open: bool, due: u64, now: u64) -> bool {
    let inbound = scene.nets.iter().any(|net| {
        let net = net.borrow();
        (open && net.receivable(1) > 0) || net.reclaimable(1) > 0
    });
    due <= now || inbound || scene.control.deliverable() > 0
}

fn client_due(scene: &Scene<'_, '_>, client: usize, now: u64) -> bool {
    let net = scene.nets[client].borrow();
    net.receivable(0) > 0
        || net.reclaimable(0) > 0
        || scene.clients[client]
            .next_deadline_us()
            .is_some_and(|due| due <= now)
}

fn select_disk(control: &crate::storage::owner_fixture::SimControl, event: &Candidate) -> u64 {
    let stage = STAGES
        .into_iter()
        .find(|stage| *stage as u8 == event.0[1])
        .expect("a disk stage");
    let index = control
        .candidates(stage)
        .iter()
        .position(|known| known == event)
        .expect("a selected disk event is ready");
    control
        .select(stage, index)
        .expect("a ready entry")
        .token
        .raw()
}

/// One scenario's actors and workload state.
struct Mixed<'w, 's, 'm> {
    scene: relaunch::Living<'w, 's, 'm>,
    /// The lifecycle and later incarnations a relaunch draws on.
    relaunches: relaunch::Relaunches<'s, 'm>,
    /// The teardown observer, which follows each relaunch to the living
    /// incarnation's media.
    observer: &'w mut Observer<'s>,
    /// A two-owner scene's second owner.
    peer: Option<peer::Peer<'s, 'm>>,
    /// The run's chooser, which rekey nonces draw from.
    draws: Draws,
    profile: &'w Profile,
    /// The scenario's plan, its budgets spent as the run goes.
    plan: Plan,
    /// The plan as the run began, recorded with the profile.
    configured: Plan,
    /// The time setup left the actors at, where the run begins.
    start: u64,
    owner_due: u64,
    service_due: u64,
    key: [u8; 32],
    object: Vec<u8>,
    /// The key GETs read and the bytes an exact read returns.
    read: ([u8; 32], Vec<u8>),
    /// How far past its due time each due owner poll and service event ran.
    late: Vec<u64>,
    gets: [Option<Get>; 2],
    overlapping_get: Option<Get>,
    /// Each client polled since its last read or outcome collection, so
    /// those can observe something new.
    polled: [bool; 2],
    held: Vec<(usize, Held<'s, 'm>)>,
    put: Option<Put>,
    attempts: u16,
    local: Local<'s, 'm>,
    reader: Option<Registration<'s, TestPlatform>>,
    acquired: bool,
    pressure: Pressure<'s, 'm>,
    expired: bool,
    evicted: bool,
    closed: bool,
    /// Owner polls the controller applied.
    owner_polls: u64,
    updates: Vec<Update>,
    acts: Vec<Act>,
    /// Kinds refused since the last event that was not an action; each
    /// waits for such an event.
    refused: Vec<ActionKind>,
    clocks: Vec<Clock>,
    /// The tick a relaunch armed on the storage it attached, until the
    /// turn that ran the relaunch records its clock.
    attached: Option<u64>,
    seen: Vec<Seen>,
    progress: u64,
    /// Set once the controller took the configuration; every turn checks
    /// it, so the record precedes the first action.
    recorded: std::cell::Cell<bool>,
    /// The content every key may hold, registered as the world proposes it.
    registry: Rc<RefCell<Registry>>,
    lenses: Lenses,
    /// The run's first failure, from every stopped boundary and teardown.
    first: FirstFailure,
    /// Stopped boundaries the world observed.
    boundaries: usize,
    /// A stopped boundary passed since the datagram accounts were last
    /// judged; [`World::emit`] judges them after the conservation rule.
    accounts_due: bool,
    /// The accounts failure of an incarnation a relaunch closed, which
    /// [`World::emit`] records after the conservation rule.
    closed_accounts: Option<Failure>,
    /// Conservation judgments [`World::emit`] made, one per turn and clock
    /// move.
    conserved: u64,
    /// The leaked-unit plant reserved its unit.
    leaked: bool,
    /// `swallowed` keeps the uncounted plant's lease drop across relaunches,
    /// which replace the multiplexer.
    swallowed: bool,
    goal: fn(&Mixed<'_, '_, '_>) -> bool,
    /// Upload actions' events since the last emission.
    log: Vec<Event>,
    emitted: bundle::Emitted,
    /// The slot and incarnation of the record whose byte a byte plant
    /// changed.
    planted: Option<(u32, u32)>,
    /// A stopped boundary, or the run's end, found that record still
    /// bound, which is when the record check reads it.
    exposed: bool,
    /// A result plant changed what a decided GET handed its client. The
    /// read check judges that GET in the action that collects it, so the
    /// plant acts where it is set.
    handed: bool,
    /// An applied event left the upload's key bound in the owner's index
    /// to a verified record. It stays set through an invalidation, an
    /// eviction and a relaunch. The owner publishes an upload in its
    /// poll after that poll's lookups and follower wakes, so the event
    /// that publishes ends with the binding and precedes every hit of it.
    bound: bool,
    /// The virtual time at which a plant reported a publication its client
    /// does not: an acknowledged upload with no result, or an upload whose
    /// outcome is unknown.
    acked_at: Option<u64>,
    /// The Progress check judged client 1's episode past its bound.
    stalled: bool,
    /// Steps of the plan's script that ran.
    scripted: usize,
    /// What a composed history's steps keep for later steps.
    history: histories::State<'s, 'm>,
    /// The first entropy draw the chooser refused, at setup or a rekey.
    /// [`World::defect`] reports it ahead of any link draw error.
    draw_refusal: std::cell::Cell<Option<DrawRefusal>>,
    /// The turn count and the time of the last turn when the goal first
    /// held. [`World::done`] sets it, which the runner calls once before
    /// each selection, so a turn's proposals and plants read it as of that
    /// turn.
    reached: std::cell::Cell<Option<(usize, u64)>>,
    /// The time of the last turn applied.
    last_us: u64,
    /// The local object's extent once it published.
    local_media: Option<std::ops::Range<usize>>,
    /// The extents of the fills pressure reserved.
    pressure_media: Vec<std::ops::Range<usize>>,
    /// Every GET collected, in order.
    decided: Vec<Decided>,
    /// What the turn's action collected so far, taken after each action.
    collected: bundle::Collected,
    /// Every episode a witnessed held-update delivery opened, in order.
    episodes: Vec<Episode>,
    /// Buffers [`binding`](Self::binding) reuses across turns.
    scratch: Scratch,
}

/// The storage lenses' output buffers, reused across turns so reading a
/// binding allocates only while a buffer grows.
#[derive(Default)]
struct Scratch {
    bindings: Vec<crate::storage::lenses::Binding>,
    facts: Vec<crate::storage::lenses::SlotFact>,
    record: Vec<u8>,
}

/// Whether `bindings` hold the record at the slot and incarnation
/// `record`, by the slots' `facts`. A binding that names a slot `facts`
/// does not hold is not that record; the boundary check reports it.
fn binds(
    bindings: &[crate::storage::lenses::Binding],
    facts: &[crate::storage::lenses::SlotFact],
    record: (u32, u32),
) -> bool {
    bindings.iter().any(|binding| {
        let slot = binding.identity.slot;
        facts
            .get(slot as usize)
            .is_some_and(|fact| (slot, fact.incarnation) == record)
    })
}

fn candidate(code: u8, actor: usize, arg: u32) -> Candidate {
    let mut bytes = [0; CANDIDATE_LEN];
    bytes[0] = Domain::Workload as u8;
    bytes[1] = code;
    bytes[2] = actor as u8;
    bytes[3..7].copy_from_slice(&arg.to_be_bytes());
    Candidate(bytes)
}

/// The zero-based index of the scripted step a mixed run's turn of
/// `event` and `outcome` completed: the SCRIPT event ran the step named by
/// its argument and it returned an outcome other than [`histories::STAY`],
/// so the history moved to its next step.
fn completed_step(event: &Candidate, outcome: u64) -> Option<u32> {
    let step = u32::from_be_bytes(event.0[3..7].try_into().expect("four bytes"));
    let script = event.0[..2] == [Domain::Workload as u8, SCRIPT];
    (script && outcome != histories::STAY).then_some(step)
}

fn action(kind: ActionKind, actor: usize, arg: u32) -> Candidate {
    candidate(ACTION + kind as u8, actor, arg)
}

/// The event that makes link `net`'s `nth` withheld reference returnable.
fn nic_return(net: usize, nth: usize) -> Candidate {
    let mut bytes = [0; CANDIDATE_LEN];
    bytes[0] = Domain::Link as u8;
    bytes[1] = EventKind::Release as u8;
    bytes[2] = net as u8;
    bytes[3..7].copy_from_slice(&(nth as u32).to_be_bytes());
    Candidate(bytes)
}

/// The link whose withheld reference `event` makes returnable, when
/// [`nic_return`] built it.
fn nic_return_link(event: &Candidate) -> Option<usize> {
    let bytes = &event.0;
    let returns = bytes[0] == Domain::Link as u8 && bytes[1] == EventKind::Release as u8;
    returns.then(|| usize::from(bytes[2]))
}

/// The action kind and fragment a PUT descriptor names.
fn put_kind(event: &Candidate) -> (ActionKind, u32) {
    match PutAction::from_candidate(event).expect("a PUT descriptor") {
        PutAction::Begin { .. } => (ActionKind::PutInvoke, 0),
        PutAction::Prepare { .. } => (ActionKind::PutPrepare, 0),
        PutAction::Supply { fragment, .. } => (ActionKind::Supply, fragment),
        PutAction::Defer { .. } => (ActionKind::DeferSupply, 0),
        PutAction::Cancel { .. } => (ActionKind::PutCancel, 0),
        PutAction::Abandon { .. } => (ActionKind::Abandon, 0),
        PutAction::Outcome { .. } => (ActionKind::PutOutcome, 0),
        PutAction::Retry { .. } => (ActionKind::Retry, 0),
    }
}

/// Whether an action's outcome witnesses its kind: a held update only at
/// its delivery, any other kind when the system took it.
fn witnessed(kind: ActionKind, outcome: u64) -> bool {
    match kind {
        ActionKind::Rekey => matches!(outcome, REKEYED | REKEY_BUSY),
        ActionKind::SessionChange => outcome == DELIVERED,
        _ => outcome != REFUSED,
    }
}

/// A hash pass under which the stranger key takes the resident object's
/// word and every other key a word of its own SHA-256.
fn colliding(name: &[u8; 32]) -> u64 {
    use sha2::{Digest, Sha256};
    let hashed = if *name == key(STRANGER) {
        key(1)
    } else {
        *name
    };
    let digest = Sha256::digest(hashed);
    u64::from_le_bytes(digest[..8].try_into().expect("eight bytes"))
}

/// The device byte range of slot `slot`'s extent.
fn slot_media(storage: &Storage<TestPlatform>, slot: usize) -> Option<std::ops::Range<usize>> {
    let mut facts = Vec::new();
    storage.slot_facts_into(&mut facts).ok()?;
    facts.get(slot)?.media()
}

fn budget() -> WorkBudget {
    WorkBudget::new(1 << 12)
}

fn removed(commit: Option<Commit>) -> bool {
    matches!(commit, Some(Commit::Evicted { .. }))
}

/// A fill of `len` body bytes under `key`, or `None` when storage refuses
/// its begin, admission or reservation.
fn fill<'s, 'm>(
    storage: &'s Storage<TestPlatform>,
    key: &[u8; 32],
    len: usize,
) -> Option<WritableFill<'s, 'm, TestPlatform>> {
    fill_at(storage, key, crate::storage::CacheVersion(0), len)
}

/// [`fill`] of `version` of `key`.
fn fill_at<'s, 'm>(
    storage: &'s Storage<TestPlatform>,
    key: &[u8; 32],
    version: crate::storage::CacheVersion,
    len: usize,
) -> Option<WritableFill<'s, 'm, TestPlatform>> {
    let mut work = budget();
    let attempt = storage.begin_fill(key, version, 2, &mut work).ok()?;
    let Decision::Admit(admitted) = storage.decide_admission(Some(0), Some(len)) else {
        return None;
    };
    attempt
        .reserve_storage(admitted, Some(0), Some(len), 2, &mut work)
        .ok()
}

impl<'s, 'm> Mixed<'_, 's, 'm> {
    fn storage(&self) -> &'s Storage<TestPlatform> {
        self.scene.storage
    }

    /// One eviction step on the owner's storage: the commit of the victim it
    /// chose, or `None` when it chose none or the step was refused.
    fn evict_commit(&self) -> Option<Commit> {
        self.storage()
            .evict_step(&mut budget(), |_, _| true)
            .ok()
            .and_then(|report| report.commit)
    }

    /// Fails a collected publication the client still holds and does not
    /// report: the upload's recorded outcome is published, its request is
    /// live, and the client's result for it is another or none. A client's
    /// published result stays until its request is retired, so the
    /// comparison holds after any turn.
    fn judge_claim(&mut self) {
        let claimed = self
            .put
            .as_ref()
            .filter(|put| put.outcome == Some(UploadOutcome::Published) && !put.retired);
        if claimed.is_some_and(|put| {
            self.scene.clients[0].put_outcome(put.id) != Some(UploadOutcome::Published)
        }) {
            self.first.record(Failure::Violation(
                crate::oracle::Obligation::History,
                "an upload collected as published without its result",
            ));
        }
    }

    /// Notes that the record whose byte the plant changed is still bound,
    /// at a stopped boundary or the run's end. An invalidation that
    /// unbinds the record before either leaves the record check nothing to
    /// read, so the plant has not acted. The record is found by its slot
    /// and incarnation, since its changed bytes no longer verify.
    fn expose(&mut self) {
        let Some(record) = self.planted else {
            return;
        };
        let Scratch {
            bindings, facts, ..
        } = &mut self.scratch;
        let media = self.scene.media();
        let storage = media.storage();
        if !self.exposed
            && storage.bindings_into(bindings).is_ok()
            && storage.slot_facts_into(facts).is_ok()
        {
            self.exposed = binds(bindings, facts, record);
        }
    }

    fn judge_boundary(&mut self) {
        let registry = self.registry.borrow();
        let media = self.scene.media();
        if let Err(failure) = boundary(&media, &registry, &mut self.lenses) {
            self.first.record(failure);
        }
        drop(registry);
        self.boundaries += 1;
    }

    /// A living-owner datagram accounts failure takes precedence over a
    /// peer-owner failure.
    fn accounts_failure(&self) -> Option<Failure> {
        let peer = self.peer.as_ref().map_or(Ok(()), |peer| peer.accounts());
        self.scene.accounts().and(peer).err()
    }

    fn judge_accounts(&mut self) {
        if let Some(failure) = self.accounts_failure() {
            self.first.record(failure);
        }
    }

    /// No extent lease is held, no retired extent waits to return and the
    /// local object is no longer bound.
    fn local_freed(&self) -> bool {
        let leased = self
            .held
            .iter()
            .any(|(_, held)| matches!(held, Held::Extent(_)));
        let returned = self
            .storage()
            .pool_report()
            .and_then(|report| report.ledger)
            .is_some_and(|ledger| ledger.raw.retired == 0);
        !leased && returned && !super::adapters::bound(&self.scene, LOCAL_KEY)
    }

    /// The newest datagrams in flight on the scene's links ([`in_flight`]).
    fn in_flight(&self) -> (usize, [Option<super::frame::FrameError>; 4]) {
        in_flight(&self.scene.nets)
    }

    fn active(&self, client: usize) -> bool {
        self.scene.clients[client].state() == SessionState::Active
    }

    fn published(&self) -> bool {
        self.put
            .as_ref()
            .is_some_and(|put| put.outcome == Some(UploadOutcome::Published))
    }

    fn unpublished(&self) -> bool {
        let ended = |put: &Put| {
            matches!(
                put.outcome,
                Some(UploadOutcome::Failed(_) | UploadOutcome::NotStarted | UploadOutcome::Unknown)
            )
        };
        self.plan.puts == 0 && self.plan.retries == 0 && self.put.as_ref().is_some_and(ended)
    }

    /// The upload's key has a mapping to end and no GET still needs it:
    /// the upload published it, every planned GET has been issued and none
    /// is still undecided in its client. A run that drains after its goal
    /// also waits for the goal, so its invalidation falls in the suffix.
    fn invalidatable(&self) -> bool {
        let reads_decided =
            (0..2).all(|client| self.plan.gets[client] == 0 && !self.get_pending(client));
        let settled = self.plan.drain == 0 || self.reached.get().is_some();
        self.published() && reads_decided && settled
    }

    /// The slot and incarnation key `name` is bound to, when the index
    /// binds it to a verified record of that key.
    fn binding(&mut self, name: u8) -> Option<(u32, u32)> {
        let Scratch {
            bindings,
            facts,
            record,
        } = &mut self.scratch;
        let media = self.scene.media();
        let storage = media.storage();
        storage.bindings_into(bindings).ok()?;
        storage.slot_facts_into(facts).ok()?;
        let wanted = key(name);
        let found = bindings.iter().find(|&&binding| {
            media
                .bound_record(binding, facts, record)
                .is_ok_and(|(key, _, _)| key == wanted)
        })?;
        let slot = found.identity.slot;
        Some((slot, facts[slot as usize].incarnation))
    }

    fn get_pending(&self, client: usize) -> bool {
        self.gets[client]
            .iter()
            .chain(self.overlapping_get.iter().filter(|_| client == 0))
            .any(|get| {
                get.outcome.is_none() && self.scene.clients[client].outcome(get.id).is_none()
            })
    }

    fn uploading(&self) -> bool {
        self.put.as_ref().is_some_and(|put| {
            put.outcome.is_none() && self.scene.clients[0].put_outcome(put.id).is_none()
        })
    }

    fn fragments(&self) -> usize {
        self.object.len().div_ceil(FRAGMENT_LEN as usize)
    }

    fn reached(&self, kind: ActionKind) -> bool {
        self.acts
            .iter()
            .any(|act| act.kind == kind && witnessed(kind, act.outcome))
    }

    /// Every planned session change and rekey was delivered.
    fn held_spent(&self) -> bool {
        self.updates.is_empty() && self.plan.sessions == 0 && self.plan.rekeys == 0
    }

    /// Every declared kind ran with its witness and every planned budget
    /// is spent.
    fn covered(&self) -> bool {
        self.profile.declared.iter().all(|&kind| self.reached(kind)) && self.plan.spent()
    }

    fn proposed(&self, now: u64) -> Vec<Candidate> {
        let declares =
            |kind| self.profile.declares(kind) && !self.closed && !self.refused.contains(&kind);
        let mut out = Vec::new();
        self.proposed_gets(&declares, &mut out);
        self.proposed_put(now, &declares, &mut out);
        self.proposed_local(now, &declares, &mut out);
        if declares(ActionKind::Release) {
            for at in 0..self.held.len() {
                out.push(action(ActionKind::Release, self.held[at].0, at as u32));
            }
        }
        if declares(ActionKind::Rekey)
            && self.plan.rekeys > 0
            && (!self.plan.rekey_during_get || self.get_pending(1))
        {
            out.push(action(ActionKind::Rekey, 0, 0));
        }
        if declares(ActionKind::Invalidate) && self.plan.invalidations > 0 && self.invalidatable() {
            out.push(action(ActionKind::Invalidate, 0, 0));
        }
        // Close ends every other proposal, so it waits for the rest of the
        // declared kinds and for every planned budget.
        let rest = self
            .profile
            .declared
            .iter()
            .all(|&kind| kind == ActionKind::Close || self.reached(kind));
        if declares(ActionKind::Close) && rest && self.plan.spent() {
            out.push(action(ActionKind::Close, 0, 0));
        }
        out
    }

    fn proposed_gets(&self, declares: &dyn Fn(ActionKind) -> bool, out: &mut Vec<Candidate>) {
        let stalled = self.put.as_ref().is_some_and(|put| put.deferrals > 0);
        // A GET of the upload's key while it is open waits for the owner's
        // upload grant, the READY's, so it finds an upload-granted fill to
        // join.
        let granted = self.put.as_ref().is_some_and(|put| {
            self.scene.clients[0]
                .put_receipt(put.id)
                .is_some_and(|(_, _, grant)| grant > 0)
        });
        let eligible = |client: usize| {
            if self.plan.get_during_upload && client == 0 {
                return self.put.as_ref().is_some_and(|put| put.prepared)
                    && self.uploading()
                    && (!self.plan.upload_reads || granted);
            }
            let joins = self.plan.read_during_stall && self.read.0 == key(PUT_KEY);
            (!self.plan.read_after_publish || self.published())
                && (!self.plan.read_during_stall || stalled)
                && (!joins || granted)
                && (!self.plan.episodes || self.held_spent())
        };
        // The planted stall leaves the GET client's episode unread.
        let unread = |client: usize| {
            self.plan.plant == Plant::StalledHeal
                && client == 1
                && self.episodes.iter().any(|episode| episode.client == 1)
        };
        for client in 0..2 {
            if client == 0 && self.plan.get_during_upload && self.scripted < self.plan.script.len()
            {
                continue;
            }
            match &self.gets[client] {
                None
                | Some(Get {
                    outcome: Some(_), ..
                }) if declares(ActionKind::Get)
                    && self.plan.gets[client] > 0
                    && self.active(client)
                    && eligible(client) =>
                {
                    out.push(action(ActionKind::Get, client, 0));
                }
                Some(get) if get.outcome.is_none() => {
                    if declares(ActionKind::Read) && self.polled[client] && !unread(client) {
                        out.push(action(ActionKind::Read, client, 0));
                    }
                    let live = self.get_pending(client);
                    let wanted = if self.plan.cancel_after_decision {
                        !live
                    } else {
                        live
                    };
                    if declares(ActionKind::Cancel) && !get.cancelled && wanted {
                        out.push(action(ActionKind::Cancel, client, 0));
                    }
                }
                _ => {}
            }
            let parked = !self.plan.while_parked || self.scene.owner.parked_count() > 0;
            if declares(ActionKind::SessionChange) && self.plan.sessions > 0 && parked {
                out.push(action(ActionKind::SessionChange, client, 0));
            }
        }
    }

    fn proposed_put(
        &self,
        now: u64,
        declares: &dyn Fn(ActionKind) -> bool,
        out: &mut Vec<Candidate>,
    ) {
        let key = u32::from(PUT_KEY);
        let local_bound = !self.plan.fragmenting || self.local_media.is_some();
        let Some(put) = &self.put else {
            if declares(ActionKind::PutInvoke)
                && self.plan.puts > 0
                && self.active(0)
                && local_bound
            {
                let attempt = self.attempts + 1;
                out.push(PutAction::Begin { key, attempt }.candidate());
            }
            return;
        };
        let attempt = put.attempt;
        match put.outcome {
            None => {
                if declares(ActionKind::PutPrepare) && !put.prepared && !put.cancelled {
                    out.push(PutAction::Prepare { key, attempt }.candidate());
                }
                let open = put.prepared && !put.cancelled && put.supplied.contains(&false);
                if open && put.deferred_until <= now {
                    // The uploading client's own GET runs while nothing is
                    // supplied, so the upload holds its record throughout.
                    let read = !self.plan.get_during_upload
                        || self.plan.gets[0] == 0
                            && !self.get_pending(0)
                            && self.scripted == self.plan.script.len();
                    let ready = put.deferrals >= self.plan.withhold && read;
                    if declares(ActionKind::Supply) && ready {
                        for (fragment, done) in put.supplied.iter().enumerate() {
                            if !done {
                                let fragment = fragment as u32;
                                out.push(
                                    PutAction::Supply {
                                        key,
                                        attempt,
                                        fragment,
                                    }
                                    .candidate(),
                                );
                            }
                        }
                    }
                    if declares(ActionKind::DeferSupply) {
                        let ready_us = u32::try_from(now + DEFER_US)
                            .expect("a deferral within u32 microseconds");
                        out.push(
                            PutAction::Defer {
                                key,
                                attempt,
                                ready_us,
                            }
                            .candidate(),
                        );
                    }
                }
                let live = self.uploading();
                let wanted = if self.plan.cancel_after_decision {
                    !live
                } else {
                    live
                };
                let parked = !self.plan.while_parked || self.scene.owner.parked_count() > 0;
                if declares(ActionKind::PutCancel) && !put.cancelled && wanted && parked {
                    out.push(PutAction::Cancel { key, attempt }.candidate());
                }
                if declares(ActionKind::PutOutcome) && self.polled[0] {
                    out.push(PutAction::Outcome { key, attempt }.candidate());
                }
            }
            Some(UploadOutcome::Unknown) if !put.retired => {
                if declares(ActionKind::Abandon) {
                    out.push(PutAction::Abandon { key, attempt }.candidate());
                }
            }
            Some(UploadOutcome::Published) if put.retired => {
                if declares(ActionKind::PutInvoke) && self.plan.puts > 0 && self.active(0) {
                    let attempt = self.attempts + 1;
                    out.push(PutAction::Begin { key, attempt }.candidate());
                }
            }
            Some(outcome) => {
                let matching = put.retired
                    && outcome != UploadOutcome::Published
                    && self.plan.retries > 0
                    && self.active(0)
                    && put.session == self.scene.clients[0].session_epoch();
                if declares(ActionKind::Retry) && matching {
                    let attempt = self.attempts + 1;
                    out.push(PutAction::Retry { key, attempt }.candidate());
                }
            }
        }
    }

    fn proposed_local(
        &self,
        now: u64,
        declares: &dyn Fn(ActionKind) -> bool,
        out: &mut Vec<Candidate>,
    ) {
        let holding = matches!(self.pressure, Pressure::Holding(_));
        match &self.local {
            Local::Unfilled if declares(ActionKind::Fill) && !holding => {
                out.push(action(ActionKind::Fill, 0, 0));
            }
            Local::Filling { fill, received } => {
                if *received < self.object.len() && declares(ActionKind::Receive) {
                    out.push(action(ActionKind::Receive, 0, 0));
                }
                let written = *received == self.object.len()
                    && self.scene.owner.fill_progress(fill).is_ready();
                if written && declares(ActionKind::Publish) {
                    out.push(action(ActionKind::Publish, 0, 0));
                }
            }
            Local::Published { expires_us } => {
                if now < *expires_us && !self.acquired && declares(ActionKind::Acquire) {
                    out.push(action(ActionKind::Acquire, 0, 0));
                }
                if now >= *expires_us && !self.expired && declares(ActionKind::Expire) {
                    out.push(action(ActionKind::Expire, 0, 0));
                }
                if self.expired && !self.evicted && declares(ActionKind::Evict) {
                    out.push(action(ActionKind::Evict, 0, 0));
                }
            }
            Local::Unfilled => {}
        }
        // Held pressure stays releasable after close or a refusal: dropping
        // its fills is always legal.
        // Pressure follows the local publication, whose fill slot it no
        // longer competes with.
        let published = matches!(self.local, Local::Published { .. });
        let freed = !self.plan.fragmenting || self.local_freed();
        let reserve = matches!(self.pressure, Pressure::Idle)
            && published
            && freed
            && declares(ActionKind::Pressure);
        if reserve || holding {
            out.push(action(ActionKind::Pressure, 0, 0));
        }
    }

    /// Executes action `kind` and records it with its outcome; a refusal
    /// waits for the next event that is not an action, and a witnessed
    /// outcome other than a deferral counts as progress.
    fn act(&mut self, kind: ActionKind, client: usize, arg: u32, now: u64) -> u64 {
        let outcome = match kind {
            ActionKind::Get => self.get(client, now),
            ActionKind::Read => self.read(client),
            ActionKind::Release => self.release(arg as usize),
            ActionKind::Cancel => self.cancel(client),
            ActionKind::SessionChange => self.hold(Update::Session(client)),
            ActionKind::Rekey => self.hold(Update::Rekey),
            ActionKind::Invalidate => self.invalidate(now),
            ActionKind::Close => {
                self.closed = true;
                self.scene.owner.close(now);
                APPLIED
            }
            ActionKind::PutInvoke | ActionKind::Retry => self.invoke(kind, now),
            ActionKind::PutPrepare
            | ActionKind::Supply
            | ActionKind::DeferSupply
            | ActionKind::PutCancel
            | ActionKind::Abandon
            | ActionKind::PutOutcome => self.act_put(kind, arg, now),
            ActionKind::Fill
            | ActionKind::Receive
            | ActionKind::Publish
            | ActionKind::Acquire
            | ActionKind::Expire
            | ActionKind::Evict
            | ActionKind::Pressure => self.act_local(kind, now),
        };
        if outcome == REFUSED {
            self.refused.push(kind);
        }
        if witnessed(kind, outcome) && kind != ActionKind::DeferSupply {
            self.progress += 1;
        }
        self.record(kind, outcome)
    }

    /// One owner turn at `now` with the world's bookkeeping: records how
    /// late the turn ran, counts the poll, checks the turn's limits and
    /// keeps the owner's next due time. Returns the turn's outcome.
    fn owner_turn(&mut self, now: u64) -> u64 {
        if self.owner_due <= now {
            self.late.push(now - self.owner_due);
        }
        let uncounted = self.plan.plant == Plant::Uncounted;
        if uncounted
            && !self.swallowed
            && self.scene.owner.transport().swallow_unarmed()
            && self
                .scene
                .nets
                .iter()
                .any(|net| net.borrow().receivable(1) > 0)
        {
            self.scene.owner.transport_mut().swallow_next();
        }
        let (before, report, due, outcome) = poll_owner(&mut self.scene, now);
        self.swallowed |= uncounted && self.scene.owner.transport().swallowed();
        self.owner_polls += 1;
        self.check_turn_limits(&before, &report);
        self.owner_due = due;
        outcome
    }

    /// GET `id`'s outcome at `client` once decided, which the turn
    /// collects; `None`, and no collection, while it is pending.
    fn collect_get(&mut self, client: usize, id: RequestId) -> Option<Outcome> {
        let outcome = self.scene.clients[client].outcome(id)?;
        let logical = u16::try_from(client).expect("a client index");
        self.collected
            .add(bundle::Collected::Get(logical, 0, outcome));
        Some(outcome)
    }

    /// Client 0's upload `id`'s outcome, as [`Self::collect_put_at`]
    /// collects it.
    fn collect_put(&mut self, id: RequestId) -> Option<UploadOutcome> {
        self.collect_put_at(0, id)
    }

    /// Upload `id`'s outcome at `client` once decided, which the turn
    /// collects; `None`, and no collection, while it is pending.
    fn collect_put_at(&mut self, client: usize, id: RequestId) -> Option<UploadOutcome> {
        let outcome = self.scene.clients[client].put_outcome(id)?;
        let logical = u16::try_from(client).expect("a client index");
        self.collected
            .add(bundle::Collected::Put(logical, 0, outcome));
        Some(outcome)
    }

    fn record(&mut self, kind: ActionKind, outcome: u64) -> u64 {
        let turn = self.seen.len();
        self.acts.push(Act {
            turn,
            kind,
            outcome,
        });
        outcome
    }

    fn get(&mut self, client: usize, now: u64) -> u64 {
        let wanted = if self.plan.get_during_upload && client == 0 && !self.plan.upload_reads {
            (key(1), payload(1000, 1))
        } else if self.plan.get_during_upload && client == 0 {
            (key(PUT_KEY), self.object.clone())
        } else {
            self.read.clone()
        };
        let Ok(id) = self.scene.clients[client].get(wanted.0, 0, 1 << 20, now, WAIT_US) else {
            return REFUSED;
        };
        self.plan.gets[client] -= 1;
        self.gets[client] = Some(Get {
            id,
            wanted,
            issued: self.seen.len(),
            bytes: Vec::new(),
            outcome: None,
            cancelled: false,
        });
        APPLIED
    }

    /// Takes every received fragment, holding each when releases are
    /// declared, and collects the outcome once decided; the outcome code
    /// counts the fragments taken and a decided outcome.
    fn read(&mut self, client: usize) -> u64 {
        self.polled[client] = false;
        let get = self.gets[client]
            .as_mut()
            .expect("a proposed read has a GET");
        let mut observed = 0;
        let releases = self.profile.declares(ActionKind::Release);
        while let Some(fragment) = self.scene.clients[client].take(get.id) {
            get.bytes.extend_from_slice(fragment.bytes());
            observed += 1;
            if releases {
                self.held.push((client, Held::Fragment(fragment)));
            }
        }
        if let Some(outcome) = self.scene.clients[client].outcome(get.id) {
            let unbound = self.seen.iter().all(|seen| seen.binding.is_none());
            let outcome = match (self.plan.plant, outcome) {
                (Plant::StagedHit, Outcome::Missing) if get.wanted.0 == self.key && unbound => {
                    get.bytes = self.object.clone();
                    self.handed = true;
                    Outcome::Complete
                }
                (Plant::ChangedRead, Outcome::Complete) if !get.bytes.is_empty() => {
                    get.bytes[0] ^= 1;
                    self.handed = true;
                    outcome
                }
                (Plant::UnpublishedHit, Outcome::Missing) => {
                    get.bytes = payload(1000, 1);
                    self.handed = true;
                    Outcome::Complete
                }
                (Plant::ExposedMiss, Outcome::Missing) => {
                    get.bytes = vec![0];
                    self.handed = true;
                    outcome
                }
                _ => outcome,
            };
            // The resident and the stranger key take their publication
            // from the registry alone: the scene binds the resident before
            // the run, and nothing registers the stranger.
            let bound = get.wanted.0 != self.key || self.bound;
            let judged = misread(
                &self.registry.borrow(),
                &get.wanted.0,
                bound,
                outcome,
                &get.bytes,
            );
            if let Some(failure) = judged {
                self.first.record(failure);
            }
            let logical = u16::try_from(client).expect("a client index");
            self.collected
                .add(bundle::Collected::Get(logical, 0, outcome));
            get.outcome = Some(outcome);
            observed += 1;
            let _ = self.scene.clients[client].retire(get.id);
            self.decided.push(Decided {
                client,
                key: get.wanted.0,
                issued: get.issued,
                decided: self.seen.len(),
                outcome,
                exact: get.bytes == get.wanted.1,
            });
        }
        observed
    }

    /// Drops held item `at`; the code is the fragment's length or the
    /// lease's slot index plus one.
    fn release(&mut self, at: usize) -> u64 {
        match self.held.remove(at).1 {
            Held::Fragment(fragment) => fragment.bytes().len() as u64,
            Held::Extent(lease) => lease.id().slot_index() as u64 + 1,
        }
    }

    /// Cancels the client's GET; the action counts only while the request
    /// was still undecided in the client.
    fn cancel(&mut self, client: usize) -> u64 {
        let live = self.get_pending(client);
        let get = self.gets[client]
            .as_mut()
            .expect("a proposed cancel has a GET");
        self.scene.clients[client].cancel(get.id);
        if !live {
            return REFUSED;
        }
        get.cancelled = true;
        APPLIED
    }

    fn hold(&mut self, update: Update) -> u64 {
        match update {
            Update::Session(_) => self.plan.sessions -= 1,
            Update::Rekey => self.plan.rekeys -= 1,
        }
        self.updates.push(update);
        HELD
    }

    /// Invalidates the upload's key through the owner, which ends its
    /// maintenance rest, so the owner is due at once; the action counts
    /// and spends its budget only when a mapping ended.
    fn invalidate(&mut self, now: u64) -> u64 {
        let invalidated = self
            .scene
            .owner
            .invalidate(&self.key, 3, &mut budget())
            .is_ok_and(|done| done.removed.is_some());
        if invalidated {
            self.plan.invalidations -= 1;
            self.owner_due = now;
        }
        u64::from(invalidated)
    }

    fn invoke(&mut self, kind: ActionKind, now: u64) -> u64 {
        let Ok(id) =
            self.scene.clients[0].put(self.key, crate::storage::CacheVersion(0), now, WAIT_US)
        else {
            return REFUSED;
        };
        let content = (self.key, self.object.clone());
        self.registry
            .borrow_mut()
            .register(content.0, Label(PUT_KEY.into()), 0, content.1);
        if kind == ActionKind::Retry {
            self.plan.retries -= 1;
        } else {
            self.plan.puts -= 1;
        }
        self.attempts += 1;
        self.put = Some(Put {
            id,
            attempt: self.attempts,
            session: self.scene.clients[0].session_epoch(),
            prepared: false,
            supplied: vec![false; self.fragments()],
            deferrals: 0,
            deferred_until: 0,
            cancelled: false,
            outcome: None,
            retired: false,
        });
        APPLIED
    }

    fn act_put(&mut self, kind: ActionKind, fragment: u32, now: u64) -> u64 {
        let uploading = self.uploading();
        let put = self
            .put
            .as_mut()
            .expect("a proposed upload action has a PUT");
        let client = &mut self.scene.clients[0];
        match kind {
            ActionKind::PutPrepare => {
                let body = self.object.len() as u32;
                let prepared = client.prepare(put.id, 0, body, TTL_MS).is_ok();
                put.prepared = prepared;
                u64::from(prepared)
            }
            ActionKind::Supply => {
                let start = fragment as usize * FRAGMENT_LEN as usize;
                let end = (start + FRAGMENT_LEN as usize).min(self.object.len());
                let supplied = client
                    .supply(put.id, fragment, &self.object[start..end])
                    .is_ok();
                put.supplied[fragment as usize] |= supplied;
                u64::from(supplied)
            }
            ActionKind::DeferSupply => {
                put.deferrals += 1;
                put.deferred_until = now + DEFER_US;
                APPLIED
            }
            ActionKind::PutCancel => {
                client.cancel(put.id);
                if !uploading {
                    return REFUSED;
                }
                put.cancelled = true;
                APPLIED
            }
            ActionKind::Abandon => {
                let abandoned = client.abandon(put.id);
                put.retired = abandoned && client.retire(put.id);
                u64::from(abandoned)
            }
            ActionKind::PutOutcome => {
                self.polled[0] = false;
                let acknowledged = client.put_receipt(put.id).is_some_and(|(_, base, _)| {
                    base as usize == self.object.len().div_ceil(FRAGMENT_LEN as usize)
                });
                let Some(outcome) = client.put_outcome(put.id) else {
                    if self.plan.plant == Plant::AckAsSuccess && acknowledged {
                        self.acked_at.get_or_insert(now);
                        put.outcome = Some(UploadOutcome::Published);
                        return upload_code(UploadOutcome::Published);
                    }
                    return REFUSED;
                };
                let planted = match self.plan.plant {
                    Plant::UnknownAsSuccess => outcome == UploadOutcome::Unknown,
                    Plant::ContendedAsSuccess => {
                        outcome == UploadOutcome::Failed(super::frame::Status::Contended)
                    }
                    _ => false,
                };
                if planted {
                    self.acked_at.get_or_insert(now);
                    self.collected
                        .add(bundle::Collected::Put(0, 0, UploadOutcome::Published));
                    put.outcome = Some(UploadOutcome::Published);
                    return upload_code(UploadOutcome::Published);
                }
                self.collected.add(bundle::Collected::Put(0, 0, outcome));
                put.outcome = Some(outcome);
                put.retired = client.retire(put.id);
                upload_code(outcome)
            }
            _ => unreachable!("{kind:?} is not an upload action on a live PUT"),
        }
    }

    fn act_local(&mut self, kind: ActionKind, now: u64) -> u64 {
        let storage = self.storage();
        let len = self.object.len();
        match kind {
            ActionKind::Fill => match fill(storage, &key(LOCAL_KEY), len) {
                Some(fill) => {
                    let object = self.object.clone();
                    self.registry.borrow_mut().register(
                        key(LOCAL_KEY),
                        Label(LOCAL_KEY.into()),
                        0,
                        object,
                    );
                    self.local = Local::Filling {
                        fill: Box::new(fill),
                        received: 0,
                    };
                    APPLIED
                }
                None => REFUSED,
            },
            ActionKind::Receive => {
                let Local::Filling { fill, received } = &mut self.local else {
                    unreachable!("a receive has a fill")
                };
                let chunk = &self.object[*received..(*received + 4096).min(len)];
                let io = &mut WorkBudget::with_io(0, usize::MAX, usize::MAX);
                let taken = self.scene.owner.receive_fill(fill, chunk, io).unwrap_or(0);
                *received += taken;
                taken as u64
            }
            ActionKind::Publish => {
                let Local::Filling { fill, .. } =
                    std::mem::replace(&mut self.local, Local::Unfilled)
                else {
                    unreachable!("a publication has a fill")
                };
                let expires_us = (now / SECOND_US + 1) * SECOND_US;
                match self
                    .scene
                    .owner
                    .publish_fill(*fill, ticks(expires_us), 2, &mut budget())
                {
                    Ok(lease) => {
                        self.local_media = slot_media(storage, lease.id().slot_index());
                        // A publication ends the owner's maintenance rest.
                        self.owner_due = now;
                        self.local = Local::Published { expires_us };
                        self.held.push((0, Held::Extent(lease)));
                        APPLIED
                    }
                    Err(_) => REFUSED,
                }
            }
            ActionKind::Acquire => {
                let reader = match &mut self.reader {
                    Some(reader) => reader,
                    empty => match storage.register() {
                        Ok(reader) => empty.insert(reader),
                        Err(_) => return REFUSED,
                    },
                };
                match reader.lookup(&key(LOCAL_KEY), 2, &mut budget()) {
                    Ok(lease) => {
                        self.acquired = true;
                        self.held.push((0, Held::Extent(lease)));
                        APPLIED
                    }
                    Err(_) => REFUSED,
                }
            }
            ActionKind::Expire => {
                let gone = storage
                    .expire_step(&mut budget())
                    .is_ok_and(|report| removed(report.commit));
                self.expired = gone;
                u64::from(gone)
            }
            ActionKind::Evict => {
                let gone = removed(self.evict_commit());
                self.evicted = gone;
                u64::from(gone)
            }
            ActionKind::Pressure => match std::mem::replace(&mut self.pressure, Pressure::Released)
            {
                Pressure::Holding(fills) => PRESSURE_RELEASED + fills.len() as u64,
                _ => {
                    let _ = storage.service_fills(ShardIndex(0), 2, &mut budget());
                    let fills: Vec<_> = (0..PRESSURE)
                        .map_while(|n| fill(storage, &key(0xa0 + n), len))
                        .collect();
                    if fills.is_empty() {
                        self.pressure = Pressure::Idle;
                        return REFUSED;
                    }
                    let reserved = fills.len() as u64;
                    self.pressure_media = fills
                        .iter()
                        .filter_map(|fill| slot_media(storage, fill.id().slot_index()))
                        .collect();
                    self.pressure = Pressure::Holding(fills);
                    reserved
                }
            },
            _ => unreachable!("{kind:?} is not a local action"),
        }
    }

    /// Applies held update `at` and records its result as the delivery's
    /// outcome, counting progress when the result witnesses its kind.
    fn deliver(&mut self, at: usize, now: u64) -> u64 {
        let update = self.updates[at];
        let before = self.endpoints();
        let (kind, outcome) = match self.updates.remove(at) {
            Update::Session(client) => {
                self.scene.clients[client].session(now);
                (ActionKind::SessionChange, DELIVERED)
            }
            Update::Rekey => {
                let keys = [[0x70; 32], [0x71; 32]];
                let entries = [
                    KeyEntry {
                        principal: PRINCIPALS[0],
                        key: &keys[0],
                    },
                    KeyEntry {
                        principal: PRINCIPALS[1],
                        key: &keys[1],
                    },
                ];
                let (draws, refused) = (Rc::clone(&self.draws), &self.draw_refusal);
                let incarnation = draws.borrow_mut().launch(ACTORS[0]);
                let drawn = move |bytes: &mut [u8; 16]| {
                    nonce(
                        &mut draws.borrow_mut(),
                        nonce_site(ACTORS[0]),
                        incarnation,
                        refused,
                    )(bytes)
                };
                let epoch = self.scene.owner.key_epoch() + 1;
                let rekeyed = self
                    .scene
                    .owner
                    .rekey_with_nonce(&entries, epoch, now, drawn);
                let outcome = match rekeyed {
                    Ok(()) => REKEYED,
                    Err(OwnerRekeyError::Rekey(RekeyError::Busy { .. })) => REKEY_BUSY,
                    Err(OwnerRekeyError::Entropy(super::EntropyError::Refused { .. })) => REKEY_CUT,
                    Err(OwnerRekeyError::Entropy(super::EntropyError::Zero)) => REKEY_ZERO,
                    Err(_) => REKEY_REFUSED,
                };
                (ActionKind::Rekey, outcome)
            }
        };
        self.progress += u64::from(witnessed(kind, outcome));
        if self.plan.episodes && witnessed(kind, outcome) {
            let clients = match update {
                Update::Session(client) => client..client + 1,
                Update::Rekey => 0..2,
            };
            for client in clients {
                self.episodes.push(Episode {
                    kind,
                    outcome,
                    client,
                    turn: self.seen.len(),
                    at_us: now,
                    before: (before.0, before.1[client]),
                    settled: None,
                });
            }
        }
        self.record(kind, outcome)
    }

    /// The owner's key epoch and each client's session epoch.
    fn endpoints(&self) -> (u32, [Option<u64>; 2]) {
        let sessions = [0, 1].map(|client| self.scene.clients[client].session_epoch());
        (self.scene.owner.key_epoch(), sessions)
    }

    /// Settles each open episode its client's later GET decided, recording
    /// whether the owner and the client showed the update. Records a
    /// Progress violation when an episode settles without healing or
    /// [`Episode::stalled`] holds.
    fn watch_episodes(&mut self, now: u64) {
        let (key_epoch, sessions) = self.endpoints();
        for at in 0..self.episodes.len() {
            let episode = self.episodes[at];
            if episode.settled.is_some() {
                continue;
            }
            let Some(got) = episode.settled_by(&self.decided) else {
                continue;
            };
            let peer = super::datagram::PeerId(episode.client as u16);
            let held = self.scene.owner.session_epoch(peer);
            let shown = episode.shown(key_epoch, sessions[episode.client], held);
            self.episodes[at].settled = Some((got, shown));
            if !self.episodes[at].healed() {
                self.first.record(Failure::Violation(
                    crate::oracle::Obligation::Progress,
                    "a healed request settled without its update",
                ));
            }
        }
        let turns = self.seen.len();
        // The stalled heal's plant acts where this check judges client 1's
        // episode late, whatever the check records.
        self.stalled |= self
            .episodes
            .iter()
            .any(|episode| episode.client == 1 && episode.stalled(turns, now));
        if self
            .episodes
            .iter()
            .any(|episode| episode.stalled(turns, now))
        {
            self.first.record(Failure::Violation(
                crate::oracle::Obligation::Progress,
                "a healed request stalled past its bound",
            ));
        }
    }

    fn apply_event(&mut self, event: Candidate, now: u64) -> u64 {
        if let Some(peer) = self.peer.as_mut()
            && peer::Peer::owns(&event)
        {
            self.refused.clear();
            let wake = self.plan.follow.unwrap_or(OWNER.follow).wake;
            let batch = u64::from(self.plan.owner_batch());
            let polled = event.0[0] == Domain::Workload as u8 && event.0[1] == PEER_OWNER_POLL;
            let uncounted = self.plan.plant == Plant::UncountedPeer;
            if uncounted
                && polled
                && !self.swallowed
                && peer.swallow_unarmed()
                && peer.nets().iter().any(|net| net.borrow().receivable(1) > 0)
            {
                peer.swallow_next();
            }
            let (outcome, progressed) = peer.apply(event, now, (batch, wake));
            self.swallowed |= uncounted && peer.swallowed();
            self.progress += u64::from(progressed);
            return outcome;
        }
        let [domain, code, actor, ..] = event.0;
        if domain == Domain::Put as u8 {
            let (kind, fragment) = put_kind(&event);
            return self.act(kind, 0, fragment, now);
        }
        if domain == Domain::Workload as u8 && code > ACTION {
            let kind = ActionKind::from_code(code - ACTION).expect("a workload action code");
            let arg = u32::from_be_bytes(event.0[3..7].try_into().expect("four bytes"));
            return self.act(kind, usize::from(actor), arg, now);
        }
        // Every event other than an action can change what an action meets.
        self.refused.clear();
        if domain == Domain::Disk as u8 {
            return select_disk(&self.scene.control, &event);
        }
        if domain == Domain::Link as u8 {
            let nth = u32::from_be_bytes(event.0[3..7].try_into().expect("four bytes"));
            self.scene.nets[usize::from(actor)]
                .borrow_mut()
                .return_tx(nth as usize);
            self.progress += 1;
            return u64::from(nth) + 1;
        }
        match code {
            OWNER_POLL => self.owner_turn(now),
            CLIENT_POLL => {
                self.polled[usize::from(actor)] = true;
                let report = self.scene.clients[usize::from(actor)].poll(now);
                u64::from(report.received) | u64::from(report.sent) << 32
            }
            SERVICE => {
                self.late.push(now - self.service_due);
                let calls = self.scene.control.driver_calls();
                self.scene.owner.service_disk();
                self.service_due = now + MAINTAIN_REST_US;
                (self.scene.control.driver_calls() - calls) as u64
            }
            SCRIPT => {
                let step = self.plan.script[self.scripted];
                let outcome = (step.run)(self, now);
                if outcome != histories::STAY {
                    self.scripted += 1;
                    self.progress += 1;
                }
                outcome
            }
            DELIVER => {
                let at = u32::from_be_bytes(event.0[3..7].try_into().expect("four bytes"));
                self.deliver(at as usize, now)
            }
            code => unreachable!("workload event code {code}"),
        }
    }
}

impl World for Mixed<'_, '_, '_> {
    fn config(&self) -> Vec<u8> {
        self.recorded.set(true);
        let mut out = self.configured.record();
        out.extend(&self.key);
        out.extend(&self.read.0);
        out.extend((self.object.len() as u64).to_le_bytes());
        out
    }

    fn recovery(&self) -> Option<RecoveryRecord> {
        self.configured.recovery().map(Recovery::record)
    }

    fn start(&self) -> u64 {
        self.start
    }

    /// Moves the link clocks, then observes the stopped boundary the clock
    /// move is: no event runs while the world compares a collected
    /// publication with the client's report, as [`Self::judge_claim`] does,
    /// and its bindings and media with its registry.
    fn advance(&mut self, now: u64) {
        for net in &self.scene.nets {
            net.borrow_mut().advance(now / LINK_TURN_US);
        }
        self.refused.clear();
        self.watch_episodes(now);
        self.expose();
        self.judge_claim();
        self.judge_boundary();
        if let Some(peer) = &mut self.peer
            && let Err(failure) = peer.advance(now, &self.registry.borrow())
        {
            self.first.record(failure);
        }
        self.accounts_due = true;
    }

    fn runnable(&self, now: u64) -> Vec<Candidate> {
        let mut out = Vec::new();
        // A closed owner skips receiving, so on its links only reclaimable
        // transmit references make it runnable ahead of its due time;
        // deliverable disk completions still do.
        if owner_ready(&self.scene, !self.closed, self.owner_due, now) {
            out.push(candidate(OWNER_POLL, 0, 0));
        }
        for client in 0..2 {
            if client_due(&self.scene, client, now) {
                out.push(candidate(CLIENT_POLL, client, 0));
            }
        }
        if self.service_due <= now {
            out.push(candidate(SERVICE, 0, 0));
        }
        for (at, update) in self.updates.iter().enumerate() {
            let (kind, actor) = match *update {
                Update::Session(client) => (ActionKind::SessionChange, client),
                Update::Rekey => (ActionKind::Rekey, 0),
            };
            let mut event = candidate(DELIVER, actor, at as u32);
            event.0[7] = kind as u8;
            out.push(event);
        }
        if !self.history.hold_nic {
            for net in 0..2 {
                for nth in 0..self.scene.nets[net].borrow().withheld() {
                    out.push(nic_return(net, nth));
                }
            }
        }
        out.extend(self.proposed(now));
        if let Some(step) = self.plan.script.get(self.scripted)
            && (step.ready)(self, now)
        {
            out.push(candidate(SCRIPT, 0, self.scripted as u32));
        }
        for stage in STAGES {
            out.extend(self.scene.control.candidates(stage));
        }
        if let Some(peer) = &self.peer {
            peer.runnable(now, &mut out);
        }
        out.sort();
        out
    }

    fn next_due(&self, now: u64) -> Option<u64> {
        let clients = (0..2).filter_map(|client| self.scene.clients[client].next_deadline_us());
        let arrivals = self
            .scene
            .nets
            .iter()
            .flat_map(|net| {
                let net = net.borrow();
                [net.next_arrival(), net.next_return()]
            })
            .flatten();
        let deferred = self.put.as_ref().map(|put| put.deferred_until);
        let expiry = match self.local {
            Local::Published { expires_us } => Some(expires_us),
            _ => None,
        };
        [
            Some(self.owner_due),
            Some(self.service_due),
            deferred,
            expiry,
            self.history.wake,
            self.peer.as_ref().and_then(|peer| peer.next_due(now)),
        ]
        .into_iter()
        .flatten()
        .chain(clients)
        .chain(arrivals.map(|turn| turn * LINK_TURN_US))
        .filter(|&due| due > now)
        .min()
    }

    fn apply(&mut self, event: Candidate, now: u64) -> u64 {
        assert!(
            self.recorded.get(),
            "a turn ran before the configuration was recorded"
        );
        self.last_us = now;
        let sampled = self.storage();
        let before = samples_taken(sampled);
        let projection = self.history.clock.unwrap_or_else(|| ticks(now));
        set_clock(self.storage(), &[Some(projection)]);
        if let Some(peer) = &self.peer {
            peer.set_clock(ticks(now));
        }
        let outcome = crate::sim::chaos::acting(|| self.apply_event(event, now));
        histories::settle(self);
        self.watch_episodes(now);
        if event.0[0] == Domain::Put as u8 {
            self.log_put(&event, outcome);
        }
        // A publication with another upload planned retires once the device
        // returned the slots it held, so the next upload can begin.
        if self.plan.puts > 0
            && let Some(put) = self.put.as_mut()
            && put.outcome == Some(UploadOutcome::Published)
            && !put.retired
        {
            put.retired = self.scene.clients[0].retire(put.id);
        }
        if self.plan.plant == Plant::Panic && self.published() {
            panic!("a planted panic once the upload published");
        }
        if self.plan.plant == Plant::DebugAssertion {
            debug_assert!(
                !self.published(),
                "a planted debug assertion once the upload published"
            );
        }
        let due = match self.plan.plant {
            Plant::PublishedByte => self.published(),
            Plant::SettledByte => self.reached.get().is_some(),
            _ => false,
        };
        if due
            && self.planted.is_none()
            && let Some(record) = self.binding(PUT_KEY)
            && bundle::change_published(&self.scene, PUT_KEY)
        {
            self.planted = Some(record);
        }
        if self.plan.plant == Plant::LeakedUnit && self.published() && !self.leaked {
            self.leaked = crate::storage::owner_fixture::leak_unit(self.storage());
        }
        // A relaunch replaces the storage, whose samples all fall in this
        // turn under the tick the relaunch armed on it.
        let (taken, projection) = match self.attached.take() {
            Some(tick) => (samples_taken(self.storage()), tick),
            None => (samples_taken(sampled) - before, projection),
        };
        if taken > 0 {
            self.clocks.push(Clock {
                now,
                projection,
                taken,
                last: last_sample(self.storage()),
            });
        }
        let binding = self.binding(PUT_KEY);
        self.bound |= binding.is_some();
        self.seen.push(Seen {
            epoch: self.scene.owner.key_epoch(),
            states: [0, 1].map(|client| self.scene.clients[client].state()),
            sessions: [0, 1].map(|client| self.scene.clients[client].session_epoch()),
            pending: [0, 1].map(|client| self.get_pending(client)),
            uploading: self.uploading(),
            live: {
                let census = self.scene.owner.census();
                census.active + census.draining
            },
            false_positives: self.scene.owner.report().false_positives,
            sources: self.scene.clients[0]
                .sources()
                .iter()
                .filter(|slot| slot.piece().is_some())
                .count(),
            receipt: self.put.as_ref().and_then(|put| {
                let (_, base, grant) = self.scene.clients[0].put_receipt(put.id)?;
                Some((base, grant))
            }),
            withheld: [0, 1].map(|net| self.scene.nets[net].borrow().withheld()),
            begins: self.scene.nets[0]
                .borrow()
                .rules()
                .captures()
                .iter()
                .filter(|capture| {
                    capture.kind == Some(Kind::PutBegin)
                        && matches!(capture.decision.drop, Some(super::rules::Dropped::Rule(_)))
                })
                .count(),
            frames: self.in_flight(),
            raw: self
                .storage()
                .pool_report()
                .and_then(|report| report.ledger)
                .map(|ledger| ledger.raw),
            writes: {
                let report = self.scene.owner.put_report();
                (report.write_commands, report.command_waits)
            },
            upload: self.put.as_ref().map(|put| {
                let receipt = self.scene.clients[0].put_receipt(put.id);
                (put.attempt, receipt.map_or(0, |(serial, _, _)| serial))
            }),
            device_held: self.scene.clients[0]
                .sources()
                .iter()
                .filter(|slot| slot.device_held())
                .count(),
            binding,
            written: self
                .scene
                .control
                .delivered(crate::storage::device::Operation::Write),
            nic: [0, 1].map(|net| self.scene.nets[net].borrow().nic_held()),
            copied: (0..4)
                .map(|at| self.scene.nets[at / 2].borrow().copied(at % 2))
                .max()
                .unwrap_or(0),
            captured: [0, 1].map(|net| self.scene.nets[net].borrow().rules().captures().len()),
            audited: [0, 1].map(|net| self.scene.nets[net].borrow().audit().records().len()),
            uploads: self
                .scene
                .clients
                .iter()
                .map(|client| client.live_uploads())
                .sum(),
            source_bytes: self
                .scene
                .clients
                .iter()
                .flat_map(|client| client.sources())
                .filter(|slot| slot.piece().is_some())
                .map(|slot| slot.bytes().len())
                .sum(),
            parked: self.scene.owner.parked_count(),
            duplicates: self.scene.owner.serve_report().duplicates,
        });
        outcome
    }

    fn observation(&mut self) -> [u8; crate::sim::trace::TURN_OBSERVATION] {
        std::mem::take(&mut self.collected).code()
    }

    fn progress(&self) -> u64 {
        self.progress
    }

    /// The goal held, then the plan's drain of further turns ran.
    fn done(&self) -> bool {
        if self.reached.get().is_none() && (self.goal)(self) {
            self.reached.set(Some((self.seen.len(), self.last_us)));
            crate::sim::chaos::silence();
        }
        self.reached
            .get()
            .is_some_and(|(at, _)| self.seen.len() >= at + self.plan.drain as usize)
    }

    fn defect(&self) -> Option<Defect> {
        self.draw_refusal
            .get()
            .map(Defect::Entropy)
            .or_else(|| {
                let peer = self.peer.iter().flat_map(|peer| peer.nets());
                self.scene
                    .nets
                    .iter()
                    .chain(peer)
                    .find_map(|net| net.borrow().draw_error())
                    .map(Defect::Choice)
            })
            .or_else(|| crate::sim::chaos::refusal().map(Defect::Choice))
    }

    /// Judges the living incarnation's tables first, so a failure the turn
    /// or clock move produced is in the first-failure cell before its events
    /// are appended. The conservation rule runs first; then a relaunched
    /// incarnation's accounts failure is recorded, and, when a clock move
    /// left them due, the living owner's and the peer owner's datagram
    /// accounts are judged, so a conservation failure at the same emission
    /// comes first.
    fn emit(&mut self, out: &mut Vec<Event>) {
        let before = self.lenses.judgments();
        if let Err(failure) = conserved(self.storage(), &mut self.lenses) {
            self.first.record(failure);
        }
        self.conserved += self.lenses.judgments() - before;
        if let Some(failure) = self.closed_accounts.take() {
            self.first.record(failure);
        }
        if std::mem::take(&mut self.accounts_due) {
            self.judge_accounts();
        }
        self.emit_into(out);
    }
}

const LIMITS: Limits = Limits {
    total: 20_000,
    same_time: 400,
    no_progress: 5_000,
};

/// The sites `plan`'s run draws at: [`sites`], an armed plan's chaos
/// points at the storage's actor, and a two-owner plan's peer key pair,
/// nonces and link faults.
fn sites_for(plan: &Plan) -> Vec<Site> {
    let mut sites = sites();
    if plan.chaos {
        sites.extend(crate::sim::chaos::sites(INDEX));
    }
    if plan.peer_owner {
        sites.push(key_pair_site(PEER_INDEX));
        sites.extend(PEER_ACTORS.map(nonce_site));
        sites.extend(PEER_LINKS.iter().flat_map(|&link| super::link::sites(link)));
    }
    sites
}

/// The sites a one-owner run draws at: the controller's, the index key
/// pair, each actor's nonce and both links' fault sites.
fn sites() -> Vec<Site> {
    let mut sites = vec![SITE, key_pair_site(INDEX)];
    sites.extend(ACTORS.map(nonce_site));
    sites.extend(LINKS.iter().flat_map(|&link| super::link::sites(link)));
    sites
}

/// What a run leaves for its test: the world's record, the report, and the
/// chooser to finish into a tape.
struct Ran {
    /// What the run settled to, for its relations.
    settled: relation::Settled,
    acts: Vec<Act>,
    seen: Vec<Seen>,
    clocks: Vec<Clock>,
    report: Report,
    /// The run's chooser, which nothing else holds once the scene ended.
    draws: Draws,
    /// Stopped boundaries the world observed.
    boundaries: usize,
    /// Conservation judgments the world's emissions made.
    conserved: u64,
    /// Whether the planted behavior broke a rule during the run:
    ///
    /// - a record's byte changed on the device, before the run or while a
    ///   later stopped boundary or the run's end found the record bound;
    /// - an acknowledged upload with no result, or an upload with an
    ///   unknown outcome, was reported published, and the clock then moved
    ///   or the run finished, which is when the world compares a collected
    ///   publication with the client's report;
    /// - a decided GET handed its client a changed byte, another key's
    ///   object or a byte of no object;
    /// - the Progress check judged client 1's episode past its bound;
    /// - the upload published under the planted panic or assertion;
    /// - the leaked-unit plant reserved its unit;
    /// - a multiplexer dropped a lease for the uncounted plant's swallow.
    acted: bool,
    /// Both links' and the device's audit, judged together.
    audit: Verdict,
    /// Each link's audited outcomes and committed captures.
    audits: Vec<Vec<Record>>,
    captures: Vec<Vec<Capture>>,
    put: Option<(Option<UploadOutcome>, u32)>,
    get: Option<(Option<Outcome>, bool)>,
    late: Vec<u64>,
    driver_calls: usize,
    /// The time setup left the actors at, where the run began.
    start: u64,
    /// The uploading client's GET outcome, when it issued one.
    own_get: Option<Option<Outcome>>,
    /// The local object's extent once it published, the extents pressure
    /// reserved, and the upload's bound extent at the end of the run.
    extents: Extents,
    /// Every GET the world collected.
    decided: Vec<Decided>,
    /// Every episode the world opened.
    episodes: Vec<Episode>,
    /// Contents the observation registry held at the end.
    registry: usize,
    /// The most commands the device held at once.
    commands: usize,
    /// Bytes of capacity the device's stores grew past their capacity at
    /// the start of the run.
    grown: usize,
    /// The owner's parked-GET counters at the end of the run.
    parked: super::parked::ParkedReport,
}

/// Device byte ranges of extents a run placed.
#[derive(Debug, Clone, Default)]
struct Extents {
    local: Option<std::ops::Range<usize>>,
    pressure: Vec<std::ops::Range<usize>>,
    upload: Option<std::ops::Range<usize>>,
}

impl Ran {
    /// The run's tape.
    fn finish(self) -> Vec<u8> {
        let draws = Rc::try_unwrap(self.draws).expect("the scene released the chooser");
        draws.into_inner().finish().expect("a well-formed tape")
    }

    fn kinds(&self) -> Vec<ActionKind> {
        self.acts.iter().map(|act| act.kind).collect()
    }

    fn first(&self, kind: ActionKind, outcome: impl Fn(u64) -> bool) -> Option<usize> {
        self.acts
            .iter()
            .find(|act| act.kind == kind && outcome(act.outcome))
            .map(|act| act.turn)
    }
}

/// Runs a mixed scenario under `profile` from `chooser`. The index key
/// pair and the owner's and both clients' boot nonces are drawn first, and
/// every fixture lives in the scene's scope. The run must report the plan's
/// observed failure.
fn mixed_with(
    chooser: Chooser,
    profile: &Profile,
    plan: Plan,
    goal: fn(&Mixed<'_, '_, '_>) -> bool,
) -> Ran {
    let (ran, first, _) = mixed_run(chooser, profile, plan, goal, LIMITS, &mut ());
    assert_eq!(
        first.as_ref(),
        plan.observed,
        "{}: the first failure a stopped boundary or teardown observed",
        profile.name
    );
    ran
}

/// A scratch directory beside the worker, new for each process, for the
/// cases that write bundles and run fresh worker processes.
pub(crate) fn scratch(name: &str) -> Result<std::path::PathBuf, String> {
    let worker = std::env::current_exe().map_err(|error| error.to_string())?;
    let dir = worker
        .parent()
        .ok_or("the worker has no directory")?
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    Ok(dir)
}

/// The files under the directory `root` whose bytes hold `needle`, text and
/// binary alike. A directory is walked; a root that is not a directory and
/// an entry that is neither a directory nor a regular file, a symlink
/// included in both, are each an error that names it.
pub(crate) fn files_holding(
    root: &std::path::Path,
    needle: &[u8],
) -> Result<Vec<std::path::PathBuf>, String> {
    let named =
        |path: &std::path::Path, error: std::io::Error| format!("{}: {error}", path.display());
    if !std::fs::symlink_metadata(root)
        .map_err(|error| named(root, error))?
        .is_dir()
    {
        return Err(format!("{} is not a directory", root.display()));
    }
    let (mut pending, mut holding) = (vec![root.to_path_buf()], Vec::new());
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).map_err(|error| named(&directory, error))? {
            let entry = entry.map_err(|error| named(&directory, error))?;
            let path = entry.path();
            let kind = entry.file_type().map_err(|error| named(&path, error))?;
            if kind.is_dir() {
                pending.push(path);
            } else if !kind.is_file() {
                return Err(format!(
                    "{} is neither a directory nor a regular file",
                    path.display()
                ));
            } else if memchr::memmem::find(
                &std::fs::read(&path).map_err(|error| named(&path, error))?,
                needle,
            )
            .is_some()
            {
                holding.push(path);
            }
        }
    }
    Ok(holding)
}

/// The draws a mixed run makes before its scene: the index key pair, then
/// the owner's and both clients' boot nonces, each actor launched first.
pub(super) fn setup_draws(
    chooser: &mut Chooser,
) -> Result<(crate::index::KeyHasher, [[u8; 16]; ACTORS.len()]), DrawRefusal> {
    setup_draws_at(chooser, INDEX, ACTORS)
}

/// [`setup_draws`] at the key pair site of `index` and the nonce sites of
/// `actors`.
fn setup_draws_at(
    chooser: &mut Chooser,
    index: u16,
    actors: [u16; 3],
) -> Result<(crate::index::KeyHasher, [[u8; 16]; 3]), DrawRefusal> {
    let incarnation = chooser.launch(index);
    let hasher = key_pair(chooser, key_pair_site(index), incarnation)?;
    let mut nonces = [[0; 16]; 3];
    for (actor, bytes) in actors.into_iter().zip(&mut nonces) {
        let incarnation = chooser.launch(actor);
        draw(chooser, nonce_site(actor), incarnation, bytes)?;
    }
    Ok((hasher, nonces))
}

fn setup_or_fallback(
    chooser: &mut Chooser,
    index: u16,
    actors: [u16; 3],
    refused: &mut Option<DrawRefusal>,
) -> (crate::index::KeyHasher, [[u8; 16]; 3]) {
    setup_draws_at(chooser, index, actors).unwrap_or_else(|refusal| {
        refused.get_or_insert(refusal);
        (
            crate::index::KeyHasher::with_key_pair(0, 0),
            actors.map(|actor| [actor as u8; 16]),
        )
    })
}

/// Sets `plan`'s link bounds, transmit returns, faults, rules, refused
/// sends and length limit on an incarnation's two links.
fn wire(plan: &Plan, nets: &[Rc<RefCell<super::link::Net<'_>>>; 2]) {
    for net in nets {
        net.borrow_mut().set_limits(plan.link);
    }
    for net in nets {
        net.borrow_mut().set_tx_release(plan.tx_release());
    }
    if plan.lose_upload {
        let lost = Faults {
            loss: 100,
            ..Faults::default()
        };
        nets[0].borrow_mut().set_faults(1, lost);
    }
    if plan.link_faults {
        let faults = Faults {
            loss: 10,
            duplicate: 10,
            reorder: 10,
            delay: 2,
            ..Faults::default()
        };
        for net in nets {
            let mut net = net.borrow_mut();
            net.set_faults(0, faults);
            net.set_faults(1, faults);
        }
    }
    for (at, net) in nets.iter().enumerate() {
        let mut rules = Vec::new();
        if plan.link_faults {
            rules.push(Rule::new(Selector::Kind(Kind::Data), Effect::Delay(1)).window(1, 3));
        }
        if plan.drop_result && at == 0 {
            rules.push(Rule::new(Selector::Kind(Kind::PutResult), Effect::Drop));
        }
        if plan.drop_begin && at == 0 {
            rules.push(Rule::new(Selector::Kind(Kind::PutBegin), Effect::Drop));
        }
        if plan.drop_first_result && at == 0 {
            let first = Rule::new(Selector::Kind(Kind::PutResult), Effect::Drop).window(0, 1);
            rules.push(first);
        }
        if !rules.is_empty() {
            let committed = [rules.len()];
            let taps: &[usize] = if plan.link_faults {
                &[1]
            } else if plan.drop_begin || plan.drop_first_result {
                &committed
            } else {
                &[]
            };
            net.borrow_mut()
                .set_rules(Chain::new(rules, taps, &MANIFEST).unwrap());
        }
    }
    if plan.unattributed {
        nets[0].borrow_mut().fail_unattributed();
    }
    if plan.short_link {
        nets[1]
            .borrow_mut()
            .set_max_len(super::datagram::HEADER_LEN);
    }
}

/// Arms the chaos points for the storage actor in `incarnation`.
///
/// # Panics
///
/// If `storage` is drained.
fn arm_over(
    draws: &Draws,
    storage: &Storage<TestPlatform>,
    incarnation: u32,
) -> crate::sim::chaos::Arming {
    let root = storage.root_descriptor();
    let limit = root
        .expect("an armed run starts on a live storage")
        .lease_limit;
    let odds = crate::sim::chaos::odds_within(limit);
    crate::sim::chaos::arm(draws, (INDEX, incarnation), odds)
}

/// [`mixed_with`] under `limits`, streaming into `hook`; returns the run,
/// the first failure a stopped boundary or teardown observed, and the
/// upload actions the world emitted.
fn mixed_run(
    chooser: Chooser,
    profile: &Profile,
    plan: Plan,
    goal: fn(&Mixed<'_, '_, '_>) -> bool,
    limits: Limits,
    hook: &mut impl Hook,
) -> (Ran, Option<Failure>, u64) {
    // A wide-unit run holds its devices' unit until it returns, and draws
    // one fixture session ahead of its scene, so the tenure's session has a
    // lower one a probe can attach under.
    let mut _unit = None;
    if plan.geometry == Geometry::WideUnit {
        use crate::storage::volume_fixture::{BUFFER, Unit};
        _unit = Some(Unit::hold(BUFFER));
        let _ = crate::storage::next_session();
    }
    let draws: Draws = Rc::new(RefCell::new(chooser));
    let mut registered = Registry::new(MANIFEST.captures);
    // The object the scene's owner publishes before the run.
    registered.register(key(1), Label(1), 0, payload(1000, 1));
    let registry = Rc::new(RefCell::new(registered));
    let first = FirstFailure::default();
    let mut refused = None;
    let (hasher, nonces) = setup_or_fallback(&mut draws.borrow_mut(), INDEX, ACTORS, &mut refused);
    let shaped = |hasher| {
        let mut storage = plan.geometry.storage();
        storage.install_hasher(if plan.collide {
            crate::index::KeyHasher::with_seam(colliding)
        } else {
            hasher
        });
        storage
    };
    let storage = shaped(hasher);
    // Each later incarnation draws its index key pair and boot nonces as
    // the first one did, as its actors' next incarnations. A warm load
    // fingerprints each restored key under the successor's own pair.
    let mut successors: Vec<_> = (0..plan.relaunches)
        .map(|_| {
            let (hasher, nonces) =
                setup_or_fallback(&mut draws.borrow_mut(), INDEX, ACTORS, &mut refused);
            Successor {
                storage: shaped(hasher),
                nonces,
                links: LINKS,
                relaunched: true,
            }
        })
        .collect();
    // The peer draws its setup after every incarnation of the scripted
    // owner, at its own actors' sites.
    if plan.peer_owner {
        let (hasher, nonces) = setup_or_fallback(
            &mut draws.borrow_mut(),
            PEER_INDEX,
            PEER_ACTORS,
            &mut refused,
        );
        successors.push(Successor {
            storage: shaped(hasher),
            nonces,
            links: PEER_LINKS,
            relaunched: false,
        });
    }
    let object = payload(plan.object_len as usize, 30);
    let mut ran = None;
    let mut puts = 0;
    let mut settle_accounts = None;
    let config = OwnerConfig {
        peer_requests: plan.share.unwrap_or(OWNER.peer_requests),
        maintain_work: if plan.manual_maintenance {
            0
        } else {
            OWNER.maintain_work
        },
        batch: plan.owner_batch(),
        put: super::put::PutConfig {
            commands: plan.put_commands.unwrap_or(OWNER.put.commands),
            ..OWNER.put
        },
        follow: plan.follow.unwrap_or(OWNER.follow),
        ..OWNER
    };
    let drawn = Drawn {
        nonces,
        draws: &draws,
        links: LINKS,
    };
    let scene = (config, plan.second_sources);
    scene_relaunching(storage, scene, drawn, successors, |scene, mut fresh| {
        let peer = plan
            .peer_owner
            .then(|| fresh.pop().expect("the peer's resources"));
        // The scripted scene holds `bundle::TOPOLOGY`'s one owner and its
        // clients; in a two-owner plan the stop event adds the peer's owner
        // and clients, as `bundle::composition` counts them.
        assert_eq!(
            usize::from(bundle::TOPOLOGY.1),
            scene.clients.len(),
            "the stop event's client count is the scene's"
        );
        let built = scene.control.footprint().reserved.total();
        wire(&plan, &scene.nets);
        if plan.corrupt_resident {
            let (mut bindings, mut facts) = (Vec::new(), Vec::new());
            scene.storage.bindings_into(&mut bindings).unwrap();
            scene.storage.slot_facts_into(&mut facts).unwrap();
            let media = facts[bindings[0].identity.slot as usize].media().unwrap();
            bundle::flip_payload(&scene.control, media);
        }
        let start = scene.turn * LINK_TURN_US;
        // The observer records the teardown verdict in `first`; constructed
        // before `world`, it drops after `world` and judges a panicking run
        // during panic unwinding.
        let mut observer = Observer::new(
            scene.media(),
            Rc::clone(&registry),
            Rc::new(RefCell::new(Vec::new())),
            first.clone(),
        )
        .quiet();
        let life = super::restart::Lifecycle::new(
            super::restart::Manifest {
                slots: 1,
                restarts: plan.relaunches as usize,
                bundles: 1,
            },
            scene.control.shared_media(),
            scene
                .buffers
                .expect("the scene's owner holds its buffer arena"),
            first.clone(),
        );
        let peer = peer.map(|fresh| peer::Peer::started(fresh, config, &plan, start));
        let mut living = Some(scene);
        let mut world = Mixed {
            scene: relaunch::Living(&mut living),
            relaunches: relaunch::Relaunches {
                life,
                fresh,
                config,
                audit: Verdict::Pass,
            },
            observer: &mut observer,
            peer,
            draws: Rc::clone(&draws),
            profile,
            plan,
            configured: plan,
            start,
            owner_due: start,
            service_due: start,
            key: key(PUT_KEY),
            object: object.clone(),
            read: if plan.read_stranger {
                (key(STRANGER), Vec::new())
            } else if plan.read_resident {
                (key(1), payload(1000, 1))
            } else {
                (key(PUT_KEY), object.clone())
            },
            late: Vec::new(),
            gets: [None, None],
            overlapping_get: None,
            polled: [false; 2],
            held: Vec::new(),
            put: None,
            attempts: 0,
            local: Local::Unfilled,
            reader: None,
            acquired: false,
            pressure: Pressure::Idle,
            expired: false,
            evicted: false,
            closed: false,
            owner_polls: 0,
            updates: Vec::new(),
            acts: Vec::new(),
            refused: Vec::new(),
            clocks: Vec::new(),
            attached: None,
            seen: Vec::new(),
            progress: 0,
            recorded: std::cell::Cell::new(false),
            registry: Rc::clone(&registry),
            lenses: Lenses::default(),
            first: first.clone(),
            boundaries: 0,
            accounts_due: false,
            closed_accounts: None,
            conserved: 0,
            leaked: false,
            swallowed: false,
            goal,
            log: Vec::new(),
            emitted: bundle::Emitted::default(),
            planted: None,
            exposed: false,
            handed: false,
            bound: false,
            acked_at: None,
            stalled: false,
            scripted: 0,
            history: histories::State::default(),
            draw_refusal: std::cell::Cell::new(refused),
            reached: std::cell::Cell::new(None),
            last_us: start,
            local_media: None,
            pressure_media: Vec::new(),
            decided: Vec::new(),
            collected: bundle::Collected::Absent,
            episodes: Vec::new(),
            scratch: Scratch::default(),
        };
        let incarnation = draws.borrow_mut().launch(SITE.actor);
        let armed = plan.chaos.then(|| {
            // A script step's storage reads run inside `acting`, where an
            // armed point would refuse the harness's own read.
            assert!(
                plan.relaunches == 0 && !plan.peer_owner && plan.script.is_empty(),
                "an armed plan runs one storage incarnation and no script"
            );
            let storage = draws.borrow().incarnation(INDEX);
            let storage = storage.expect("setup launched the storage's actor");
            arm_over(&draws, world.scene.storage, storage)
        });
        let report = run_hooked(
            &mut world,
            profile,
            &draws,
            (SITE, incarnation),
            limits,
            hook,
        );
        // Points decide only inside a turn's action, and the loop polls
        // `World::defect` after each one, so a latched refusal has already
        // ended the run.
        let latched = armed.and_then(crate::sim::chaos::Arming::disarm);
        assert!(
            latched.is_none() || matches!(report.end, End::Defect(_)),
            "a latched chaos refusal ended the run: {latched:?}"
        );
        puts = world.emitted.puts;
        // A run that finishes ran no stopped boundary after its last turn,
        // so a publication that turn collected is compared here.
        if report.end == End::Done {
            world.judge_claim();
        }
        // The observer's teardown reads the media every run ends with.
        world.expose();
        if let Some(peer) = &mut world.peer
            && let Err(failure) = peer.boundary(&registry.borrow())
        {
            world.first.record(failure);
        }
        // The final accounts check covers datagrams delivered after the last
        // clock move. It reads the reports while the scene lives and records
        // after the observer's teardown judgment, so a final boundary
        // failure comes first.
        settle_accounts = world.accounts_failure();
        if matches!(report.end, End::Defect(_)) {
            let peer = world.peer.iter().flat_map(|peer| peer.nets());
            for net in world.scene.nets.iter().chain(peer) {
                net.borrow_mut().take_draw_error();
            }
        }
        let index = world.living_device();
        let living = judged(
            &world.scene.nets,
            &world.scene.control,
            index,
            plan.declared,
        );
        let living = match &world.peer {
            Some(peer) => living.then(peer.judged(plan.declared)),
            None => living,
        };
        let audit = world.relaunches.audit.then(living);
        let settled = relation::settled(&world, &report, audit, profile, limits);
        ran = Some(Ran {
            settled,
            put: world.put.as_ref().map(|put| (put.outcome, put.deferrals)),
            get: world.gets[1]
                .as_ref()
                .map(|get| (get.outcome, get.bytes == world.read.1)),
            driver_calls: world.scene.control.driver_calls(),
            own_get: world.gets[0].as_ref().map(|get| get.outcome),
            extents: Extents {
                local: world.local_media.clone(),
                pressure: world.pressure_media.clone(),
                upload: bundle::bound_media(&world.scene, PUT_KEY),
            },
            audit,
            boundaries: world.boundaries,
            conserved: world.conserved,
            acted: plan.corrupt_resident
                || world.exposed
                || world.handed
                || match plan.plant {
                    Plant::StalledHeal => world.stalled,
                    Plant::AckAsSuccess | Plant::UnknownAsSuccess | Plant::ContendedAsSuccess => {
                        world
                            .acked_at
                            .is_some_and(|at| report.virtual_us > at || report.end == End::Done)
                    }
                    Plant::Panic | Plant::DebugAssertion => world.published(),
                    Plant::LeakedUnit => world.leaked,
                    Plant::Uncounted | Plant::UncountedPeer => world.swallowed,
                    _ => false,
                },
            audits: links(&world)
                .map(|net| net.borrow().audit().records().to_vec())
                .collect(),
            captures: links(&world)
                .map(|net| net.borrow().rules().captures().to_vec())
                .collect(),
            decided: std::mem::take(&mut world.decided),
            episodes: std::mem::take(&mut world.episodes),
            registry: registry.borrow().len(),
            commands: world.scene.control.footprint().device,
            grown: world
                .scene
                .control
                .footprint()
                .reserved
                .total()
                .saturating_sub(built),
            parked: world.scene.owner.report().parked,
            acts: std::mem::take(&mut world.acts),
            seen: std::mem::take(&mut world.seen),
            clocks: std::mem::take(&mut world.clocks),
            late: std::mem::take(&mut world.late),
            report,
            draws: Rc::clone(&draws),
            start,
        });
        let events = std::mem::take(&mut world.history.events);
        COHORT_EVENTS.with(|cohort| *cohort.borrow_mut() = events);
        drop(world);
        drop(observer);
        if let Some(failure) = settle_accounts.take() {
            first.record(failure);
        }
    });
    let mut ran = ran.expect("the scene ran");
    // The observer's teardown verdict joins the settled obligations.
    ran.settled.first = first.get();
    (ran, first.get(), puts)
}

/// The scripted owner's links, then a peer owner's, in link-index order.
fn links<'a, 'm>(
    world: &'a Mixed<'_, '_, 'm>,
) -> impl Iterator<Item = &'a Rc<RefCell<super::link::Net<'m>>>> {
    let peer = world.peer.iter().flat_map(|peer| peer.nets());
    world.scene.nets.iter().chain(peer)
}

/// One incarnation's two links' verdicts and its device's audit, whose
/// records carry device index `index`, under the `declared` production
/// outcomes: the first failure, else the first inconclusive bound, else a
/// pass.
fn judged(
    nets: &[Rc<RefCell<super::link::Net<'_>>>; 2],
    control: &crate::storage::owner_fixture::SimControl,
    index: u16,
    declared: &[Reason],
) -> Verdict {
    let mut device = Audit::new(MANIFEST.records);
    device.absorb(control, index);
    let links = nets[0].borrow().verdict(declared);
    links
        .then(nets[1].borrow().verdict(declared))
        .then(device.verdict(declared))
}

thread_local! {
    /// The cohort events the last mixed run on this thread recorded.
    static COHORT_EVENTS: RefCell<Vec<histories::Event>> = const { RefCell::new(Vec::new()) };
}

/// Collects every event a run emits.
#[derive(Default)]
struct Events(Vec<Event>);

impl Hook for Events {
    fn clock(&mut self, _: &[u8], _: u64, events: &[Event]) {
        self.0.extend_from_slice(events);
    }

    fn turn(&mut self, _: &[u8], _: &crate::sim::turn::Turn, events: &[Event]) {
        self.0.extend_from_slice(events);
    }
}

/// Takes the cohort events the last mixed run on this thread recorded.
fn take_cohort_events() -> Vec<histories::Event> {
    COHORT_EVENTS.with(|events| std::mem::take(&mut *events.borrow_mut()))
}

fn mixed(profile: &Profile, plan: Plan, goal: fn(&Mixed<'_, '_, '_>) -> bool) -> Ran {
    mixed_with(profile.recorder(&sites_for(&plan)), profile, plan, goal)
}

fn published_then_read(world: &Mixed<'_, '_, '_>) -> bool {
    world.published()
        && world.gets[1]
            .as_ref()
            .is_some_and(|get| get.outcome == Some(Outcome::Complete))
}

fn exactly_read(world: &Mixed<'_, '_, '_>) -> bool {
    published_then_read(world)
        && world.gets[1]
            .as_ref()
            .is_some_and(|get| get.bytes == world.read.1)
}

/// [`exactly_read`], once every metadata command the volume submitted has ended within the run.
fn exactly_read_settled(world: &Mixed<'_, '_, '_>) -> bool {
    exactly_read(world) && metadata_settled(world)
}

fn metadata_settled(world: &Mixed<'_, '_, '_>) -> bool {
    let volume = world.scene.owner.volume_report();
    volume.metadata_submitted == volume.metadata_done + volume.metadata_failed
}

/// Every declared kind ran with its witness, every issued GET decided, at
/// least one episode opened, and every episode settled as
/// [`Episode::healed`] requires.
fn healed(world: &Mixed<'_, '_, '_>) -> bool {
    world.covered()
        && world.gets.iter().flatten().all(|get| get.outcome.is_some())
        && !world.episodes.is_empty()
        && world.episodes.iter().all(Episode::healed)
}

/// Every declared kind ran with its witness, and the owner refused a GET
/// for the stranger key as `Missing`.
fn refused_read(world: &Mixed<'_, '_, '_>) -> bool {
    world.covered()
        && world
            .decided
            .iter()
            .any(|got| got.key == key(STRANGER) && got.outcome == Outcome::Missing)
}

fn get_decided(world: &Mixed<'_, '_, '_>) -> bool {
    world.gets[1]
        .as_ref()
        .is_some_and(|get| get.outcome.is_some())
}

const UPLOAD: [ActionKind; 6] = [
    ActionKind::Get,
    ActionKind::Read,
    ActionKind::PutInvoke,
    ActionKind::PutPrepare,
    ActionKind::Supply,
    ActionKind::PutOutcome,
];

fn upload_profile(root: u64) -> Profile {
    Profile {
        name: "mixed upload then exact read",
        declared: UPLOAD.to_vec(),
        root,
    }
}

const UPLOAD_PLAN: Plan = Plan {
    gets: [0, 1],
    puts: 1,
    read_after_publish: true,
    ..QUIET
};

/// The disk turns of a report, as each selected entry's stage and its
/// acceptance ordinal.
fn disk_turns(report: &Report) -> Vec<(usize, u8, u64)> {
    report
        .turns
        .iter()
        .enumerate()
        .filter(|(_, turn)| turn.event.0[0] == Domain::Disk as u8)
        .map(|(at, turn)| {
            let ordinal = u64::from_be_bytes(turn.event.0[2..10].try_into().expect("eight bytes"));
            (at, turn.event.0[1], ordinal)
        })
        .collect()
}

/// How many of the newest datagrams in flight, one per direction of each
/// link of `nets`, parse as frames, with each other one's parse error at
/// twice its link's index plus the end it travels toward. A datagram toward
/// the owner, end 1 of its link, is read as the owner reads it
/// ([`refused_frame`]).
fn in_flight(
    nets: &[std::rc::Rc<std::cell::RefCell<super::link::Net<'_>>>; 2],
) -> (usize, [Option<super::frame::FrameError>; 4]) {
    let mut parsed = 0;
    let mut errors = [None; 4];
    for (at, error) in errors.iter_mut().enumerate() {
        let Some(bytes) = nets[at / 2].borrow().peek(at % 2) else {
            continue;
        };
        match refused_frame(&bytes, at % 2 == 1) {
            None => parsed += 1,
            refused => *error = refused,
        }
    }
    (parsed, errors)
}

/// The first parse error among the frames of `bytes`, or `None` when every
/// frame parses. A datagram toward the owner that is a packed datagram is
/// read frame by frame, as the owner reads it; every other datagram is one
/// frame.
fn refused_frame(bytes: &[u8], toward_owner: bool) -> Option<super::frame::FrameError> {
    let crc = crate::storage::Crc32c::detect();
    let refused = |frame: &[u8]| super::frame::parse(crc, frame, false).err();
    if toward_owner && !bytes.is_empty() {
        super::rules::frames_of(bytes).find_map(refused)
    } else {
        refused(bytes)
    }
}

/// The in-flight observer reads a packed datagram toward the owner frame by
/// frame and counts it once. Over two links, two valid GET frames back to
/// back toward the owner parse, and the same bytes toward a client are one
/// frame, which the parser refuses for the bytes after its header. The same
/// datagram with a nonzero reserved byte in its second frame alone records
/// `Reserved` toward the owner. A 384-byte PUT DATA datagram toward the
/// owner parses whole, and an empty datagram records a parse error.
#[test]
fn the_in_flight_observer_reads_a_packed_datagram_frame_by_frame() {
    use super::frame::FrameError;
    let faults = [Faults::default(); 2];
    let (_near0, _far0, first) = super::link::network(8, 8384, 41, faults);
    let (_near1, _far1, second) = super::link::network(8, 8384, 42, faults);
    let nets = [first, second];
    assert_eq!(
        in_flight(&nets),
        (0, [None; 4]),
        "empty queues count nothing"
    );
    let get = |request| {
        let raw = super::frame_tests::Raw::get();
        super::frame_tests::Raw { request, ..raw }
    };
    let packed = [get(1).bytes(), get(2).bytes()].concat();
    assert_eq!(packed.len(), 384);
    nets[0].borrow_mut().inject(1, &packed);
    nets[1].borrow_mut().inject(0, &packed);
    let (parsed, errors) = in_flight(&nets);
    assert_eq!(
        parsed, 1,
        "the packed datagram toward the owner counts once"
    );
    assert_eq!((errors[0], errors[1], errors[3]), (None, None, None));
    assert!(
        matches!(errors[2], Some(FrameError::DatagramLen { .. })),
        "toward a client the two frames are one datagram: {errors:?}"
    );
    let reserved = [get(1).bytes(), get(2).edited(|bytes| bytes[14] = 1)].concat();
    nets[0].borrow_mut().inject(1, &reserved);
    let (parsed, errors) = in_flight(&nets);
    assert_eq!((parsed, errors[1]), (0, Some(FrameError::Reserved)));
    let base = super::frame::parse(crate::storage::Crc32c::detect(), &get(3).bytes(), false)
        .unwrap()
        .header();
    let (data, _) = super::frame_tests::put_frame(Kind::PutData, &base);
    let data = super::frame::Header {
        total: 192,
        body_len: 192,
        datagram_len: 192,
        ..data
    };
    let mut whole = vec![0u8; 192];
    super::frame::encode(
        crate::storage::Crc32c::detect(),
        &data,
        [&[0x3C; 192], &[]],
        (&mut whole[..]).try_into().unwrap(),
    )
    .unwrap();
    whole.extend_from_slice(&[0x3C; 192]);
    nets[0].borrow_mut().inject(1, &whole);
    nets[1].borrow_mut().inject(1, &[]);
    let (parsed, errors) = in_flight(&nets);
    assert_eq!(
        (parsed, errors[1]),
        (1, None),
        "a 384-byte PUT DATA datagram toward the owner is one frame"
    );
    assert!(errors[3].is_some(), "an empty datagram is a parse error");
}

/// A generated schedule publishes the client's upload through invoke,
/// preparation, supply and outcome collection, and the other client's GET
/// after it reads the uploaded bytes exactly; every declared kind runs with
/// its witness, disk commands execute and post as separate selected events,
/// the record precedes the turns, checked work and time are reported apart,
/// and the schedule replays from its tape to the same turns and supplier
/// order.
#[test]
fn a_generated_upload_publishes_and_a_later_get_reads_its_bytes() {
    let (mut executed, mut interleaved) = (false, false);
    for root in 1..=4 {
        let profile = upload_profile(root);
        let ran = mixed(&profile, UPLOAD_PLAN, exactly_read_settled);
        let report = &ran.report;
        assert_eq!(report.end, End::Done, "root {root}");
        assert_eq!(ran.audit, Verdict::Pass, "root {root}");
        assert!(ran.boundaries > 0, "root {root}");
        assert!(report.record.starts_with(&profile.record()));
        for kind in UPLOAD {
            assert!(
                ran.acts
                    .iter()
                    .any(|act| act.kind == kind && witnessed(kind, act.outcome)),
                "root {root}: {kind:?} never ran with its witness"
            );
        }
        assert!(
            report
                .turns
                .windows(2)
                .all(|pair| pair[0].now <= pair[1].now)
        );
        assert!(report.progress > 0 && report.wall > std::time::Duration::ZERO);
        assert!(report.skipped_us <= report.virtual_us);
        let disk = disk_turns(report);
        let execute = disk.iter().filter(|turn| turn.1 == Stage::Execute as u8);
        for &(at, _, ordinal) in execute {
            let post = |turn: &&(usize, u8, u64)| turn.2 == ordinal && turn.1 == Stage::Post as u8;
            let posted = disk
                .iter()
                .find(post)
                .expect("every executed command posts");
            assert!(at < posted.0, "root {root}: execute precedes post");
            interleaved |= posted.0 > at + 1;
        }
        executed |= disk.iter().any(|turn| turn.1 == Stage::Execute as u8);
        let (kinds, turns, record) = (
            ran.kinds(),
            ran.report.turns.clone(),
            ran.report.record.clone(),
        );
        let tape = ran.finish();
        let replay = Chooser::replay(&sites_for(&UPLOAD_PLAN), tape);
        let again = mixed_with(replay, &profile, UPLOAD_PLAN, exactly_read_settled);
        assert_eq!(
            again.report.turns, turns,
            "root {root}: the tape replays every turn"
        );
        assert_eq!(
            again.kinds(),
            kinds,
            "root {root}: and every supplier input in order"
        );
        assert_eq!(again.report.record, record, "root {root}: the same record");
        again.finish();
    }
    assert!(executed, "some root executed a command before posting it");
    assert!(
        interleaved,
        "some command's execute and post were separate turns with work between"
    );
}

/// Events runnable at one time run in orders the root selects: for some
/// pair of roots, the first three turns at the start time hold the same
/// events in different orders.
#[test]
fn equal_time_events_run_in_distinct_orders_across_roots() {
    let at_start: Vec<Vec<Candidate>> = (1..=8)
        .map(|root| {
            let ran = mixed(&upload_profile(root), UPLOAD_PLAN, published_then_read);
            let start = ran
                .report
                .turns
                .iter()
                .take_while(|turn| turn.now == ran.start);
            start.map(|turn| turn.event).take(3).collect()
        })
        .collect();
    let reordered = at_start.iter().enumerate().any(|(a, left)| {
        at_start[a + 1..].iter().any(|right| {
            let (mut l, mut r) = (left.clone(), right.clone());
            l.sort();
            r.sort();
            l == r && left != right
        })
    });
    assert!(reordered, "{at_start:?}");
}

/// The run begins where setup left the actors: the first turn runs at the
/// scene's time, so the owner, the clients and the links see one clock that
/// only moves forward across the handoff.
#[test]
fn the_run_starts_at_the_scene_time() {
    let ran = mixed(&upload_profile(1), UPLOAD_PLAN, published_then_read);
    assert!(ran.start > 0, "setup moved the actors forward");
    assert_eq!(ran.report.turns[0].now, ran.start);
}

/// Every owner-side turn consumes only its own projection: the samples it
/// took leave the platform at the turn's tick, so no turn consumes a sample
/// another turn armed.
#[test]
fn each_turns_clock_samples_equal_its_projection() {
    let ran = mixed(&upload_profile(3), UPLOAD_PLAN, exactly_read);
    assert_eq!(ran.report.end, End::Done);
    assert!(!ran.clocks.is_empty());
    for clock in ran.clocks {
        assert!(clock.taken > 0);
        assert_eq!(clock.projection, ticks(clock.now), "{clock:?}");
        assert_eq!(clock.last, Some(clock.projection), "{clock:?}");
    }
}

/// An upload whose supplier only defers stalls, yet the other client's
/// GET of a resident object, proposed only once the stall began, reads it
/// exactly beside the stall; a profile
/// that requires the upload then ends `Inconclusive`, never `Done`, as does
/// one that never proposes the PUT.
#[test]
fn a_stalled_supplier_leaves_an_eligible_get_completing() {
    let profile = Profile {
        name: "stalled upload beside a GET",
        declared: [UPLOAD.as_slice(), &[ActionKind::DeferSupply]].concat(),
        root: 5,
    };
    let stalled = Plan {
        withhold: u32::MAX,
        read_after_publish: false,
        read_during_stall: true,
        read_resident: true,
        ..UPLOAD_PLAN
    };
    let ran = mixed(&profile, stalled, get_decided);
    assert_eq!(
        ran.report.end,
        End::Done,
        "the GET completed beside the stalled upload"
    );
    assert_eq!(
        ran.get,
        Some((Some(Outcome::Complete), true)),
        "an exact read"
    );
    assert!(
        matches!(ran.put, Some((None, deferrals)) if deferrals > 0),
        "{:?}",
        ran.put
    );
    let deferred = ran.first(ActionKind::DeferSupply, |_| true).unwrap();
    let read = ran
        .first(ActionKind::Read, |outcome| outcome != REFUSED)
        .unwrap();
    assert!(deferred < read);
    let required = mixed(&profile, stalled, published_then_read).report;
    assert!(
        matches!(required.end, End::Inconclusive(_)),
        "{:?}",
        required.end
    );
    let free = mixed(&profile, UPLOAD_PLAN, published_then_read).report;
    assert_ne!(
        free.record, required.record,
        "another plan is another record"
    );
    let unproposed = Profile {
        name: "no PUT proposed",
        declared: vec![ActionKind::Get, ActionKind::Read],
        root: 5,
    };
    let end = mixed(&unproposed, UPLOAD_PLAN, published_then_read)
        .report
        .end;
    assert!(matches!(end, End::Inconclusive(_)), "{end:?}");
}

/// A supplier that defers three times and then becomes ready publishes,
/// and the later GET reads the uploaded bytes exactly.
#[test]
fn a_supplier_ready_after_deferring_publishes_for_an_exact_read() {
    let profile = Profile {
        name: "deferring then ready upload",
        declared: [UPLOAD.as_slice(), &[ActionKind::DeferSupply]].concat(),
        root: 6,
    };
    let healed = Plan {
        withhold: 3,
        ..UPLOAD_PLAN
    };
    let ran = mixed(&profile, healed, exactly_read);
    assert_eq!(ran.report.end, End::Done);
    let supplied = ran
        .first(ActionKind::Supply, |outcome| outcome != REFUSED)
        .unwrap();
    let deferrals = ran
        .acts
        .iter()
        .filter(|act| act.kind == ActionKind::DeferSupply && act.turn < supplied);
    assert!(deferrals.count() >= 3);
}

/// A session change and a rekey are held until their delivery events: from
/// each enqueue to its delivery every turn leaves the client's session and
/// the owner's key epoch as they were, and the delivery turn changes them,
/// its result recorded as that event's outcome.
#[test]
fn held_updates_apply_only_at_their_delivery() {
    let profile = Profile {
        name: "held updates",
        declared: vec![ActionKind::Rekey, ActionKind::SessionChange],
        root: 8,
    };
    let plan = Plan {
        sessions: 1,
        rekeys: 1,
        ..QUIET
    };
    let delivered = |world: &Mixed<'_, '_, '_>| {
        world.updates.is_empty() && world.plan.rekeys == 0 && world.plan.sessions == 0
    };
    let ran = mixed(&profile, plan, delivered);
    assert_eq!(ran.report.end, End::Done);
    for kind in [ActionKind::Rekey, ActionKind::SessionChange] {
        let held = ran.first(kind, |outcome| outcome == HELD).unwrap();
        let applied = ran.first(kind, |outcome| outcome > HELD).unwrap();
        assert!(held < applied, "{kind:?}");
        let view = |seen: &Seen| match kind {
            ActionKind::Rekey => (seen.epoch, [SessionState::Idle; 2], [None; 2]),
            _ => (0, seen.states, seen.sessions),
        };
        for turn in held..applied {
            let (now, then) = (view(&ran.seen[turn]), view(&ran.seen[held]));
            assert_eq!(now, then, "{kind:?} applied before its delivery");
        }
        let (after, before) = (view(&ran.seen[applied]), view(&ran.seen[applied - 1]));
        assert_ne!(after, before, "{kind:?} applied at its delivery");
    }
    assert!(
        ran.first(ActionKind::Rekey, |outcome| outcome == REKEYED)
            .is_some()
    );
    let session = ran
        .first(ActionKind::SessionChange, |outcome| outcome == DELIVERED)
        .unwrap();
    assert!(ran.seen[session].states.contains(&SessionState::Opening));
}

/// A rekey delivered while the GET client's request is live is refused
/// busy, the refusal is that delivery's recorded outcome, and the key epoch
/// stays; some root delivers it while the request is live.
#[test]
fn a_busy_rekey_is_recorded_as_its_delivery_outcome() {
    let plan = Plan {
        rekeys: 1,
        rekey_during_get: true,
        ..UPLOAD_PLAN
    };
    let delivered = |world: &Mixed<'_, '_, '_>| {
        world.plan.rekeys == 0 && world.updates.is_empty() && get_decided(world)
    };
    let busy = (1..=8).any(|root| {
        let profile = Profile {
            name: "rekey during a GET",
            declared: [UPLOAD.as_slice(), &[ActionKind::Rekey]].concat(),
            root,
        };
        let ran = mixed(&profile, plan, delivered);
        let Some(turn) = ran.first(ActionKind::Rekey, |outcome| outcome == REKEY_BUSY) else {
            return false;
        };
        assert_eq!(ran.seen[turn].epoch, 1, "a busy rekey changes no key");
        true
    });
    assert!(busy, "some root recorded a busy refusal");
}

/// With no workload the owner is still polled at each maintenance due
/// time and the disk service at its own, never later, while world time
/// skips ahead between them; idle turns are not progress.
#[test]
fn maintenance_polls_survive_idle_acceleration() {
    let profile = Profile {
        name: "idle",
        declared: Vec::new(),
        root: 2,
    };
    let ran = mixed(&profile, QUIET, |_| false);
    let report = &ran.report;
    for code in [OWNER_POLL, SERVICE] {
        let at = report
            .turns
            .iter()
            .filter(|turn| turn.event == candidate(code, 0, 0));
        assert!(at.count() > 3, "{code}");
    }
    assert!(
        ran.late.iter().all(|&late| late == 0),
        "a due poll or service ran late"
    );
    assert!(ran.driver_calls > 0);
    let serviced = report
        .turns
        .iter()
        .any(|turn| turn.event == candidate(SERVICE, 0, 0) && turn.outcome > 0);
    assert!(serviced, "a service event itself drove the disk");
    assert!(report.skipped_us > 0);
    assert_eq!(report.progress, 0);
    assert!(matches!(report.end, End::Inconclusive(_)));
}

/// Reading, releasing a read fragment and returning a withheld transmit
/// reference are separate selected events: with the links withholding every
/// reference, the upload still publishes and the GET still reads its bytes
/// exactly once releases and NIC returns run.
#[test]
fn reads_releases_and_nic_returns_are_their_own_events() {
    let profile = Profile {
        name: "withheld transmit references",
        declared: [UPLOAD.as_slice(), &[ActionKind::Release]].concat(),
        root: 13,
    };
    let plan = Plan {
        withheld_tx: true,
        ..UPLOAD_PLAN
    };
    let released = |world: &Mixed<'_, '_, '_>| {
        exactly_read(world) && world.held.is_empty() && world.reached(ActionKind::Release)
    };
    let ran = mixed(&profile, plan, released);
    assert_eq!(ran.report.end, End::Done);
    let returns = ran
        .report
        .turns
        .iter()
        .filter(|turn| turn.event.0[0] == Domain::Link as u8 && turn.outcome > 0)
        .count();
    assert!(
        returns > 0,
        "NIC returns ran as events and returned references"
    );
}

/// Four profiles that together declare every kind: the local storage path
/// with maintenance actions, GETs and close; held control updates; a
/// deferring upload whose published key is then invalidated; and an upload
/// whose outcome is unknown, with its abandonment and matching retry.
fn coverage(root: u64) -> [(Profile, Plan); 4] {
    let local = Profile {
        name: "local storage, maintenance, reads and close",
        declared: vec![
            ActionKind::Fill,
            ActionKind::Receive,
            ActionKind::Publish,
            ActionKind::Acquire,
            ActionKind::Release,
            ActionKind::Expire,
            ActionKind::Evict,
            ActionKind::Pressure,
            ActionKind::Get,
            ActionKind::Read,
            ActionKind::Cancel,
            ActionKind::Close,
        ],
        root,
    };
    let control = Profile {
        name: "held control updates",
        declared: vec![ActionKind::SessionChange, ActionKind::Rekey],
        root,
    };
    let deferring = Profile {
        name: "deferring upload, then its invalidation",
        declared: [
            UPLOAD.as_slice(),
            &[ActionKind::DeferSupply, ActionKind::Invalidate],
        ]
        .concat(),
        root,
    };
    let uncertain = Profile {
        name: "uncertain upload",
        declared: vec![
            ActionKind::PutInvoke,
            ActionKind::PutCancel,
            ActionKind::PutOutcome,
            ActionKind::Abandon,
            ActionKind::Retry,
        ],
        root,
    };
    [
        (
            local,
            Plan {
                gets: [0, 2],
                read_resident: true,
                manual_maintenance: true,
                ..QUIET
            },
        ),
        (
            control,
            Plan {
                sessions: 1,
                rekeys: 1,
                ..QUIET
            },
        ),
        (
            deferring,
            Plan {
                gets: [0, 2],
                invalidations: 1,
                ..UPLOAD_PLAN
            },
        ),
        (
            uncertain,
            Plan {
                puts: 1,
                retries: 1,
                lose_upload: true,
                ..QUIET
            },
        ),
    ]
}

/// Every kind is declared by some profile, each declared kind runs with its
/// witness under its precondition, and an undeclared kind never runs. An
/// upload whose datagrams never reach the owner collects `Unknown`, never
/// `Published`; an invalidation runs only after every planned GET.
#[test]
fn every_declared_action_kind_is_reached() {
    let mut declared: Vec<ActionKind> = Vec::new();
    for root in [21, 22] {
        for (profile, plan) in coverage(root) {
            declared.extend(&profile.declared);
            let ran = mixed(&profile, plan, |world| world.covered());
            assert_eq!(ran.report.end, End::Done, "{}: root {root}", profile.name);
            assert_eq!(ran.audit, Verdict::Pass, "{}: root {root}", profile.name);
            assert!(
                ran.late.iter().all(|&late| late == 0),
                "{}: a due poll ran late",
                profile.name
            );
            assert!(
                ran.kinds().iter().all(|kind| profile.declares(*kind)),
                "{}: an undeclared kind ran",
                profile.name
            );
            if profile.declares(ActionKind::Invalidate) {
                let invalidated = ran
                    .first(ActionKind::Invalidate, |outcome| outcome != REFUSED)
                    .unwrap();
                let gets_before = ran
                    .acts
                    .iter()
                    .filter(|act| {
                        act.kind == ActionKind::Get
                            && act.outcome != REFUSED
                            && act.turn < invalidated
                    })
                    .count();
                assert_eq!(
                    gets_before as u32,
                    plan.gets.iter().sum::<u32>(),
                    "{}: root {root}: every planned GET ran before the invalidation",
                    profile.name
                );
            }
            if profile.declares(ActionKind::Pressure) {
                let reserved = 1..=u64::from(PRESSURE);
                assert!(
                    ran.first(ActionKind::Pressure, |outcome| reserved.contains(&outcome))
                        .is_some(),
                    "{}: root {root}: pressure never held a fill",
                    profile.name
                );
            }
            if plan.lose_upload {
                let published = upload_code(UploadOutcome::Published);
                let collected: Vec<u64> = ran
                    .acts
                    .iter()
                    .filter(|act| act.kind == ActionKind::PutOutcome)
                    .map(|act| act.outcome)
                    .collect();
                assert!(collected.contains(&upload_code(UploadOutcome::Unknown)));
                assert!(!collected.contains(&published), "{collected:?}");
            }
        }
    }
    declared.sort();
    declared.dedup();
    assert_eq!(declared, ActionKind::ALL);
    let unreachable = Profile {
        name: "evict without a local object",
        declared: vec![ActionKind::Evict],
        root: 21,
    };
    let ran = mixed(&unreachable, QUIET, |world| world.covered());
    assert!(
        matches!(ran.report.end, End::Inconclusive(_)),
        "an unmet precondition credits nothing"
    );
    assert!(ran.acts.is_empty());
}

/// A client's GET budget is spent one request at a time: once a GET is
/// collected, the next planned one is proposed, and coverage waits for the
/// whole budget.
#[test]
fn a_collected_get_lets_the_next_planned_one_run() {
    let profile = Profile {
        name: "two reads",
        declared: vec![ActionKind::Get, ActionKind::Read],
        root: 1,
    };
    let plan = Plan {
        gets: [0, 2],
        read_resident: true,
        ..QUIET
    };
    let ran = mixed(&profile, plan, |world| world.covered());
    assert_eq!(ran.report.end, End::Done);
    let gets = ran
        .acts
        .iter()
        .filter(|act| act.kind == ActionKind::Get && act.outcome != REFUSED)
        .count();
    assert_eq!(gets, 2);
}

/// Close is proposed only once every other declared kind is reached and
/// every planned budget is spent, so a run that declares Close can still
/// issue its remaining planned requests and reach coverage.
#[test]
fn a_close_waits_for_the_planned_budgets() {
    for root in 1..=8 {
        let profile = Profile {
            name: "two reads, then close",
            declared: vec![ActionKind::Get, ActionKind::Read, ActionKind::Close],
            root,
        };
        let plan = Plan {
            gets: [0, 2],
            read_resident: true,
            ..QUIET
        };
        let ran = mixed(&profile, plan, |world| world.covered());
        assert_eq!(ran.report.end, End::Done, "root {root}");
        let close = ran.first(ActionKind::Close, |_| true).unwrap();
        let gets = ran
            .acts
            .iter()
            .filter(|act| act.kind == ActionKind::Get && act.turn < close)
            .count();
        assert_eq!(gets, 2, "root {root}: both GETs ran before close");
    }
}

/// A client poll can decide a GET or upload before the harness reads or
/// collects it; cancellation earns witness credit only while the request
/// remains undecided in the client.
#[test]
fn a_cancel_counts_only_on_an_undecided_request() {
    let cases = |root, cancel_after_decision| {
        [
            (
                Profile {
                    name: "cancel a GET",
                    declared: vec![ActionKind::Get, ActionKind::Cancel],
                    root,
                },
                Plan {
                    gets: [0, 1],
                    read_resident: true,
                    cancel_after_decision,
                    ..QUIET
                },
                ActionKind::Cancel,
            ),
            (
                Profile {
                    name: "cancel an upload",
                    declared: vec![
                        ActionKind::PutInvoke,
                        ActionKind::PutPrepare,
                        ActionKind::Supply,
                        ActionKind::PutCancel,
                    ],
                    root,
                },
                Plan {
                    puts: 1,
                    cancel_after_decision,
                    ..QUIET
                },
                ActionKind::PutCancel,
            ),
        ]
    };
    let mut cancelled = [false; 2];
    for root in 1..=2 {
        for cancel_after_decision in [false, true] {
            for (case, (profile, plan, kind)) in
                cases(root, cancel_after_decision).into_iter().enumerate()
            {
                let ran = mixed(&profile, plan, |world| world.covered());
                let credited = ran
                    .acts
                    .iter()
                    .filter(|act| act.kind == kind && witnessed(kind, act.outcome));
                for act in credited {
                    let before = ran.seen[act.turn - 1];
                    let live = match kind {
                        ActionKind::Cancel => before.pending[1],
                        _ => before.uploading,
                    };
                    assert!(
                        live,
                        "{}: root {root} credited a cancel of a decided request at turn {}",
                        profile.name, act.turn
                    );
                    cancelled[case] = true;
                }
                if cancel_after_decision {
                    assert!(
                        matches!(ran.report.end, End::Inconclusive(_)),
                        "{}: root {root} ended {:?}",
                        profile.name,
                        ran.report.end
                    );
                    assert!(
                        ran.first(kind, |outcome| outcome == REFUSED).is_some(),
                        "{}: root {root} never refused a cancel of a decided request",
                        profile.name
                    );
                }
            }
        }
    }
    assert_eq!(cancelled, [true; 2], "some root cancels each live request");
}

#[test]
fn only_an_evicted_commit_witnesses_a_removal() {
    let victim = AllocationId::new(SlotIndex(0), 1);
    for retirement in [RetireOutcome::Recorded, RetireOutcome::Parked] {
        assert!(removed(Some(Commit::Evicted {
            victim,
            fingerprint: 0,
            retirement
        })));
    }
    let kept = [
        None,
        Some(Commit::Replacing),
        Some(Commit::Absent),
        Some(Commit::Contended),
        Some(Commit::Poisoned),
        Some(Commit::Corrupt),
    ];
    for commit in kept {
        assert!(!removed(commit), "{commit:?} credited a removal");
    }
}

/// Every fixture a scenario uses lives in the scenario's own scope and
/// returns when it ends: repeated cases and a long idle run leave this
/// thread's live heap bytes where they started.
#[test]
fn repeated_scenarios_keep_fixture_memory_constant() {
    let live = crate::instrument::live_bytes;
    let case = || drop(mixed(&upload_profile(1), UPLOAD_PLAN, exactly_read));
    let idle = Profile {
        name: "idle",
        declared: Vec::new(),
        root: 2,
    };
    let long = || {
        let ran = mixed(&idle, QUIET, |_| false);
        assert!(ran.report.turns.len() >= LIMITS.no_progress as usize);
    };
    case();
    long();
    let before = live();
    for _ in 0..3 {
        case();
        assert_eq!(live(), before, "a case left heap bytes behind");
    }
    long();
    assert_eq!(live(), before, "a long run left heap bytes behind");
}

/// With every link fault drawn from the run's chooser, delayed transmit
/// returns and a tapped rule, a generated upload still publishes and is
/// read exactly; the tape replays the same turns, record, audited outcomes
/// and captures, and the audit passes.
#[test]
fn link_faults_replay_from_the_run_tape() {
    let plan = Plan {
        link_faults: true,
        ..UPLOAD_PLAN
    };
    let profile = upload_profile(31);
    let ran = mixed(&profile, plan, exactly_read);
    assert_eq!(ran.report.end, End::Done);
    assert_eq!(ran.audit, Verdict::Pass);
    let injected = ran
        .audits
        .iter()
        .flatten()
        .filter(|record| record.class == Class::Injected);
    assert!(injected.count() > 0, "the faults fired");
    assert!(ran.captures.iter().any(|captures| !captures.is_empty()));
    let (turns, record) = (ran.report.turns.clone(), ran.report.record.clone());
    let (audits, captures) = (ran.audits.clone(), ran.captures.clone());
    let replay = Chooser::replay(&sites_for(&plan), ran.finish());
    let again = mixed_with(replay, &profile, plan, exactly_read);
    assert_eq!(again.report.turns, turns);
    assert_eq!(again.report.record, record);
    assert_eq!(again.audits, audits);
    assert_eq!(again.captures, captures);
    assert_eq!((again.report.end, again.audit), (End::Done, Verdict::Pass));
    again.finish();
}

/// A send that fails with no origin the harness can name fails the world's
/// audit, whatever the run's goal reached.
#[test]
fn an_unattributed_link_failure_fails_the_world() {
    let plan = Plan {
        unattributed: true,
        ..UPLOAD_PLAN
    };
    let ran = mixed(&upload_profile(4), plan, published_then_read);
    let Verdict::Fail(record) = ran.audit else {
        panic!("a harness defect fails the world: {:?}", ran.audit);
    };
    assert_eq!(
        (record.class, record.reason),
        (Class::Harness, Reason::Unattributed)
    );
}

/// A production refusal the scenario provokes on purpose and declares judges
/// as modeled and passes; the same refusal undeclared fails the world.
#[test]
fn a_declared_production_outcome_passes_and_an_undeclared_one_fails() {
    let refused = |world: &Mixed<'_, '_, '_>| {
        let net = world.scene.nets[1].borrow();
        net.audit().count(Reason::Oversize) > 0
    };
    let profile = Profile {
        name: "short GET link",
        declared: vec![ActionKind::Get, ActionKind::Read],
        root: 7,
    };
    let short = Plan {
        gets: [0, 1],
        read_resident: true,
        short_link: true,
        ..QUIET
    };
    let undeclared = mixed(&profile, short, refused);
    assert_eq!(undeclared.report.end, End::Done);
    let Verdict::Fail(record) = undeclared.audit else {
        panic!(
            "an undeclared oversize refusal fails the world: {:?}",
            undeclared.audit
        );
    };
    assert_eq!(
        (record.class, record.reason),
        (Class::Production, Reason::Oversize)
    );
    let declared = Plan {
        declared: &[Reason::Oversize],
        ..short
    };
    let ran = mixed(&profile, declared, refused);
    assert_eq!(ran.report.end, End::Done);
    assert_eq!(ran.audit, Verdict::Pass);
    let other = Plan {
        declared: &[Reason::NotHoldable],
        ..short
    };
    let ran = mixed(&profile, other, refused);
    let Verdict::Fail(record) = ran.audit else {
        panic!(
            "declaring another reason leaves oversize failing: {:?}",
            ran.audit
        );
    };
    assert_eq!(
        (record.class, record.reason),
        (Class::Production, Reason::Oversize)
    );
}

static CHANGED: Failure = Failure::Violation(
    crate::oracle::Obligation::Bytes,
    "a bound slot's record fails its header or chunk checks",
);

/// A resident record changed on the device before the run is caught at the
/// world's first stopped boundary and kept as the run's first failure.
#[test]
fn a_stopped_boundary_catches_a_changed_resident_record() {
    let plan = Plan {
        corrupt_resident: true,
        observed: Some(&CHANGED),
        ..QUIET
    };
    let idle = Profile {
        name: "idle over a corrupted resident",
        declared: Vec::new(),
        root: 3,
    };
    let ran = mixed(&idle, plan, |world| world.boundaries > 0);
    assert!(ran.boundaries > 0);
}

#[test]
fn an_undeclared_observed_failure_fails_the_run() {
    let idle = Profile {
        name: "idle over an undeclared corruption",
        declared: Vec::new(),
        root: 3,
    };
    let undeclared = Plan {
        corrupt_resident: true,
        ..QUIET
    };
    let unprovoked = Plan {
        observed: Some(&CHANGED),
        ..QUIET
    };
    for plan in [undeclared, unprovoked] {
        let run = || drop(mixed(&idle, plan, |world| world.boundaries > 0));
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run));
        let payload = failed.expect_err("the run's observations passed");
        let message = payload
            .downcast_ref::<String>()
            .expect("a formatted message");
        assert!(
            message.contains("the first failure a stopped boundary or teardown observed"),
            "{plan:?}: {message}"
        );
    }
}

/// The world's evidence that the owner bound the upload's key outlives
/// the binding. With one GET, one invalidation and no drain, the
/// invalidation waits only for the GET's decision in its client, so on
/// some roots it removes the mapping before the world collects the read.
/// That read is a hit of a published version and breaks no rule.
#[test]
fn a_hit_collected_after_its_invalidation_breaks_no_rule() {
    let plan = Plan {
        invalidations: 1,
        ..UPLOAD_PLAN
    };
    let mut after = 0;
    for root in 1..=200 {
        let mut profile = upload_profile(root);
        profile.declared.push(ActionKind::Invalidate);
        let ran = mixed(&profile, plan, exactly_read);
        assert_eq!(ran.settled.first, None, "root {root}");
        let invalidated = ran.first(ActionKind::Invalidate, |outcome| outcome != REFUSED);
        let collected = ran
            .decided
            .iter()
            .find(|decided| decided.client == 1 && decided.outcome == Outcome::Complete)
            .map(|decided| decided.decided);
        if let (Some(invalidated), Some(collected)) = (invalidated, collected) {
            after += usize::from(invalidated < collected);
        }
    }
    assert!(
        after > 0,
        "no root collected the read after the invalidation"
    );
}

/// A decided GET breaks a rule by what it handed its client: a complete
/// read of a key with no registered content is an unpublished hit, a
/// complete read of bytes that are no one content's body breaks the bytes
/// obligation, a read that failed after handing out bytes that start no
/// content breaks containment, and so does a read that ended `Missing`,
/// refused under pressure or failed before any byte, and handed out
/// bytes. An exact read, a failed read of a prefix
/// and a refused read of no bytes break none.
#[test]
fn a_decided_get_is_judged_by_the_bytes_it_handed_out() {
    use crate::net::frame::Status;
    use crate::oracle::Obligation;
    let mut registry = Registry::new(8);
    registry.register(key(1), Label(1), 0, payload(1000, 1));
    let content = payload(1000, 1);
    let mut changed = content.clone();
    changed[999] ^= 1;
    let judged =
        |name: u8, outcome, bytes: &[u8]| misread(&registry, &key(name), true, outcome, bytes);
    let violation = |obligation, rule| Some(Failure::Violation(obligation, rule));
    let failed = Status::DeviceError;
    assert_eq!(judged(1, Outcome::Complete, &content), None);
    assert_eq!(
        judged(1, Outcome::Incomplete(failed), &content[..400]),
        None
    );
    assert_eq!(judged(1, Outcome::Incomplete(failed), &[]), None);
    for outcome in [
        Outcome::Missing,
        Outcome::Pressure(Status::ObjectPressure),
        Outcome::Failed(failed),
    ] {
        assert_eq!(judged(1, outcome, &[]), None);
        assert_eq!(judged(STRANGER, outcome, &[]), None);
        assert_eq!(
            judged(1, outcome, &content[..1]),
            violation(Obligation::Contain, "a refused read exposed bytes")
        );
    }
    for bytes in [&changed[..], &content[..999], &[]] {
        assert_eq!(
            judged(1, Outcome::Complete, bytes),
            violation(
                Obligation::Bytes,
                "a complete read returned bytes other than the label's content"
            )
        );
    }
    for bytes in [&content[..], &[]] {
        assert_eq!(
            judged(STRANGER, Outcome::Complete, bytes),
            violation(
                Obligation::History,
                "a hit of a version no linearized fill published"
            )
        );
    }
    // A registered key the world has not seen bound: its exact content is
    // a hit of a version nothing published, and so is any other body.
    for bytes in [&content[..], &changed[..]] {
        assert_eq!(
            misread(&registry, &key(1), false, Outcome::Complete, bytes),
            violation(
                Obligation::History,
                "a hit of a version no linearized fill published"
            )
        );
    }
    assert_eq!(
        misread(
            &registry,
            &key(1),
            false,
            Outcome::Incomplete(failed),
            &content[..400]
        ),
        None
    );
    for name in [1, STRANGER] {
        assert_eq!(
            judged(name, Outcome::Incomplete(failed), &changed),
            violation(
                Obligation::Contain,
                "a failed read exposed bytes outside the verified prefix"
            )
        );
    }
}

/// Each turn's and each clock move's emitted events, in order, with whether
/// a clock move emitted them.
#[derive(Default)]
struct Batches(Vec<(bool, Vec<Event>)>);

impl Hook for Batches {
    fn clock(&mut self, _: &[u8], _: u64, events: &[Event]) {
        self.0.push((true, events.to_vec()));
    }

    fn turn(&mut self, _: &[u8], _: &crate::sim::turn::Turn, events: &[Event]) {
        self.0.push((false, events.to_vec()));
    }
}

/// The upload plan with `plant`, run from `root` through `hook`.
fn leaked_run(plant: Plant, root: u64, hook: &mut impl Hook) -> (Ran, Option<Failure>) {
    let profile = upload_profile(root);
    let plan = Plan {
        plant,
        ..UPLOAD_PLAN
    };
    let chooser = profile.recorder(&sites_for(&plan));
    let (ran, first, _) = mixed_run(chooser, &profile, plan, published_then_read, LIMITS, hook);
    (ran, first)
}

/// The leaked-unit plant reserves one payload unit in the turn whose
/// outcome collection finds the upload published, and the conservation
/// call at the top of that turn's emission records the free-run text as
/// the first failure: its failure event closes that turn's events, after
/// the collection's action record and before any later clock move. The
/// same plan without the plant passes.
#[test]
fn a_leaked_unit_fails_the_free_runs_in_the_turn_that_leaked() {
    let published = upload_code(UploadOutcome::Published).to_le_bytes();
    for root in [1, 2, 3] {
        let mut batches = Batches::default();
        let (ran, first) = leaked_run(Plant::LeakedUnit, root, &mut batches);
        assert!(
            ran.acted,
            "root {root}: premise: the plant reserved its unit"
        );
        assert_eq!(
            first,
            Some(Failure::Violation(
                crate::oracle::Obligation::Resources,
                super::observe::FREE_RUNS
            )),
            "root {root}"
        );
        let failed = batches
            .0
            .iter()
            .position(|(_, events)| events.iter().any(|event| event.kind == bundle::FAILURE))
            .expect("a failure event");
        let (clock, events) = &batches.0[failed];
        assert!(!clock, "root {root}: a turn emitted the failure");
        let collected = events.iter().position(|event| {
            event.kind == bundle::ACT
                && event.payload[0] == ActionKind::PutOutcome as u8
                && event.payload[1..9] == published
        });
        let failure = events
            .iter()
            .position(|event| event.kind == bundle::FAILURE);
        assert!(
            collected.is_some_and(|collected| Some(collected) < failure),
            "root {root}: the turn that collected the publication leaked: {events:?}"
        );
        let (plain, first) = leaked_run(Plant::None, root, &mut ());
        assert_eq!(first, None, "root {root}");
        assert!(!plain.acted, "root {root}");
        assert_eq!(
            plain.report.end,
            End::Done,
            "root {root}: the sibling finished"
        );
        assert_eq!(plain.audit, Verdict::Pass, "root {root}");
    }
}

/// The mixed world judges conservation once per emission: once after each
/// applied turn and once after each clock move.
#[test]
fn conservation_is_judged_after_every_turn_and_clock_move() {
    for root in [1, 2] {
        let (ran, first) = leaked_run(Plant::None, root, &mut ());
        assert_eq!(first, None);
        assert_eq!(ran.report.end, End::Done, "root {root}");
        assert!(ran.report.turn_count > 0 && ran.boundaries > 0);
        assert_eq!(
            ran.conserved,
            ran.report.turn_count + ran.boundaries as u64,
            "root {root}"
        );
    }
}

/// With `drain = 0`, `mixed_run` reports the peer's swallowed lease after
/// the final emission; with `drain = 400` a clock move's emission records
/// the failure. Each `Plant::None` run finishes with `first = None`.
#[test]
fn a_lease_the_peers_multiplexer_swallows_fails_the_datagram_accounts() {
    for (root, (drain, at_boundary)) in [1, 2]
        .into_iter()
        .flat_map(|root| [(root, (0, false)), (root, (400, true))])
    {
        let profile = upload_profile(root);
        let plan = Plan {
            peer_owner: true,
            plant: Plant::UncountedPeer,
            drain,
            ..UPLOAD_PLAN
        };
        let chooser = profile.recorder(&sites_for(&plan));
        let mut batches = Batches::default();
        let (ran, first, _) = mixed_run(
            chooser,
            &profile,
            plan,
            published_then_read,
            LIMITS,
            &mut batches,
        );
        assert!(
            ran.acted,
            "root {root}: premise: the peer's multiplexer swallowed a lease"
        );
        assert_eq!(
            first,
            Some(Failure::Violation(
                crate::oracle::Obligation::Contain,
                super::observe::UNACCOUNTED
            )),
            "root {root}"
        );
        assert_eq!(
            failure_batch(&batches),
            at_boundary.then_some(true),
            "root {root} drain {drain}: the emission that recorded the failure"
        );
        let plain = Plan {
            plant: Plant::None,
            ..plan
        };
        let chooser = profile.recorder(&sites_for(&plain));
        let (plain, first, _) = mixed_run(
            chooser,
            &profile,
            plain,
            published_then_read,
            LIMITS,
            &mut (),
        );
        assert_eq!(first, None, "root {root}");
        assert_eq!(
            plain.report.end,
            End::Done,
            "root {root}: the sibling finished"
        );
        assert_eq!(plain.audit, Verdict::Pass, "root {root}");
    }
}

/// Whether the first batch containing `bundle::FAILURE` belongs to a clock
/// move, or `None` when no batch holds one.
fn failure_batch(batches: &Batches) -> Option<bool> {
    batches
        .0
        .iter()
        .find(|(_, events)| events.iter().any(|event| event.kind == bundle::FAILURE))
        .map(|(clock, _)| *clock)
}

/// The uncounted plant's swallowed lease fails the datagram accounts at the
/// stopped boundary of a clock move, whose emission records the failure.
#[test]
fn a_swallowed_lease_fails_the_datagram_accounts_at_a_stopped_boundary() {
    for root in [1, 2, 3] {
        let mut batches = Batches::default();
        let (ran, first) = leaked_run(Plant::Uncounted, root, &mut batches);
        assert!(ran.acted, "root {root}: premise: the lease was swallowed");
        assert_eq!(
            first,
            Some(Failure::Violation(
                crate::oracle::Obligation::Contain,
                super::observe::UNACCOUNTED
            )),
            "root {root}"
        );
        assert_eq!(
            failure_batch(&batches),
            Some(true),
            "root {root}: a clock move's emission recorded the failure"
        );
    }
}

fn swallowed(world: &Mixed<'_, '_, '_>) -> bool {
    world.swallowed
}

/// The run ends on the swallowing turn. Only the final judgment reports
/// `UNACCOUNTED`.
#[test]
fn the_final_judgment_fails_a_lease_swallowed_on_the_last_turn() {
    for root in [1, 2, 3] {
        let profile = upload_profile(root);
        let plan = Plan {
            plant: Plant::Uncounted,
            ..UPLOAD_PLAN
        };
        let chooser = profile.recorder(&sites_for(&plan));
        let mut batches = Batches::default();
        let (ran, first, _) = mixed_run(chooser, &profile, plan, swallowed, LIMITS, &mut batches);
        assert!(ran.acted, "root {root}: premise: the lease was swallowed");
        assert_eq!(ran.report.end, End::Done, "root {root}");
        assert_eq!(
            failure_batch(&batches),
            None,
            "root {root}: no emission recorded a failure"
        );
        assert_eq!(
            first,
            Some(Failure::Violation(
                crate::oracle::Obligation::Contain,
                super::observe::UNACCOUNTED
            )),
            "root {root}"
        );
    }
}
