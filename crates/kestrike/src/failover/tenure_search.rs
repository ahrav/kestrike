//! The tenure search models hosts A and C, the reconciler and the store's request path acting on one shard record.
//! In an unplanted world every store request is issued through `storage::store::Client` and every mint comes from
//! `Session::activate`; the `Release` action delivers a parked request through the store double, and its outcome
//! returns to no client.
//!
//! The search starts after A's create of [`root_record`] and A's acknowledged bump: A owns `g = 3` at `E = 1`, C holds
//! the spare, the record's standby field is empty, the record names a checkpoint of `g = 3`, and the ghost history
//! holds the root tenure's mint. The bound is world state: a host's bump or takeover reads at `E` below [`Bound::top`],
//! a lost or parked reply spends one of [`Bound::faults`], a designation that issues its request spends one of
//! [`Bound::designations`], and a transfer whose request reaches the store spends one of [`Bound::transfers`]. A
//! designation and a flip read at any `E`; a designation keeps `E`, and a flip writes `E = 0`. With no handoff no
//! record's `E` exceeds the top; a transfer step and its target's bump write `E` up to `top + handoff`.
//!
//! Each write takes one of the arms the model schedules: `Pass`, `Timeout` with and without commit, or `Hold`, which
//! parks the write until the `Release` action. A replay stops at any other arm, as at a disabled action. Under the
//! `double-win` plant a host's `Pass` bump action takes `Arm::DoubleWin`; the bump inside a transfer step takes
//! `Pass` under every plant.
//!
//! World fields and the canonical form:
//! - `store`: the form includes the store's current version and value, its flip sources, and the write in `parked`.
//!   Older versions shape a step only through a held read, and the form holds each held read. The arm queue is empty
//!   between steps. Stores that differ only in drained outcomes or acknowledgment counts yield the same steps and
//!   verdicts.
//! - `record`: the store's current version and decoded value. The form encodes each shard record, the current one,
//!   each held read and the parked write's read, by its generation, active volume, owner, `E`, spare and standby.
//!   Every write of this model, the plants' included, copies the shard, checkpoint, cut, pages, page cap, namespace
//!   and ancestry from its read, or for a flip sets the checkpoint, cut and ancestry to empty values, the cut and
//!   ancestry the root holds. So six of those fields equal the root's in every reached record, and the checkpoint is
//!   the root's at `g = 3` and empty at every later generation: the generation the form holds determines it.
//! - `hosts` and `reconciler`: the canonical form retains each actor's held read. Actor states that differ only in
//!   watermark share a canonical form. A watermark holds the highest version and `(g, E)` its actor observed, and an
//!   adopted checkpoint, which is empty or the root's checkpoint at `g = 3`, since no reached record of one generation
//!   names another checkpoint; under the scheduled arms of an unplanted world every read returns the current version
//!   and every acknowledged commit lands above the version its read held, with `(g, E)` never falling in version
//!   order, so every result passes the watermark check. Under the `double-win` plant a bump that commits over a record
//!   of a later generation lowers `(g, E)`, and monitor 3 ends the search at that step.
//! - `request`, `faults`, `designations`, `transfers`, `handed` and `mints`, the ghost history's mints in
//!   `(g, owner, E)` order: each enables a later step or feeds a monitor or a witness, and the form holds each.
//!   `handed` is the tenure a committed transfer intended, which enables its target's bump above the top and its
//!   witness until that bump is acknowledged. The form holds a request, the world's or the
//!   one a parked flip carries, by its target and volume: every request comes from `Retirement::new` for the active
//!   role on the volume-state trigger, so its role, trigger and recovery flag are the same in every reached world.
//! - `parked`: the parked write's kind, writer, expected version, the read its value comes from and the request it
//!   carries, in the form. In an unplanted world the client computes the parked value from that read and kind; the
//!   `unnamed-standby` plant computes it from the read and the writer. As
//!   `a_canonical_form_without_the_parked_write_reaches_fewer_states` demonstrates, the parked write distinguishes
//!   reachable states.
//! - `lost`: the writer and version of the one write that committed while its writer's reply was lost, by a
//!   `Timeout` that committed or a held write committed at its release. Its one reader is the witness of an
//!   acknowledged bump after a lost commit, and worlds that differ only in `lost` share a canonical form, so the
//!   search observes the witness at a bump from the world it stored first under that form, when that world's `lost`
//!   names the bumping host at its read's version.
//!
//! Each step checks its reply after its action and before any monitor judges the step. In an unplanted world a
//! `Regression`, `Withdrawn`, `Log`, `Codec`, `Successor` or `Namespace` reply lies outside what the store double under
//! the scheduled arms and the kept watermark log return, and ends the search as `Verdict::Unexpected` naming the action
//! and the reply. Under the `double-win` plant a `Regression` is the plant's expected reply and reaches the monitors.
//!
//! After every step, the search checks the monitors in this order and reports the first violation. At the committing
//! step, the search checks the commit against the writer's read and request that the step carried, and against the
//! replaced and written values from the store double's history. A transfer step's commits, its bump's and its
//! transfer's, pair with its writes in issue order, and every commit clause judges each of them.
//! 1. `NoEpochReuse`: each `(g, E)` appears at most once among the mints. Quint: `tenure-NoEpochReuse`.
//! 2. `NamedStandbyTakesOver`: a commit that changes the owner at one generation replaces a value naming the new
//!    owner as standby at `E > 0`, and writes `E + 1`, an empty standby field and the same volume. Quint:
//!    `tenure-takeover-NamedStandbyTakesOver`.
//! 3. `BumpAtOwnGeneration`: a committed bump, takeover or transfer replaces a value at its writer's read generation,
//!    and the store's flip sources hold no generation twice. Quint: `tenure-BumpAtOwnGeneration` and
//!    `tenure-OneFlipPerGeneration`.
//! 4. `StaleRequestRefused`: a commit that raises the generation by one comes from a flip that carries a request,
//!    and that request's generation, owner and `E` equal the replaced value's, and its volume is the replaced
//!    value's active volume.
//!
//! [`COPIED`] lists the rules the record world and the fence world of `fence_search` restate, and its length equals
//! [`CEILING`]. The record world restates `sequence-routing` and `flip-admission`, and the fence world restates
//! `tenure-check` and `step-order`.
//!
//! The transfer instance ([`TRANSFER_BOUND`]) adds a host's planned transfer to the other host as one step: the host
//! bumps its held read, activates its session from that acknowledged bump, and calls `Client::transfer` on the bump's
//! committed read, both writes under `Pass`; it is one step because the world keeps no session between steps. Only A
//! transfers. A transfer is enabled while A's read names A owner below the top and `E + 2` is at most `top + handoff`.
//! `Client::transfer` decides its clauses. Within [`TRANSFER_BOUND`] every call is over A's bumped tenure at `g = 3`,
//! so the search reaches its standby refusal, `Stale::Target` after the bump committed, and none of its checkpoint,
//! tenure, shard, owner-as-target or attempt refusals. The target's bump of the exact tenure the transfer wrote is
//! enabled on a read at `E` below `top + handoff`. The instance runs with no lost or parked reply. A search of
//! [`BOUND`] with its one fault and a transfer runs longer than the five-second budget set for this development-build
//! search, so [`BOUND`] issues no transfer. Outside the transfer instance lie a write between the owner's bump and its
//! transfer, a transfer by C, `Client::transfer`'s refusals other than the standby clause and its failed version
//! condition, a transfer under a lost or parked reply, and the planned exit's step order and inline checks around the
//! write.
//!
//! A host takes over toward the `(g, owner, E)` of its own read, and the reconciler designates toward that of its read,
//! so the target clauses of `Client::take_over` and `Client::designate` never refuse. Within the bound every refusal of
//! `Client::take_over` before its request fails its standby clause, and every refusal of `Client::designate` before its
//! request fails its `E = 0` clause and no other: only a designation names a standby, at `E > 0`, a bump keeps it at a
//! higher `E`, and a takeover, a transfer or a flip clears it, so no read names a standby at `E = 0`, and the
//! reconciler names the host other than its read's owner. A host reads only when it holds no read, and this rule keeps
//! every canonical state and every shortest path: a host's held read changes only at that host's own read or write, a
//! read changes only the reader's watermark and held read, and only that host's own steps read its held read, so a path
//! that rereads reaches, after its earlier unconsumed read is deleted, the same canonical world in one step fewer. The
//! reconciler rereads whenever its held read is stale or absent, since a reread of the current version leaves its world
//! unchanged.
//!
//! A pass shows that every monitor holds at every state within the bound, with each decision made by the production
//! function the step calls. The step order and inline checks of the restart, fresh, takeover and reconciler sequences,
//! the deployed store, a third host and a larger bound lie outside it. The monitors read `Client::read`,
//! `Retirement::new` and `Client::designate` only through the steps they enable. Three more limits stand: the
//! `double-win` plant breaks monitor 3 through its commit clause, and the one-flip-per-generation clause holds in every
//! planted run; the cap control withholds credit through the verdict and the totals, the fault-free control through the
//! witness set alone, the canonical-form control through the totals, the kinds and the witness set together, the
//! transfer instance's cap control through the verdict and the totals, and its handoff control through the witness set
//! alone, so only the witness clause has a control that refuses on it alone, and the verdict, totals, kinds and
//! decisions clauses taken alone rest on the unplanted run's own assertions; and path minimality rests on breadth-first
//! order alone, while the stub model in the tests checks the search's four exits and the replay's `Disabled`,
//! `Violation` and `Unexpected` exits.

use super::flip::transferred;
use super::reconcile::StandbyGate;
use super::retire::{Retirement, Role, Stale, Target, Trigger};
use super::search::{Model, Seen};
use crate::failover::records::{Host, NamedCheckpoint, Namespace, Record, ShardRecord, VolumeId};
use crate::storage::Session;
use crate::storage::store::sim::{Arm, SimStore};
use crate::storage::store::{
    Bumped, Client, Item, Key, Outcome, Outgoing, Read, Refusal, Store, StoreError, Unavailable,
    Version, Watermark, WatermarkLog, Write,
};
use crate::storage::store_tests::{OWNER, SPARE, record, shard};

pub(crate) const NO_EPOCH_REUSE: &str = "NoEpochReuse";
pub(crate) const NAMED_STANDBY_TAKES_OVER: &str = "NamedStandbyTakesOver";
pub(crate) const BUMP_AT_OWN_GENERATION: &str = "BumpAtOwnGeneration";
pub(crate) const STALE_REQUEST_REFUSED: &str = "StaleRequestRefused";

pub(crate) const TAKEOVER_COMMITTED: &str = "takeover-committed";
pub(crate) const FLIP_COMMITTED: &str = "flip-committed";
pub(crate) const FRESH_BUMP_AFTER_FLIP: &str = "fresh-bump-after-flip";
pub(crate) const LOST_AFTER_COMMIT: &str = "unknown-outcome-mints-nothing/lost-after-commit";
pub(crate) const LOST_WITHOUT_COMMIT: &str = "unknown-outcome-mints-nothing/lost-without-commit";
pub(crate) const PARKED: &str = "unknown-outcome-mints-nothing/parked";
pub(crate) const CONDITION_REFUSED: &str = "condition-refused";
pub(crate) const STALE_RETIREMENT_REFUSED: &str = "stale-retirement-refused";
pub(crate) const TAKEOVER_CONDITION_REFUSED: &str = "takeover-condition-refused";
pub(crate) const PARKED_BUMP_REFUSED_AFTER_FLIP: &str = "parked-bump-refused-after-flip";
pub(crate) const BUMP_AFTER_LOST_COMMIT: &str = "acknowledged-bump-after-lost-commit";
pub(crate) const SECOND_FLIP_REFUSED: &str = "second-flip-refused";
pub(crate) const PARKED_COMMITTED_AT_RELEASE: &str = "parked-write-committed-at-release";
pub(crate) const TRANSFER_COMMITTED: &str = "transfer-committed";
pub(crate) const TARGET_BUMP_AFTER_TRANSFER: &str = "target-bump-after-transfer";

pub(crate) const WITNESSES: [&str; 13] = [
    TAKEOVER_COMMITTED,
    FLIP_COMMITTED,
    FRESH_BUMP_AFTER_FLIP,
    LOST_AFTER_COMMIT,
    LOST_WITHOUT_COMMIT,
    PARKED,
    CONDITION_REFUSED,
    STALE_RETIREMENT_REFUSED,
    TAKEOVER_CONDITION_REFUSED,
    PARKED_BUMP_REFUSED_AFTER_FLIP,
    BUMP_AFTER_LOST_COMMIT,
    SECOND_FLIP_REFUSED,
    PARKED_COMMITTED_AT_RELEASE,
];

/// The witnesses of the transfer instance at [`TRANSFER_BOUND`]: the record world's witnesses that a bound with no
/// lost or parked reply reaches, and the two of the transfer.
pub(crate) const TRANSFER_WITNESSES: [&str; 8] = [
    TAKEOVER_COMMITTED,
    FLIP_COMMITTED,
    FRESH_BUMP_AFTER_FLIP,
    CONDITION_REFUSED,
    STALE_RETIREMENT_REFUSED,
    TAKEOVER_CONDITION_REFUSED,
    TRANSFER_COMMITTED,
    TARGET_BUMP_AFTER_TRANSFER,
];

pub(crate) const DECISIONS: [&str; 9] = [
    "Client::read",
    "Client::bump",
    "Client::take_over",
    "Client::designate",
    "Client::flip",
    "flip::flipped",
    "Retirement::new",
    "Retirement::admit",
    "Session::activate",
];

pub(crate) const KINDS: [&str; 8] = [
    "Read",
    "Bump",
    "TakeOver",
    "ReconcilerRead",
    "Request",
    "Designate",
    "Flip",
    "Release",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Side {
    A,
    C,
}

impl Side {
    pub(crate) fn host(self) -> Host {
        let number = match self {
            Self::A => OWNER,
            Self::C => SPARE,
        };
        Host::new(number).expect("nonzero host")
    }

    fn of(host: Host) -> Self {
        match host.get() {
            OWNER => Self::A,
            SPARE => Self::C,
            _ => unreachable!("the model's records name only hosts A and C"),
        }
    }

    pub(crate) fn other(self) -> Self {
        match self {
            Self::A => Self::C,
            Self::C => Self::A,
        }
    }

    pub(crate) fn index(self) -> usize {
        self as usize
    }
}

const PASS: Arm = Arm::Pass;
const LOST: Arm = Arm::Timeout { commit: true };
const DROPPED: Arm = Arm::Timeout { commit: false };
const HELD: Arm = Arm::Hold;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Read(Side),
    Bump(Side, Arm),
    TakeOver(Side, Arm),
    /// A host's planned transfer to the other host: the bump of the held read, the session that bump activates, and
    /// `Client::transfer` over the bump's committed read. Both writes take `Pass`. Only `Transfer(A)` is in the
    /// alphabet; the side keeps the action's form that of `Bump` and `TakeOver`.
    Transfer(Side),
    ReconcilerRead,
    Request,
    Designate(Arm),
    Flip(Arm),
    Release,
}

use Action::{Bump, Designate, Flip, ReconcilerRead, Release, Request, TakeOver, Transfer};
use Side::{A, C};

pub(crate) const ALPHABET: [Action; 30] = [
    Action::Read(A),
    Action::Read(C),
    Bump(A, PASS),
    Bump(A, LOST),
    Bump(A, DROPPED),
    Bump(A, HELD),
    Bump(C, PASS),
    Bump(C, LOST),
    Bump(C, DROPPED),
    Bump(C, HELD),
    TakeOver(A, PASS),
    TakeOver(A, LOST),
    TakeOver(A, DROPPED),
    TakeOver(A, HELD),
    TakeOver(C, PASS),
    TakeOver(C, LOST),
    TakeOver(C, DROPPED),
    TakeOver(C, HELD),
    Transfer(A),
    ReconcilerRead,
    Request,
    Designate(PASS),
    Designate(LOST),
    Designate(DROPPED),
    Designate(HELD),
    Flip(PASS),
    Flip(LOST),
    Flip(DROPPED),
    Flip(HELD),
    Release,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plant {
    None,
    RereadAfterUnknown,
    UnnamedStandby,
    DoubleWin,
    RetirementUnadmitted,
    /// The transfer writes the value `flip::transferred` computes with the bump's `E` in place of `E + 1`, by a raw
    /// exact-version write; where `flip::transferred` refuses, the step returns that refusal.
    TransferKeepsE,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Bound {
    pub(crate) top: u32,
    pub(crate) faults: u8,
    pub(crate) designations: u8,
    /// The planned transfers a world may issue; a transfer spends one when its request reaches the store.
    pub(crate) transfers: u8,
    /// The attempts above `top` that a transfer step and its target's bump may write. A transfer is enabled on a read
    /// at `E` below `top` with `E + 2` at most `top + handoff`, and the target's bump of the tenure the transfer wrote
    /// is enabled on a read at `E` below `top + handoff`.
    pub(crate) handoff: u32,
}

pub(crate) const BOUND: Bound = Bound {
    top: 2,
    faults: 1,
    designations: 1,
    transfers: 0,
    handoff: 0,
};

/// The transfer instance: [`BOUND`] with one transfer by A, two attempts above `top` for the transfer's write and its
/// target's bump, and no lost or parked reply.
pub(crate) const TRANSFER_BOUND: Bound = Bound {
    faults: 0,
    transfers: 1,
    handoff: 2,
    ..BOUND
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Canonical {
    Full,
    WithoutParked,
}

pub(crate) struct Records {
    pub(crate) plant: Plant,
    pub(crate) bound: Bound,
    pub(crate) canonical: Canonical,
    pub(crate) volumes: [VolumeId; 2],
}

/// The record the world creates: the store tests' record naming a checkpoint of its generation, which every write but a
/// flip copies and `Client::transfer` requires. Every reached record at the root generation names this checkpoint and
/// every record at a later generation names none, so a record's generation determines its checkpoint.
pub(crate) fn root_record() -> ShardRecord {
    let record = record();
    ShardRecord {
        checkpoint: Some(NamedCheckpoint {
            slot: 1,
            session: crate::net::ownership::session_of(record.generation.get() as u32, 2),
            capture: 1,
            units: 1,
        }),
        ..record
    }
}

impl Records {
    pub(crate) fn new(plant: Plant) -> Self {
        let root = root_record();
        let (spare, _) = root.spare.expect("the root record names a spare");
        Self {
            plant,
            bound: BOUND,
            canonical: Canonical::Full,
            volumes: [root.active, spare],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Writer {
    Host(Side),
    Reconciler,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Kind {
    Bump,
    TakeOver,
    Designate,
    Flip,
    Transfer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pending {
    pub(crate) kind: Kind,
    pub(crate) writer: Writer,
    pub(crate) read: ShardRecord,
    pub(crate) expect: Version,
    pub(crate) request: Option<Retirement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reply {
    Done,
    Refused(StoreError),
    Unadmitted(Stale),
    Raw(Outcome),
    Released(Vec<Outcome>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Commit {
    pub(crate) below: ShardRecord,
    pub(crate) written: ShardRecord,
    pub(crate) pending: Pending,
}

/// A step's reply and the commits its writes made, matched to the writes in issue order by the store double's
/// history: `commit` is the step's last commit, and `earlier` the transfer step's bump when its transfer also
/// committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Event {
    pub(crate) reply: Reply,
    pub(crate) commit: Option<Commit>,
    pub(crate) earlier: Option<Commit>,
}

#[derive(Clone, Default)]
struct Holder {
    mark: Watermark,
    read: Option<Read<ShardRecord>>,
}

#[derive(Clone)]
pub(crate) struct World {
    store: SimStore,
    record: (Version, ShardRecord),
    hosts: [Holder; 2],
    reconciler: Holder,
    request: Option<Retirement>,
    faults: u8,
    designations: u8,
    mints: Vec<Target>,
    parked: Option<Pending>,
    lost: Option<(Writer, Version)>,
    /// The transfers the world may still issue; a transfer spends one when its request reaches the store.
    transfers: u8,
    /// The tenure a committed transfer intended, taken from the transfer's input: the transferred read's generation,
    /// the other host as owner and the read's `E + 1`. The target's acknowledged bump from a read naming that tenure
    /// clears it.
    handed: Option<Target>,
}

struct Lent<'a>(&'a mut SimStore);

impl Store for Lent<'_> {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        self.0.read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        self.0.write(key, write)
    }

    fn namespace(&self) -> Namespace {
        self.0.namespace()
    }
}

struct Kept<'a>(&'a mut Watermark);

impl WatermarkLog for Kept<'_> {
    fn load(&self) -> std::io::Result<Watermark> {
        Ok(self.0.clone())
    }

    fn record(&mut self, mark: &Watermark) -> std::io::Result<()> {
        if self.0 != mark {
            mark.clone_into(self.0);
        }
        Ok(())
    }
}

pub(crate) fn key() -> Key {
    Key::Shard(shard())
}

impl World {
    pub(crate) fn mints(&self) -> &[Target] {
        &self.mints
    }

    /// The tenure a committed transfer intended, until its target's acknowledged bump of it.
    pub(crate) fn handed(&self) -> Option<Target> {
        self.handed
    }

    fn holder(&mut self, who: Writer) -> &mut Holder {
        match who {
            Writer::Host(side) => &mut self.hosts[side.index()],
            Writer::Reconciler => &mut self.reconciler,
        }
    }

    fn open(&mut self, who: Writer) -> Client<Lent<'_>, Kept<'_>> {
        let mark = match who {
            Writer::Host(side) => &mut self.hosts[side.index()].mark,
            Writer::Reconciler => &mut self.reconciler.mark,
        };
        Client::open(Lent(&mut self.store), Kept(mark)).expect("the kept log loads")
    }

    /// The store's current shard record.
    pub(crate) fn record(&self) -> &ShardRecord {
        &self.record.1
    }

    /// The shard record as `side`'s client reads it now; the host's held read stays as it was.
    pub(crate) fn reread(&mut self, side: Side) -> Result<ShardRecord, StoreError> {
        let read = self.open(Writer::Host(side)).read::<ShardRecord>(key())?;
        Ok(*read.value())
    }

    pub(crate) fn schedule(&mut self, arm: Arm) {
        self.store.schedule(arm);
    }

    fn current(&self) -> &Item {
        self.store
            .current(&key())
            .expect("the root creates the record")
    }
}

/// Records `target` among the world's mints, kept in `(g, owner, E)` order.
pub(crate) fn mint(world: &mut World, target: Target) {
    let key = |target: &Target| (target.generation, target.owner, target.attempts);
    let at = world
        .mints
        .partition_point(|held| key(held) <= key(&target));
    world.mints.insert(at, target);
}

fn decoded(item: &Item) -> ShardRecord {
    ShardRecord::decode(&item.value).expect("the store holds shard records")
}

impl Records {
    /// Whether a write may take `arm`: `true` for `Pass`, `true` for a lost or parked reply while a fault remains, and
    /// `false` for every other arm of the store double.
    fn admits(&self, arm: Arm, world: &World) -> bool {
        match arm {
            PASS => true,
            LOST | DROPPED | HELD => world.faults > 0,
            _ => false,
        }
    }

    fn host_write(
        &self,
        world: &mut World,
        side: Side,
        arm: Arm,
        kind: Kind,
        seen: &mut Seen,
    ) -> (Reply, Pending) {
        let writer = Writer::Host(side);
        let read = world.hosts[side.index()].read.take().expect("enabled");
        let pending = Pending {
            kind,
            writer,
            read: *read.value(),
            expect: read.version(),
            request: None,
        };
        let me = side.host();
        if kind == Kind::TakeOver
            && self.plant == Plant::UnnamedStandby
            && read.value().standby != Some(me)
        {
            return (unnamed_takeover(world, &read, me, arm), pending);
        }
        let scheduled = match (kind, self.plant, arm) {
            (Kind::Bump, Plant::DoubleWin, PASS) => Arm::DoubleWin,
            _ => arm,
        };
        let after_lost = world.lost == Some((writer, read.version()));
        world.store.schedule(scheduled);
        let result = match kind {
            Kind::Bump => {
                seen.decision("Client::bump");
                world.open(writer).bump(&read)
            }
            Kind::TakeOver => {
                seen.decision("Client::take_over");
                let target = Target::of(read.value());
                world.open(writer).take_over(&read, target, me)
            }
            Kind::Designate | Kind::Flip | Kind::Transfer => {
                unreachable!("a host's write is a bump or a takeover")
            }
        };
        world.store.unschedule();
        let error = match result {
            Ok(bumped) => {
                if kind == Kind::Bump {
                    acknowledged_bump(world, read.value(), after_lost, &bumped, seen);
                }
                activate(world, bumped, seen);
                return (Reply::Done, pending);
            }
            Err(error) => error,
        };
        match (kind, error) {
            (Kind::Bump, StoreError::Refused(Refusal::Condition)) => {
                seen.witness(CONDITION_REFUSED);
            }
            (Kind::TakeOver, StoreError::Refused(Refusal::Condition)) => {
                seen.witness(TAKEOVER_CONDITION_REFUSED);
            }
            (_, StoreError::Unknown) if self.plant == Plant::RereadAfterUnknown => {
                reread_after_unknown(world, side, seen);
            }
            _ => {}
        }
        (Reply::Refused(error), pending)
    }

    /// The owner's planned transfer to the other host: its bump on the held read, the session that acknowledged bump
    /// activates, and `Client::transfer` over the bump's committed read, both writes under `Pass`. The bump earns the
    /// witnesses of a host's acknowledged bump, and the transfer spends one of the world's transfers when its request
    /// reaches the store. Returns the reply and the step's writes in issue order: the bump, and the transfer when the
    /// bump was acknowledged.
    fn transfer(
        &self,
        world: &mut World,
        side: Side,
        seen: &mut Seen,
    ) -> (Reply, Pending, Option<Pending>) {
        let writer = Writer::Host(side);
        let read = world.hosts[side.index()].read.take().expect("enabled");
        let bump = Pending {
            kind: Kind::Bump,
            writer,
            read: *read.value(),
            expect: read.version(),
            request: None,
        };
        let after_lost = world.lost == Some((writer, read.version()));
        world.store.schedule(PASS);
        seen.decision("Client::bump");
        let bumped = world.open(writer).bump(&read);
        world.store.unschedule();
        let bumped = match bumped {
            Ok(bumped) => bumped,
            Err(error) => {
                if error == StoreError::Refused(Refusal::Condition) {
                    seen.witness(CONDITION_REFUSED);
                }
                return (Reply::Refused(error), bump, None);
            }
        };
        acknowledged_bump(world, read.value(), after_lost, &bumped, seen);
        let committed = bumped.committed().clone();
        let session = activate(world, bumped, seen);
        let target = side.other().host();
        let transfer = Pending {
            kind: Kind::Transfer,
            writer,
            read: *committed.value(),
            expect: committed.version(),
            request: None,
        };
        let requests = world.store.requests(&key());
        world.store.schedule(PASS);
        let reply = if self.plant == Plant::TransferKeepsE {
            transfer_keeping_e(world, &committed, &session, target)
        } else {
            seen.decision("Client::transfer");
            let result = world.open(writer).transfer(
                &StandbyGate::qualified(),
                &committed,
                &Outgoing::of(&session),
                target,
            );
            result.err().map_or(Reply::Done, Reply::Refused)
        };
        world.store.unschedule();
        if world.store.requests(&key()) > requests {
            world.transfers -= 1;
        }
        (reply, bump, Some(transfer))
    }

    fn designate(&self, world: &mut World, arm: Arm, seen: &mut Seen) -> (Reply, Pending) {
        let read = world.reconciler.read.take().expect("enabled");
        let pending = Pending {
            kind: Kind::Designate,
            writer: Writer::Reconciler,
            read: *read.value(),
            expect: read.version(),
            request: None,
        };
        let standby = Side::of(read.value().owner).other().host();
        world.store.schedule(arm);
        seen.decision("Client::designate");
        let target = Target::of(read.value());
        let result = world
            .open(Writer::Reconciler)
            .designate(&read, target, standby);
        world.store.unschedule();
        if !matches!(result, Err(StoreError::Stale(_))) {
            world.designations -= 1;
        }
        (result.err().map_or(Reply::Done, Reply::Refused), pending)
    }

    fn flip(&self, world: &mut World, arm: Arm, seen: &mut Seen) -> (Reply, Option<Pending>) {
        let read = world.reconciler.read.take().expect("enabled");
        let request = world.request.clone().expect("enabled");
        if self.plant != Plant::RetirementUnadmitted {
            seen.decision("Retirement::admit");
            if let Err(stale) = request.admit(read.value()) {
                seen.witness(STALE_RETIREMENT_REFUSED);
                return (Reply::Unadmitted(stale), None);
            }
        }
        let generation = read.value().generation.get();
        let pending = Pending {
            kind: Kind::Flip,
            writer: Writer::Reconciler,
            read: *read.value(),
            expect: read.version(),
            request: Some(request),
        };
        world.store.schedule(arm);
        seen.decision("Client::flip");
        seen.decision("flip::flipped");
        let result = world.open(Writer::Reconciler).flip(&read);
        world.store.unschedule();
        match result {
            Ok(_) => {
                world.request = None;
                (Reply::Done, Some(pending))
            }
            Err(error) => {
                if error == StoreError::Refused(Refusal::Condition)
                    && world.store.flips.contains(&generation)
                {
                    seen.witness(SECOND_FLIP_REFUSED);
                }
                (Reply::Refused(error), Some(pending))
            }
        }
    }

    fn release(&self, world: &mut World, seen: &mut Seen) -> (Reply, Pending) {
        let pending = world
            .parked
            .take()
            .expect("a parked write keeps its record");
        let outcomes = world.store.release();
        let generation = world.record.1.generation.get();
        for outcome in &outcomes {
            if *outcome != Outcome::NotCommitted(Refusal::Condition) {
                continue;
            }
            match pending.kind {
                Kind::Bump if generation > pending.read.generation.get() => {
                    seen.witness(PARKED_BUMP_REFUSED_AFTER_FLIP);
                }
                Kind::Flip if world.store.flips.contains(&pending.read.generation.get()) => {
                    seen.witness(SECOND_FLIP_REFUSED);
                }
                _ => {}
            }
        }
        (Reply::Released(outcomes), pending)
    }

    /// `Err` naming `action` and the reply when `reply` is one of the replies the module documentation lists as outside
    /// an unplanted world's contract, except a `Regression` under the `double-win` plant; `Ok` for every other reply.
    pub(crate) fn expected(&self, action: Action, reply: &Reply) -> Result<(), String> {
        let Reply::Refused(error) = reply else {
            return Ok(());
        };
        let outside = matches!(
            error,
            StoreError::Regression(_)
                | StoreError::Withdrawn
                | StoreError::Log
                | StoreError::Codec(_)
                | StoreError::Successor(_)
                | StoreError::Namespace
        );
        let planted = matches!(
            (self.plant, error),
            (Plant::DoubleWin, StoreError::Regression(_))
        );
        if outside && !planted {
            return Err(format!("{action:?} returned {error:?}"));
        }
        Ok(())
    }
}

/// The `reread-after-unknown` plant's wrong decision, run in the host write that returned `StoreError::Unknown`: the
/// host rereads the record and mints the tenure the record names for it.
fn reread_after_unknown(world: &mut World, side: Side, seen: &mut Seen) {
    seen.decision("Client::read");
    if let Ok(reread) = world.open(Writer::Host(side)).read::<ShardRecord>(key()) {
        if reread.value().owner == side.host() {
            mint(world, Target::of(reread.value()));
        }
        world.hosts[side.index()].read = Some(reread);
    }
}

/// Pairs the store double's versions committed after its first `commits` with the step's `writes` in issue order,
/// records each commit's witnesses and the world's lost commit and handed tenure, and advances the world's record. A
/// step's writes commit in the order it issued them, and a write that fails ends the step's writes, so the new versions
/// pair with a prefix of `writes`. Returns the transfer step's bump when its transfer also committed, and the step's
/// last commit.
fn observe(
    next: &mut World,
    action: Action,
    unknown: bool,
    commits: usize,
    mut writes: [Option<Pending>; 2],
    seen: &mut Seen,
) -> (Option<Commit>, Option<Commit>) {
    let issued = writes.iter().flatten().count();
    let added = next.store.commit_count(&key()) - commits;
    assert!(added <= writes.len(), "a step commits at most two writes");
    let mut observed = [None, None];
    for (at, slot) in observed.iter_mut().enumerate().take(added) {
        let item = &next.store.versions(&key())[commits + at];
        let (version, value) = (item.version, decoded(item));
        let pending = writes[at]
            .take()
            .expect("each commit comes from one of the step's writes");
        if (unknown || action == Release) && at + 1 == issued {
            next.lost = Some((pending.writer, version));
        }
        if action == Release {
            seen.witness(PARKED_COMMITTED_AT_RELEASE);
        }
        match pending.kind {
            Kind::TakeOver => seen.witness(TAKEOVER_COMMITTED),
            Kind::Flip => seen.witness(FLIP_COMMITTED),
            Kind::Transfer => {
                seen.witness(TRANSFER_COMMITTED);
                let Writer::Host(side) = pending.writer else {
                    unreachable!("a host transfers")
                };
                next.handed = Some(Target {
                    owner: side.other().host(),
                    attempts: pending
                        .read
                        .attempts
                        .checked_add(1)
                        .expect("a committed transfer left room for two attempts"),
                    ..Target::of(&pending.read)
                });
            }
            Kind::Bump | Kind::Designate => {}
        }
        *slot = Some(Commit {
            below: next.record.1,
            written: value,
            pending,
        });
        next.record = (version, value);
    }
    match observed {
        [first, Some(second)] => (first, Some(second)),
        [first, None] => (None, first),
    }
}

/// The witnesses of a host's acknowledged bump of `read`: a fresh bump after a flip, a bump after a lost commit when
/// `after_lost` held before the bump, and the target's bump of the tenure a committed transfer intended, which clears
/// that tenure.
fn acknowledged_bump(
    world: &mut World,
    read: &ShardRecord,
    after_lost: bool,
    bumped: &Bumped,
    seen: &mut Seen,
) {
    if bumped.attempt() == 0 {
        seen.witness(FRESH_BUMP_AFTER_FLIP);
    }
    if after_lost {
        seen.witness(BUMP_AFTER_LOST_COMMIT);
    }
    if world.handed == Some(Target::of(read)) {
        seen.witness(TARGET_BUMP_AFTER_TRANSFER);
        world.handed = None;
    }
}

/// Activates the session of an acknowledged bump or takeover and records its mint.
fn activate(world: &mut World, bumped: Bumped, seen: &mut Seen) -> Session {
    seen.decision("Session::activate");
    let session = Session::activate(bumped).expect("the bound keeps g and E small");
    mint(world, session.target());
    session
}

/// The `transfer-keeps-e` plant's wrong write: the value `flip::transferred` computes over `committed` with the bump's
/// `E` kept, written by a raw exact-version write on `committed`'s version.
fn transfer_keeping_e(
    world: &mut World,
    committed: &Read<ShardRecord>,
    session: &Session,
    target: Host,
) -> Reply {
    let own = (session.shard(), session.target());
    let value = match transferred(committed.value(), own, target) {
        Ok(value) => ShardRecord {
            attempts: committed.value().attempts,
            ..value
        },
        Err(refusal) => return Reply::Refused(refusal.into()),
    };
    let write = Write::Exact {
        expect: committed.version(),
        value: value.encode(),
    };
    Reply::Raw(world.store.write(&key(), &write))
}

fn unnamed_takeover(world: &mut World, read: &Read<ShardRecord>, me: Host, arm: Arm) -> Reply {
    let value = ShardRecord {
        owner: me,
        attempts: read.value().attempts + 1,
        standby: None,
        ..*read.value()
    };
    let write = Write::Exact {
        expect: read.version(),
        value: value.encode(),
    };
    world.store.schedule(arm);
    let outcome = world.store.write(&key(), &write);
    world.store.unschedule();
    Reply::Raw(outcome)
}

fn arm_of(action: Action) -> Option<Arm> {
    match action {
        Bump(_, arm) | TakeOver(_, arm) | Designate(arm) | Flip(arm) => Some(arm),
        _ => None,
    }
}

/// The capacity of a canonical form in bytes; [`Canon::push`] panics on a form longer than this.
const CANON: usize = 96;

/// A world's canonical form, the fields the module documentation lists for it, one byte per value.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Canon {
    bytes: [u8; CANON],
    len: usize,
}

impl Canon {
    fn push(&mut self, value: u64) {
        assert!(
            self.len < CANON,
            "a canonical form holds at most {CANON} bytes"
        );
        self.bytes[self.len] =
            u8::try_from(value).expect("the bound keeps every model value below 256");
        self.len += 1;
    }

    fn target(&mut self, target: &Target) {
        self.push(target.generation.get());
        self.push(target.owner.get());
        self.push(u64::from(target.attempts));
    }
}

impl Model for Records {
    type World = World;
    type Action = Action;
    type Event = Event;
    type Canon = Canon;

    fn root(&self) -> World {
        assert!(
            self.bound.faults <= 1,
            "the world tracks one parked write and one release at a time"
        );
        let mut world = World {
            store: SimStore::new(),
            record: (Version::FIRST, root_record()),
            hosts: Default::default(),
            reconciler: Holder::default(),
            request: None,
            faults: self.bound.faults,
            designations: self.bound.designations,
            mints: Vec::new(),
            parked: None,
            lost: None,
            transfers: self.bound.transfers,
            handed: None,
        };
        let owner = Writer::Host(A);
        let created = world
            .open(owner)
            .create(key(), root_record())
            .expect("the empty store creates the record");
        let bumped = world
            .open(owner)
            .bump(&created)
            .expect("the owner bumps its created record");
        world.record = (world.current().version, decoded(world.current()));
        let session = Session::activate(bumped).expect("the root generation activates");
        mint(&mut world, session.target());
        world
    }

    fn alphabet(&self) -> &[Action] {
        &ALPHABET
    }

    fn enabled(&self, world: &World, action: Action) -> bool {
        let below_top = |read: &Read<ShardRecord>| read.value().attempts < self.bound.top;
        let ceiling = u64::from(self.bound.top) + u64::from(self.bound.handoff);
        let handed = |read: &Read<ShardRecord>| {
            world.handed == Some(Target::of(read.value()))
                && u64::from(read.value().attempts) < ceiling
        };
        let held = |side: Side| world.hosts[side.index()].read.as_ref();
        let stale = |read: &Read<ShardRecord>| read.version() != world.record.0;
        match action {
            Action::Read(side) => held(side).is_none(),
            ReconcilerRead => world.reconciler.read.as_ref().is_none_or(stale),
            Bump(side, arm) => {
                self.admits(arm, world)
                    && held(side).is_some_and(|read| {
                        read.value().owner == side.host() && (below_top(read) || handed(read))
                    })
            }
            TakeOver(side, arm) => {
                self.admits(arm, world)
                    && held(side)
                        .is_some_and(|read| read.value().owner != side.host() && below_top(read))
            }
            Transfer(side) => {
                world.transfers > 0
                    && held(side).is_some_and(|read| {
                        read.value().owner == side.host()
                            && below_top(read)
                            && u64::from(read.value().attempts) + 2 <= ceiling
                    })
            }
            Request => world.reconciler.read.as_ref().is_some_and(|read| {
                world
                    .request
                    .as_ref()
                    .is_none_or(|request| request.target != Target::of(read.value()))
            }),
            Designate(arm) => {
                self.admits(arm, world) && world.designations > 0 && world.reconciler.read.is_some()
            }
            Flip(arm) => {
                self.admits(arm, world)
                    && world.reconciler.read.is_some()
                    && world.request.is_some()
            }
            Release => !world.store.parked().is_empty(),
        }
    }

    fn kind(&self, action: Action) -> &'static str {
        match action {
            Action::Read(_) => "Read",
            Bump(..) => "Bump",
            TakeOver(..) => "TakeOver",
            Transfer(_) => "Transfer",
            ReconcilerRead => "ReconcilerRead",
            Request => "Request",
            Designate(_) => "Designate",
            Flip(_) => "Flip",
            Release => "Release",
        }
    }

    fn step(
        &self,
        world: &World,
        action: Action,
        seen: &mut Seen,
    ) -> Result<(World, Event), String> {
        let mut next = world.clone();
        let commits = next.store.commit_count(&key());
        let queued = next.store.parked().len();
        let (reply, writes) = match action {
            Action::Read(_) | ReconcilerRead => {
                let who = match action {
                    Action::Read(side) => Writer::Host(side),
                    _ => Writer::Reconciler,
                };
                seen.decision("Client::read");
                let reply = match next.open(who).read::<ShardRecord>(key()) {
                    Ok(read) => {
                        next.holder(who).read = Some(read);
                        Reply::Done
                    }
                    Err(error) => Reply::Refused(error),
                };
                (reply, [None, None])
            }
            Bump(side, arm) => {
                let (reply, pending) = self.host_write(&mut next, side, arm, Kind::Bump, seen);
                (reply, [Some(pending), None])
            }
            TakeOver(side, arm) => {
                let (reply, pending) = self.host_write(&mut next, side, arm, Kind::TakeOver, seen);
                (reply, [Some(pending), None])
            }
            Transfer(side) => {
                let (reply, bump, transfer) = self.transfer(&mut next, side, seen);
                (reply, [Some(bump), transfer])
            }
            Request => {
                seen.decision("Retirement::new");
                let read = next.reconciler.read.as_ref().expect("enabled").value();
                next.request = Retirement::new(
                    read.active,
                    Role::Active,
                    Target::of(read),
                    Trigger::VolumeState,
                );
                (Reply::Done, [None, None])
            }
            Designate(arm) => {
                let (reply, pending) = self.designate(&mut next, arm, seen);
                (reply, [Some(pending), None])
            }
            Flip(arm) => {
                let (reply, pending) = self.flip(&mut next, arm, seen);
                (reply, [pending, None])
            }
            Release => {
                let (reply, pending) = self.release(&mut next, seen);
                (reply, [Some(pending), None])
            }
        };
        self.expected(action, &reply)?;
        let committed = next.store.commit_count(&key()) > commits;
        let unknown = matches!(
            reply,
            Reply::Refused(StoreError::Unknown) | Reply::Raw(Outcome::Unknown)
        );
        let parked = next.store.parked().len() > queued;
        if parked {
            next.parked = writes.iter().flatten().last().cloned();
        }
        if let (Some(arm), true) = (arm_of(action), unknown) {
            next.faults -= 1;
            if matches!(action, Bump(..) | TakeOver(..)) && next.mints == world.mints {
                match arm {
                    LOST if committed => seen.witness(LOST_AFTER_COMMIT),
                    DROPPED if !committed && !parked => seen.witness(LOST_WITHOUT_COMMIT),
                    HELD if !committed && parked => seen.witness(PARKED),
                    _ => {}
                }
            }
        }
        let (earlier, commit) = observe(&mut next, action, unknown, commits, writes, seen);
        Ok((
            next,
            Event {
                reply,
                commit,
                earlier,
            },
        ))
    }

    fn monitor(&self, world: &World, event: Option<&Event>) -> Option<&'static str> {
        let epoch = |target: &Target| (target.generation, target.attempts);
        let mints = &world.mints;
        if (1..mints.len()).any(|at| mints[..at].iter().any(|m| epoch(m) == epoch(&mints[at]))) {
            return Some(NO_EPOCH_REUSE);
        }
        let commits = || {
            event
                .into_iter()
                .flat_map(|event| event.earlier.iter().chain(&event.commit))
        };
        for Commit { below, written, .. } in commits() {
            if written.owner != below.owner && written.generation == below.generation {
                let named = below.standby == Some(written.owner)
                    && below.attempts > 0
                    && written.attempts == below.attempts + 1
                    && written.standby.is_none()
                    && written.active == below.active;
                if !named {
                    return Some(NAMED_STANDBY_TAKES_OVER);
                }
            }
        }
        if commits().any(|Commit { below, pending, .. }| {
            matches!(pending.kind, Kind::Bump | Kind::TakeOver | Kind::Transfer)
                && below.generation != pending.read.generation
        }) {
            return Some(BUMP_AT_OWN_GENERATION);
        }
        let flips = &world.store.flips;
        if (1..flips.len()).any(|at| flips[..at].contains(&flips[at])) {
            return Some(BUMP_AT_OWN_GENERATION);
        }
        for Commit {
            below,
            written,
            pending,
        } in commits()
        {
            if written.generation.get() == below.generation.get() + 1 {
                let served = pending.request.as_ref().is_some_and(|request| {
                    request.target.generation == below.generation
                        && request.target.owner == below.owner
                        && request.target.attempts == below.attempts
                        && request.volume == below.active
                });
                if !served {
                    return Some(STALE_REQUEST_REFUSED);
                }
            }
        }
        None
    }

    fn canonical(&self, world: &World) -> Canon {
        let World {
            store,
            record: (version, current),
            hosts,
            reconciler,
            request,
            faults,
            designations,
            mints,
            parked,
            lost: _,
            transfers,
            handed,
        } = world;
        let [active, spare] = self.volumes;
        let volume = |volume: VolumeId| match volume {
            _ if volume == active => 0,
            _ if volume == spare => 1,
            _ => unreachable!("the model names the root's two volumes"),
        };
        let mut canon = Canon {
            bytes: [0; CANON],
            len: 0,
        };
        let encode_record = |canon: &mut Canon, record: &ShardRecord| {
            let ShardRecord {
                shard: _,
                generation,
                active,
                owner,
                attempts,
                spare,
                checkpoint: _,
                cut: _,
                pages: _,
                page_cap: _,
                namespace: _,
                ancestry: _,
                standby,
            } = record;
            canon.push(generation.get());
            canon.push(volume(*active));
            canon.push(owner.get());
            canon.push(u64::from(*attempts));
            let (spare, host) = spare.map_or((2, 0), |(spare, host)| (volume(spare), host.get()));
            canon.push(spare);
            canon.push(host);
            canon.push(standby.map_or(0, Host::get));
        };
        let encode_request = |canon: &mut Canon, request: Option<&Retirement>| {
            canon.push(u64::from(request.is_some()));
            if let Some(request) = request {
                canon.target(&request.target);
                canon.push(volume(request.volume));
            }
        };
        canon.push(version.get());
        encode_record(&mut canon, current);
        canon.push(store.flips.len() as u64);
        for &flip in &store.flips {
            canon.push(flip);
        }
        for Holder { mark: _, read } in hosts.iter().chain([reconciler]) {
            canon.push(read.as_ref().map_or(0, |read| read.version().get()));
            if let Some(read) = read {
                encode_record(&mut canon, read.value());
            }
        }
        encode_request(&mut canon, request.as_ref());
        canon.push(u64::from(*faults));
        canon.push(u64::from(*designations));
        canon.push(u64::from(*transfers));
        canon.push(u64::from(handed.is_some()));
        if let Some(handed) = handed {
            canon.target(handed);
        }
        canon.push(mints.len() as u64);
        for mint in mints {
            canon.target(mint);
        }
        if let (Canonical::Full, Some(pending)) = (self.canonical, parked) {
            let Pending {
                kind,
                writer,
                read,
                expect,
                request,
            } = pending;
            canon.push(expect.get());
            encode_record(&mut canon, read);
            canon.push(*kind as u64);
            canon.push(match writer {
                Writer::Host(side) => *side as u64,
                Writer::Reconciler => 2,
            });
            encode_request(&mut canon, request.as_ref());
        }
        canon
    }
}

pub(crate) struct Site {
    pub(crate) file: &'static str,
    pub(crate) owner: &'static str,
    pub(crate) function: &'static str,
}

pub(crate) struct Copied {
    pub(crate) name: &'static str,
    pub(crate) rule: &'static str,
    pub(crate) sites: &'static [Site],
}

pub(crate) const CEILING: usize = 4;

pub(crate) const COPIED: &[Copied] = &[
    Copied {
        name: "sequence-routing",
        rule: "A host bumps a record that names it owner (restart at E > 0, fresh bump at E = 0) and otherwise \
               attempts the takeover.",
        sites: &[
            Site {
                file: "restart.rs",
                owner: "Restart",
                function: "records",
            },
            Site {
                file: "fresh.rs",
                owner: "Fresh",
                function: "records",
            },
            Site {
                file: "takeover.rs",
                owner: "Takeover",
                function: "records",
            },
        ],
    },
    Copied {
        name: "flip-admission",
        rule: "The reconciler admits its request against the read it flips from, and flips that read.",
        sites: &[Site {
            file: "reconcile.rs",
            owner: "Reconciler",
            function: "flip_for",
        }],
    },
    Copied {
        name: "tenure-check",
        rule: "Before the preempt and before the capability, the record still names the issuer's tenure and volume. \
               The fence world uses the rule twice: in its preempt step and after the fencing boundary.",
        sites: &[Site {
            file: "takeover.rs",
            owner: "Takeover",
            function: "current",
        }],
    },
    Copied {
        name: "step-order",
        rule: "Report #1, Register, the check, the preempt, Report #2.",
        sites: &[Site {
            file: "takeover.rs",
            owner: "Takeover",
            function: "run",
        }],
    },
];
