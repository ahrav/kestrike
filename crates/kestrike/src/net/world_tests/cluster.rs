//! The generated cluster world: several production owners, each with its
//! own storage, device and two links, and two logical clients that each
//! hold one session with every owner, all driven by one turn controller
//! from one chooser.
//!
//! A profile in [`PROFILES`] declares ranges, and the run's root draws the
//! topology inside them before any owner starts: the owner count, the key
//! count and the hot key. The swarm family's root also selects the shape
//! itself, as [`swarm`] describes. Every key routes to one owner by the declared
//! contract `key % owners`. Logical client 0 uploads and both clients
//! read, so competing GETs and PUTs meet on shared keys, and each client's
//! requests cross owners as the keys they name route.
//!
//! A run alternates fault phases and healthy phases on one retained world.
//! A fault phase turns on the profile's link faults, device faults and
//! delayed transmit returns and issues its budget of generated operations,
//! each selected by the chooser among the operations valid in the current
//! state; a hot key's operations take more candidate slots. A device fault
//! makes a write or read command report an I/O error after it moved no
//! byte, or, as a torn write or a partial read, after it moved a prefix of
//! whole sectors, so the upload that wrote it ends unpublished and the GET
//! that read it ends with no complete object. The phase ends as its last
//! operation is issued, or, when the profile sustains its faults, once the
//! outcome of every operation it issued was also collected. The healthy
//! phase that follows turns the faults off, drains every outstanding
//! operation, then probes every owner: client 0 publishes a fresh version
//! of a key the owner holds and the other client must read exactly that
//! version. A
//! client keeps an upload's source slot while a link holds a device
//! reference to it, so once the owner's links hold none, no source slot or
//! upload may remain held. A probe that fails three times, or a healed
//! owner that keeps finished work's resources, ends the run unsuccessful.
//!
//! The generator sends each key's operations to the owner the checker's
//! contract names; the wrong-owner control sends key 0's to the next
//! owner. Every uploaded object's bytes name its key, version and
//! the owner it was sent to, and the checker matches each completed GET
//! against the uploads it recorded. A complete GET whose bytes are not
//! exactly one upload of its key at its uploaded length, an incomplete GET
//! whose exposed bytes are not a prefix of one such upload, a read of an
//! upload its owner reported as not published, a key served from an owner
//! the contract does not name, or a version older than the newest
//! publication collected or read before the GET was issued, or one an
//! invalidation completed before the GET was issued removed, is a
//! violation. So are an incomplete GET that exposed no bytes; an owner
//! whose index binds a version it reported as not published, one an
//! invalidation removed, one its acknowledged INVALIDATE covers, one
//! older than a publication of the key at that
//! owner, or another version than a publication it reports; a removal
//! report that disagrees with the owner's index; and a report that a
//! version an invalidation removed was not published. Each owner's stopped
//! boundaries, and its state once the run ends, also run the registry and
//! media check every mixed run uses. A control profile whose run records
//! no failure ends as [`unmet`] names: unsuccessful under [`NO_EFFECT`]
//! when it finished before its plant did what a rule forbids, and under
//! [`UNSEEN`] when the plant did and no check failed.
//!
//! A profile may rest the world idle for a virtual gap between a healthy
//! phase and the next fault phase, and cuts a reporting window every
//! `window` phases and at its last phase, in the middle of a fault phase
//! while operations are outstanding, so a phase count `window` does not
//! divide ends in a shorter final window. When the profile compacts, no
//! check failed and every audit passed, the cut retires each key's uploads
//! below its floor, every outstanding GET's floor and every upload whose
//! outcome is still to be reported, and the registry content of those
//! uploads. A GET issued since, or still outstanding, legally returns only
//! a retained version, so a GET that returns a retired version is still a
//! stale read, and every pending outcome report still finds its upload.
//!
//! A GET with outcome `Missing`, `Pressure` or `Failed` exposes zero bytes.
//!
//! In a profile with versioned sessions each owner holds a fenced
//! coverage over a store of its own. An upload names its cache version,
//! one above its checker version. An invalidation is
//! client 0's INVALIDATE of its key over every version the key has taken;
//! the owner removes the key's object when it first holds the frame's
//! entry, a cover event writes the coverage page, and the owner then sends
//! INVALIDATED.
//! The client poll that receives it raises the key's floor past those
//! versions, so a GET issued later that returns one of them is a stale
//! read. It also marks each upload of the key to that owner up to those
//! versions as covered. The owner's index that binds one binds a version
//! an acknowledged invalidation covered. The binding is judged when the
//! acknowledgment arrives, when an upload's publication is collected and
//! at each stopped boundary, while the checker carries the upload. An
//! upload admitted
//! before the INVALIDATE that publishes after it is such a binding. The
//! client sends each INVALIDATE once. When the links lose it or the
//! owner's INVALIDATED, the client receives no acknowledgment, which
//! raises no floor and covers nothing. A direct
//! invalidation alone reports its removal, so the checks of that report
//! against the owner's index, and the rule against reporting a removed
//! version as not published, judge direct invalidations only.
//!
//! Node lifecycle, session lifecycle, membership and placement are
//! unsupported here; a run reports them as unavailable dimensions.

use std::cell::RefCell;
use std::rc::Rc;

use crate::oracle::{Label, Obligation};
use crate::sim::action::{ActionKind, Profile};
use crate::sim::choice::{CANDIDATE_LEN, Candidate, ChoiceError, Chooser, Domain, Site};
use crate::sim::entropy::{DrawRefusal, draw, key_pair, key_pair_site, nonce_site};
use crate::sim::trace::Event;
use crate::sim::turn::{Defect, End, Hook, Limits, Report, World, run_hooked};
use crate::storage::device::sim::{Report as Honesty, ScriptReason, ScriptRefusal, Stage};
use crate::storage::owner_fixture::{Fault, leak_unit, set_clock};
use crate::storage::store::Client as StoreClient;
use crate::storage::store::sim::{MemLog, Shared};
use crate::storage::store_tests::seeded_under;
use crate::storage::{
    AllocationId, CacheVersion, CommandToken, DeviceStatus, Operation, SECTOR, SlotIndex,
    WorkBudget,
};

use super::super::audit::{Audit, Class, Verdict};
use super::super::client::SessionState;
use super::super::fetch::Outcome as Fetched;
use super::super::geometry::FRAGMENT_LEN;
use super::super::link::{Draws, Faults, LinkLimits, TxRelease};
use super::super::observe::{Failure, FirstFailure, Lenses, Registry, boundary, conserved};
use super::super::owner_tests::{OWNER, PRINCIPALS, key, payload};
use super::super::put_tests::{Drawn, Scene, fenced_coverage, scene_drawn};
use super::super::requests::RequestId;
use super::super::rules::MANIFEST;
use super::super::upload::UploadOutcome;
use super::bundle::Collected;
use super::{
    Geometry, LINK_TURN_US, STAGES, TTL_MS, WAIT_US, WorldKind, check_turn_limits, poll_owner,
    ticks, upload_code,
};

pub(crate) mod causes;
mod order;
#[cfg(test)]
mod order_tests;
mod swarm;
#[cfg(test)]
mod tests;

/// The generator version every cluster profile's record names.
pub(crate) const GENERATOR: u8 = 4;

/// The most owners a cluster profile admits.
pub(crate) const MAX_OWNERS: u8 = 4;

/// The most keys a cluster profile admits.
pub(crate) const MAX_KEYS: u8 = 8;

/// Logical clients: client 0 uploads and reads, client 1 reads.
pub(crate) const CLIENTS: usize = 2;

/// Probe attempts a healthy phase gives each owner before the run ends
/// unsuccessful.
const PROBES: u32 = 3;

/// The wait before a failed probe's next attempt: a request's deadline plus
/// the owner's linger, past which the owner holds no result of a request
/// the fault phase left, so the retry meets none of them.
const RETRY_WAIT_US: u64 = WAIT_US + OWNER.serve.linger_us;

/// A deliberately wrong cluster behavior a control profile plants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Plant {
    None,
    /// Key 0's operations go to the owner after the one its contract names.
    WrongOwner,
    /// A completed GET of a key with two publications returns the older
    /// publication's bytes.
    StaleRead,
    /// A completed GET issued before the latest window cut returns the
    /// bytes of the version just below its floor: a delayed completion that
    /// crosses a cut with stale bytes.
    LateStale,
    /// One upload's request is never retired, so its source slots stay
    /// held: a leaked credit.
    Leak,
    /// A payload byte of a bound object on owner 0's device changes.
    Corrupt,
    /// A completed GET hands its client a last byte other than the one the
    /// owner sent.
    Misread,
    /// Client 0's INVALIDATE names a key no upload takes, and the run
    /// tracks it as the INVALIDATE of its own key: an acknowledged
    /// invalidation that removed nothing, which leaves the key's object
    /// bound. It takes effect only in a shape that invalidates over
    /// versioned sessions.
    Unremoved,
    /// Owner 0's first poll once the plant is armed reserves one payload
    /// unit from its extent allocator and records it in no slot, which the
    /// conservation rule judges at the end of that turn.
    LeakedUnit,
    /// Owner 0's first poll once the plant is armed with a datagram due
    /// toward it arms that owner's multiplexer's swallow, so its next
    /// receive that fills a slot drops the last lease it filled and reports
    /// one fewer, which the datagram accounts check judges at that
    /// partition's next stopped boundary.
    Uncounted,
    /// The plant selects at most one read of a run, a complete read of the
    /// hot key's first version under the depth 1 orders of [`order`], and
    /// changes the last byte that read hands its client.
    Depth1,
    /// [`Plant::Depth1`] under the depth 2 orders.
    Depth2,
    /// [`Plant::Depth1`] under the depth 3 orders.
    Depth3,
}

/// One device's faults, each the percentage of its write commands or of
/// its read commands that fail: `write_error` and `read_error` move no
/// byte and report an I/O error, `write_torn` lands a prefix of whole
/// sectors and `read_partial` writes one into the buffer, each then
/// reporting an I/O error. An operation's two rates sum to at most 100.
/// A command draws once, as the selection that executes it is applied,
/// against its operation's rates in force then, and two zero rates draw
/// nothing; a hit of a prefix kind draws its prefix length at the same
/// site. A torn write the device refuses on a range its persistence
/// profile qualifies fails with the no-byte error instead. A generated
/// profile draws honest faults only: each fails its command and reports
/// the failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DeviceFaults {
    pub(crate) write_error: u64,
    pub(crate) read_error: u64,
    pub(crate) write_torn: u64,
    pub(crate) read_partial: u64,
}

/// A device with every fault off.
const SOUND: DeviceFaults = DeviceFaults {
    write_error: 0,
    read_error: 0,
    write_torn: 0,
    read_partial: 0,
};

/// The least of each reached quantity a profile requires before its run
/// counts. The generated workload's publications and reads contribute to
/// `published`, `hits` and `cross`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Minima {
    pub(crate) published: u64,
    pub(crate) hits: u64,
    /// Exact reads by a logical client that has, with this read, read from
    /// two or more owners.
    pub(crate) cross: u64,
    pub(crate) faults: u64,
    pub(crate) healthy: u64,
    /// Publications that bound a slot an earlier publication at the same
    /// owner bound.
    pub(crate) reused: u64,
}

/// The rule a run names once one owner's probes all failed.
pub(crate) const PROBES_FAILED: &str = "healthy work made no progress after the faults healed";

/// The rule a run names once a healed owner kept finished work's resources.
pub(crate) const KEPT_RESOURCES: &str = "a healed owner kept the resources of finished work";

/// The rule a control's run names when its plant did what a rule forbids
/// and the run finished or stopped at a limit with no failure: the checks
/// missed the plant.
pub(crate) const UNSEEN: &str = "the control's plant met no check";

/// The rule a control's run names when it finished with no failure before
/// its plant did what a rule forbids, or, for the control that starts the
/// version counter at its end, before the counter refused an upload.
pub(crate) const NO_EFFECT: &str = "the control's plant took no effect";

/// The failure of a control's run that recorded none and ended as `end`,
/// by whether its plant `acted`: [`UNSEEN`] once the plant acted and the
/// run finished or stopped at a limit, [`NO_EFFECT`] for a run that
/// finished before the plant acted, and none for a run a limit stopped
/// before the plant acted, which stays inconclusive, or a run a hook or a
/// defect ended.
pub(crate) fn unmet(end: End, acted: bool) -> Option<Failure> {
    match (end, acted) {
        (End::Done | End::Inconclusive(_), true) => Some(Failure::Unsuccessful(UNSEEN)),
        (End::Done, false) => Some(Failure::Unsuccessful(NO_EFFECT)),
        _ => None,
    }
}

/// The dimensions a cluster run leaves unavailable, as the capability
/// listing and a bundle's summary name them.
pub(crate) const UNAVAILABLE: &str = "node-lifecycle,session-lifecycle,membership,placement";

/// One cluster profile: its ranges, workload and fault dimensions, and the
/// minima its run must reach.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Shape {
    pub(crate) name: &'static str,
    /// The inclusive range the root draws the owner count from.
    pub(crate) owners: (u8, u8),
    /// The inclusive range the root draws the key count from; the count is
    /// raised to the owner count, so every owner holds a key.
    pub(crate) keys: (u8, u8),
    /// Object lengths an upload chooses among.
    pub(crate) sizes: &'static [u32],
    /// Candidate slots the hot key's operations take; every other key's
    /// take one.
    pub(crate) hot: u8,
    /// Outstanding GETs one logical client holds at one owner.
    pub(crate) concurrency: u8,
    /// Fault phases, each followed by a healthy phase.
    pub(crate) phases: u32,
    /// Generated operations each fault phase issues.
    pub(crate) phase_ops: u32,
    /// Each link direction's faults during a fault phase.
    pub(crate) faults: Faults,
    /// Each owner's device faults during a fault phase.
    pub(crate) device: DeviceFaults,
    /// Whether a fault phase keeps its faults on, once its budget is
    /// spent, until the outcome of every operation it issued was
    /// collected; `false` heals the faults as the last operation is
    /// issued.
    pub(crate) sustained: bool,
    /// Transmit references return after a drawn delay during a fault
    /// phase.
    pub(crate) delayed_returns: bool,
    pub(crate) invalidate: bool,
    /// Whether each owner holds a fenced coverage: each upload names its
    /// cache version, and an invalidation is client 0's INVALIDATE of
    /// every version its key has taken, which the owner acknowledges once
    /// its coverage page write commits. `false` runs owners that hold no
    /// coverage, whose uploads name cache version 0, and invalidates by
    /// calling the owner.
    pub(crate) versioned: bool,
    pub(crate) cancel: bool,
    pub(crate) plant: Plant,
    /// Windows that close before the plant takes effect.
    pub(crate) plant_after: u32,
    pub(crate) minima: Minima,
    /// Virtual microseconds the world rests after each healed phase before
    /// the next fault phase; 0 runs them back to back. The rest is idle
    /// time the controller skips.
    pub(crate) gap_us: u64,
    /// Phases per reporting window. A window cuts in the middle of its last
    /// fault phase, while its operations may still be outstanding; the
    /// run's last phase closes a final window of the phases left over.
    pub(crate) window: u32,
    /// The version the first upload of each key takes: a boundary control
    /// that reaches the version counter's end.
    first_version: u32,
    /// Whether each window cut retires the checker and registry history
    /// its carried frontier discharged; `false` keeps the whole history.
    compact: bool,
    /// The upload bound the shape declares in place of its own: a member of
    /// a drawn family declares the bound of the family's envelope.
    uploads: Option<u64>,
}

/// Faults of `loss`, `duplicate` and `reorder` percent and at most `delay`
/// turns of delay, with every other fault off.
const fn link_faults(loss: u64, duplicate: u64, reorder: u64, delay: u64) -> Faults {
    Faults {
        loss,
        duplicate,
        reorder,
        delay,
        stale: 0,
        truncate: 0,
        would_block: 0,
        error: 0,
        burst: 0,
        resend_loss: 0,
    }
}

const SIZES: [u32; 3] = [FRAGMENT_LEN / 2, 2 * FRAGMENT_LEN, 3 * FRAGMENT_LEN - 100];

const NO_MINIMA: Minima = Minima {
    published: 0,
    hits: 0,
    cross: 0,
    faults: 0,
    healthy: 0,
    reused: 0,
};

/// The broad profile: two to four owners, three to six keys, faulty links
/// with delayed returns, invalidations and cancels, then a healthy phase,
/// three times over.
const BROAD: Shape = Shape {
    name: "cluster-broad",
    owners: (2, 4),
    keys: (3, 6),
    sizes: &SIZES,
    hot: 3,
    concurrency: 2,
    phases: 3,
    phase_ops: 24,
    faults: link_faults(10, 10, 10, 2),
    device: SOUND,
    sustained: false,
    delayed_returns: true,
    invalidate: true,
    versioned: false,
    cancel: true,
    plant: Plant::None,
    plant_after: 0,
    gap_us: 0,
    window: 1,
    first_version: 0,
    compact: true,
    uploads: None,
    minima: Minima {
        published: 4,
        hits: 1,
        cross: 0,
        faults: 1,
        healthy: 3,
        reused: 0,
    },
};

/// The pressure profile: two or three owners on the fixture geometry with
/// six to eight keys of the two largest sizes, so publications displace
/// each other and storage reuses slots.
const PRESSURE: Shape = Shape {
    name: "cluster-pressure",
    owners: (2, 3),
    keys: (6, 8),
    sizes: &[2 * FRAGMENT_LEN, 3 * FRAGMENT_LEN - 100],
    hot: 2,
    concurrency: 1,
    phases: 2,
    phase_ops: 40,
    faults: link_faults(5, 5, 5, 1),
    device: SOUND,
    sustained: false,
    delayed_returns: false,
    invalidate: false,
    versioned: false,
    cancel: false,
    plant: Plant::None,
    plant_after: 0,
    gap_us: 0,
    window: 1,
    first_version: 0,
    compact: true,
    uploads: None,
    minima: Minima {
        published: 10,
        hits: 4,
        cross: 1,
        faults: 1,
        healthy: 2,
        reused: 1,
    },
};

/// A virtual day.
const DAY_US: u64 = 86_400_000_000;

/// The long profile: 731 fault and healthy phase pairs on one retained
/// world, with a virtual day of idle rest between consecutive pairs, 730
/// days of rest plus phase time in all, past two virtual years. A reporting
/// window spans 30 phases, and a final window spans the last 11.
const LONG: Shape = Shape {
    name: "cluster-long",
    owners: (2, 3),
    keys: (4, 6),
    phases: 731,
    phase_ops: 16,
    gap_us: DAY_US,
    window: 30,
    minima: Minima {
        published: 1_000,
        hits: 100,
        cross: 1,
        faults: 500,
        healthy: 731,
        reused: 1,
    },
    ..BROAD
};

/// The controls that must still fail after window cuts retired history:
/// each plant takes effect once two windows closed.
const LATE: Shape = Shape {
    name: "cluster-late",
    phases: 12,
    window: 2,
    plant_after: 2,
    gap_us: DAY_US,
    minima: NO_MINIMA,
    ..BROAD
};

/// Every cluster profile admission accepts: the broad, pressure and long
/// profiles, the controls whose planted wrong behavior the checks must
/// fail, the swarm family's envelope and the envelope of each swarm
/// control.
pub(crate) const PROFILES: [Shape; 20] = [
    BROAD,
    PRESSURE,
    Shape {
        name: "cluster-wrong-owner",
        owners: (2, 3),
        phases: 1,
        // Cancels would end the key-0 reads whose bytes expose the wrong
        // owner before they complete.
        cancel: false,
        plant: Plant::WrongOwner,
        minima: NO_MINIMA,
        ..BROAD
    },
    Shape {
        name: "cluster-stale-read",
        owners: (2, 3),
        phases: 1,
        // An invalidation turns a key's reads into misses until it is
        // republished, and a miss hands the plant no bytes to swap.
        invalidate: false,
        plant: Plant::StaleRead,
        // The plant substitutes an older publication, which the whole
        // history keeps.
        compact: false,
        minima: NO_MINIMA,
        ..BROAD
    },
    LONG,
    Shape {
        name: "cluster-late-stale",
        plant: Plant::LateStale,
        ..LATE
    },
    Shape {
        name: "cluster-late-leak",
        plant: Plant::Leak,
        ..LATE
    },
    Shape {
        name: "cluster-late-corrupt",
        plant: Plant::Corrupt,
        ..LATE
    },
    Shape {
        name: "cluster-version-end",
        phases: 1,
        first_version: u32::MAX,
        minima: NO_MINIMA,
        ..BROAD
    },
    swarm::ENVELOPE,
    swarm::control(0),
    swarm::control(1),
    swarm::control(2),
    swarm::control(3),
    swarm::control(4),
    swarm::control(5),
    swarm::control(6),
    ordered("cluster-order-1", Plant::Depth1),
    ordered("cluster-order-2", Plant::Depth2),
    ordered("cluster-order-3", Plant::Depth3),
];

const fn ordered(name: &'static str, plant: Plant) -> Shape {
    Shape {
        name,
        plant,
        minima: NO_MINIMA,
        ..BROAD
    }
}

impl Shape {
    /// Whether the profile is a control expected to fail: a planted wrong
    /// behavior, or a version counter started at its end.
    pub(crate) fn control(&self) -> bool {
        self.plant != Plant::None || self.first_version != 0
    }

    /// The most uploads a run starts: one per generated operation and one
    /// per probe attempt at every owner the profile admits, or the bound
    /// the shape declares in its place.
    pub(crate) const fn upload_attempts(&self) -> u64 {
        match self.uploads {
            Some(uploads) => uploads,
            None => {
                self.phases as u64 * (self.phase_ops as u64 + self.owners.1 as u64 * PROBES as u64)
            }
        }
    }

    /// The longest object an upload sends.
    pub(crate) fn largest(&self) -> u32 {
        self.sizes.iter().copied().max().unwrap_or(0)
    }

    /// Client 0's source-byte bound: the larger of its source slot pool and
    /// its largest upload object.
    pub(crate) fn source_bytes(&self) -> u64 {
        let pool = u64::from(super::super::put_tests::SOURCES) * u64::from(FRAGMENT_LEN);
        u64::from(self.largest()).max(pool)
    }

    /// The profile's capability listing line.
    pub(crate) fn listing(&self) -> String {
        let Self {
            name,
            owners: (owners_low, owners_high),
            keys: (keys_low, keys_high),
            hot,
            concurrency,
            phases,
            phase_ops,
            gap_us,
            window,
            compact,
            faults:
                Faults {
                    loss,
                    duplicate,
                    reorder,
                    delay,
                    stale,
                    truncate,
                    would_block,
                    error,
                    burst: _,
                    resend_loss: _,
                },
            device:
                DeviceFaults {
                    write_error,
                    read_error,
                    write_torn,
                    read_partial,
                },
            sustained,
            delayed_returns,
            invalidate,
            versioned,
            cancel,
            minima:
                Minima {
                    published,
                    hits,
                    cross,
                    faults,
                    healthy,
                    reused,
                },
            ..
        } = *self;
        let sizes = self
            .sizes
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "cluster: {name} generator={GENERATOR} owners={owners_low}..{owners_high} keys={keys_low}..{keys_high} clients={CLIENTS} sizes={sizes} hot_slots={hot} concurrency={concurrency} phases={phases} phase_ops={phase_ops} gap_us={gap_us} window={window} compact={compact} faults=loss:{loss},duplicate:{duplicate},reorder:{reorder},delay:{delay},stale:{stale},truncate:{truncate},would_block:{would_block},error:{error} device=write_error:{write_error},read_error:{read_error},write_torn:{write_torn},read_partial:{read_partial} sustained={sustained} delayed_returns={delayed_returns} invalidate={invalidate} versioned={versioned} cancel={cancel} minima=published:{published},hits:{hits},cross:{cross},faults:{faults},healthy:{healthy},reused:{reused} unavailable={UNAVAILABLE}\n"
        )
    }
}

/// The profile `name` names.
pub(crate) fn shape(name: &str) -> Option<&'static Shape> {
    PROFILES.iter().find(|shape| shape.name == name)
}

/// The shape a run of the profile `name` has at `root`: the profile's
/// own, or for the swarm family the member `root` selects, whose minima
/// and counts are the run's, or for a swarm control that member with the
/// control's plant.
pub(crate) fn shape_at(name: &str, root: u64) -> Option<&'static Shape> {
    if name == swarm::NAME {
        Some(swarm::member(root))
    } else {
        swarm::planted(name, root).or_else(|| shape(name))
    }
}

/// The action kinds a cluster run executes.
pub(crate) const DECLARED: [ActionKind; 8] = [
    ActionKind::Get,
    ActionKind::Read,
    ActionKind::Cancel,
    ActionKind::Invalidate,
    ActionKind::PutInvoke,
    ActionKind::PutPrepare,
    ActionKind::Supply,
    ActionKind::PutOutcome,
];

/// The controller's selection site.
const SITE: Site = Site {
    domain: Domain::Workload,
    actor: 0,
    site: 1,
};
/// The actor whose entropy site the topology draw reads.
const TOPOLOGY: u16 = 90;

/// Owner `cell`'s storage key-pair actor, its owner and two clients' nonce
/// actors, and its two links' actors.
fn actors(cell: u8) -> (u16, [u16; 3], [u16; 2]) {
    let base = 100 + 10 * u16::from(cell);
    (base, [base + 1, base + 2, base + 3], [base + 4, base + 5])
}

/// The site an owner's device draws a fault for a command of `op` at; the
/// owner's storage key-pair actor `index` decides there.
fn device_site(index: u16, op: Operation) -> Site {
    Site {
        domain: Domain::Disk,
        actor: index,
        site: match op {
            Operation::Read => 1,
            Operation::Write => 2,
        },
    }
}

/// The kind of device fault one draw selects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeviceKind {
    /// The command moves no byte and reports an I/O error.
    Error,
    /// The command moves a prefix of whole sectors, landed on media by a
    /// write or written into its buffer by a read, and reports an I/O
    /// error. A torn write the device refuses on a range its persistence
    /// profile qualifies moves no byte and carries the no-byte error
    /// instead.
    Prefix,
}

/// The bound below which `fault_command` draws the value that selects
/// the device kind.
const DRAW: u64 = 100;

/// The kind a draw of `drawn`, below [`DRAW`], selects for an operation
/// whose no-byte error rate is `error` and whose prefix rate is `prefix`:
/// a value below `error` selects the error, one at or above it and below
/// `error + prefix` the prefix kind, and any other value none. The two
/// rates sum to at most [`DRAW`], so each kind is selected for exactly its
/// rate's share of the values.
fn device_kind(drawn: u64, error: u64, prefix: u64) -> Option<DeviceKind> {
    if drawn < error {
        Some(DeviceKind::Error)
    } else if drawn < error + prefix {
        Some(DeviceKind::Prefix)
    } else {
        None
    }
}

/// The fault every drawn device fault attaches: for [`DeviceKind::Error`]
/// an I/O error status, and for [`DeviceKind::Prefix`] a torn write or a
/// partial read of the first `sectors` 512-byte sectors of a command of
/// `op`. `sectors` is read for the prefix kind only.
fn device_fault(op: Operation, kind: DeviceKind, sectors: u32) -> Fault {
    match (kind, op) {
        (DeviceKind::Error, _) => Fault::Status(DeviceStatus::Kernel(-libc::EIO)),
        (DeviceKind::Prefix, Operation::Write) => Fault::TornWrite { sectors },
        (DeviceKind::Prefix, Operation::Read) => Fault::PartialReadFailure { sectors },
    }
}

/// The fault a command of `op` carries in place of a torn write the device
/// refuses on a range its persistence profile qualifies: the no-byte
/// error.
fn refused_tear(op: Operation) -> Fault {
    device_fault(op, DeviceKind::Error, 0)
}

/// The device faults a run applied, by kind. A torn write hit the device
/// refused on a range its persistence profile qualifies counts in
/// `torn_refused` alone, though its command carries the no-byte error.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Applied {
    pub(crate) write_error: u64,
    pub(crate) read_error: u64,
    /// Torn writes the device admitted.
    pub(crate) write_torn: u64,
    /// Torn write hits refused on a qualified range.
    pub(crate) torn_refused: u64,
    pub(crate) read_partial: u64,
    /// Admitted torn writes and partial reads whose prefix is longer than
    /// one sector and shorter than its command.
    pub(crate) interior: u64,
}

impl Applied {
    /// The counts of `self` and `other` added field by field.
    pub(crate) fn plus(self, other: Self) -> Self {
        Self {
            write_error: self.write_error + other.write_error,
            read_error: self.read_error + other.read_error,
            write_torn: self.write_torn + other.write_torn,
            torn_refused: self.torn_refused + other.torn_refused,
            read_partial: self.read_partial + other.read_partial,
            interior: self.interior + other.interior,
        }
    }
}

/// Every site a cluster run draws at, for the most owners any profile
/// admits.
pub(crate) fn sites() -> Vec<Site> {
    let mut sites = vec![SITE, nonce_site(TOPOLOGY)];
    for cell in 0..MAX_OWNERS {
        let (index, nonces, links) = actors(cell);
        sites.push(key_pair_site(index));
        sites.extend([Operation::Read, Operation::Write].map(|op| device_site(index, op)));
        sites.extend(nonces.map(nonce_site));
        sites.extend(
            links
                .iter()
                .flat_map(|&link| super::super::link::sites(link)),
        );
    }
    sites
}

const OWNER_POLL: u8 = 1;
const CLIENT_POLL: u8 = 2;
const SERVICE: u8 = 3;
const READ: u8 = 4;
const PREPARE: u8 = 5;
const SUPPLY: u8 = 6;
const OUTCOME: u8 = 7;
pub(super) const PROBE: u8 = 8;
const COVER: u8 = 9;
/// The first generated operation's code: `Cluster::apply` sends codes at
/// or above it to the workload, `PROBE` to the healthy phase's probe and
/// every other lower code to its partition, so every partition event code
/// stays below it.
const GET: u8 = 16;
const PUT: u8 = 17;
const INVALIDATE: u8 = 18;
const CANCEL: u8 = 19;

/// Outcome codes of refused and applied operations.
const REFUSED: u64 = 0;
const APPLIED: u64 = 1;

/// A cluster candidate: the workload domain, its code, the cell, the
/// client, a big-endian argument, then the key and the candidate slot.
fn candidate(code: u8, cell: u8, client: usize, arg: u32, key: u8, slot: u8) -> Candidate {
    let mut bytes = [0; CANDIDATE_LEN];
    bytes[0] = Domain::Workload as u8;
    bytes[1] = code;
    bytes[2] = cell;
    bytes[3] = client as u8;
    bytes[4..8].copy_from_slice(&arg.to_be_bytes());
    bytes[8] = key;
    bytes[9] = slot;
    Candidate(bytes)
}

/// The bytes of key `key`'s object of `version`, sent to owner `owner`:
/// a header naming all three, then a fill seeded by them.
pub(crate) fn content(key: u8, version: u32, owner: u8, len: u32) -> Vec<u8> {
    let mut out = vec![0xC1, key, owner];
    out.extend(version.to_le_bytes());
    let seed = u64::from(key) << 40 | u64::from(owner) << 32 | u64::from(version);
    out.extend(payload(len as usize - out.len(), seed));
    out
}

/// Changes the last byte of the read `bytes`, the effect of the misread
/// plant and of an ordering plant, and leaves every other byte as the
/// owner sent it. Returns whether a byte changed: an empty read has none.
fn misread(bytes: &mut [u8]) -> bool {
    let Some(last) = bytes.last_mut() else {
        return false;
    };
    *last ^= 1;
    true
}

/// The key, owner and version `bytes` name when they are exactly the
/// object [`content`] builds for them.
fn decoded(bytes: &[u8]) -> Option<(u8, u8, u32)> {
    let (key, owner, version) = header(bytes)?;
    let len = u32::try_from(bytes.len()).ok()?;
    (content(key, version, owner, len) == bytes).then_some((key, owner, version))
}

/// The key, owner and version the header of `bytes` names, when `bytes`
/// start with the header [`content`] writes.
fn header(bytes: &[u8]) -> Option<(u8, u8, u32)> {
    let [0xC1, key, owner, a, b, c, d, ..] = *bytes else {
        return None;
    };
    Some((key, owner, u32::from_le_bytes([a, b, c, d])))
}

/// The 32-byte key logical key `key` names; distinct from the object each
/// owner publishes before the run.
fn key_bytes(key: u8) -> [u8; 32] {
    super::super::owner_tests::key(KEY_BASE + key)
}

/// The cache version an upload at checker version `version` names under
/// versioned sessions: one above it. A fencing refuses a fill of cache
/// version 0 once its coverage holds any interval of the key, so no
/// upload takes that version.
fn cache_version(version: u32) -> u64 {
    u64::from(version) + 1
}

/// Whether one of `acknowledged`, each the key and newest version an
/// acknowledged INVALIDATE named, names `version` of `key`: the same key,
/// and a version up to that newest one.
fn names(acknowledged: &[(u8, u32)], key: u8, version: u32) -> bool {
    acknowledged
        .iter()
        .any(|&(named, newest)| named == key && version <= newest)
}

/// The rule a run names when an owner's fencing withdrew from its
/// coverage pages, which the store of a cluster run gives no cause for.
const WITHDRAWN: &str = "an owner's fencing withdrew from its coverage pages";

/// An INVALIDATE client 0 sent whose INVALIDATED it is yet to take: the
/// frame's request field, its key, and the newest version the key had
/// taken when it was sent. The frame's interval ends at that version's
/// cache version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Invalidating {
    request: u64,
    key: u8,
    newest: u32,
}

/// A fixture key index no upload takes.
const UNTAKEN: u8 = KEY_BASE - 1;

/// The fixture key index logical key 0 takes.
const KEY_BASE: u8 = 100;

/// The registry label of the upload of `key` at `version`.
fn upload_label(key: u8, version: u32) -> Label {
    Label(1 << 48 | u64::from(key) << 32 | u64::from(version))
}

/// The key and version an [`upload_label`] names, `None` for another label.
fn upload_of(Label(label): Label) -> Option<(u8, u32)> {
    (label >> 48 == 1).then_some((((label >> 32) & 0xFF) as u8, label as u32))
}

/// One upload the checker recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Upload {
    owner: u8,
    /// The object's length.
    len: u32,
    /// Its owner published it: its outcome said so or a GET read it.
    published: bool,
    /// Its owner reported it as not published: it failed or never started.
    no_effect: bool,
    /// An invalidation removed it from its owner's index, so its owner
    /// bound it.
    removed: bool,
    /// Its owner acknowledged an INVALIDATE that covers its version, so
    /// that owner's index may not bind it from then on. The owner may
    /// have bound it before, or never: an upload the owner had not
    /// published when it held the INVALIDATE's entry is revoked or
    /// refused, and ends as not published.
    covered: bool,
}

/// What the checker holds for one key.
#[derive(Clone, Debug, Default)]
pub(crate) struct KeyState {
    /// The key's carried uploads by version: every upload at or above
    /// `retired_below`.
    uploads: std::collections::BTreeMap<u32, Upload>,
    /// The version the next upload takes, `None` once the counter ended.
    next: Option<u32>,
    /// Versions below this were retired at a window cut: each lay below
    /// the key's floor, every outstanding GET's floor and every upload
    /// whose outcome was still to be reported, so no GET issued since may
    /// return one.
    retired_below: u32,
    /// The least version a GET issued now may return: the newest collected
    /// or read publication, or past every version an invalidation removed.
    floor: u32,
    /// Some upload of the key published, retired or not.
    published: bool,
    /// `retired_below` when the upload at the counter's last version was
    /// invoked; `None` while the counter runs.
    ended_retired: Option<u32>,
}

impl KeyState {
    /// The key retains publication evidence after the upload at `version`
    /// retires.
    fn learned(&mut self, version: u32) {
        if let Some(upload) = self.uploads.get_mut(&version) {
            upload.published = true;
        }
        self.published = true;
        self.floor = self.floor.max(version);
    }
}

/// The run's coverage event, recorded before its stop event: the drawn
/// owner and key counts and hot key, then each [`Reached`] count in field
/// order as a little-endian `u32`, saturating.
pub(crate) const COVERAGE: u8 = 13;

const _: () = assert!(
    3 + 4 * Reached::COUNT <= crate::sim::trace::PAYLOAD,
    "the coverage event holds the topology and every count"
);

/// What a run reached, for its minima and its coverage event.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Reached {
    /// Generated uploads whose collected outcome was published.
    pub(crate) published: u64,
    /// Generated GETs that read one upload exactly and passed every check.
    pub(crate) hits: u64,
    /// Generated GETs the owner answered with a miss.
    pub(crate) misses: u64,
    /// Decided generated GETs that read no complete object and found no
    /// miss: the owner refused under pressure, the request failed, timed
    /// out or was cancelled, or it ended after a partial transfer.
    pub(crate) refused: u64,
    /// Invalidations that removed a bound object, and under versioned
    /// sessions the INVALIDATEs whose acknowledgment client 0 took.
    pub(crate) invalidated: u64,
    /// Cancels of an undecided GET.
    pub(crate) cancelled: u64,
    /// Exact generated reads by a logical client that has, with this read,
    /// read from two or more owners through generated reads.
    pub(crate) cross: u64,
    /// Publications that bound a slot an earlier publication at the same
    /// owner bound, probes' included.
    pub(crate) reused: u64,
    /// Healthy phases whose probes passed at every owner.
    pub(crate) healthy: u64,
    /// Faults the links delivered: injected audit records.
    pub(crate) faults: u64,
}

/// The cluster checker: the routing contract, each key's carried uploads
/// by version and its retired frontier, and each logical client's exact
/// reads by owner.
struct Checker {
    owners: u8,
    keys: Vec<KeyState>,
    /// Owners each logical client has an exact read from.
    served: [Vec<bool>; CLIENTS],
    reached: Reached,
    /// The owner, key and version the last decided GET read exactly, `None`
    /// when it missed, was refused or failed a check.
    last: Option<(u8, u8, u32)>,
    first: FirstFailure,
    /// The most uploads the checker carried at once.
    carried: usize,
    /// Window cuts so far.
    windows: u32,
    /// The plant is armed: its windows closed.
    planted: bool,
    /// The owner whose client holds the request the leak plant left
    /// unretired.
    leaked: Option<u8>,
    /// The plant did what a rule forbids: an owner the contract does not
    /// name completed a GET of key 0, a completed GET's bytes were swapped
    /// for a version below its floor or had a byte changed, a healed probe
    /// judged the resources of the owner in [`Self::leaked`], a bound
    /// object's byte changed, a key's ended version counter refused an
    /// upload, an owner's index bound a version an INVALIDATE named when
    /// its acknowledgment arrived, or a GET issued after an acknowledged
    /// INVALIDATE of its key completed with a version that INVALIDATE
    /// named. The leaked-unit plant acts when `leak_unit` reserves its
    /// unit, and the uncounted plant acts when owner 0's transport reports
    /// its armed swallow spent. An ordering plant acts when it changes a
    /// read. A partition records the same binding observed later in its
    /// own [`Cell::late`], and [`Cluster::planted`] reads both. A run that
    /// finishes or stops at a limit with no failure after either missed
    /// the plant.
    acted: bool,
    order: order::Order,
}

impl Reached {
    /// The number of counts.
    pub(crate) const COUNT: usize = Self::NAMES.len();

    /// Each count in field order.
    pub(crate) fn counts(&self) -> [u64; Self::COUNT] {
        [
            self.published,
            self.hits,
            self.misses,
            self.refused,
            self.invalidated,
            self.cancelled,
            self.cross,
            self.reused,
            self.healthy,
            self.faults,
        ]
    }

    /// The names of [`counts`](Self::counts), in order.
    pub(crate) const NAMES: [&'static str; 10] = [
        "published",
        "hits",
        "misses",
        "refused",
        "invalidated",
        "cancelled",
        "cross",
        "reused",
        "healthy",
        "faults",
    ];
}

/// The drawn owner count, key count and hot key and each count a
/// [`COVERAGE`] event records.
pub(crate) fn coverage_of(event: &Event) -> (Topology, [u32; Reached::COUNT]) {
    let payload = &event.payload;
    let counts = std::array::from_fn(|at| {
        u32::from_le_bytes(
            payload[3 + 4 * at..7 + 4 * at]
                .try_into()
                .expect("four bytes"),
        )
    });
    let topology = Topology {
        owners: payload[0],
        keys: payload[1],
        hot: payload[2],
    };
    (topology, counts)
}

/// The [`COVERAGE`] event of a run over `topology` that reached `reached`.
pub(crate) fn coverage_event(topology: Topology, reached: &Reached) -> Event {
    let mut payload = [0; crate::sim::trace::PAYLOAD];
    payload[..3].copy_from_slice(&[topology.owners, topology.keys, topology.hot]);
    for (at, count) in reached.counts().into_iter().enumerate() {
        let count = u32::try_from(count).unwrap_or(u32::MAX);
        payload[3 + 4 * at..7 + 4 * at].copy_from_slice(&count.to_le_bytes());
    }
    Event {
        kind: COVERAGE,
        payload,
    }
}

/// The rule an owner breaks by reporting a version an invalidation removed
/// from its index as not published.
const REMOVED_UNPUBLISHED: &str =
    "an owner reported a version an invalidation removed as not published";

/// The rule an owner breaks by binding a version an invalidation already
/// removed from its index.
const REMOVED_REBOUND: &str = "an owner binds a version an invalidation removed";

/// The rule an owner breaks by binding a version its acknowledged
/// INVALIDATE covers: the owner removes the key's object when it first
/// holds the INVALIDATE's entry, and its coverage refuses a later fill of
/// each version the INVALIDATE names.
const COVERED_REBOUND: &str = "an owner binds a version an acknowledged invalidation covered";

impl Checker {
    fn route(&self, key: u8) -> u8 {
        key % self.owners
    }

    /// The version the next upload of `key` takes, or `None` once the key's
    /// version counter reached its end.
    fn next_version(&self, key: u8) -> Option<u32> {
        self.keys[usize::from(key)].next
    }

    /// Records an upload of `key` of `len` bytes sent to `owner`, the
    /// version [`next_version`](Self::next_version) named.
    fn invoked(&mut self, key: u8, owner: u8, len: u32) {
        let state = &mut self.keys[usize::from(key)];
        let Some(version) = state.next else {
            return;
        };
        state.next = version.checked_add(1);
        if state.next.is_none() {
            state.ended_retired = Some(state.retired_below);
        }
        state.uploads.insert(
            version,
            Upload {
                owner,
                len,
                published: false,
                no_effect: false,
                removed: false,
                covered: false,
            },
        );
        self.carried = self.carried.max(self.carried_now());
    }

    /// Uploads the checker carries now.
    fn carried_now(&self) -> usize {
        self.keys.iter().map(|state| state.uploads.len()).sum()
    }

    fn published(&mut self, key: u8, version: u32, probe: bool) {
        self.keys[usize::from(key)].learned(version);
        self.reached.published += u64::from(!probe);
    }

    /// Retires, for each key, every upload below both the key's floor and
    /// the least of its entries in `outstanding`, each outstanding GET's
    /// floor and each upload whose outcome is still to be reported: no GET
    /// issued later may return one, no outstanding GET may legally return
    /// one either, and every outcome report still finds its upload. The
    /// carried frontier is the floors, those entries and every upload at
    /// or above them.
    fn compact(&mut self, outstanding: &[(u8, u32)]) {
        for (key, state) in self.keys.iter_mut().enumerate() {
            let low = outstanding
                .iter()
                .filter(|(at, _)| usize::from(*at) == key)
                .map(|(_, floor)| *floor)
                .fold(state.floor, u32::min);
            state.uploads = state.uploads.split_off(&low);
            state.retired_below = state.retired_below.max(low);
        }
    }

    /// The caller reports that uploading `key` at `version` had no effect.
    /// The report contradicts a GET that already read the same version, an
    /// invalidation that already removed it, and an index that binds it.
    ///
    /// `bound` is the version the owner's index binds `key` to when the
    /// caller reports the upload outcome.
    fn unpublished(&mut self, key: u8, version: u32, bound: Option<u32>) {
        if let Some(upload) = self.keys[usize::from(key)].uploads.get_mut(&version) {
            upload.no_effect = true;
            let Upload {
                published, removed, ..
            } = *upload;
            if published {
                self.violation("an owner reported a version a GET read as not published");
            }
            if removed {
                self.violation(REMOVED_UNPUBLISHED);
            }
        }
        if bound == Some(version) {
            self.violation("an owner reported a version it binds as not published");
        }
    }

    /// An invalidation of `key` completed, removing the object its owner
    /// bound, whose bytes name version `removed`: that version
    /// and every collected or read publication are removed. Uploads of one
    /// key run one at a time, so an upload still running holds a newer
    /// version and stays readable once it publishes. The removed upload is
    /// marked removed; a removal of a version its owner reported as not
    /// published, of one an earlier invalidation removed, or of one no
    /// upload of the key took, is a violation.
    ///
    /// `bound` is whether the owner's index still binds `key` once the
    /// invalidation reported the removal.
    fn invalidated(&mut self, key: u8, removed: u32, bound: bool) {
        if bound {
            self.violation("an owner reported a removal while its index binds the key");
        }
        let Some(upload) = self.keys[usize::from(key)].uploads.get_mut(&removed) else {
            self.foreign("an invalidation removed bytes no upload of its key wrote");
            return;
        };
        let (again, no_effect) = (upload.removed, upload.no_effect);
        upload.removed = true;
        if again {
            self.violation(REMOVED_REBOUND);
        }
        if no_effect {
            self.violation(REMOVED_UNPUBLISHED);
        }
        let state = &mut self.keys[usize::from(key)];
        let newest = state
            .uploads
            .iter()
            .rev()
            .find(|(_, upload)| upload.published)
            .map_or(removed, |(&version, _)| version.max(removed));
        match newest.checked_add(1) {
            Some(next) => state.floor = state.floor.max(next),
            None => {
                self.first.record(Failure::Unsuccessful(
                    "an invalidation's floor passed the version counter's end",
                ));
            }
        }
        self.reached.invalidated += 1;
    }

    /// The version below the next one an upload of `key` takes, `u32::MAX`
    /// once the key's counter ended; `None` while the next version is 0.
    fn taken(&self, key: u8) -> Option<u32> {
        match self.keys[usize::from(key)].next {
            Some(next) => next.checked_sub(1),
            None => Some(u32::MAX),
        }
    }

    /// `owner` acknowledged an INVALIDATE of `key` over every version up
    /// to `newest`: it removed the key's object when it first held the
    /// request's entry, and its coverage refuses a later fill of those
    /// versions, so a GET issued from now on may return none of them and
    /// that owner's index may bind none. Each upload of the key to
    /// `owner` up to `newest` is marked covered, which
    /// [`binding_rule`](Self::binding_rule) reads while the checker
    /// carries the upload: right after this call, for the binding the
    /// index holds when the acknowledgment arrives, then when an upload's
    /// publication is collected and at every stopped boundary. An upload
    /// admitted before the INVALIDATE that publishes after it is one of
    /// them. A binding that comes and goes between those points is not
    /// observed.
    fn acknowledged(&mut self, key: u8, newest: u32, owner: u8) {
        let state = &mut self.keys[usize::from(key)];
        for (_, upload) in state.uploads.range_mut(..=newest) {
            upload.covered |= upload.owner == owner;
        }
        match newest.checked_add(1) {
            Some(next) => {
                state.floor = state.floor.max(next);
            }
            None => {
                self.first.record(Failure::Unsuccessful(
                    "an invalidation's floor passed the version counter's end",
                ));
            }
        }
        self.reached.invalidated += 1;
    }

    /// An invalidation completed and reported no removal; `bound` is
    /// whether the owner's index bound the key when the call began.
    fn unremoved(&mut self, bound: bool) {
        if bound {
            self.violation("an owner reported no removal while its index bound the key");
        }
    }

    /// An invalidation reported removing `removed`, where `before` is the
    /// allocation the owner's index bound the key to when the call began:
    /// a removal of any other allocation disagrees with the index. A
    /// removal while the index bound the key to none passes, since storage
    /// may end another key's mapping of the same fingerprint.
    fn removal(&self, before: Option<AllocationId>, removed: AllocationId) {
        if before.is_some_and(|before| before != removed) {
            self.violation("an owner reported removing an allocation its index did not bind");
        }
    }

    fn floor(&self, key: u8) -> u32 {
        self.keys[usize::from(key)].floor
    }

    fn recorded(&self, key: u8, bytes: &[u8]) -> Option<u32> {
        let (named, written, version) = decoded(bytes)?;
        let upload = self.keys.get(usize::from(key))?.uploads.get(&version)?;
        (named == key && upload.owner == written && upload.len as usize == bytes.len())
            .then_some(version)
    }

    /// The version of `key` a read returned, when it completed and `bytes`
    /// are exactly the object an upload of `key` wrote at that version.
    fn complete_read(&self, complete: bool, key: u8, bytes: &[u8]) -> Option<u32> {
        if !complete {
            return None;
        }
        self.recorded(key, bytes)
    }

    /// The rule an index breaks by binding the upload of `key` at `version`
    /// sent to `owner`: one its owner reported as not published, one an
    /// invalidation removed or an acknowledged INVALIDATE covers, or one
    /// older than an upload of the key to the same owner whose publication
    /// was collected or read. `None` for a binding no rule refuses and for
    /// a version no upload took.
    fn binding_rule(&self, key: u8, version: u32, owner: u8) -> Option<&'static str> {
        let uploads = &self.keys.get(usize::from(key))?.uploads;
        let upload = uploads.get(&version)?;
        if upload.no_effect {
            return Some("an owner binds a version it reported as not published");
        }
        if upload.removed {
            return Some(REMOVED_REBOUND);
        }
        if upload.covered {
            return Some(COVERED_REBOUND);
        }
        uploads
            .range((
                std::ops::Bound::Excluded(version),
                std::ops::Bound::Unbounded,
            ))
            .any(|(_, newer)| newer.published && newer.owner == owner)
            .then_some("an owner binds a version older than one it published")
    }

    /// Judges `owner`'s index binding of `key`, `bound`, as the upload of
    /// `key` at `version` reports publication: a binding of another version,
    /// or of bytes no upload of the key wrote, and a binding
    /// [`binding_rule`](Self::binding_rule) refuses are violations. Whether
    /// the index binds this upload.
    fn collected(&self, key: u8, version: u32, owner: u8, bound: Option<Option<u32>>) -> bool {
        match bound {
            None => false,
            Some(bound) if bound != Some(version) => {
                self.violation(
                    "an owner reported a publication while its index binds another version",
                );
                false
            }
            Some(_) => {
                if let Some(rule) = self.binding_rule(key, version, owner) {
                    self.violation(rule);
                }
                true
            }
        }
    }

    /// The value of `read`, recording its failure as the run's first when it
    /// failed.
    fn settled<T>(&self, read: Result<T, Failure>) -> Option<T> {
        read.map_err(|failure| self.first.record(failure)).ok()
    }

    fn violation(&self, rule: &'static str) {
        self.first
            .record(Failure::Violation(Obligation::History, rule));
    }

    fn foreign(&self, rule: &'static str) {
        self.first
            .record(Failure::Violation(Obligation::Bytes, rule));
    }

    /// The stale-read plant's replacement for a complete read of `bytes`:
    /// the object of the newest publication of their key below their
    /// version, built for the owner `bytes` name. `None` unless `bytes` are
    /// exactly a recorded upload's object that its owner did not report as
    /// not published.
    fn older_publication(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        let (key, owner, version) = decoded(bytes)?;
        let uploads = &self.keys.get(usize::from(key))?.uploads;
        uploads.get(&version).filter(|named| {
            !named.no_effect && named.owner == owner && named.len as usize == bytes.len()
        })?;
        let (&older, upload) = uploads
            .range(..version)
            .rev()
            .find(|(_, upload)| upload.published)?;
        Some(content(key, older, owner, upload.len))
    }

    /// Judges a decided GET, and keeps what it read exactly as `last`.
    fn decided(&mut self, get: Judged, outcome: Fetched, bytes: &[u8]) {
        self.last = self
            .judged(get, outcome, bytes)
            .map(|version| (get.owner, get.key, version));
    }

    /// Whether `bytes` are a prefix of one upload of `key` its owner did
    /// not report as unpublished.
    fn prefix_of_one(&self, key: u8, bytes: &[u8]) -> bool {
        self.prefixed(key, bytes).next().is_some()
    }

    /// The version and record of each upload of `key` whose object starts
    /// with `bytes`.
    fn starting<'b>(
        &'b self,
        key: u8,
        bytes: &'b [u8],
    ) -> impl Iterator<Item = (u32, &'b Upload)> + 'b {
        self.keys[usize::from(key)]
            .uploads
            .iter()
            .filter(move |(version, upload)| {
                bytes.len() <= upload.len as usize
                    && content(key, **version, upload.owner, upload.len)[..bytes.len()] == *bytes
            })
            .map(|(&version, upload)| (version, upload))
    }

    /// The version and owner of each upload of `key` whose object starts
    /// with `bytes`, among the uploads still reported as possibly published.
    fn prefixed<'b>(&'b self, key: u8, bytes: &'b [u8]) -> impl Iterator<Item = (u32, u8)> + 'b {
        self.starting(key, bytes)
            .filter(|(_, upload)| !upload.no_effect)
            .map(|(version, upload)| (version, upload.owner))
    }

    /// The version of each upload the GET could read complete that starts
    /// with `bytes`: one sent to the owner the GET went to and the contract
    /// names, at or above the GET's floor, and not reported as not
    /// published.
    fn readable<'b>(&'b self, get: Judged, bytes: &'b [u8]) -> impl Iterator<Item = u32> + 'b {
        let routed = get.owner == self.route(get.key);
        routed
            .then(|| self.prefixed(get.key, bytes))
            .into_iter()
            .flatten()
            .filter(move |&(version, owner)| owner == get.owner && version >= get.floor)
            .map(|(version, _)| version)
    }

    /// The version a complete GET read when every check passes. A GET that
    /// passes raises its key's floor to the version it read, for GETs
    /// issued later.
    fn judged(&mut self, get: Judged, outcome: Fetched, bytes: &[u8]) -> Option<u32> {
        let Judged {
            client,
            owner,
            key,
            floor,
            probe,
        } = get;
        match outcome {
            Fetched::Complete => {}
            Fetched::Incomplete(_) if bytes.is_empty() => {
                self.foreign("an incomplete GET exposed no bytes");
                return None;
            }
            Fetched::Incomplete(_) if !self.prefix_of_one(key, bytes) => {
                // The bytes are a prefix of an object of a version a window
                // cut retired, which the whole history reads as one the GET
                // could not read.
                let retired = decoded(bytes).is_some_and(|(named, _, version)| {
                    let state = &self.keys[usize::from(key)];
                    named == key
                        && version < state.retired_below
                        && !state.uploads.contains_key(&version)
                });
                if retired {
                    self.violation(
                        "an incomplete GET exposed bytes of a version or owner it could not read",
                    );
                } else if self.starting(key, bytes).next().is_some() {
                    self.violation("a GET returned a version its owner reported as not published");
                } else {
                    self.foreign("an incomplete GET exposed bytes no one upload of its key wrote");
                }
                return None;
            }
            Fetched::Incomplete(_) if self.readable(get, bytes).next().is_none() => {
                self.violation(
                    "an incomplete GET exposed bytes of a version or owner it could not read",
                );
                return None;
            }
            Fetched::Incomplete(_) => {
                self.reached.refused += u64::from(!probe);
                // When one upload the GET could read starts with the
                // prefix, as every prefix holding the object header does,
                // the owner served that upload's bytes, so it was bound.
                let named = {
                    let mut readable = self.readable(get, bytes);
                    readable.next().filter(|_| readable.next().is_none())
                };
                if let Some(version) = named {
                    self.keys[usize::from(key)].learned(version);
                }
                return None;
            }
            Fetched::Missing | Fetched::Pressure(_) | Fetched::Failed(_) if !bytes.is_empty() => {
                self.foreign("a GET exposed bytes under an outcome that hands none out");
                return None;
            }
            Fetched::Missing => {
                self.reached.misses += u64::from(!probe);
                return None;
            }
            Fetched::Pressure(_) | Fetched::Failed(_) => {
                self.reached.refused += u64::from(!probe);
                return None;
            }
        }
        if let Some((named, _, version)) = decoded(bytes) {
            let state = &self.keys[usize::from(key)];
            if named == key
                && !state.uploads.contains_key(&version)
                && version < state.retired_below
            {
                self.violation(
                    "a GET returned a version older than one collected or removed before it",
                );
                return None;
            }
        }
        let Some(version) = self.recorded(key, bytes) else {
            self.foreign("a GET returned bytes no upload of its key wrote");
            return None;
        };
        let upload = self.keys[usize::from(key)].uploads[&version];
        if upload.no_effect {
            self.violation("a GET returned a version its owner reported as not published");
            return None;
        }
        if upload.owner != self.route(key) || upload.owner != owner {
            self.violation("a key was served from an owner its routing contract does not name");
            return None;
        }
        if version < floor {
            self.violation(
                "a GET returned a version older than one collected or removed before it",
            );
            return None;
        }
        self.keys[usize::from(key)].learned(version);
        if probe {
            return Some(version);
        }
        self.reached.hits += 1;
        let served = &mut self.served[client];
        served[usize::from(owner)] = true;
        if served.iter().filter(|&&at| at).count() >= 2 {
            self.reached.cross += 1;
        }
        Some(version)
    }
}

/// A decided GET as the checker judges it: the logical client that issued
/// it, the owner it went to, its key, the key's floor when it was issued,
/// and whether it was a healthy phase's probe, which reaches no coverage
/// count.
#[derive(Clone, Copy, Debug)]
struct Judged {
    client: usize,
    owner: u8,
    key: u8,
    floor: u32,
    probe: bool,
}

/// One GET a logical client holds at a cell.
struct Get {
    id: RequestId,
    key: u8,
    floor: u32,
    /// Window cuts before the GET was issued.
    window: u32,
    /// Entries of the partition's unremoved-plant acknowledgments taken
    /// before the GET was issued.
    acknowledged: usize,
    /// The GET's issue number at its partition, from 1.
    issue: u64,
    probe: bool,
    bytes: Vec<u8>,
}

/// Client 0's upload at a cell.
struct Put {
    id: RequestId,
    key: u8,
    version: u32,
    object: Vec<u8>,
    prepared: bool,
    supplied: Vec<bool>,
    outcome: Option<UploadOutcome>,
    /// Whether this upload is a healthy phase's probe, whose upload stays
    /// until the cluster takes its outcome.
    probe: bool,
}

/// One owner's partition of the cluster: its scene, the operations its
/// sessions hold, and the checks of its stopped boundaries.
struct Part<'s, 'm> {
    cell: u8,
    scene: Scene<'s, 'm>,
    owner_due: u64,
    service_due: u64,
    /// Each client polled since its last read or outcome collection, so
    /// those can observe something new.
    polled: [bool; CLIENTS],
    gets: [Vec<Get>; CLIENTS],
    put: Option<Put>,
    registry: Registry,
    lenses: Lenses,
    audited: [usize; 2],
    /// Slots a publication at this owner has bound, so a slot bound again
    /// counts as reuse.
    slots: Vec<usize>,
    /// An upload step was refused; it waits for an owner poll, client poll,
    /// service or disk event applied at this partition.
    blocked: bool,
    /// Decided requests each client has yet to retire: a request keeps its
    /// receive promise or source slots until its client retires it.
    retiring: [Vec<RequestId>; CLIENTS],
    /// The device's outcomes, absorbed after every event this partition
    /// applies, so its bounded event log drops none unread.
    device: Audit,
    /// Device events logged over its life that `device` has read.
    device_seen: u64,
    /// The number of GETs this partition's sessions accepted, of every
    /// key: the issue number of the latest, 0 before the first.
    accepted_gets: u64,
    /// The next decided upload's request is never retired.
    leak: bool,
    /// The leaked-unit plant reserved its unit.
    leaked_unit: bool,
    /// A stopped boundary passed since the datagram accounts were last
    /// judged; [`Part::account`] judges them after the conservation rule.
    accounts_due: bool,
    /// The owner's polls and disk service rest until this time while the
    /// cluster rests; maintenance resumes there.
    resting: u64,
    /// Injected link faults read from the links' audits, over the run.
    injected: u64,
    /// The run's chooser, which decides each command's device fault.
    draws: Draws,
    /// The incarnation of the owner's storage key-pair actor, whose sites
    /// the device fault draws use.
    incarnation: u32,
    /// The coverage store's client under versioned sessions: the owner
    /// writes its coverage pages through it.
    store: Option<StoreClient<Shared, MemLog>>,
    /// The INVALIDATEs client 0 sent whose INVALIDATED it is yet to take,
    /// oldest first. One the owner never acknowledges, and one whose
    /// INVALIDATED a link, the owner's reply queue or the client's inbox
    /// dropped, stays for the length of the run, so the list holds at most
    /// one entry for each INVALIDATE the run sent.
    invalidating: Vec<Invalidating>,
    /// Under the unremoved plant, the key and newest version of each
    /// acknowledgment client 0 took, in the order it took them.
    unremoved: Vec<(u8, u32)>,
    /// Under the unremoved plant, an upload's outcome collection or a
    /// stopped boundary found the index binding a version one of those
    /// acknowledgments named: an upload that published after the
    /// acknowledgment, or an object bound since before it. The entries and
    /// the binding are read here, apart from the checker's coverage marks,
    /// so a run that binds one and fails no check is a missed control.
    /// [`Cluster::planted`] reads it beside [`Checker::acted`].
    late: bool,
    /// The device faults in force.
    device_faults: DeviceFaults,
    /// The first device fault draw the chooser refused.
    draw_error: Option<ChoiceError>,
    /// The device faults this partition attached.
    applied: Applied,
    /// The most records one link audit held before passing ones retired.
    kept_peak: usize,
    /// What the turn's action collected at this partition.
    collected: Collected,
}

/// What the cluster asks of one owner's partition. The trait erases each
/// partition's scene lifetimes, so partitions built in nested scopes share
/// one world.
trait Cell {
    fn runnable(&self, now: u64, out: &mut Vec<Candidate>);
    fn next_due(&self, now: u64) -> Option<u64>;
    fn advance(&mut self, now: u64, checker: &Checker);
    /// Runs the registry and media check on the partition's state, and
    /// fails an index binding that [`Checker::binding_rule`] refuses.
    fn check(&mut self, checker: &Checker);
    /// Judges the partition's storage tables with the conservation rule,
    /// recording a failure in `checker`; returns whether the rule ran. The
    /// default, for a partition that holds no storage, returns `false`.
    fn conserve(&mut self, _checker: &Checker) -> bool {
        false
    }
    /// Judges the owner's datagram accounts when a stopped boundary left
    /// them due, recording a failure in `checker`. The default, for a
    /// partition with no owner, judges nothing.
    fn account(&mut self, _checker: &Checker) {}
    fn apply(&mut self, event: &Candidate, now: u64, checker: &mut Checker, plant: Plant) -> u64;
    /// Issues a GET of `key` by `client`, recording the key's floor and the
    /// window cuts so far as `issued`; a `probe` GET is the healthy phase's
    /// own read.
    fn get(&mut self, client: usize, key: u8, issued: (u32, u32), probe: bool, now: u64) -> u64;
    fn put(&mut self, key: u8, version: u32, object: Vec<u8>, probe: bool, now: u64) -> u64;
    /// Invalidates `key`. Under versioned sessions client 0 sends an
    /// INVALIDATE, `APPLIED` when the client took the frame, and the
    /// acknowledgment reaches `checker` at the client poll that receives
    /// it. Otherwise the call invalidates at the owner and reports the
    /// result to `checker`; `APPLIED` when the owner removed an object. A
    /// failed read of the index before the call, or a binding of bytes no
    /// upload of `key` wrote, refuses the invalidation.
    fn invalidate(&mut self, key: u8, now: u64, checker: &mut Checker, plant: Plant) -> u64;
    /// Whether `client` holds an undecided GET of `key`.
    fn cancellable(&self, client: usize, key: u8) -> bool;
    fn cancel(&mut self, client: usize, key: u8) -> u64;
    fn set_faults(&mut self, links: Faults, device: DeviceFaults, release: TxRelease);
    /// A link holds a device reference of a datagram: one it has queued,
    /// or one it delivered whose reference the sender is yet to reclaim.
    fn returning(&self) -> bool;
    fn active(&self, client: usize) -> bool;
    fn pending(&self, client: usize) -> usize;
    fn uploading(&self) -> bool;
    /// No GET or upload is outstanding, and the owner holds no active or
    /// draining request: a healthy phase probes a quiesced owner.
    fn idle(&self) -> bool;
    /// Retires every decided request its client lets go; whether none
    /// remains.
    fn retired(&mut self) -> bool;
    /// No source slot holds a piece and no upload is live.
    fn reclaimed(&self) -> bool;
    /// Takes a decided probe upload's outcome.
    fn take_probe(&mut self) -> Option<UploadOutcome>;
    /// Takes what the partition collected since the last call.
    fn take_collected(&mut self) -> Collected;
    fn audits(&mut self, out: &mut Vec<Event>);
    /// Reads the device events logged since the last call into the
    /// partition's device audit.
    fn absorb(&mut self);
    fn verdict(&self) -> Verdict;
    fn take_draw_errors(&mut self);
    fn defect(&self) -> Option<Defect>;
    fn set_clocks(&self, now: u64);
    /// The time the partition's setup left its actors at.
    fn start(&self) -> u64;
    /// Faults its links delivered: injected audit records.
    fn injected(&self) -> u64;
    /// Truncated datagrams the partition's links delivered toward its
    /// owner, and those its owner dropped as truncated; a partition with
    /// no links has neither.
    fn truncation(&self) -> Truncation {
        Truncation::default()
    }
    /// The device faults the partition attached, by kind.
    fn applied(&self) -> Applied;
    /// Whether an outcome collection or a stopped boundary of this
    /// partition observed the unremoved plant's effect, which the
    /// partition alone records.
    fn late(&self) -> bool {
        false
    }
    /// Rests the owner's polls and disk service until `until`.
    fn rest(&mut self, until: u64);
    /// Each outstanding GET's key and floor.
    fn outstanding(&self, out: &mut Vec<(u8, u32)>);
    /// The key and version of the partition's upload while it holds one,
    /// whose outcome a window cut keeps checkable.
    fn uploading_version(&self) -> Option<(u8, u32)>;
    /// Retires registry content of uploads `checker` retired; returns the
    /// entries that remain.
    fn compact(&mut self, checker: &Checker) -> usize;
    /// Audit records the links keep now, which the link audits bound.
    fn kept(&self) -> usize;
    /// The most registry entries the partition held at once, and the most
    /// records one of its link audits held at once before it retired the
    /// passing ones.
    fn peaks(&self) -> (usize, usize);
    /// Makes the next decided upload's request leak.
    fn leak(&mut self);
    /// Changes a payload byte of a bound uploaded object; whether one was
    /// bound. The stopped boundary that follows detects it.
    fn corrupt(&mut self, keys: u8) -> bool;
}

impl<'s, 'm> Part<'s, 'm> {
    fn inbound(&self, side: usize, net: usize) -> bool {
        self.scene.nets[net].borrow().receivable(side) > 0
    }

    fn client_due(&self, client: usize, now: u64) -> bool {
        self.inbound(0, client)
            || self.scene.nets[client].borrow().reclaimable(0) > 0
            || self.scene.clients[client]
                .next_deadline_us()
                .is_some_and(|due| due <= now)
    }

    /// Draws the device fault of the command `event` names, ready entry
    /// `index` of `stage`, when this selection executes the command: an
    /// `Execute` selection, or a `Post` selection of a command still in
    /// the `Execute` ready set. The rates in force now decide, whenever the
    /// command was submitted, and two zero rates draw nothing. One draw
    /// below [`DRAW`] selects the kind through [`device_kind`]; a prefix hit
    /// draws again at the same site for its length, from one sector to the
    /// command's length. A torn write the device refuses as `Qualified`
    /// carries [`refused_tear`]'s fault instead; any other refusal is a harness
    /// defect and panics. A draw the chooser refuses latches as the
    /// partition's draw error and leaves the command sound.
    fn fault_command(&mut self, event: &Candidate, stage: Stage, index: usize) {
        let rates = self.device_faults;
        // A disk candidate's byte 10 names its operation: 0 a read, 1 a write.
        let (op, error, prefix) = match event.0[10] {
            0 => (Operation::Read, rates.read_error, rates.read_partial),
            _ => (Operation::Write, rates.write_error, rates.write_torn),
        };
        if error + prefix == 0 {
            return;
        }
        if stage == Stage::Post {
            let mut unmoved = *event;
            unmoved.0[1] = Stage::Execute as u8;
            if !self
                .scene
                .control
                .candidates(Stage::Execute)
                .contains(&unmoved)
            {
                return;
            }
        }
        // Bytes 11 and 12 give the command's length in 512-byte sectors.
        let length = u16::from_be_bytes([event.0[11], event.0[12]]);
        let site = device_site(actors(self.cell).0, op);
        let Some(drawn) = self.latched(site, DRAW) else {
            return;
        };
        let Some(kind) = device_kind(drawn, error, prefix) else {
            return;
        };
        let sectors = match kind {
            DeviceKind::Error => 0,
            DeviceKind::Prefix => {
                let Some(drawn) = self.latched(site, u64::from(length)) else {
                    return;
                };
                1 + drawn as u32
            }
        };
        let token = self.scene.control.ready(stage)[index];
        let len = u32::from(length) * SECTOR as u32;
        let fault = device_fault(op, kind, sectors);
        match self.attach(token, fault, len) {
            Ok(()) => {
                let applied = &mut self.applied;
                *match (op, kind) {
                    (Operation::Write, DeviceKind::Error) => &mut applied.write_error,
                    (Operation::Read, DeviceKind::Error) => &mut applied.read_error,
                    (Operation::Write, DeviceKind::Prefix) => &mut applied.write_torn,
                    (Operation::Read, DeviceKind::Prefix) => &mut applied.read_partial,
                } += 1;
                if let Fault::TornWrite { sectors } | Fault::PartialReadFailure { sectors } = fault
                    && (2..u32::from(length)).contains(&sectors)
                {
                    applied.interior += 1;
                }
            }
            Err(ScriptRefusal {
                reason: ScriptReason::Qualified(_),
                ..
            }) => {
                if let Err(refusal) = self.attach(token, refused_tear(op), len) {
                    panic!("{refusal:?}\n{}", self.scene.control.describe());
                }
                self.applied.torn_refused += 1;
            }
            Err(refusal) => panic!("{refusal:?}\n{}", self.scene.control.describe()),
        }
    }

    /// Draws below `bound` at `site` for the partition's incarnation; a
    /// draw the chooser refuses latches as the partition's first draw
    /// error and returns `None`.
    fn latched(&mut self, site: Site, bound: u64) -> Option<u64> {
        let drawn = self
            .draws
            .borrow_mut()
            .bounded(site, self.incarnation, bound);
        drawn
            .map_err(|error| self.draw_error.get_or_insert(error))
            .ok()
    }

    /// Attaches `fault` to the pending command `token` of `len` bytes, the
    /// one place the world attaches a device fault: a generated profile
    /// draws honest faults only, and a prefix covers at least one sector
    /// and at most the command, so an admitted prefix fault moves bytes.
    fn attach(&self, token: CommandToken, fault: Fault, len: u32) -> Result<(), ScriptRefusal> {
        assert_eq!(
            fault.report(len),
            Honesty::Honest,
            "a generated profile draws {fault:?}, a lying fault"
        );
        if let Fault::TornWrite { sectors } | Fault::PartialReadFailure { sectors } = fault {
            assert!(
                (1..=len / SECTOR as u32).contains(&sectors),
                "a prefix of {sectors} sectors on a command of {len} bytes"
            );
        }
        self.scene.control.try_fault(token, fault)
    }

    /// Sends client 0's INVALIDATE of `key` over every version the key has
    /// taken and tracks it until its acknowledgment; `REFUSED` when the
    /// key took no version or the client refused the frame. Under the
    /// unremoved plant the frame names [`UNTAKEN`] in place of `key`.
    fn request_invalidation(&mut self, key: u8, checker: &Checker, plant: Plant) -> u64 {
        let Some(newest) = checker.taken(key) else {
            return REFUSED;
        };
        let named = match plant {
            Plant::Unremoved => super::super::owner_tests::key(UNTAKEN),
            _ => key_bytes(key),
        };
        let sent = self.scene.clients[0].invalidate(named, 1, cache_version(newest));
        let Ok(request) = sent else {
            return REFUSED;
        };
        self.invalidating.push(Invalidating {
            request,
            key,
            newest,
        });
        APPLIED
    }

    /// Takes every INVALIDATED client 0 received and reports each one that
    /// answers a tracked INVALIDATE to `checker`, and fails this
    /// partition's index when [`Checker::binding_rule`] refuses the
    /// version it binds the key to, as it does a version that INVALIDATE
    /// named while the checker carries its upload; an index read that
    /// fails is the run's failure. Under the unremoved plant it also
    /// records each one for the plant's own judgment. An
    /// INVALIDATED answers the INVALIDATE whose request field it carries,
    /// and the key and version reported are the ones that INVALIDATE was
    /// sent with: the frame's own key and interval are not read.
    fn take_acknowledgments(&mut self, checker: &mut Checker, plant: Plant) {
        while let Some(acknowledged) = self.scene.clients[0].take_invalidated() {
            let tracked = self
                .invalidating
                .iter()
                .position(|sent| sent.request == acknowledged.request);
            if let Some(at) = tracked {
                let sent = self.invalidating.remove(at);
                checker.acknowledged(sent.key, sent.newest, self.cell);
                // The owner removed the key's object before it acknowledged,
                // so its index binds none of the versions the INVALIDATE
                // named. The binding is judged as a stopped boundary judges
                // it, for an upload the checker still carries.
                let bound = checker
                    .settled(self.bound(sent.key, checker))
                    .flatten()
                    .and_then(|(_, version)| version);
                if plant == Plant::Unremoved {
                    let acknowledged = (sent.key, sent.newest);
                    checker.acted |=
                        bound.is_some_and(|version| names(&[acknowledged], sent.key, version));
                    self.unremoved.push(acknowledged);
                }
                if let Some(rule) =
                    bound.and_then(|version| checker.binding_rule(sent.key, version, self.cell))
                {
                    checker.violation(rule);
                }
            }
        }
    }

    /// Writes the coverage pages of the INVALIDATEs the owner holds, which
    /// queues the INVALIDATED of each one whose page write committed, and
    /// returns how many entries the writes acknowledged. A withdrawal ends
    /// the run unsuccessful.
    fn cover(&mut self, now: u64, checker: &Checker) -> u64 {
        let store = self.store.as_mut().expect("a versioned partition");
        let mut acknowledged = Vec::new();
        match self
            .scene
            .owner
            .cover_pending(store, &mut acknowledged, now)
        {
            Ok(()) => {
                if !acknowledged.is_empty() {
                    self.owner_due = now;
                }
                acknowledged.len() as u64
            }
            Err(_) => {
                checker.first.record(Failure::Unsuccessful(WITHDRAWN));
                REFUSED
            }
        }
    }

    /// The first `found` returns, over each record the index binds: its
    /// allocation, the key it binds and its bytes. A lens read that fails,
    /// or a binding whose record fails verification, is the error.
    fn find_bound<T>(
        &self,
        mut found: impl FnMut(AllocationId, [u8; 32], &[u8]) -> Option<T>,
    ) -> Result<Option<T>, Failure> {
        let media = self.scene.media();
        let storage = media.storage();
        let (mut bindings, mut facts, mut record) = (Vec::new(), Vec::new(), Vec::new());
        let unreadable = |_| Failure::Unsuccessful("the storage was no longer live");
        storage.bindings_into(&mut bindings).map_err(unreadable)?;
        storage.slot_facts_into(&mut facts).map_err(unreadable)?;
        for &binding in &bindings {
            let (bound, _, payload) = media.bound_record(binding, &facts, &mut record)?;
            let slot = binding.identity.slot as usize;
            // `bound_record` verified a resident fact at this slot.
            let allocation = AllocationId::new(SlotIndex(slot), facts[slot].incarnation);
            if let Some(found) = found(allocation, bound, payload) {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    /// The allocation the index binds `key` to, and the version its bytes
    /// name when they are an object of `key`, when it binds one.
    fn bound(
        &self,
        key: u8,
        checker: &Checker,
    ) -> Result<Option<(AllocationId, Option<u32>)>, Failure> {
        self.find_bound(|allocation, bound, payload| {
            (bound == key_bytes(key)).then(|| (allocation, checker.recorded(key, payload)))
        })
    }

    fn read(&mut self, client: usize, at: usize, checker: &mut Checker, plant: Plant) -> u64 {
        self.polled[client] = false;
        let get = &mut self.gets[client][at];
        let mut observed = 0;
        while let Some(fragment) = self.scene.clients[client].take(get.id) {
            get.bytes.extend_from_slice(fragment.bytes());
            observed += 1;
        }
        let Some(outcome) = self.scene.clients[client].outcome(get.id) else {
            return observed;
        };
        let logical = u16::try_from(client).expect("a client index");
        self.collected
            .add(Collected::Get(logical, self.cell.into(), outcome));
        self.retiring[client].push(get.id);
        let get = self.gets[client].remove(at);
        let judged = Judged {
            client,
            owner: self.cell,
            key: get.key,
            floor: get.floor,
            probe: get.probe,
        };
        let mut bytes = get.bytes;
        let complete = outcome == Fetched::Complete;
        let older = match plant {
            _ if !complete => None,
            Plant::StaleRead => checker.older_publication(&bytes),
            Plant::LateStale
                if checker.planted && get.window < checker.windows && get.floor > 0 =>
            {
                decoded(&bytes).map(|(key, owner, _)| {
                    let older = get.floor - 1;
                    let len = checker.keys[usize::from(key)]
                        .uploads
                        .get(&older)
                        .map_or(bytes.len() as u32, |upload| upload.len);
                    content(key, older, owner, len)
                })
            }
            _ => None,
        };
        if let Some(older) = older {
            checker.acted |= decoded(&older).is_some_and(|(_, _, version)| version < get.floor);
            bytes = older;
        }
        checker.acted |=
            plant == Plant::WrongOwner && complete && self.cell != checker.route(get.key);
        // The plant acted once a GET issued after an acknowledgment of its
        // key completes with a version that acknowledgment named.
        checker.acted |= plant == Plant::Unremoved
            && complete
            && decoded(&bytes).is_some_and(|(key, _, version)| {
                names(&self.unremoved[..get.acknowledged], key, version)
            });
        // The plant decides on a copy, so the read it consults can borrow
        // the checker's uploads.
        let mut order = checker.order;
        let selected = order.decided(client, get.issue, get.key, || {
            checker.complete_read(complete, get.key, &bytes)
        });
        checker.order = order;
        if (selected || plant == Plant::Misread && complete) && misread(&mut bytes) {
            checker.acted = true;
        }
        checker.decided(judged, outcome, &bytes);
        observed + 1
    }

    fn act_put(&mut self, code: u8, fragment: u32, checker: &mut Checker) -> u64 {
        let Some(put) = self.put.as_mut() else {
            return REFUSED;
        };
        let client = &mut self.scene.clients[0];
        match code {
            PREPARE => {
                let prepared = client
                    .prepare(put.id, 0, put.object.len() as u32, TTL_MS)
                    .is_ok();
                put.prepared = prepared;
                u64::from(prepared)
            }
            SUPPLY => {
                let start = fragment as usize * FRAGMENT_LEN as usize;
                let end = (start + FRAGMENT_LEN as usize).min(put.object.len());
                let supplied = client
                    .supply(put.id, fragment, &put.object[start..end])
                    .is_ok();
                put.supplied[fragment as usize] |= supplied;
                u64::from(supplied)
            }
            OUTCOME => {
                self.polled[0] = false;
                let Some(outcome) = client.put_outcome(put.id) else {
                    return REFUSED;
                };
                self.collected
                    .add(Collected::Put(0, self.cell.into(), outcome));
                put.outcome = Some(outcome);
                if outcome == UploadOutcome::Unknown {
                    client.abandon(put.id);
                }
                if self.leak {
                    self.leak = false;
                    checker.leaked = Some(self.cell);
                } else {
                    self.retiring[0].push(put.id);
                }
                let (key, version, probe) = (put.key, put.version, put.probe);
                match outcome {
                    UploadOutcome::Published => {
                        checker.published(key, version, probe);
                        checker.order.published(key, version, self.accepted_gets);
                        let bound = checker.settled(self.bound(key, checker));
                        if let Some(Some((_, Some(bound)))) = bound {
                            self.late |= names(&self.unremoved, key, bound);
                        }
                        if let Some(bound) = bound
                            && let Some((allocation, _)) = bound.filter(|&(_, named)| {
                                checker.collected(key, version, self.cell, Some(named))
                            })
                        {
                            let slot = allocation.slot_index();
                            if self.slots.contains(&slot) {
                                checker.reached.reused += 1;
                            } else {
                                self.slots.push(slot);
                            }
                        }
                    }
                    UploadOutcome::Failed(_) | UploadOutcome::NotStarted => {
                        if let Some(bound) = checker.settled(self.bound(key, checker)) {
                            let bound = bound.and_then(|(_, version)| version);
                            self.late |=
                                bound.is_some_and(|bound| names(&self.unremoved, key, bound));
                            checker.unpublished(key, version, bound);
                        }
                    }
                    UploadOutcome::Unknown => {}
                }
                // A probe's upload stays until the cluster takes its outcome.
                if !probe {
                    self.put = None;
                }
                upload_code(outcome)
            }
            _ => unreachable!("upload code {code}"),
        }
    }
}

impl Cell for Part<'_, '_> {
    fn runnable(&self, now: u64, out: &mut Vec<Candidate>) {
        let cell = self.cell;
        let owner_inbound = (0..2)
            .any(|net| self.inbound(1, net) || self.scene.nets[net].borrow().reclaimable(1) > 0);
        if self.owner_due <= now || owner_inbound || self.scene.control.deliverable() > 0 {
            out.push(candidate(OWNER_POLL, cell, 0, 0, 0, 0));
        }
        for client in 0..CLIENTS {
            if self.client_due(client, now) {
                out.push(candidate(CLIENT_POLL, cell, client, 0, 0, 0));
            }
            for (at, get) in self.gets[client].iter().enumerate() {
                // A decided GET stays readable without another poll.
                if self.polled[client] || self.scene.clients[client].outcome(get.id).is_some() {
                    out.push(candidate(READ, cell, client, at as u32, 0, 0));
                }
            }
        }
        if self.service_due <= now {
            out.push(candidate(SERVICE, cell, 0, 0, 0, 0));
        }
        if self.store.is_some() && self.scene.owner.held_invalidations() > 0 {
            out.push(candidate(COVER, cell, 0, 0, 0, 0));
        }
        if let Some(put) = &self.put
            && put.outcome.is_none()
            && !self.blocked
        {
            if !put.prepared {
                out.push(candidate(PREPARE, cell, 0, 0, put.key, 0));
            } else {
                for (fragment, done) in put.supplied.iter().enumerate() {
                    if !done {
                        out.push(candidate(SUPPLY, cell, 0, fragment as u32, put.key, 0));
                    }
                }
            }
            if self.polled[0] || self.scene.clients[0].put_outcome(put.id).is_some() {
                out.push(candidate(OUTCOME, cell, 0, 0, put.key, 0));
            }
        }
        // A disk candidate carries the partition in its ordinal's top byte,
        // which every ordinal below 2^56 leaves zero; `apply` clears it again
        // before matching the device's own candidate.
        for stage in STAGES {
            for mut disk in self.scene.control.candidates(stage) {
                assert_eq!(disk.0[2], 0, "a disk ordinal below 2^56");
                disk.0[2] = cell;
                out.push(disk);
            }
        }
    }

    fn next_due(&self, now: u64) -> Option<u64> {
        let clients =
            (0..CLIENTS).filter_map(|client| self.scene.clients[client].next_deadline_us());
        let arrivals = self
            .scene
            .nets
            .iter()
            .flat_map(|net| {
                let net = net.borrow();
                [net.next_arrival(), net.next_return()]
            })
            .flatten()
            .map(|turn| turn * LINK_TURN_US);
        [self.owner_due, self.service_due]
            .into_iter()
            .chain(clients)
            .chain(arrivals)
            .filter(|&due| due > now)
            .min()
    }

    fn advance(&mut self, now: u64, checker: &Checker) {
        for net in &self.scene.nets {
            net.borrow_mut().advance(now / LINK_TURN_US);
        }
        self.check(checker);
    }

    fn check(&mut self, checker: &Checker) {
        let media = self.scene.media();
        if let Err(failure) = boundary(&media, &self.registry, &mut self.lenses) {
            checker.first.record(failure);
        }
        self.accounts_due = true;
        // The header names the upload, so only an object whose header
        // names a binding a rule refuses is rebuilt in full. The plant's
        // late effect is read from each header before the rule is, from
        // this partition's own acknowledgments. A refused binding ends the
        // walk, and the run then has a failure and reads no effect.
        let mut late = self.late;
        let refused = self.find_bound(|_, _, payload| {
            let (key, owner, version) = header(payload)?;
            late |= owner == self.cell && names(&self.unremoved, key, version);
            checker
                .binding_rule(key, version, owner)
                .filter(|_| decoded(payload).is_some())
        });
        self.late = late;
        if let Some(Some(rule)) = checker.settled(refused) {
            checker.violation(rule);
        }
    }

    fn late(&self) -> bool {
        self.late
    }

    fn account(&mut self, checker: &Checker) {
        if std::mem::take(&mut self.accounts_due)
            && let Err(failure) = self.scene.accounts()
        {
            checker.first.record(failure);
        }
    }

    fn conserve(&mut self, checker: &Checker) -> bool {
        let before = self.lenses.judgments();
        if let Err(failure) = conserved(self.scene.storage, &mut self.lenses) {
            checker.first.record(failure);
        }
        self.lenses.judgments() > before
    }

    fn apply(&mut self, event: &Candidate, now: u64, checker: &mut Checker, plant: Plant) -> u64 {
        let bytes = event.0;
        if !matches!(bytes[1], PREPARE | SUPPLY | OUTCOME | READ)
            || bytes[0] != Domain::Workload as u8
        {
            self.blocked = false;
        }
        self.retired();
        if bytes[0] == Domain::Disk as u8 {
            let mut wanted = *event;
            wanted.0[2] = 0;
            let stage = STAGES
                .into_iter()
                .find(|stage| *stage as u8 == bytes[1])
                .expect("a disk stage");
            let index = self
                .scene
                .control
                .candidates(stage)
                .iter()
                .position(|known| *known == wanted)
                .expect("a selected disk event is ready");
            if stage != Stage::Admit {
                self.fault_command(&wanted, stage, index);
            }
            let selected = self
                .scene
                .control
                .select(stage, index)
                .expect("a ready entry");
            return selected.token.raw();
        }
        let client = usize::from(bytes[3]);
        let arg = u32::from_be_bytes(bytes[4..8].try_into().expect("four bytes"));
        match bytes[1] {
            OWNER_POLL => {
                if plant == Plant::LeakedUnit
                    && checker.planted
                    && self.cell == 0
                    && !self.leaked_unit
                {
                    self.leaked_unit = leak_unit(self.scene.storage);
                    checker.acted |= self.leaked_unit;
                }
                let uncounted = plant == Plant::Uncounted && checker.planted && self.cell == 0;
                if uncounted
                    && self.scene.owner.transport().swallow_unarmed()
                    && (0..2).any(|net| self.inbound(1, net))
                {
                    self.scene.owner.transport_mut().swallow_next();
                }
                let (before, report, due, outcome) = poll_owner(&mut self.scene, now);
                checker.acted |= uncounted && self.scene.owner.transport().swallowed();
                check_turn_limits(
                    &self.scene.owner,
                    (&before, &report),
                    u64::from(OWNER.batch),
                    OWNER.follow.wake,
                );
                self.owner_due = due.max(self.resting);
                outcome
            }
            CLIENT_POLL => {
                self.polled[client] = true;
                let report = self.scene.clients[client].poll(now);
                if client == 0 {
                    self.take_acknowledgments(checker, plant);
                }
                u64::from(report.received) | u64::from(report.sent) << 32
            }
            COVER => self.cover(now, checker),
            SERVICE => {
                let calls = self.scene.control.driver_calls();
                self.scene.owner.service_disk();
                self.service_due = (now + super::super::owner::MAINTAIN_REST_US).max(self.resting);
                (self.scene.control.driver_calls() - calls) as u64
            }
            READ => self.read(client, arg as usize, checker, plant),
            PREPARE | SUPPLY | OUTCOME => {
                let outcome = self.act_put(bytes[1], arg, checker);
                self.blocked = outcome == REFUSED && bytes[1] != OUTCOME;
                outcome
            }
            code => unreachable!("cell event code {code}"),
        }
    }

    fn get(
        &mut self,
        client: usize,
        key: u8,
        (floor, window): (u32, u32),
        probe: bool,
        now: u64,
    ) -> u64 {
        let Ok(id) = self.scene.clients[client].get(key_bytes(key), 0, 1 << 20, now, WAIT_US)
        else {
            return REFUSED;
        };
        self.accepted_gets += 1;
        self.gets[client].push(Get {
            id,
            key,
            floor,
            window,
            acknowledged: self.unremoved.len(),
            issue: self.accepted_gets,
            probe,
            bytes: Vec::new(),
        });
        APPLIED
    }

    fn put(&mut self, key: u8, version: u32, object: Vec<u8>, probe: bool, now: u64) -> u64 {
        let named = CacheVersion(match self.store {
            Some(_) => cache_version(version),
            None => 0,
        });
        let Ok(id) = self.scene.clients[0].put(key_bytes(key), named, now, WAIT_US) else {
            return REFUSED;
        };
        self.registry.register(
            key_bytes(key),
            upload_label(key, version),
            0,
            object.clone(),
        );
        let fragments = object.len().div_ceil(FRAGMENT_LEN as usize);
        self.put = Some(Put {
            id,
            key,
            version,
            object,
            prepared: false,
            supplied: vec![false; fragments],
            outcome: None,
            probe,
        });
        APPLIED
    }

    fn invalidate(&mut self, key: u8, now: u64, checker: &mut Checker, plant: Plant) -> u64 {
        if self.store.is_some() {
            return self.request_invalidation(key, checker, plant);
        }
        let Some(before) = checker.settled(self.bound(key, checker)) else {
            return REFUSED;
        };
        if let Some((_, None)) = before {
            checker.foreign("an owner binds bytes no upload of its key wrote");
            return REFUSED;
        }
        let mut budget = WorkBudget::new(1 << 20);
        let Ok(done) = self.scene.owner.invalidate(&key_bytes(key), 3, &mut budget) else {
            return REFUSED;
        };
        let Some((removed, _)) = done.removed else {
            checker.unremoved(before.is_some());
            return REFUSED;
        };
        checker.removal(before.map(|(allocation, _)| allocation), removed);
        self.owner_due = now;
        // With the index binding `key` to none, the removal ended another
        // key's mapping of the same fingerprint, so `key`'s versions, floor
        // and counts stay as they were.
        let Some((_, Some(version))) = before else {
            return APPLIED;
        };
        let after = checker
            .settled(self.bound(key, checker))
            .is_some_and(|after| after.is_some());
        checker.invalidated(key, version, after);
        APPLIED
    }

    fn cancellable(&self, client: usize, key: u8) -> bool {
        self.gets[client]
            .iter()
            .any(|get| get.key == key && self.scene.clients[client].outcome(get.id).is_none())
    }

    fn cancel(&mut self, client: usize, key: u8) -> u64 {
        let session = &self.scene.clients[client];
        let Some(get) = self.gets[client]
            .iter()
            .find(|get| get.key == key && session.outcome(get.id).is_none())
        else {
            return REFUSED;
        };
        let id = get.id;
        self.scene.clients[client].cancel(id);
        APPLIED
    }

    fn set_faults(&mut self, links: Faults, device: DeviceFaults, release: TxRelease) {
        for net in &self.scene.nets {
            let mut net = net.borrow_mut();
            net.set_faults(0, links);
            net.set_faults(1, links);
            net.set_tx_release(release);
        }
        self.device_faults = device;
    }

    fn returning(&self) -> bool {
        self.scene
            .nets
            .iter()
            .any(|net| net.borrow().nic_held() > 0)
    }

    fn active(&self, client: usize) -> bool {
        self.scene.clients[client].state() == SessionState::Active
    }

    fn pending(&self, client: usize) -> usize {
        self.gets[client].len()
    }

    fn uploading(&self) -> bool {
        self.put.is_some()
    }

    fn idle(&self) -> bool {
        let census = self.scene.owner.census();
        self.gets.iter().all(Vec::is_empty)
            && self.put.is_none()
            && census.active + census.draining == 0
    }

    fn retired(&mut self) -> bool {
        for client in 0..CLIENTS {
            let scene = &mut self.scene;
            self.retiring[client].retain(|&id| !scene.clients[client].retire(id));
        }
        self.retiring.iter().all(Vec::is_empty)
    }

    fn reclaimed(&self) -> bool {
        let client = &self.scene.clients[0];
        self.retiring.iter().all(Vec::is_empty)
            && client.live_uploads() == 0
            && client
                .sources()
                .iter()
                .all(|slot| slot.piece().is_none() && !slot.device_held())
    }

    fn take_probe(&mut self) -> Option<UploadOutcome> {
        let outcome = self.put.as_ref().filter(|put| put.probe)?.outcome?;
        self.put = None;
        Some(outcome)
    }

    fn take_collected(&mut self) -> Collected {
        std::mem::take(&mut self.collected)
    }

    /// Emits the audit records the links added since the last call, then
    /// retires the passing ones it read, so the link audits keep only
    /// failing records between calls.
    fn audits(&mut self, out: &mut Vec<Event>) {
        for net in 0..2 {
            let mut link = self.scene.nets[net].borrow_mut();
            let records = link.audit().records();
            for record in &records[self.audited[net].min(records.len())..] {
                // A cluster AUDIT event names partition `cell`'s link `net`
                // as `2 * cell + net`.
                out.push(super::bundle::audit_event(
                    2 * self.cell + net as u8,
                    record,
                ));
                self.injected += u64::from(record.class == Class::Injected);
            }
            self.kept_peak = self.kept_peak.max(records.len());
            let from = self.audited[net].min(records.len());
            self.audited[net] = link.retire_audit(from);
        }
    }

    fn absorb(&mut self) {
        self.device.absorb_since(
            &self.scene.control,
            u16::from(self.cell),
            &mut self.device_seen,
        );
    }

    fn verdict(&self) -> Verdict {
        self.scene.nets[0]
            .borrow()
            .verdict(&[])
            .then(self.scene.nets[1].borrow().verdict(&[]))
            .then(self.device.verdict(&[]))
    }

    fn take_draw_errors(&mut self) {
        for net in &self.scene.nets {
            net.borrow_mut().take_draw_error();
        }
        self.draw_error = None;
    }

    fn defect(&self) -> Option<Defect> {
        self.scene
            .nets
            .iter()
            .find_map(|net| net.borrow().draw_error())
            .or(self.draw_error)
            .map(Defect::Choice)
    }

    fn set_clocks(&self, now: u64) {
        set_clock(self.scene.storage, &[Some(ticks(now))]);
    }

    fn start(&self) -> u64 {
        self.scene.turn * LINK_TURN_US
    }

    fn injected(&self) -> u64 {
        self.injected
    }

    fn truncation(&self) -> Truncation {
        Truncation {
            delivered: self
                .scene
                .nets
                .iter()
                .map(|net| net.borrow().report(1).truncated)
                .sum(),
            dropped: self.scene.owner.report().dropped_by
                [crate::net::DropReason::Truncated as usize],
        }
    }

    fn applied(&self) -> Applied {
        self.applied
    }

    fn rest(&mut self, until: u64) {
        self.resting = until;
        self.owner_due = self.owner_due.max(until);
        self.service_due = self.service_due.max(until);
    }

    fn outstanding(&self, out: &mut Vec<(u8, u32)>) {
        out.extend(self.gets.iter().flatten().map(|get| (get.key, get.floor)));
    }

    fn uploading_version(&self) -> Option<(u8, u32)> {
        self.put.as_ref().map(|put| (put.key, put.version))
    }

    fn compact(&mut self, checker: &Checker) -> usize {
        self.registry.retire(|_, label| match upload_of(label) {
            Some((key, version)) => checker
                .keys
                .get(usize::from(key))
                .is_none_or(|state| version >= state.retired_below),
            None => true,
        });
        self.registry.len()
    }

    fn kept(&self) -> usize {
        self.scene
            .nets
            .iter()
            .map(|net| net.borrow().audit().records().len())
            .sum()
    }

    fn peaks(&self) -> (usize, usize) {
        (self.registry.peak(), self.kept_peak)
    }

    fn leak(&mut self) {
        self.leak = true;
    }

    fn corrupt(&mut self, keys: u8) -> bool {
        (0..keys).any(|key| super::bundle::change_published(&self.scene, KEY_BASE + key))
    }
}

/// A healthy phase's probe of one owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Probe {
    /// The fresh upload is not yet issued.
    Start,
    /// The fresh upload of this version runs.
    Uploading(u32),
    /// The upload of this version published; its read is not yet issued.
    Published(u32),
    /// The read of this version runs.
    Reading(u32),
}

/// Where a run stands in its phases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// A fault phase with this many operations left to issue.
    Faulted(u32),
    /// A healthy phase waiting for every outstanding operation to decide.
    Draining,
    /// A healthy phase probing `owner` on attempt `attempt`.
    Probing {
        owner: u8,
        attempt: u32,
        probe: Probe,
    },
    /// The world rests idle until this time, then a fault phase begins.
    Resting(u64),
    Done,
}

/// The window event, recorded at every window cut. Its payload holds the
/// window's index as a little-endian `u32` in bytes 0 to 3; at byte
/// [`WINDOW_VERDICT`] 1 when the checks passed through the window's closing
/// action and every audit passed, and 0 otherwise: a recorded failure, a
/// failing audit or an inconclusive one; then from byte 5 nine
/// little-endian `u32`s, each saturating: the uploads the checker carries,
/// the registry entries every partition keeps after the cut retired
/// history, the outstanding GETs, the audit records the links keep, and the
/// publications, exact reads, delivered faults, reused slots and healed
/// phases reached so far. [`window_words`] reads the ten words in that
/// order, the index first.
pub(crate) const WINDOW: u8 = 14;

/// The byte of a [`WINDOW`] payload that holds its verdict.
pub(crate) const WINDOW_VERDICT: usize = 4;

/// The byte at which a [`WINDOW`] payload's word `n` starts: the index at
/// 0, then each later word after the verdict byte.
const fn window_word(n: usize) -> usize {
    if n == 0 {
        0
    } else {
        WINDOW_VERDICT + 1 + 4 * (n - 1)
    }
}

/// The ten words of a [`WINDOW`] payload in order: the index, carried,
/// registry, outstanding, kept, published, hits, faults, reused, healed.
pub(crate) fn window_words(payload: &[u8; crate::sim::trace::PAYLOAD]) -> [u32; 10] {
    std::array::from_fn(|n| {
        let at = window_word(n);
        u32::from_le_bytes(payload[at..at + 4].try_into().expect("four bytes"))
    })
}

const _: () = assert!(
    window_word(9) + 4 <= crate::sim::trace::PAYLOAD,
    "the window event holds every word"
);

/// What a window cut measured: the carried checker uploads, registry
/// entries, outstanding GETs and kept audit records.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Marks {
    pub(crate) carried: u64,
    pub(crate) registry: u64,
    pub(crate) outstanding: u64,
    pub(crate) kept: u64,
}

impl Marks {
    /// Each mark the larger of `self`'s and `other`'s.
    fn max(self, other: Self) -> Self {
        Self {
            carried: self.carried.max(other.carried),
            registry: self.registry.max(other.registry),
            outstanding: self.outstanding.max(other.outstanding),
            kept: self.kept.max(other.kept),
        }
    }
}

/// The topology the root drew inside the profile's ranges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Topology {
    pub(crate) owners: u8,
    pub(crate) keys: u8,
    /// The hot key's index, below `keys`; [`Shape::hot`] is the candidate
    /// slots its operations take.
    pub(crate) hot: u8,
}

impl Topology {
    /// The topology `bytes` select inside `shape`'s ranges.
    fn drawn(shape: &Shape, bytes: [u8; 16]) -> Self {
        let within = |(low, high): (u8, u8), byte: u8| low + byte % (high - low + 1);
        let owners = within(shape.owners, bytes[0]);
        let keys = within(shape.keys, bytes[1]).max(owners);
        Self {
            owners,
            keys,
            hot: bytes[2] % keys,
        }
    }
}

/// The reading client of a probe.
const READER: usize = CLIENTS - 1;

/// The cluster world over its partitions.
struct Cluster<'c> {
    shape: &'static Shape,
    topology: Topology,
    cells: Vec<Box<dyn Cell + 'c>>,
    checker: Checker,
    phase: Phase,
    progress: u64,
    start: u64,
    /// Actions executed since the last `emit`.
    acts: Vec<(ActionKind, u64)>,
    failure_emitted: bool,
    boundaries: u64,
    /// Conservation judgments each partition made from [`World::emit`].
    conserved: Vec<u64>,
    draw_refusal: Option<DrawRefusal>,
    puts: u64,
    /// A generated operation or probe step was refused; both wait for an
    /// event that is neither.
    stalled: bool,
    /// The time of the latest clock move or turn.
    now: u64,
    /// Window events not yet emitted.
    window_events: Vec<Event>,
    /// The largest of each window cut's measures.
    marks: Marks,
    /// The corrupt plant changed a byte.
    corrupted: bool,
    /// Virtual time the world spent resting between phases.
    rested_us: u64,
    /// Probe steps wait until this turn time.
    resume_at: u64,
}

impl Cluster<'_> {
    /// Whether the control's plant did what a rule forbids: the checker
    /// recorded it, or a partition observed the unremoved plant's effect.
    fn planted(&self) -> bool {
        self.checker.acted || self.cells.iter().any(|cell| cell.late())
    }

    /// Moves the world's time to `now`, crediting the part of a rest the
    /// clock passed through.
    fn elapse(&mut self, now: u64) {
        if let Phase::Resting(until) = self.phase {
            let end = now.min(until);
            if end > self.now {
                self.rested_us += end - self.now;
            }
        }
        self.now = now;
    }

    /// Cuts a window with operations outstanding: when the profile
    /// compacts, no check failed and every audit passed, retires the
    /// history the carried frontier, outstanding GETs' floors and held
    /// uploads included, discharged, then records the window event and its
    /// marks, and arms a plant whose windows closed. The event's verdict
    /// byte holds whether the cut passed; `emit` clears it when the
    /// closing action then fails a check or audit. The cut keeps every
    /// pending operation and floor.
    fn cut(&mut self) {
        let mut outstanding = Vec::new();
        for cell in &self.cells {
            cell.outstanding(&mut outstanding);
        }
        let passing = self.passing();
        if self.shape.compact && passing {
            let mut frontier = outstanding.clone();
            frontier.extend(
                self.cells
                    .iter()
                    .filter_map(|cell| cell.uploading_version()),
            );
            self.checker.compact(&frontier);
        }
        // With the frontier unmoved, a partition's compaction retires
        // nothing.
        let registry: usize = self
            .cells
            .iter_mut()
            .map(|cell| cell.compact(&self.checker))
            .sum();
        let marks = Marks {
            carried: self.checker.carried_now() as u64,
            registry: registry as u64,
            outstanding: outstanding.len() as u64,
            kept: self.cells.iter().map(|cell| cell.kept() as u64).sum(),
        };
        self.marks = self.marks.max(marks);
        let reached = Reached {
            faults: self.cells.iter().map(|cell| cell.injected()).sum(),
            ..self.checker.reached
        };
        let index = self.checker.windows;
        self.checker.windows += 1;
        let mut payload = [0; crate::sim::trace::PAYLOAD];
        payload[WINDOW_VERDICT] = u8::from(passing);
        let words = [
            u64::from(index),
            marks.carried,
            marks.registry,
            marks.outstanding,
            marks.kept,
            reached.published,
            reached.hits,
            reached.faults,
            reached.reused,
            reached.healthy,
        ];
        for (n, word) in words.into_iter().enumerate() {
            let word = u32::try_from(word).unwrap_or(u32::MAX).to_le_bytes();
            let at = window_word(n);
            payload[at..at + 4].copy_from_slice(&word);
        }
        self.window_events.push(Event {
            kind: WINDOW,
            payload,
        });
        self.arm();
    }

    /// Whether no check failed and every partition's audit passed.
    fn passing(&self) -> bool {
        self.checker.first.get().is_none() && self.audit() == Verdict::Pass
    }

    /// The partitions' audit verdicts joined in partition order.
    fn audit(&self) -> Verdict {
        self.cells
            .iter()
            .fold(Verdict::Pass, |verdict, cell| verdict.then(cell.verdict()))
    }

    /// Arms the profile's plant once `plant_after` windows closed: the
    /// leak plant makes owner 0's next decided upload leak.
    fn arm(&mut self) {
        if !self.checker.planted && self.checker.windows >= self.shape.plant_after {
            self.checker.planted = true;
            if self.shape.plant == Plant::Leak {
                self.cells[0].leak();
            }
        }
    }

    /// The owner a key's operations go to: the contract's, or under the
    /// wrong-owner plant, key 0's to the next owner.
    fn destination(&self, key: u8) -> u8 {
        let route = self.checker.route(key);
        if self.shape.plant == Plant::WrongOwner && key == 0 {
            (route + 1) % self.topology.owners
        } else {
            route
        }
    }

    fn enter_faulted(&mut self) {
        let release = if self.shape.delayed_returns {
            TxRelease::Delayed(3)
        } else {
            TxRelease::AtDelivery
        };
        for cell in &mut self.cells {
            cell.set_faults(self.shape.faults, self.shape.device, release);
        }
        self.phase = Phase::Faulted(self.shape.phase_ops);
    }

    fn enter_healthy(&mut self) {
        for cell in &mut self.cells {
            cell.set_faults(Faults::default(), SOUND, TxRelease::AtDelivery);
        }
        self.phase = Phase::Draining;
    }

    /// The outcome of every GET and upload was collected: no partition
    /// holds one.
    fn decided(&self) -> bool {
        self.cells
            .iter()
            .all(|cell| !cell.uploading() && (0..CLIENTS).all(|client| cell.pending(client) == 0))
    }

    /// Generated operations valid now, the hot key's taking its weight in
    /// candidate slots.
    fn proposed(&self, out: &mut Vec<Candidate>) {
        if self.stalled || !matches!(self.phase, Phase::Faulted(left) if left > 0) {
            return;
        }
        let concurrency = usize::from(self.shape.concurrency);
        for key in 0..self.topology.keys {
            let owner = self.destination(key);
            let cell = &self.cells[usize::from(owner)];
            let slots = if key == self.topology.hot {
                self.shape.hot
            } else {
                1
            };
            let published = self.checker.keys[usize::from(key)].published;
            for slot in 0..slots {
                for client in 0..CLIENTS {
                    if cell.active(client) && cell.pending(client) < concurrency {
                        out.push(candidate(GET, owner, client, 0, key, slot));
                    }
                    if self.shape.cancel && cell.cancellable(client, key) {
                        out.push(candidate(CANCEL, owner, client, 0, key, slot));
                    }
                }
                if cell.active(0) && !cell.uploading() {
                    for size in 0..self.shape.sizes.len() {
                        out.push(candidate(PUT, owner, 0, size as u32, key, slot));
                    }
                }
                if self.shape.invalidate && published {
                    out.push(candidate(INVALIDATE, owner, 0, 0, key, slot));
                }
            }
        }
    }

    /// The probe step valid now, the healthy phase's own operation.
    fn probing(&self, now: u64, out: &mut Vec<Candidate>) {
        let Phase::Probing { owner, probe, .. } = self.phase else {
            return;
        };
        if now < self.resume_at {
            return;
        }
        let cell = &self.cells[usize::from(owner)];
        let ready = match probe {
            Probe::Start => cell.active(0) && !cell.uploading(),
            Probe::Published(_) => cell.active(READER) && cell.pending(READER) == 0,
            Probe::Uploading(_) | Probe::Reading(_) => false,
        };
        if ready && !self.stalled {
            out.push(candidate(PROBE, owner, 0, 0, owner, 0));
        }
    }

    fn workload(
        &mut self,
        code: u8,
        owner: u8,
        (client, arg, key): (usize, u32, u8),
        now: u64,
    ) -> u64 {
        if let Phase::Faulted(left) = &mut self.phase {
            *left -= 1;
            let phase = self.checker.reached.healthy + 1;
            let window_ends = phase.is_multiple_of(u64::from(self.shape.window.max(1)))
                || phase == u64::from(self.shape.phases);
            if window_ends && *left == self.shape.phase_ops / 2 {
                self.cut();
            }
        }
        let cell = usize::from(owner);
        let (kind, outcome) = match code {
            GET => {
                let floor = (self.checker.floor(key), self.checker.windows);
                (
                    ActionKind::Get,
                    self.cells[cell].get(client, key, floor, false, now),
                )
            }
            PUT => match self.checker.next_version(key) {
                Some(_) => (
                    ActionKind::PutInvoke,
                    self.upload(owner, key, self.shape.sizes[arg as usize], false, now),
                ),
                None => {
                    self.refuse_ended();
                    (ActionKind::PutInvoke, REFUSED)
                }
            },
            INVALIDATE => (
                ActionKind::Invalidate,
                self.cells[cell].invalidate(key, now, &mut self.checker, self.shape.plant),
            ),
            CANCEL => {
                let outcome = self.cells[cell].cancel(client, key);
                self.checker.reached.cancelled += outcome;
                (ActionKind::Cancel, outcome)
            }
            code => unreachable!("workload code {code}"),
        };
        self.acted(kind, outcome)
    }

    /// Starts an upload of `key` of `len` bytes at `owner`; the checker
    /// records it and the run counts it only when the client accepted it.
    fn upload(&mut self, owner: u8, key: u8, len: u32, probe: bool, now: u64) -> u64 {
        let Some(version) = self.checker.next_version(key) else {
            return REFUSED;
        };
        let object = content(key, version, owner, len);
        let outcome = self.cells[usize::from(owner)].put(key, version, object, probe, now);
        if outcome != REFUSED {
            self.checker.invoked(key, owner, len);
            self.puts += 1;
        }
        outcome
    }

    /// Records an executed action: progress when it was not refused, then
    /// its act for the bundle.
    fn acted(&mut self, kind: ActionKind, outcome: u64) -> u64 {
        if outcome != REFUSED {
            self.progress += 1;
        }
        self.acts.push((kind, outcome));
        outcome
    }

    /// Ends the run at an upload a key's ended version counter refuses.
    /// The refusal is the effect of the control that starts the counter at
    /// its end, so it counts that plant as acted.
    fn refuse_ended(&mut self) {
        self.checker.acted = true;
        self.checker.first.record(Failure::Unsuccessful(
            "a key's version counter reached its end",
        ));
        self.phase = Phase::Done;
    }

    /// Runs the probe step: publish a fresh version of the key the probed
    /// owner holds, then read it from the reading client.
    fn probe_step(&mut self, now: u64) -> u64 {
        let Phase::Probing {
            owner,
            attempt,
            probe,
        } = self.phase
        else {
            unreachable!("a probe outside its phase");
        };
        let (cell, key) = (usize::from(owner), owner);
        let (kind, outcome, next) = match probe {
            Probe::Start => {
                let Some(version) = self.checker.next_version(key) else {
                    self.refuse_ended();
                    return REFUSED;
                };
                let outcome = self.upload(owner, key, self.shape.sizes[0], true, now);
                (ActionKind::PutInvoke, outcome, Probe::Uploading(version))
            }
            Probe::Published(version) => {
                let floor = (self.checker.floor(key), self.checker.windows);
                let outcome = self.cells[cell].get(READER, key, floor, true, now);
                (ActionKind::Get, outcome, Probe::Reading(version))
            }
            Probe::Uploading(_) | Probe::Reading(_) => unreachable!("a probe step that waits"),
        };
        if outcome != REFUSED {
            self.phase = Phase::Probing {
                owner,
                attempt,
                probe: next,
            };
        }
        self.acted(kind, outcome)
    }

    /// Starts `owner`'s probe over, or ends the run unsuccessful once its
    /// attempts are spent.
    fn retry(&mut self, owner: u8, attempt: u32, now: u64) {
        if attempt + 1 >= PROBES {
            self.checker
                .first
                .record(Failure::Unsuccessful(PROBES_FAILED));
            self.phase = Phase::Done;
        } else {
            self.resume_at = now + RETRY_WAIT_US;
            self.phase = Phase::Probing {
                owner,
                attempt: attempt + 1,
                probe: Probe::Start,
            };
        }
    }

    /// Moves the phase on once its condition holds: a fault phase whose
    /// budget is spent heals, a sustained one once its operations'
    /// outcomes were also collected, a healthy phase whose operations all decided
    /// and whose links hold no device reference probes its first owner, a
    /// decided probe upload is read or retried, a decided probe read passes
    /// to the next owner once its owner retired and reclaimed its work, and
    /// the last owner's passes the world to rest, to the next fault phase
    /// or to its end; a rest whose time came begins the next fault phase. A
    /// probe read whose owner kept work waits while the owner's links hold
    /// a device reference and ends the run unsuccessful once they hold
    /// none. A reference the links never return keeps the healthy phase and
    /// the probe read waiting, and one of the run's limits then ends the
    /// run `inconclusive`.
    fn settle(&mut self, now: u64) {
        loop {
            match self.phase {
                Phase::Faulted(0) if !self.shape.sustained || self.decided() => {
                    self.enter_healthy();
                }
                Phase::Resting(until) if self.now >= until => self.enter_faulted(),
                Phase::Draining
                    if self
                        .cells
                        .iter()
                        .all(|cell| cell.idle() && !cell.returning()) =>
                {
                    self.phase = Phase::Probing {
                        owner: 0,
                        attempt: 0,
                        probe: Probe::Start,
                    };
                }
                Phase::Probing {
                    owner,
                    attempt,
                    probe: Probe::Uploading(version),
                } => match self.cells[usize::from(owner)].take_probe() {
                    Some(UploadOutcome::Published) => {
                        self.phase = Phase::Probing {
                            owner,
                            attempt,
                            probe: Probe::Published(version),
                        };
                    }
                    Some(_) => self.retry(owner, attempt, now),
                    None => return,
                },
                Phase::Probing {
                    owner,
                    attempt,
                    probe: Probe::Reading(version),
                } if self.cells[usize::from(owner)].pending(READER) == 0 => {
                    if self.checker.last != Some((owner, owner, version)) {
                        self.retry(owner, attempt, now);
                        continue;
                    }
                    let owned = &mut self.cells[usize::from(owner)];
                    let kept = !owned.retired() || !owned.reclaimed();
                    // A client keeps an upload's source slot while the
                    // device holds a reference to it, so the judgment
                    // waits for the links to return every reference.
                    if kept && owned.returning() {
                        return;
                    }
                    // The rule forbids a healed owner keeping finished
                    // work's resources, so a leaked request breaks it at
                    // this judgment of its owner, whatever the judgment
                    // finds.
                    self.checker.acted |= self.checker.leaked == Some(owner);
                    if kept {
                        self.checker
                            .first
                            .record(Failure::Unsuccessful(KEPT_RESOURCES));
                        self.phase = Phase::Done;
                        return;
                    }
                    if owner + 1 < self.topology.owners {
                        self.phase = Phase::Probing {
                            owner: owner + 1,
                            attempt: 0,
                            probe: Probe::Start,
                        };
                    } else {
                        self.checker.reached.healthy += 1;
                        if self.checker.reached.healthy >= u64::from(self.shape.phases) {
                            self.phase = Phase::Done;
                        } else if self.shape.gap_us > 0 {
                            let until = self.now.saturating_add(self.shape.gap_us);
                            for cell in &mut self.cells {
                                cell.rest(until);
                            }
                            // The armed corrupt plant changes a bound
                            // object while every owner rests, so no upload
                            // replaces it before the stopped boundary at
                            // the rest's end checks it; it tries each rest
                            // until one object was bound.
                            if self.checker.planted
                                && self.shape.plant == Plant::Corrupt
                                && !self.corrupted
                            {
                                self.corrupted = self.cells[0].corrupt(self.topology.keys);
                                self.checker.acted |= self.corrupted;
                            }
                            self.phase = Phase::Resting(until);
                        } else {
                            self.enter_faulted();
                        }
                    }
                }
                _ => return,
            }
        }
    }

    /// The topology and every profile field that shapes the run's actions,
    /// as the configuration record's bytes. The minima judge the finished
    /// run and stay out; the profile name and `GENERATOR` fix them.
    fn record(&self) -> Vec<u8> {
        let shape = self.shape;
        let mut out = vec![GENERATOR];
        out.extend(shape.name.as_bytes());
        out.push(0);
        out.extend([
            self.topology.owners,
            self.topology.keys,
            self.topology.hot,
            shape.owners.0,
            shape.owners.1,
            shape.keys.0,
            shape.keys.1,
            shape.hot,
            shape.concurrency,
            u8::from(shape.sustained),
            u8::from(shape.delayed_returns),
            u8::from(shape.invalidate),
            u8::from(shape.versioned),
            u8::from(shape.cancel),
            shape.plant as u8,
        ]);
        for value in [
            shape.phases,
            shape.phase_ops,
            shape.plant_after,
            shape.window,
            shape.first_version,
        ] {
            out.extend(value.to_le_bytes());
        }
        out.extend(shape.gap_us.to_le_bytes());
        out.push(u8::from(shape.compact));
        let Faults {
            loss,
            duplicate,
            reorder,
            delay,
            stale,
            truncate,
            would_block,
            error,
            burst,
            resend_loss,
        } = shape.faults;
        // The record carries neither shape, so a cluster run draws neither.
        assert_eq!(
            (burst, resend_loss),
            (0, 0),
            "a cluster shape draws no burst or resend loss"
        );
        let DeviceFaults {
            write_error,
            read_error,
            write_torn,
            read_partial,
        } = shape.device;
        for value in [
            loss,
            duplicate,
            reorder,
            delay,
            stale,
            truncate,
            would_block,
            error,
            write_error,
            read_error,
            write_torn,
            read_partial,
        ] {
            out.extend(value.to_le_bytes());
        }
        out.push(shape.sizes.len() as u8);
        for size in shape.sizes {
            out.extend(size.to_le_bytes());
        }
        out
    }
}

impl World for Cluster<'_> {
    fn config(&self) -> Vec<u8> {
        self.record()
    }

    fn start(&self) -> u64 {
        self.start
    }

    /// Moves every partition's link clocks and checks every partition's
    /// stopped boundary.
    fn advance(&mut self, now: u64) {
        self.elapse(now);
        for cell in &mut self.cells {
            cell.advance(now, &self.checker);
        }
        self.boundaries += 1;
    }

    fn runnable(&self, now: u64) -> Vec<Candidate> {
        let mut out = Vec::new();
        for cell in &self.cells {
            cell.runnable(now, &mut out);
        }
        self.proposed(&mut out);
        self.probing(now, &mut out);
        out.sort();
        out
    }

    fn next_due(&self, now: u64) -> Option<u64> {
        let resume = (self.resume_at > now).then_some(self.resume_at);
        self.cells
            .iter()
            .filter_map(|cell| cell.next_due(now))
            .chain(resume)
            .min()
    }

    fn apply(&mut self, event: Candidate, now: u64) -> u64 {
        self.elapse(now);
        for cell in &self.cells {
            cell.set_clocks(now);
        }
        let bytes = event.0;
        let workload = bytes[0] == Domain::Workload as u8;
        let cell = bytes[2];
        let arg = u32::from_be_bytes(bytes[4..8].try_into().expect("four bytes"));
        let outcome = if workload && bytes[1] >= GET {
            let outcome =
                self.workload(bytes[1], cell, (usize::from(bytes[3]), arg, bytes[8]), now);
            self.stalled = outcome == REFUSED;
            outcome
        } else if workload && bytes[1] == PROBE {
            let outcome = self.probe_step(now);
            self.stalled = outcome == REFUSED;
            outcome
        } else {
            self.stalled = false;
            let plant = self.shape.plant;
            let applied =
                self.cells[usize::from(cell)].apply(&event, now, &mut self.checker, plant);
            let kind = match bytes[1] {
                READ => Some(ActionKind::Read),
                PREPARE => Some(ActionKind::PutPrepare),
                SUPPLY => Some(ActionKind::Supply),
                OUTCOME => Some(ActionKind::PutOutcome),
                _ => None,
            };
            if let Some(kind) = kind.filter(|_| workload) {
                self.acted(kind, applied);
            }
            applied
        };
        for cell in &mut self.cells {
            cell.absorb();
        }
        self.settle(now);
        outcome
    }

    /// Every partition's collection during the turn, one at most to be
    /// attributed.
    fn observation(&mut self) -> [u8; crate::sim::trace::TURN_OBSERVATION] {
        let mut collected = Collected::Absent;
        for cell in &mut self.cells {
            collected.add(cell.take_collected());
        }
        collected.code()
    }

    fn progress(&self) -> u64 {
        self.progress
    }

    fn done(&self) -> bool {
        self.phase == Phase::Done
    }

    fn defect(&self) -> Option<Defect> {
        self.draw_refusal
            .map(Defect::Entropy)
            .or_else(|| self.cells.iter().find_map(|cell| cell.defect()))
    }

    /// Judges every partition's tables first, so a failure the turn or
    /// clock move produced fails any window that turn closes. Every
    /// partition's conservation rule runs before any partition's datagram
    /// accounts, so a run that breaks both records the conservation text.
    fn emit(&mut self, out: &mut Vec<Event>) {
        for (at, cell) in self.cells.iter_mut().enumerate() {
            self.conserved[at] += u64::from(cell.conserve(&self.checker));
        }
        for cell in &mut self.cells {
            cell.account(&self.checker);
        }
        for (kind, outcome) in self.acts.drain(..) {
            super::bundle::act_events(out, kind, outcome, outcome != REFUSED);
        }
        for cell in &mut self.cells {
            cell.audits(out);
        }
        // A window cuts during its closing action, and its event closes
        // the record of that action, so a failure the action recorded
        // after the cut makes the window non-passing.
        if !self.window_events.is_empty() && !self.passing() {
            for event in &mut self.window_events {
                event.payload[WINDOW_VERDICT] = 0;
            }
        }
        out.append(&mut self.window_events);
        if !self.failure_emitted
            && let Some(failure) = self.checker.first.get()
        {
            self.failure_emitted = true;
            out.push(super::bundle::failure_event(&failure));
        }
    }
}

/// What a cluster run leaves for its bundle: the report, the first
/// failure, the merged audit verdict, the topology, what it reached, the
/// stopped boundaries it checked, the uploads it started and the chooser.
/// The topology is present once the setup draw succeeds; a refused draw
/// runs the world on a placeholder, which the Config record names while
/// the coverage and stop events name a drawn topology only.
pub(crate) struct Ran {
    pub(crate) report: Report,
    pub(crate) failure: Option<Failure>,
    /// Whether `failure` reached the stream as an event during the run. A
    /// failure the teardown check or the minimum check records after the
    /// controller returns did not.
    pub(crate) failure_emitted: bool,
    /// [`Checker::acted`] when the run ended.
    pub(crate) acted: bool,
    pub(crate) audit: Verdict,
    pub(crate) topology: Option<Topology>,
    pub(crate) reached: Reached,
    /// The device faults the run's partitions attached, by kind. They are
    /// kept apart from [`Reached`], whose fields alone build the coverage
    /// event and the summary line; `Reached::faults` counts link faults.
    pub(crate) applied: Applied,
    pub(crate) boundaries: u64,
    /// Conservation judgments each partition made from the world's
    /// emissions, in partition order.
    pub(crate) conserved: Vec<u64>,
    /// Truncated datagrams every partition's links delivered toward its
    /// owner, and those the owners dropped as truncated.
    pub(crate) truncated: Truncation,
    pub(crate) puts: u64,
    pub(crate) draws: Draws,
    /// The run's high-water marks: the most uploads the checker carried
    /// at once, the most registry entries one partition held at once, the
    /// most outstanding GETs at a window cut, and the most records one link
    /// audit held at once.
    pub(crate) marks: Marks,
    /// Window cuts the run made.
    pub(crate) windows: u32,
    /// Each key's state when the run ended, indexed by key.
    pub(crate) retained: Vec<KeyState>,
    /// Virtual time the world rested idle between phases, which the
    /// controller skips; the rest of `report.skipped_us`, the clock's whole
    /// advance from the world's start, is phase time.
    pub(crate) rested_us: u64,
}

/// Truncated datagrams links delivered toward owners, and those the owners
/// dropped as truncated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Truncation {
    pub(crate) delivered: u64,
    pub(crate) dropped: u64,
}

/// A hook that forwards every [`Hook`] callback to the hook it wraps and
/// streams the run whatever that hook answers: the report keeps no turn
/// and a recording chooser releases each choice once the hook saw it, so
/// every recorded cluster run holds a bounded record. A replaying chooser
/// keeps the tape it replays.
struct Streaming<'h, H>(&'h mut H);

impl<H: Hook> Hook for Streaming<'_, H> {
    fn begin(&mut self, record: &[u8], choices: &[u8]) {
        self.0.begin(record, choices);
    }

    fn enter(&mut self) {
        self.0.enter();
    }

    fn leave(&mut self) {
        self.0.leave();
    }

    fn clock(&mut self, choices: &[u8], now: u64, events: &[Event]) {
        self.0.clock(choices, now, events);
    }

    fn turn(&mut self, choices: &[u8], turn: &crate::sim::turn::Turn, events: &[Event]) {
        self.0.turn(choices, turn, events);
    }

    fn stopped(&mut self, chooser: &RefCell<Chooser>) {
        self.0.stopped(chooser);
    }

    fn select(&mut self, runnable: &[Candidate], chooser: &RefCell<Chooser>) {
        self.0.select(runnable, chooser);
    }

    fn end(&mut self, choices: &[u8]) {
        self.0.end(choices);
    }

    fn retains(&self) -> bool {
        false
    }

    fn halted(&self) -> bool {
        self.0.halted()
    }
}

/// One partition's drawn setup: its owner's and two clients' boot nonces
/// and its index key pair.
struct Setup {
    nonces: [[u8; 16]; 3],
    hasher: crate::index::KeyHasher,
    /// The incarnation of the partition's storage key-pair actor.
    incarnation: u32,
}

/// Draws the topology inside `shape`'s ranges and every partition's setup
/// from `draws`.
fn drawn_setup(draws: &Draws, shape: &Shape) -> Result<(Topology, Vec<Setup>), DrawRefusal> {
    let mut chooser = draws.borrow_mut();
    let mut bytes = [0; 16];
    let incarnation = chooser.launch(TOPOLOGY);
    draw(&mut chooser, nonce_site(TOPOLOGY), incarnation, &mut bytes)?;
    let topology = Topology::drawn(shape, bytes);
    let mut setups = Vec::new();
    for cell in 0..topology.owners {
        let (index, nonce_actors, _) = actors(cell);
        let incarnation = chooser.launch(index);
        let hasher = key_pair(&mut chooser, key_pair_site(index), incarnation)?;
        let mut nonces = [[0; 16]; 3];
        for (actor, bytes) in nonce_actors.into_iter().zip(&mut nonces) {
            let incarnation = chooser.launch(actor);
            draw(&mut chooser, nonce_site(actor), incarnation, bytes)?;
        }
        setups.push(Setup {
            nonces,
            hasher,
            incarnation,
        });
    }
    Ok((topology, setups))
}

/// The innermost body of [`nest`], run over every partition.
type Body<'b> = dyn FnMut(Vec<Box<dyn Cell + '_>>) + 'b;

/// Builds partition `at` of `setups` in its own scene and recurses into the
/// next; the innermost call runs `body` over every partition.
fn nest<'c>(
    at: usize,
    (setups, draws, versioned): (&[Setup], &Draws, bool),
    (registry, link): (usize, LinkLimits),
    cells: Vec<Box<dyn Cell + 'c>>,
    body: &mut Body<'_>,
) {
    let Some(setup) = setups.get(at) else {
        body(cells);
        return;
    };
    let (shape, chunk_len) = Geometry::Fixture.shape();
    let mut storage = crate::storage::owner_fixture::storage_shaped_as(shape, chunk_len);
    storage.install_hasher(setup.hasher.clone());
    let cell = at as u8;
    let (_, _, links) = actors(cell);
    let drawn = Drawn {
        nonces: setup.nonces,
        draws,
        links,
    };
    scene_drawn(storage, OWNER, &PRINCIPALS, Some(drawn), |mut scene| {
        // `install_coverage` accepts a fencing only before the owner's
        // first publication, so a versioned owner's fencing over a fresh
        // store is installed here.
        let store = versioned.then(|| {
            let seeded = seeded_under(scene.owner.tenure());
            let (fencing, client) = fenced_coverage(&seeded, scene.owner.tenure());
            let installed = scene.owner.install_coverage(fencing);
            assert!(installed.is_ok(), "an owner that published nothing");
            client
        });
        let mut known = Registry::new(registry);
        // The object every scene's owner publishes before the run.
        known.register(key(1), Label(1), 0, payload(1000, 1));
        for net in &scene.nets {
            net.borrow_mut().set_limits(link);
        }
        let start = scene.turn * LINK_TURN_US;
        let part = Part {
            cell,
            scene,
            owner_due: start,
            service_due: start,
            polled: [false; CLIENTS],
            gets: [Vec::new(), Vec::new()],
            put: None,
            registry: known,
            lenses: Lenses::default(),
            audited: [0; 2],
            slots: Vec::new(),
            blocked: false,
            retiring: [Vec::new(), Vec::new()],
            device: Audit::new(MANIFEST.records),
            device_seen: 0,
            leak: false,
            accepted_gets: 0,
            leaked_unit: false,
            accounts_due: false,
            injected: 0,
            draws: Rc::clone(draws),
            incarnation: setup.incarnation,
            store,
            invalidating: Vec::new(),
            unremoved: Vec::new(),
            late: false,
            device_faults: SOUND,
            draw_error: None,
            applied: Applied::default(),
            resting: 0,
            kept_peak: 0,
            collected: Collected::Absent,
        };
        let mut cells: Vec<Box<dyn Cell + '_>> = cells;
        cells.push(Box::new(part));
        nest(
            at + 1,
            (setups, draws, versioned),
            (registry, link),
            cells,
            body,
        );
    });
}

/// Runs `shape` under `profile` from `chooser` within `limits`, each
/// partition's content registry bounded by `registry` and its links by
/// `link`, streaming into `hook`.
pub(crate) fn run(
    chooser: Chooser,
    profile: &Profile,
    shape: &'static Shape,
    (limits, registry, link): (Limits, usize, LinkLimits),
    hook: &mut impl Hook,
) -> Ran {
    let DeviceFaults {
        write_error,
        read_error,
        write_torn,
        read_partial,
    } = shape.device;
    for (error, prefix) in [(write_error, write_torn), (read_error, read_partial)] {
        assert!(
            error <= DRAW && prefix <= DRAW - error,
            "an operation's device rates {error} and {prefix} sum past {DRAW}"
        );
    }
    let draws: Draws = Rc::new(RefCell::new(chooser));
    let (topology, setups, draw_refusal) = match drawn_setup(&draws, shape) {
        Ok((topology, setups)) => (topology, setups, None),
        Err(refusal) => {
            let topology = Topology::drawn(shape, [0; 16]);
            let setups = (0..topology.owners)
                .map(|cell| Setup {
                    nonces: actors(cell).1.map(|actor| [actor as u8; 16]),
                    hasher: crate::index::KeyHasher::with_key_pair(0, 0),
                    incarnation: 0,
                })
                .collect();
            (topology, setups, Some(refusal))
        }
    };
    let first = FirstFailure::default();
    let mut ran = None;
    nest(
        0,
        (&setups, &draws, shape.versioned),
        (registry, link),
        Vec::new(),
        &mut |cells| {
            let start = cells.iter().map(|cell| cell.start()).max().unwrap_or(0);
            let mut world = Cluster {
                shape,
                conserved: vec![0; cells.len()],
                topology,
                cells,
                checker: Checker {
                    owners: topology.owners,
                    keys: vec![
                        KeyState {
                            next: Some(shape.first_version),
                            retired_below: shape.first_version,
                            floor: shape.first_version,
                            ..KeyState::default()
                        };
                        usize::from(topology.keys)
                    ],
                    served: [0; CLIENTS].map(|_| vec![false; usize::from(topology.owners)]),
                    reached: Reached::default(),
                    last: None,
                    first: first.clone(),
                    carried: 0,
                    windows: 0,
                    planted: false,
                    leaked: None,
                    acted: false,
                    order: order::Order::new(shape.plant, topology.hot),
                },
                phase: Phase::Done,
                progress: 0,
                start,
                acts: Vec::new(),
                failure_emitted: false,
                boundaries: 0,
                draw_refusal,
                puts: 0,
                stalled: false,
                now: start,
                window_events: Vec::new(),
                marks: Marks::default(),
                corrupted: false,
                rested_us: 0,
                resume_at: 0,
            };
            world.arm();
            world.enter_faulted();
            let incarnation = draws.borrow_mut().launch(SITE.actor);
            let report = run_hooked(
                &mut world,
                profile,
                &draws,
                (SITE, incarnation),
                limits,
                &mut Streaming(&mut *hook),
            );
            if matches!(report.end, End::Defect(_)) {
                for cell in &mut world.cells {
                    cell.take_draw_errors();
                }
            }
            // The turns after the last clock move left state no stopped
            // boundary checked; judge it as the mixed world's teardown does,
            // every partition's check before any partition's accounts.
            for cell in &mut world.cells {
                cell.check(&world.checker);
            }
            for cell in &mut world.cells {
                cell.account(&world.checker);
            }
            let audit = world.audit();
            let mut reached = world.checker.reached;
            reached.faults = world.cells.iter().map(|cell| cell.injected()).sum();
            let short = (report.end == End::Done)
                .then(|| short_of(&shape.minima, &reached))
                .flatten();
            if let Some(rule) = short {
                first.record(Failure::Unsuccessful(rule));
            } else if shape.control()
                && first.get().is_none()
                && let Some(failure) = unmet(report.end, world.planted())
            {
                first.record(failure);
            }
            ran = Some(Ran {
                report,
                failure: first.get(),
                failure_emitted: world.failure_emitted,
                acted: world.checker.acted,
                audit,
                topology: draw_refusal.is_none().then_some(topology),
                reached,
                applied: world
                    .cells
                    .iter()
                    .fold(Applied::default(), |sum, cell| sum.plus(cell.applied())),
                boundaries: world.boundaries,
                conserved: world.conserved.clone(),
                truncated: world.cells.iter().map(|cell| cell.truncation()).fold(
                    Truncation::default(),
                    |sum, cell| Truncation {
                        delivered: sum.delivered + cell.delivered,
                        dropped: sum.dropped + cell.dropped,
                    },
                ),
                puts: world.puts,
                draws: Rc::clone(&draws),
                marks: Marks {
                    carried: world.checker.carried as u64,
                    registry: world
                        .cells
                        .iter()
                        .map(|cell| cell.peaks().0 as u64)
                        .max()
                        .unwrap_or(0),
                    kept: world
                        .cells
                        .iter()
                        .map(|cell| cell.peaks().1 as u64)
                        .max()
                        .unwrap_or(0),
                    ..world.marks
                },
                windows: world.checker.windows,
                retained: world.checker.keys.clone(),
                rested_us: world.rested_us,
            });
        },
    );
    ran.expect("the cluster ran")
}

impl Ran {
    /// The run's terminal as a cluster bundle judges it.
    pub(crate) fn judged(&self) -> crate::sim::trace::Terminal {
        super::bundle::judge(
            self.report.end,
            self.failure.as_ref(),
            self.audit,
            (true, self.puts),
            self.boundaries as usize,
        )
        .0
    }

    /// How the run stopped, as a summary names it.
    pub(crate) fn stop(&self) -> &'static str {
        let stop = super::bundle::stop_event(self.report.end, None);
        super::bundle::stop_name((stop.payload[0], stop.payload[1]))
    }
}

/// Runs the cluster profile the admitted manifest names as a session,
/// streaming into `hook`, under the manifest's limits and bounds; `None`
/// when the manifest names no cluster profile.
pub(crate) fn session(admitted: &super::bundle::Admitted<'_>, hook: &mut impl Hook) -> Option<Ran> {
    let shape = admitted.cluster()?;
    let (_, profile) = admitted.parts();
    Some(run(
        admitted.recorder(),
        profile,
        shape,
        (admitted.limits(), admitted.registry(), admitted.link()),
        hook,
    ))
}

/// The first of `minima` that `reached` falls short of, as the rule an
/// unsuccessful run names.
pub(crate) fn short_of(minima: &Minima, reached: &Reached) -> Option<&'static str> {
    [
        (
            reached.published < minima.published,
            "fewer publications than the profile requires",
        ),
        (
            reached.hits < minima.hits,
            "fewer exact reads than the profile requires",
        ),
        (
            reached.cross < minima.cross,
            "no logical client read from two owners",
        ),
        (
            reached.faults < minima.faults,
            "fewer delivered faults than the profile requires",
        ),
        (
            reached.healthy < minima.healthy,
            "fewer healed phases than the profile requires",
        ),
        (
            reached.reused < minima.reused,
            "fewer reused slots than the profile requires",
        ),
    ]
    .into_iter()
    .find_map(|(short, rule)| short.then_some(rule))
}

/// The scenario a cluster profile's name selects: its profile and a plan
/// naming its shape, which for the swarm family and its controls is the
/// member `root` selects. A cluster run ends at its last healthy phase.
pub(super) fn named(name: &str, root: u64) -> Option<super::bundle::Scenario> {
    let shape = shape_at(name, root)?;
    let profile = Profile {
        name: shape.name,
        declared: DECLARED.to_vec(),
        root,
    };
    let plan = super::Plan {
        world: WorldKind::Cluster(shape),
        ..super::QUIET
    };
    Some((profile, plan, |_| false))
}
