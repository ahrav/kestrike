//! [`bring_up`] takes the [`Tenure`] that [`recover`](super::recover::recover) returned to a `Live` owner endpoint
//! over that tenure's volume. [`serve`] polls that owner until one [`Exit`] ends its tenure and tears it down, and
//! [`wait`] holds a process with no tenure, rereading its role once per view period.
//!
//! Invariants:
//!
//! - FENCE-BEFORE-USE: [`bring_up`] installs the tenure's coverage fencing before the owner's first poll, so the
//!   fencing covers every FILL and INVALIDATE the tenure admits.
//! - ONE-ATTACH: an incarnation attaches its volume once and reaches `Live` only through the bootstrap of that
//!   attach.
//! - CUSTODY-RETURNS: a bring-up that ends short of `Live` returns the transport and the value that holds the
//!   driver, in [`Custody`], so the caller can stop the driver.
//! - HOST-LOSS-KEEPS-VOLUME: a bring-up that ends short of `Live` requests a flip only where the tenure's authority
//!   withdrew with one. When the bootstrap or the replay ends short of `Live`, a withdrawal that requested a flip
//!   yields [`Exit::Retire`] at its target, and every other outcome yields [`Exit::Held`] at the tenure's
//!   `(g, owner, E)`. A refused setup step yields [`Exit::Fault`], and a turn that unwinds yields
//!   [`Rerun::Unwound`].
//! - ONE-ARENA: the volume attaches over the arena the tenure's fencer built its table over, the one whose memory
//!   the recovered driver registered.
//! - ONE-EXIT, NoPredecessorEffectAfterFB: [`serve`] ends its tenure through one [`Exit`], then closes the owner
//!   and polls until [`Owner::blockers`] reports nothing, a close or a poll unwinds, or the caller's patience ends.
//!   [`Owner::shutdown`] follows and returns the driver and the transport for the proven stop only for an owner
//!   with no blocker, and [`serve`] returns the exit as the caller's to act on only beside those parts
//!   ([`Served::Ended`]); any other owner comes back whole ([`Served::Kept`]).
//! - ROLE-BOUND: a tenure whose authority observed a later tenure ends `Deposed` with no retirement request of its
//!   own; a tenure whose planned transfer the store acknowledged ends `Stopped`, with no retirement request, though
//!   its committed record shows the later tenure. [`wait`] issues only role reads: no store write and no device command. A role read that raises the
//!   client's watermark records it in the client's host-local log.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};

use super::exit::{Exit, Rerun};
use super::gate::HostGate;
use super::recover::{Role, Tenure, survey};
use crate::entropy::{EntropyError, os_entropy};
use crate::failover::poll::Holder;
use crate::failover::records::{ShardRecord, VolumeRecord};
use crate::failover::retire::Target;
use crate::failover::serving::{Cause, State};
use crate::net::ownership::Shard;
use crate::net::{
    Blockers, Bundle, Datagrams, Handoff, Keys, Owner, OwnerConfig, PacketPool, Shutdown,
};
use crate::storage::store::{Client, Store, StoreError, WatermarkLog};
use crate::storage::{
    AuthorityReport, Disk, EngineBudget, MetadataOutcome, PhysicalClock, Platform, RECOVERY_PHASES,
    Readiness, RecoveryPhase, Storage, TickConfig, Volume, contain,
};

/// The storage side of one attach, as [`Volume::attach`] takes it; the arena comes with the [`Tenure`].
pub struct Attachment<'s, P: Platform> {
    pub storage: &'s Storage<P>,
    pub clock: Box<dyn PhysicalClock>,
    pub depth: u16,
    pub tick: TickConfig,
}

/// The network side of one owner, as [`Owner::start`] takes it.
pub struct Endpoint<'k, 'm, 'a, T> {
    pub config: OwnerConfig,
    pub keys: Keys<'k>,
    pub transport: T,
    pub receive: &'m PacketPool<'a>,
}

/// The custody a failed [`bring_up`] returns. The caller stops a `Driver` directly, a `Volume` after its quiesced
/// `Volume::release_driver`, and an `Owner` after the owner's teardown. A `Volume` from a refused registration or
/// owner start comes back after the storage's one facade dropped, which closes the storage's admission for the rest
/// of its life, so the volume serves only its release.
pub enum Custody<'s, 'a, 'm, P: Platform, D: Disk, T> {
    Driver {
        disk: D,
        transport: T,
    },
    Volume {
        volume: Box<Volume<'s, 'a, P, D>>,
        transport: T,
    },
    Owner(Box<Owner<'s, 'a, 'm, P, D, T>>),
}

/// A bring-up that ended short of `Live`: the incarnation's [`Exit`] and the custody it holds.
pub struct Unbrought<'s, 'a, 'm, P: Platform, D: Disk, T> {
    pub exit: Exit,
    pub custody: Custody<'s, 'a, 'm, P, D, T>,
}

/// An owner, or the bring-up that ended before it with its exit and custody. [`bring_up`]'s owner is `Live`.
pub type BringUp<'s, 'a, 'm, P, D, T> =
    Result<Owner<'s, 'a, 'm, P, D, T>, Box<Unbrought<'s, 'a, 'm, P, D, T>>>;

/// Brings `tenure` to a `Live` owner over the tenure's arena. Each poll runs at `now_us()`: microseconds on one
/// clock that never decreases and advances as time passes, which is also the volume's tick value and the clock the
/// caller keeps polling the returned owner on: the one timeline that [`serve`] and [`teardown`] continue, a
/// teardown of an owner this function returned short of `Live` included. Successive turns may read the same value, but paced recovery reads
/// drain the host's recovery I/O share only as ticks elapse, and every owner under one share polls at the same unit
/// and rate. The turn clock is distinct from the tenure's serving clock and from the attachment's physical clock.
///
/// `bring_up` sets no deadline of its own: the loop ends when the bootstrap leaves its initializing states, which a
/// completed load, a refused load and an authority withdrawal each do. A caller ends a stalled bring-up by calling
/// [`Storage::withdraw`] on the attachment's storage, from `now_us` or another thread; the loop then ends with the
/// owner in custody. A clock advance alone does not complete a bootstrap, which also needs device and authority
/// progress.
///
/// A tenure whose record names no checkpoint starts cold, and `bring_up` formats its volume when the bootstrap reads
/// `Unformatted`, both root slots invalid.
///
/// The host has no invalidation-feed client. A loaded volume begins replay at position 0 of the storage's own feed
/// contract and reports it complete at once, so a `Live` warm tenure honors the invalidations its fenced coverage
/// and its certified suffixes carry.
///
/// # Errors
///
/// [`Exit::Fault`] when the storage's facade is already issued, or [`Volume::attach`], the facade, its
/// registration, [`Owner::start`] or [`Owner::install_coverage`] refuses; none requests a flip. A refused attach and
/// an issued facade return the driver and leave the storage's facade and attach untouched. When the bootstrap or the
/// replay ends short of `Live`, a withdrawal that requested the flip parks as [`Exit::Retire`] at its target, and
/// every other end is [`Exit::Held`] at the tenure's `(g, owner, E)`. A turn that unwinds ends [`Rerun::Unwound`]
/// with the owner, in builds whose panics unwind; [`Volume::attach`] and [`Owner::start`] take the driver by value
/// and run outside that boundary.
pub fn bring_up<'s, 'a, 'm, P, D, T>(
    gate: &HostGate,
    tenure: Tenure<'a, P, D>,
    attachment: Attachment<'s, P>,
    endpoint: Endpoint<'_, 'm, 'a, T>,
    budget: &mut EngineBudget,
    mut now_us: impl FnMut() -> u64,
) -> BringUp<'s, 'a, 'm, P, D, T>
where
    P: Platform,
    D: Disk,
    T: Datagrams<'a>,
{
    let mut owner = start_up(gate, tenure, attachment, endpoint, budget)?;
    let ended = contain(|| {
        loop {
            match turn_up(gate, &mut owner, &mut now_us) {
                Rising::Initializing => {}
                Rising::Live => break None,
                Rising::Short(exit) => break Some(exit),
            }
        }
    });
    // A turn that unwound resumes nothing; the owner keeps every read and command until its teardown drains them.
    let exit = match ended {
        Ok(None) => return Ok(owner),
        Ok(Some(exit)) => exit,
        Err(_) => Exit::Rerun(Rerun::Unwound),
    };
    Err(Box::new(Unbrought {
        exit,
        custody: Custody::Owner(Box::new(owner)),
    }))
}

/// Where one [`turn_up`] left a bring-up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Rising {
    /// The bootstrap is still initializing: the turn polled the owner once.
    Initializing,
    /// The owner reads `Live`.
    Live,
    /// The bring-up ended short of `Live` with this exit, and the owner is the caller's custody.
    Short(Exit),
}

/// One turn of [`bring_up`]'s loop over `owner`, which [`start_up`] returned. While the bootstrap initializes, the
/// turn formats the volume once when it reads `Unformatted`, then polls the owner once at `now_us()`, the one clock
/// read of the turn. A turn whose poll leaves the bootstrap still initializing returns [`Rising::Initializing`]. Once
/// the bootstrap has left its initializing states, after the turn's poll or a refused format, the same turn begins
/// and completes the replay of a loaded volume and returns [`Rising::Live`], or the exit of a bring-up that ended
/// short of `Live`: [`Exit::Retire`] at a withdrawal's flip request and otherwise [`Exit::Held`] at the
/// `(g, owner, E)` of the owner's tenure. The replay begins under the feed contract of the storage the owner's volume
/// attached over. `now_us` follows the timeline [`bring_up`] states for its own clock. A caller that drives a
/// bring-up through `turn_up` keeps the owner between turns and polls it only through `turn_up` until a turn returns
/// `Live` or `Short`. [`bring_up`] retains the owner across `turn_up` calls until a turn returns `Live` or `Short`.
pub(crate) fn turn_up<'a, P: Platform, D: Disk, T: Datagrams<'a>>(
    _gate: &HostGate,
    owner: &mut Owner<'_, 'a, '_, P, D, T>,
    now_us: impl FnOnce() -> u64,
) -> Rising {
    if owner.readiness().initializing() {
        // `Volume::format` accepts only the `Unformatted` phase, so a refused format ends the bootstrap short of
        // `Live` and an accepted one formats once.
        let refused = owner.volume_metadata_outcome() == MetadataOutcome::Unformatted
            && owner.format().is_err();
        if !refused {
            owner.poll(now_us());
            if owner.readiness().initializing() {
                return Rising::Initializing;
            }
        }
    }
    if owner.readiness() == Readiness::Loaded {
        // A load that restored no binding reaches `Live` here; one that restored bindings reaches `Replaying`.
        let replay = owner.begin_replay(owner.storage().feed_contract(), 0);
        if replay == Ok(Readiness::Replaying) {
            let _ = owner.complete_replay();
        }
    }
    match owner.readiness() {
        Readiness::Live => Rising::Live,
        _ => Rising::Short(short_of_live(
            &owner.authority_report(),
            owner.tenure().target(),
        )),
    }
}

/// The exit of a bring-up that ended short of `Live` under the tenure's `target`, from the owner's `authority`
/// report: a withdrawal's flip request parks as `Retire`, and every other end holds (HOST-LOSS-KEEPS-VOLUME). A
/// deposing status withdraws with no successor named, and the Report that judges its holder runs in the next
/// incarnation's sequence, so it holds as well.
fn short_of_live(authority: &AuthorityReport, target: Target) -> Exit {
    match authority.flip {
        Some(flip) if authority.state == State::Withdrawn => Exit::Retire(flip),
        _ => Exit::Held { recovery: target },
    }
}

/// The bring-up's steps before the owner's first poll: the attach over the tenure's arena, the facade and its
/// registration, the owner's start and the coverage fencing's install. Returns the owner unpolled; [`turn_up`]
/// judges an end short of `Live` by the `(g, owner, E)` of the owner's tenure. A storage whose facade is already
/// issued refuses before the attach, and a refused attach leaves the storage's facade unissued.
///
/// # Errors
///
/// [`Exit::Fault`] with the custody that holds the driver, as [`bring_up`] states for its setup steps.
pub(crate) fn start_up<'s, 'a, 'm, P, D, T>(
    gate: &HostGate,
    tenure: Tenure<'a, P, D>,
    attachment: Attachment<'s, P>,
    endpoint: Endpoint<'_, 'm, 'a, T>,
    budget: &mut EngineBudget,
) -> BringUp<'s, 'a, 'm, P, D, T>
where
    P: Platform,
    D: Disk,
    T: Datagrams<'a>,
{
    start_up_with_nonce(gate, tenure, attachment, endpoint, budget, os_entropy)
}

/// [`start_up`] with the owner's boot nonce filled by `nonce` where `start_up` reads the operating system's entropy,
/// as [`Owner::start_with_nonce`] states. [`bring_up`] starts through `start_up`; a simulation passes a fill that
/// is a function of its run.
///
/// # Errors
///
/// As [`start_up`].
pub(crate) fn start_up_with_nonce<'s, 'a, 'm, P, D, T>(
    _gate: &HostGate,
    tenure: Tenure<'a, P, D>,
    attachment: Attachment<'s, P>,
    endpoint: Endpoint<'_, 'm, 'a, T>,
    budget: &mut EngineBudget,
    nonce: impl FnOnce(&mut [u8; 16]) -> Result<(), EntropyError>,
) -> BringUp<'s, 'a, 'm, P, D, T>
where
    P: Platform,
    D: Disk,
    T: Datagrams<'a>,
{
    let Tenure {
        authority,
        fencing,
        disk,
        arena,
        lineage: _,
    } = tenure;
    let Attachment {
        storage,
        clock,
        depth,
        tick,
    } = attachment;
    let Endpoint {
        config,
        keys,
        transport,
        receive,
    } = endpoint;
    let fault = |text: String, custody| {
        Box::new(Unbrought {
            exit: Exit::Fault(text),
            custody,
        })
    };
    if storage.is_issued() {
        return Err(fault(
            "storage: the facade is already issued".to_owned(),
            Custody::Driver { disk, transport },
        ));
    }
    let volume = match Volume::attach(storage, arena, disk, clock, authority, depth, tick, budget) {
        Ok(volume) => volume,
        Err((error, disk)) => {
            return Err(fault(
                format!("volume attach: {error:?}"),
                Custody::Driver { disk, transport },
            ));
        }
    };
    let issued = storage
        .issue_cache()
        .map_err(|error| format!("{error:?}"))
        .and_then(|cache| match cache.register() {
            Ok(registration) => Ok((cache, registration)),
            Err(error) => Err(format!("{error:?}")),
        });
    let (cache, registration) = match issued {
        Ok(issued) => issued,
        Err(error) => {
            return Err(fault(
                format!("storage: {error}"),
                Custody::Volume {
                    volume: Box::new(volume),
                    transport,
                },
            ));
        }
    };
    let bundle = Bundle {
        cache,
        registration,
        volume,
    };
    let started = Owner::start_with_nonce(config, bundle, keys, transport, receive, budget, nonce);
    let mut owner = match started {
        Ok(owner) => owner,
        Err(refused) => {
            let refused = *refused;
            return Err(fault(
                format!("owner start: {:?}", refused.error),
                Custody::Volume {
                    volume: Box::new(refused.bundle.volume),
                    transport: refused.transport,
                },
            ));
        }
    };
    if owner.install_coverage(fencing).is_err() {
        return Err(fault(
            "coverage: the owner refused the tenure's fencing".to_owned(),
            Custody::Owner(Box::new(owner)),
        ));
    }
    Ok(owner)
}

/// What [`teardown`] returns: the shut-down owner's parts, or the owner and its blockers when [`Owner::shutdown`]
/// refused, with every custody kept. A refusal follows a drain that outlasted the caller's patience, a close, a
/// clock read or a teardown poll that unwound with a blocker left, or a volume whose release refused. The caller
/// keeps a returned owner, and may pass it to [`teardown`] again; it neither detaches nor waits device-free while
/// it holds one.
pub type Teardown<'s, 'a, 'm, P, D, T> =
    Result<Shutdown<'s, P, D, T>, Box<(Owner<'s, 'a, 'm, P, D, T>, Blockers)>>;

/// How one serving tenure ended. An [`Exit`] is the caller's to act on only in [`Served::Ended`], beside the
/// shut-down owner's parts.
pub enum Served<'s, 'a, 'm, P: Platform, D: Disk, T> {
    /// The tenure ended through `exit` and the owner shut down. Under `Quiesced::AllReturned` the caller still
    /// proves the controller stopped with the returned driver.
    Ended {
        exit: Exit,
        shutdown: Box<Shutdown<'s, P, D, T>>,
    },
    /// The owner refused to shut down, and `kept` holds it with its blockers and every custody. `ending` is the
    /// exit the tenure takes once a [`teardown`] of that owner returns its parts; until then the process neither
    /// parks nor ends on it.
    Kept {
        ending: Exit,
        kept: Box<(Owner<'s, 'a, 'm, P, D, T>, Blockers)>,
    },
}

/// Serves `owner`, the `Live` owner that [`bring_up`] returned with its tenure's coverage fencing installed.
/// Each turn reads `now()`, polls the owner at that time, runs `duties` on it at that time, the caller's per-turn
/// work such as the record view, and reads `stop` once. The tenure ends at the first turn whose `duties` call
/// returns an exit or whose state [`ended`] names one, the exit from [`ended`] taking precedence, or at the first
/// turn that reads `stop` set ([`Exit::Stopped`]). A turn in which the clock, the poll, the
/// duties, the record write or the exit reading unwinds ends it with [`Rerun::Unwound`], in a build whose panics
/// unwind. [`teardown`] follows every exit, with `patience_us` as its drain bound.
///
/// The caller owes four things `serve` cannot check. `now` returns microseconds, nondecreasing, on the one
/// timeline that [`bring_up`], `serve` and [`teardown`] share, the timeline of [`Owner::poll`]: the owner's
/// suspend-inclusive elapsed clock, on which a planned exit's deadline counts time the host spent suspended. A turn passes its one sample to the poll and the duties, so a decision the duties take in that turn
/// reads the turn's start time. `duties` runs on the owner's thread inside the turn, so it does bounded work that never blocks: a
/// record view enters as the result a store lane already holds. `duties` leaves the close to the teardown and ends
/// a tenure by returning an exit or through `stop`, except that a planned transfer's duties close the owner in their withdrawal turn; while
/// the submitted transfer is outstanding the loop polls the closed owner and reads `stop`, so the tenure ends at the
/// first exit the duties or [`ended`] return, or [`Exit::Stopped`] at a stop request.
/// `record` is written on the owner's thread too, so the caller passes a sink that never blocks, a bounded buffer
/// or a handoff it drains on another thread; a sink that blocks stalls the polls, the stop read and the teardown
/// for that write.
///
/// Once the recovery report's first-safe-hit span has closed, `serve` makes one attempt to write one
/// [`recovery_line`] to `record`, on the turn that closed the span even when that turn's duties unwound. A write
/// error is neither retried nor reported, so the sink may hold a partial line, and a tenure that ends before its
/// first safe hit writes no line.
pub fn serve<'s, 'a, 'm, P, D, T>(
    gate: &HostGate,
    mut owner: Owner<'s, 'a, 'm, P, D, T>,
    stop: &AtomicBool,
    mut now: impl FnMut() -> u64,
    mut duties: impl FnMut(&mut Owner<'s, 'a, 'm, P, D, T>, u64) -> Option<Exit>,
    record: &mut dyn std::io::Write,
    patience_us: u64,
) -> Served<'s, 'a, 'm, P, D, T>
where
    P: Platform,
    D: Disk,
    T: Datagrams<'a>,
{
    let mut recorded = false;
    // One unwind boundary holds every turn, so a turn that unwinds ends the loop, and a turn that completes
    // crosses no boundary of its own.
    let turns = contain(|| {
        loop {
            let at = now();
            owner.poll(at);
            let duty = duties(&mut owner, at);
            if !recorded {
                record_line(&owner, &mut recorded, record);
            }
            if let Some(exit) = ended(&owner).or(duty) {
                break exit;
            }
            if stop.load(Ordering::Acquire) {
                break Exit::Stopped;
            }
        }
    });
    let exit = turns.unwrap_or_else(|_| {
        // The turn that unwound takes the reading a completed turn takes: the line of a span its poll closed,
        // then the exits, whose first reading of a lost volume withdraws the storage's readiness.
        let _ = contain(|| {
            if !recorded {
                record_line(&owner, &mut recorded, record);
            }
            ended(&owner)
        });
        Exit::Rerun(Rerun::Unwound)
    });
    match teardown(gate, owner, now, patience_us) {
        Ok(shutdown) => Served::Ended {
            exit,
            shutdown: Box::new(shutdown),
        },
        Err(kept) => Served::Kept { ending: exit, kept },
    }
}

/// Writes `owner`'s [`recovery_line`] to `record` once the line exists. It sets `recorded` before the write, so a
/// write that unwinds is still the tenure's one attempt. It inlines into the serving loop, where a turn before the
/// first safe hit costs the one read [`recovery_line`] starts with.
#[inline(always)]
fn record_line<'a, P: Platform, D: Disk, T: Datagrams<'a>>(
    owner: &Owner<'_, 'a, '_, P, D, T>,
    recorded: &mut bool,
    record: &mut dyn std::io::Write,
) {
    if let Some(line) = recovery_line(owner) {
        *recorded = true;
        // The line is an operator record; a sink that refuses it changes no serving decision.
        let _ = writeln!(record, "{line}");
    }
}

/// The exit a serving turn shows, if any, from [`Owner::poisoned`], [`Owner::lost`], [`Owner::authority_state`]
/// and, for a withdrawn or closed authority, [`Owner::transfer`], [`Owner::has_successor`], [`Owner::authority_flip`],
/// [`Owner::authority_withdrawal`] and [`Owner::lapse_verified`]. The rows apply in order:
///
/// - an owner that an earlier unwound turn poisoned reruns ([`Rerun::Poisoned`]);
/// - a volume that lost its device, as a `ControllerEvent` leaves it at its next refused submit, reruns
///   ([`Rerun::ControllerEvent`]);
/// - a planned transfer the owner's driver has outstanding ([`Handoff::Outstanding`]) keeps the withdrawn tenure
///   polling with no exit, and an acknowledged one ([`Handoff::Committed`]) ends it [`Exit::Stopped`], ahead of the
///   successor row below, which its committed record raises;
/// - a withdrawn or closed authority one of whose causes named a later tenure of the shard ends [`Exit::Deposed`],
///   whatever its first cause was and ahead of a flip request it holds, so the exit carries no retirement request
///   (ROLE-BOUND). A later shard record, a store write refused for a later tenure and a page fence that is an
///   activated session each name one;
/// - a page fence that is no activated session names no tenure and leaves the rows below to the authority's other
///   causes. A tenure it withdrew requests no flip and reruns ([`Rerun::Withdrawn`]);
/// - otherwise a withdrawal that requested the flip parks as [`Exit::Retire`];
/// - a withdrawal under a recorded holder of another host (`Cause::RecordedHolder`) or with nobody holding
///   (`Cause::Unheld`) keeps the tenure withdrawn and polling while the authority is open, and a closed authority
///   under a recorded holder reruns ([`Rerun::RecordedHolder`]);
/// - a withdrawal over a lapsed deferral's unverified registrant (`Cause::Unverified`, LAPSE-UNVERIFIED) keeps the
///   tenure withdrawn and polling while the authority is open, until an owner poll reads a shard record naming the
///   tenure beside a volume record that enrolls every deferred pair or a Report that lists none of them
///   ([`Owner::lapse_verified`]); the tenure then reruns ([`Rerun::Withdrawn`]), as it does once closed. The poll's
///   `Retire` and `Deposed` verdicts end it through the rows above;
/// - a withdrawal for a planned exit (`Cause::Planned`), open or closed, reruns ([`Rerun::Planned`]);
/// - every other withdrawal, and a closed authority with no cause, reruns ([`Rerun::Withdrawn`]). A deposing
///   command status is one: the Report that judges its holder is the next incarnation's first.
///
/// `ended` inlines into its caller, so a serving turn that shows no exit reads the owner's poisoned, lost and
/// authority state in place; the rows of a withdrawn or closed authority stay out of line.
#[inline(always)]
pub fn ended<'a, P: Platform, D: Disk, T: Datagrams<'a>>(
    owner: &Owner<'_, 'a, '_, P, D, T>,
) -> Option<Exit> {
    if owner.poisoned() {
        return Some(Exit::Rerun(Rerun::Poisoned));
    }
    if owner.lost() {
        return Some(Exit::Rerun(Rerun::ControllerEvent));
    }
    match owner.authority_state() {
        State::PreBoundary | State::Recovering | State::Serving => None,
        State::Withdrawn => withdrawn(owner, true),
        State::Closed => withdrawn(owner, false),
    }
}

/// The rows of [`ended`] for an authority that withdrew: `open` while it is withdrawn, and false once it closed.
#[cold]
fn withdrawn<'a, P: Platform, D: Disk, T: Datagrams<'a>>(
    owner: &Owner<'_, 'a, '_, P, D, T>,
    open: bool,
) -> Option<Exit> {
    match owner.transfer() {
        Some(Handoff::Outstanding { .. }) => return None,
        Some(Handoff::Committed) => return Some(Exit::Stopped),
        None => {}
    }
    if owner.has_successor() {
        return Some(Exit::Deposed);
    }
    if let Some(target) = owner.authority_flip() {
        return Some(Exit::Retire(target));
    }
    match owner.authority_withdrawal() {
        Some(Cause::Unheld | Cause::RecordedHolder) if open => None,
        Some(Cause::Unverified) if open && !owner.lapse_verified() => None,
        Some(Cause::RecordedHolder) => Some(Exit::Rerun(Rerun::RecordedHolder)),
        Some(Cause::Planned) => Some(Exit::Rerun(Rerun::Planned)),
        _ => Some(Exit::Rerun(Rerun::Withdrawn)),
    }
}

/// Closes `owner` at `now()`, polls it until [`Owner::blockers`] reports nothing, and calls [`Owner::shutdown`],
/// which releases the driver only for an owner with no blocker and a quiesced volume. The polls end early in
/// three cases, each of which leaves the decision to that same check: the close, a clock read or a poll unwound,
/// or a clock read passed the close by more than `patience_us`, the caller's drain bound on the timeline of
/// [`serve`]. Each clock read gates only the poll that follows it, so the bound ends a drain only while `now()`
/// advances and each close and poll returns; `u64::MAX` drains without a bound. Elapsed time releases nothing:
/// an owner with a blocker left comes back with it in [`Teardown`]. [`Owner::shutdown`] makes the one driver
/// call this function leaves unguarded, the volume's release, and an unwind there propagates.
pub fn teardown<'s, 'a, 'm, P, D, T>(
    _gate: &HostGate,
    mut owner: Owner<'s, 'a, 'm, P, D, T>,
    mut now: impl FnMut() -> u64,
    patience_us: u64,
) -> Teardown<'s, 'a, 'm, P, D, T>
where
    P: Platform,
    D: Disk,
    T: Datagrams<'a>,
{
    let mut closed_at = 0;
    let mut drains = contain(|| {
        closed_at = now();
        owner.close(closed_at);
    })
    .is_ok();
    while drains && owner.blockers().is_some() {
        drains = contain(|| {
            let at = now();
            let waits = at.saturating_sub(closed_at) <= patience_us;
            if waits {
                owner.poll(at);
            }
            waits
        })
        .unwrap_or(false);
    }
    owner.shutdown()
}

/// The names of the recovery phases in a [`recovery_line`], in phase order.
const PHASES: [(&str, RecoveryPhase); RECOVERY_PHASES] = [
    ("initialization", RecoveryPhase::Initialization),
    ("adoption", RecoveryPhase::Adoption),
    ("replay", RecoveryPhase::Replay),
    ("first-safe-hit", RecoveryPhase::FirstSafeHit),
    ("retained-readiness", RecoveryPhase::RetainedReadiness),
    ("fill-readiness", RecoveryPhase::FillReadiness),
];

/// The recovery record line of `owner`'s tenure once its first-safe-hit span has closed, as the report stands at
/// this call:
///
/// ```text
/// recovery g <g> a <a> <phase> <start>..<end> operations <n> rows <n> ... installed <n> omitted <n>
/// failed-units <n> unread-units <n> suffix-damage <n> suffix-tails <n> suffix-dropped <n> suffix-unread <n>
/// slot-superseded <n> slot-withheld <n>
/// ```
///
/// on one line. `(g, a)` is the tenure. The phases follow in the order initialization, adoption, replay,
/// first-safe-hit, retained-readiness, fill-readiness, each with its span and its own counts. A span's ticks are
/// the `now()` values the owner's polls took, on the caller's timeline, and `-` stands for a tick the report does
/// not hold at this call: a phase still open then, such as a fill readiness that follows the first hit, prints
/// `-`. The warm load's counts by cause end the line.
///
/// `recovery_line` inlines into its caller as the read of the span's end; the line is formatted out of line.
#[inline(always)]
pub fn recovery_line<'a, P: Platform, D: Disk, T: Datagrams<'a>>(
    owner: &Owner<'_, 'a, '_, P, D, T>,
) -> Option<String> {
    // Nothing else uses this report value, which lets the compiler reduce the read to the one field's load, so
    // a call before the first safe hit copies no report.
    owner
        .recovery_report()
        .phase(RecoveryPhase::FirstSafeHit)
        .end?;
    Some(line_of(owner))
}

/// The line [`recovery_line`] returns for a tenure whose first-safe-hit span has closed, from the report as it
/// stands at this call.
#[cold]
fn line_of<'a, P: Platform, D: Disk, T: Datagrams<'a>>(
    owner: &Owner<'_, 'a, '_, P, D, T>,
) -> String {
    let report = owner.recovery_report();
    let (generation, epoch) = owner.authority_report().tenure;
    // One allocation holds the line: its labels take about 360 bytes, and its 36 numbers the rest.
    let mut line = String::with_capacity(1024);
    let _ = write!(line, "recovery g {} a {}", generation.get(), epoch.get());
    let at = |tick: Option<u64>| tick.map_or_else(|| "-".to_owned(), |tick| tick.to_string());
    for (name, phase) in PHASES {
        let span = report.phase(phase);
        let _ = write!(
            line,
            " {name} {}..{} operations {} rows {}",
            at(span.start),
            at(span.end),
            span.operations,
            span.rows
        );
    }
    let warm = report.warm;
    let _ = write!(
        line,
        " installed {} omitted {} failed-units {} unread-units {} suffix-damage {} suffix-tails {} \
         suffix-dropped {} suffix-unread {} slot-superseded {} slot-withheld {}",
        warm.installed,
        warm.omitted,
        warm.failed_units,
        warm.unread_units,
        warm.suffix_damage,
        warm.suffix_tails,
        warm.suffix_dropped,
        warm.suffix_unread,
        warm.slot_superseded,
        warm.slot_withheld
    );
    line
}

/// Holds a process with no tenure while it parks in `waiting`: the role the records name for this host when the
/// park begins, which is `Restart` after a tenure or an acknowledged bump or takeover of this host, `Fresh` after a
/// fresh refusal before its bump, and `Retired` for a retired volume. Once per view period it calls `period`, which
/// returns once the period passed, reads `stop`, and rereads its role with [`role`](super::recover::role). A read
/// of `waiting` or of a retired role keeps the park. A restart or fresh role other than `waiting` ends it with
/// [`Rerun::RoleChanged`], and so does every standby or unnamed role: the next incarnation's recovery returns
/// [`Recovery::Waits`](super::recover::Recovery::Waits) and its caller runs
/// [`stand_by`](super::recover::stand_by), which holds the work of those two roles. A set `stop` ends the park
/// with [`Exit::Stopped`].
///
/// If a role read fails and the client remains usable, the park waits until the next period to retry. A failed
/// role read on a withdrawn client ends the park with [`Rerun::Records`], so the next incarnation reads the role
/// through a client opened from the durable watermark. The park issues only role reads.
pub fn wait<S: Store, L: WatermarkLog>(
    gate: &HostGate,
    waiting: Role,
    (shard, holder): (Shard, &Holder),
    client: &mut Client<S, L>,
    stop: &AtomicBool,
    period: impl FnMut(),
) -> Exit {
    let parked = |read: Surveyed, _: &mut Client<S, L>| match read {
        Ok((Role::Standby { .. } | Role::Unnamed, ..)) => {
            Some(Err(Exit::Rerun(Rerun::RoleChanged)))
        }
        Ok((read @ (Role::Restart | Role::Fresh), ..)) if read != waiting => {
            Some(Err(Exit::Rerun(Rerun::RoleChanged)))
        }
        _ => None::<Result<std::convert::Infallible, Exit>>,
    };
    match wait_with(gate, (shard, holder), client, stop, period, parked) {
        Err(exit) => exit,
        Ok(never) => match never {},
    }
}

/// What one view period's role read returned: the role, and the volume record and the shard record of that read.
pub type Surveyed = Result<(Role, VolumeRecord, ShardRecord), StoreError>;

/// [`wait`] and [`stand_by`](super::recover::stand_by) share this loop. If `stop` is set, the loop returns
/// [`Exit::Stopped`] before reading the role. The loop returns the first value `act` produces. If the role read
/// fails and `client.withdrawn()` is true, `wait_with` returns `Err(Exit::Rerun(Rerun::Records))` before calling
/// `act`. For all other role reads, `act` decides whether to end the wait and handles enrollment for the unnamed
/// host or takeover for the standby.
pub fn wait_with<S: Store, L: WatermarkLog, X>(
    _gate: &HostGate,
    (shard, holder): (Shard, &Holder),
    client: &mut Client<S, L>,
    stop: &AtomicBool,
    mut period: impl FnMut(),
    mut act: impl FnMut(Surveyed, &mut Client<S, L>) -> Option<Result<X, Exit>>,
) -> Result<X, Exit> {
    loop {
        period();
        if stop.load(Ordering::Acquire) {
            return Err(Exit::Stopped);
        }
        let read = survey(client, shard, holder);
        if read.is_err() && client.withdrawn() {
            return Err(Exit::Rerun(Rerun::Records));
        }
        if let Some(acted) = act(read, client) {
            return acted;
        }
    }
}

#[cfg(test)]
#[path = "serve_loop_tests.rs"]
pub(super) mod loop_tests;
#[cfg(test)]
#[path = "serve_tests.rs"]
pub(super) mod tests;
