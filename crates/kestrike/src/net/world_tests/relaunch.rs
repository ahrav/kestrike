//! The mixed world's owner relaunch: a scripted history closes its owner,
//! the closed incarnation dies and the next one starts over the same media,
//! all in one selected event. [`Mixed::relaunch`] starts it cold;
//! [`Mixed::relaunch_warm`] attaches it warm from the checkpoint a shard
//! record names, under that record's session, and returns the warm load's
//! outcome.
//!
//! Two warm loads run with no owner, each through [`loaded_over`] on a
//! storage and a buffer arena of its own. [`Mixed::relaunch_warm_after`]
//! takes an optional one as a tenure between the incarnations, over the
//! run's media: it runs after the closed incarnation's boundary judgment
//! and the release of its bundle and before the next incarnation attaches,
//! inside the one relaunch the lifecycle counts. Its writes stay on the
//! media the next incarnation loads, and its device joins no audit of the
//! run, which judges each incarnation's own device. [`Mixed::probe_warm`]
//! loads over a copy of the closed incarnation's media, so the load
//! changes neither the run's media nor its lifecycle.
//!
//! Each incarnation attaches its own storage, so one volume runs per storage
//! over that storage's life, and every incarnation's device reports the
//! same attach facts over one media handle. A relaunch runs only once the
//! owner closed and its device holds no pending command: the dead queue
//! then drains at once, so its disposition frees writable attach before the
//! next volume reads the media, and the dead bundle is released before the
//! next incarnation starts. A relaunch is a stopped boundary: the world
//! judges the closed incarnation's bindings and raw media against the
//! registry, then kills it. Once its audit is judged, the dead
//! incarnation's links drop every datagram in flight and return every
//! transmit reference they hold, and its clients and custody leave with its
//! bundle, so every later custody check reads only the living incarnation.
//! The world's content registry and first-failure cell stay as they stand,
//! and the teardown observer judges the living incarnation's media.
//!
//! The relaunch launches the next incarnation's links on the run's chooser
//! after the dead links' last draw, and advances their clocks to the
//! relaunch's link turn. [`unopened`] builds the next incarnation's scene
//! with `spare` set to `None` and the blank GET header in each template, so
//! a history displaces client 0 or reads a learned template only before its
//! relaunch.

use std::cell::RefCell;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;

use crate::failover::records::{Layout, ShardRecord};
use crate::storage::device::sim::Media;
use crate::storage::page_coverage::Coverage;
use crate::storage::warm_sim::{LoadClock, warm_device};
use crate::storage::{MetadataOutcome, Session, Storage};

use crate::storage::owner_fixture::{
    Device, QuiesceMode, TestPlatform, arena, set_clock, storage_warm_as,
};

use super::super::audit::Verdict;
use super::super::owner::OwnerConfig;
use super::super::put_tests::{SOURCES, Scene, unopened};
use super::super::restart::{Disposition, Fresh, Lifecycle, incarnate};
use super::{Geometry, LINK_TURN_US, Mixed};

/// What names a warm load: the shard record whose checkpoint it loads, the
/// records layout and the successor's session.
pub(super) type Named<'r> = (&'r ShardRecord, Layout, Session);

/// The living incarnation's scene, which a relaunch replaces.
pub(super) struct Living<'w, 's, 'm>(pub(super) &'w mut Option<Scene<'s, 'm>>);

impl<'s, 'm> Deref for Living<'_, 's, 'm> {
    type Target = Scene<'s, 'm>;

    /// # Panics
    ///
    /// When no incarnation lives, which holds only inside a relaunch's
    /// `relaunch_from`, from the take of the closed scene until the next
    /// incarnation's start, the tenure between the incarnations included.
    /// `DerefMut` panics under the same condition.
    fn deref(&self) -> &Scene<'s, 'm> {
        self.0.as_ref().expect("an incarnation lives")
    }
}

impl DerefMut for Living<'_, '_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().expect("an incarnation lives")
    }
}

/// What a mixed run's relaunches draw on: the lifecycle over the run's
/// media, each later incarnation's resources in launch order, the owner
/// configuration every incarnation starts under, and the audit verdicts of
/// the incarnations relaunches released, folded in order with
/// [`Verdict::then`] from `Pass`.
pub(super) struct Relaunches<'s, 'm> {
    pub(super) life: Lifecycle<'s, 'm>,
    pub(super) fresh: Vec<Fresh<'s, 'm>>,
    pub(super) config: OwnerConfig,
    pub(super) audit: Verdict,
}

/// Starts an incarnation's owner over `device` under `config` and its two
/// clients, each of which sends its HELLO at its next poll from `now`, so
/// the turn controller carries every session open. The storage clock
/// starts at `tick` and both links at `now`, so the first frames' link
/// delays count from the relaunch.
pub(super) fn started<'s, 'm>(
    device: Device<'s, 'm>,
    fresh: Fresh<'s, 'm>,
    config: OwnerConfig,
    now: u64,
    tick: u64,
) -> Scene<'s, 'm> {
    let (storage, buffers, sourcing) = (fresh.storage, fresh.buffers, fresh.sourcing);
    let turn = now / LINK_TURN_US;
    set_clock(storage, &[Some(tick)]);
    for net in &fresh.links.nets {
        net.borrow_mut().advance(turn);
    }
    let (owner, nets, clients) = incarnate(device, fresh, (config, SOURCES));
    let mut scene = unopened(owner, nets, storage, clients, sourcing, turn);
    scene.buffers = Some(buffers);
    for client in &mut scene.clients {
        client.session(now);
    }
    scene
}

impl Mixed<'_, '_, '_> {
    /// The owner closed, its device holds no pending command and a later
    /// incarnation's resources remain.
    pub(super) fn relaunchable(&self) -> bool {
        self.closed && self.scene.control.pending() == 0 && !self.relaunches.fresh.is_empty()
    }

    /// Kills the closed owner and starts the next incarnation over the
    /// shared media at `now`, after judging the closed incarnation's
    /// bindings, media and storage tables at a stopped boundary and reading
    /// its datagram accounts, whose failure the turn's emission records
    /// after the conservation rule. The world's workload state
    /// for the owner starts over beside the new incarnation, and its
    /// counters, logs, lenses and registry stay. The dead incarnation's
    /// link and device audits join the run's audit before its bundle is
    /// released.
    ///
    /// # Panics
    ///
    /// Unless [`relaunchable`](Self::relaunchable) holds. The plan's
    /// lifecycle bounds admit the death and relaunch that follow.
    pub(super) fn relaunch(&mut self, now: u64) {
        self.relaunch_from(now, None, |_| ());
    }

    /// [`relaunch`](Self::relaunch) whose next incarnation attaches warm
    /// from the checkpoint `named` names, through [`warm_device`], and
    /// returns the warm load's outcome, which the installed owner reads
    /// before any later poll. The successor storage's clock reads the
    /// relaunch's tick at the attach. The load checks restored entries
    /// against `coverage`, the fenced coverage of the closed tenure's stored
    /// pages, and against an empty fenced coverage under `None`.
    ///
    /// # Panics
    ///
    /// As [`relaunch`](Self::relaunch); unless the plan's geometry is
    /// `Geometry::Warm`; when `warm_device` returns `None`, which builds no
    /// device; and at the successor owner's start when the load built a
    /// device and ended in an outcome that closes the storage's admission,
    /// as a refused load does. [`probe_warm`](Self::probe_warm) reads a
    /// load that must be refused. A load still initializing when
    /// `warm_device` returns starts its owner, and `relaunch_warm` returns
    /// the outcome the owner then reads, which is other than `Open`.
    pub(super) fn relaunch_warm(
        &mut self,
        now: u64,
        named: Named<'_>,
        coverage: Option<&Coverage>,
    ) -> MetadataOutcome {
        assert!(
            self.plan.geometry == super::Geometry::Warm,
            "a warm relaunch runs under a plan declared with warm(..)"
        );
        self.relaunch_from(now, Some((named, None, coverage)), |_| ());
        self.scene.owner.volume_metadata_outcome()
    }

    /// [`relaunch_warm`](Self::relaunch_warm) with a tenure between the two
    /// incarnations: `between` runs over the run's media once the closed
    /// incarnation is judged and its bundle released, and before the next
    /// incarnation's warm load, so each boundary judges one incarnation's
    /// bindings against media only that incarnation and its predecessors
    /// wrote. The run's lifecycle counts one relaunch. The next
    /// incarnation's load samples `clock`: the volume reads its physical
    /// reading, and the successor storage reads its monotonic sample at the
    /// attach and on every later owner turn, until a step sets the
    /// history's clock or another relaunch clears it.
    ///
    /// # Panics
    ///
    /// As [`relaunch_warm`](Self::relaunch_warm), and when `clock`'s
    /// monotonic sample lies before the relaunch's tick.
    pub(super) fn relaunch_warm_after<R>(
        &mut self,
        now: u64,
        (named, clock): (Named<'_>, LoadClock),
        between: impl FnOnce(&Media) -> R,
    ) -> (MetadataOutcome, R) {
        assert!(
            self.plan.geometry == super::Geometry::Warm,
            "a warm relaunch runs under a plan declared with warm(..)"
        );
        let mut ran = None;
        self.relaunch_from(now, Some((named, Some(clock), None)), |media| {
            ran = Some(between(media));
        });
        (
            self.scene.owner.volume_metadata_outcome(),
            ran.expect("the relaunch ran the tenure between its incarnations"),
        )
    }

    /// Kills the closed incarnation and starts the next one, cold, or warm
    /// when `warm` names the record, layout and session of a warm attach,
    /// with its load clock and the coverage its load checks against.
    /// `between` runs over the run's media after the dead bundle's release
    /// and before the next attach. The history's clock holds a warm load
    /// clock's monotonic sample from the relaunch on, and is clear after
    /// any other relaunch.
    fn relaunch_from(
        &mut self,
        now: u64,
        warm: Option<(Named<'_>, Option<LoadClock>, Option<&Coverage>)>,
        between: impl FnOnce(&Media),
    ) {
        assert!(
            self.relaunchable(),
            "a relaunch follows a close whose device queue emptied"
        );
        self.judge_boundary();
        // `World::emit` records the closing incarnation's accounts failure
        // after the conservation rule.
        if let Err(failure) = self.scene.accounts() {
            self.closed_accounts.get_or_insert(failure);
        }
        let scene = self.scene.0.take().expect("an incarnation lives");
        let life = &mut self.relaunches.life;
        let Ok(()) = life.die(scene) else {
            panic!("the lifecycle holds the one dead bundle a relaunch holds");
        };
        self.held.clear();
        self.local = super::Local::Unfilled;
        self.reader = None;
        self.acquired = false;
        self.expired = false;
        self.evicted = false;
        self.local_media = None;
        self.pressure = super::Pressure::Idle;
        self.pressure_media.clear();
        self.owner_due = now;
        self.service_due = now;
        self.gets = [None, None];
        self.overlapping_get = None;
        self.polled = [false; 2];
        self.put = None;
        self.closed = false;
        self.updates.clear();
        self.emitted.relaunched();
        self.history.relaunched();
        let clock = warm.as_ref().and_then(|(_, clock, _)| *clock);
        let tick = clock.map_or(super::ticks(now), |clock| clock.monotonic_ns);
        assert!(
            tick >= super::ticks(now),
            "a load's monotonic sample lies at or after the world's tick"
        );
        self.history.clock = clock.map(|clock| clock.monotonic_ns);
        self.attached = Some(tick);
        let life = &mut self.relaunches.life;
        let dead = life.dead().len() - 1;
        assert_eq!(
            life.dead()[dead].control().pending(),
            0,
            "a relaunch runs only once the dead queue holds no pending command"
        );
        let disposed = life.dead_mut(dead).dispose(QuiesceMode::AllReturned);
        assert_eq!(
            disposed,
            Ok(Disposition::AllReturned),
            "the dead queue drained"
        );
        let bundle = &life.dead()[dead];
        let device = device_index(bundle.incarnation());
        let verdict = super::judged(&bundle.nets, bundle.control(), device, self.plan.declared);
        self.relaunches.audit = self.relaunches.audit.then(verdict);
        for net in &bundle.nets {
            let mut net = net.borrow_mut();
            net.clear(0);
            net.clear(1);
            net.release_tx();
        }
        life.release(dead)
            .expect("a drained bundle frees writable attach");
        let fresh = self.relaunches.fresh.remove(0);
        for net in &fresh.links.nets {
            net.borrow_mut().launch();
        }
        let config = self.relaunches.config;
        let Ok(scene) = life.relaunch_over(fresh, |media, fresh| {
            between(media);
            let device = match warm {
                Some((named, clock, coverage)) => {
                    set_clock(fresh.storage, &[Some(tick)]);
                    warm_device(fresh.storage, fresh.buffers, media, named, clock, coverage)
                        .expect("a warm relaunch's record names a checkpoint its attach admits")
                }
                None => Device::over(fresh.storage, fresh.buffers, Rc::clone(media)),
            };
            started(device, fresh, config, now, tick)
        }) else {
            panic!("the lifecycle admits every relaunch the plan's resources hold");
        };
        *self.scene.0 = Some(scene);
        super::wire(&self.plan, &self.scene.nets);
        self.observer.follow(self.scene.media());
    }

    pub(super) fn living_device(&self) -> u16 {
        device_index(self.relaunches.life.incarnation())
    }

    /// The probe loads the checkpoint `named` names through
    /// [`warm_device`]. The probe uses private storage, a
    /// private buffer arena, and a copy of the closed incarnation's media,
    /// so the world's media, incarnations and relaunches keep their state
    /// after a refused load. For `MetadataOutcome::Open` the probe returns
    /// `Some(Ok(open(&storage)))`, for each other outcome
    /// `Some(Err(outcome))`, and `None` when `warm_device` builds no device.
    ///
    /// # Panics
    ///
    /// Unless [`relaunchable`](Self::relaunchable) holds, so no command
    /// the closed incarnation's device accepted changes the media after
    /// the copy, which holds the bytes that landed; and unless the plan's
    /// geometry is `Geometry::Warm`.
    pub(super) fn probe_warm<R>(
        &self,
        named: Named<'_>,
        open: impl FnOnce(&Storage<TestPlatform>) -> R,
    ) -> Option<Result<R, MetadataOutcome>> {
        assert!(
            self.relaunchable(),
            "a probe follows a close whose device queue emptied"
        );
        assert!(
            self.plan.geometry == super::Geometry::Warm,
            "a warm probe runs under a plan declared with warm(..)"
        );
        let media = self.scene.control.shared_media().borrow().clone();
        let media = Rc::new(RefCell::new(media));
        loaded_over(&media, named, None, |storage, _| open(storage))
    }
}

/// Loads `named` warm under `clock` through [`warm_device`] over `media`, on
/// a storage of the warm geometry and a buffer arena built for the load, and
/// runs `open` over them after an `Open` load. The storage's index routes
/// keys under `PRIVATE_PAIR`, so the load's routing is the same in every
/// process. Returns `Some(Ok(open(..)))` after an `Open` load,
/// `Some(Err(outcome))` after any other, and `None` when `warm_device`
/// builds no device.
pub(super) fn loaded_over<R>(
    media: &Media,
    named: Named<'_>,
    clock: Option<LoadClock>,
    open: impl for<'s> FnOnce(&'s Storage<TestPlatform>, &mut Device<'s, '_>) -> R,
) -> Option<Result<R, MetadataOutcome>> {
    let (shape, chunk_len) = Geometry::Warm.shape();
    let mut storage = storage_warm_as(shape, chunk_len);
    let (k0, k1) = PRIVATE_PAIR;
    storage.install_hasher(crate::index::KeyHasher::with_key_pair(k0, k1));
    let buffers = arena(8);
    let mut device = warm_device(&storage, &buffers, media, named, clock, None)?;
    let outcome = device.volume.metadata_outcome();
    if outcome != MetadataOutcome::Open {
        return Some(Err(outcome));
    }
    Some(Ok(open(&storage, &mut device)))
}

/// The index key pair of the storage an owner-less load runs on.
const PRIVATE_PAIR: (u64, u64) = (0x6c6f_6164_6564_5f6f, 0x7665_725f_7061_6972);

/// An incarnation's lifecycle index as the device index of its audit
/// records.
fn device_index(incarnation: u32) -> u16 {
    u16::try_from(incarnation).expect("a run's incarnations fit a device index")
}
