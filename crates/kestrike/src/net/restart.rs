//! Process death and relaunch over shared media, for the composed world. Death is its own action at a stopped boundary, apart from device
//! and link death: the owner is extracted between turns with its volume
//! open, its device queue intact and every custody it holds, and the media
//! bytes stay as they stand. The device queue, custody set, device control,
//! transport, clients and links move to a [`Dead`] bundle. The arenas and
//! storages the bundle borrows outlive it, so its control drains or drops
//! before them.
//!
//! A dead bundle keeps its custody until it is released, which needs a
//! freeing disposition. The disposition is recorded once from what the
//! device did: once its queue drains with no command pending it records
//! `AllReturned`, and with no scripted command drop every issued write has
//! landed; a stop that reports `Quiesced` with
//! both queues empty records `Reset`; a halted queue records `Unproven` and
//! keeps its charge; a stop reporting a failure records `Failed`. A writable
//! relaunch over the same media waits for every dead bundle to record
//! `AllReturned` or `Reset`. A relaunch starts a new storage and boot nonce
//! over the shared media while the old record bytes stay on the media.
//! [`Lifecycle::relaunch`] attaches it cold under a new session, so its
//! frontier starts empty; [`Lifecycle::relaunch_over`] leaves the attach,
//! and so the frontier, to its caller.
//!
//! Incarnation slots, restarts and dead bundles are bounded by a
//! [`Manifest`]; a death or relaunch past a bound is refused before it
//! changes the lifecycle, returning what it was given. An incarnation holds its slot while
//! it lives and, once dead, until its bundle is released, which only a
//! freeing disposition allows, so an unproven stop consumes its slot. A
//! relaunch refused for want of a slot no release can free records the run
//! unsuccessful in the lifecycle's first-failure cell.

use std::cell::RefCell;
use std::rc::Rc;

use crate::storage::QuiesceProgress;
use crate::storage::device::sim::{Media, QuiesceMode};
use crate::storage::owner_fixture::{Device, SimControl, SimDisk, TestPlatform};
use crate::storage::{BufferArena, EngineBudget, Storage};

use super::client::Client;
use super::link::{LinkEnd, Net};
use super::observe::{Failure, FirstFailure};
use super::owner::{Extracted, OwnerConfig};
use super::owner_tests::{Mux, OWNER, PRINCIPALS, TestOwner, sourced_client};
use super::packet::PacketPool;
use super::put_tests::{Scene, assemble, start_on};
use super::witness::{View, Witness};

/// The bounds of a run's incarnations. The slot bound refuses a relaunch
/// only when `slots` is at most `bundles`, since `die` keeps every dead
/// bundle count below `bundles + 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Manifest {
    /// Incarnations holding a slot at once: the living one and every dead
    /// bundle not yet released.
    pub(crate) slots: usize,
    pub(crate) restarts: usize,
    /// Dead bundles held at once.
    pub(crate) bundles: usize,
}

pub(crate) const MANIFEST: Manifest = Manifest {
    slots: 3,
    restarts: 2,
    bundles: 2,
};

/// Ticks a drain gives the dead queue before it records the queue halted.
const DRAIN_TICKS: usize = 10_000;

/// How a dead incarnation's device queue ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    /// The queue drained: no command stays pending.
    AllReturned,
    /// A stop proved both queues empty.
    Reset,
    /// The queue halted with work outstanding; its charge stays.
    Unproven,
    /// The stop failed with this code.
    Failed(Option<i32>),
}

impl Disposition {
    /// Whether a writable relaunch over the same media may attach.
    pub(crate) fn frees(self) -> bool {
        matches!(self, Self::AllReturned | Self::Reset)
    }
}

/// Why a death, a disposition, a release or a relaunch was refused; the
/// lifecycle and the bundle stand as they were.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    /// Every dead-bundle place is taken.
    Bundles,
    Restarts,
    /// No incarnation slot is free: the run is incomplete.
    Slots,
    /// A dead bundle has no disposition that frees writable attach.
    Withheld,
    /// The bundle already recorded this disposition.
    Disposed(Disposition),
    /// An incarnation lives: only a death frees the media for a relaunch.
    Living,
}

/// A dead incarnation: the clients and links of its incarnation, whose late
/// traffic lands in the dead transport, its owner's custody, bundle and
/// transport, and the device control of its queue.
pub(crate) struct Dead<'s, 'm> {
    /// The lifecycle index of the incarnation that died; its volume ran at
    /// session `1 + incarnation`.
    incarnation: u32,
    /// The buffer arena the incarnation's volume attached with.
    buffers: &'m BufferArena<TestPlatform>,
    pub(crate) clients: [Client<'m, LinkEnd<'m>>; 2],
    pub(crate) nets: [Rc<RefCell<Net<'m>>>; 2],
    pub(crate) owner: Extracted<'s, 'm, 'm, TestPlatform, SimDisk, Mux<'m>>,
    disposition: Option<Disposition>,
    control: SimControl,
}

impl<'m> Dead<'_, 'm> {
    /// The lifecycle index of the incarnation that died.
    pub(crate) fn incarnation(&self) -> u32 {
        self.incarnation
    }

    pub(crate) fn buffers(&self) -> &'m BufferArena<TestPlatform> {
        self.buffers
    }

    /// The control of the bundle's own device queue.
    pub(crate) fn control(&self) -> &SimControl {
        &self.control
    }

    /// Whether the bundle's disposition frees writable attach and its slot.
    fn frees(&self) -> bool {
        self.disposition.is_some_and(Disposition::frees)
    }

    /// The disposition the bundle recorded, if any.
    pub(crate) fn disposition(&self) -> Option<Disposition> {
        self.disposition
    }

    /// Ends the dead queue under `mode` and records what the device did,
    /// once. `AllReturned` ticks the queue until no command is pending and
    /// records it then; a queue still pending after the drain's ticks
    /// records `Unproven`. The other modes make one stop attempt on the dead
    /// volume: a `Quiesced` stop with both queues empty records `Reset`, a
    /// failed stop `Failed`, and any other stop `Unproven`.
    ///
    /// # Errors
    ///
    /// `Disposed` when the bundle already recorded a disposition, which
    /// stays.
    pub(crate) fn dispose(&mut self, mode: QuiesceMode) -> Result<Disposition, Refused> {
        if let Some(disposition) = self.disposition {
            return Err(Refused::Disposed(disposition));
        }
        let disposition = if mode == QuiesceMode::AllReturned {
            for _ in 0..DRAIN_TICKS {
                if self.control.pending() == 0 {
                    break;
                }
                self.control.tick(64);
            }
            if self.control.pending() == 0 {
                Disposition::AllReturned
            } else {
                Disposition::Unproven
            }
        } else {
            self.control.set_quiesce(mode);
            match self.owner.bundle.volume.close() {
                QuiesceProgress::Quiesced(_) if self.control.outstanding() == 0 => {
                    Disposition::Reset
                }
                QuiesceProgress::Unproven {
                    code: Some(code), ..
                } => Disposition::Failed(Some(code)),
                _ if matches!(mode, QuiesceMode::Failed(_)) => Disposition::Failed(None),
                _ => Disposition::Unproven,
            }
        };
        self.disposition = Some(disposition);
        Ok(disposition)
    }
}

/// What a relaunch needs, built in the run's outer scope: the new storage,
/// its arenas and pools, the links and the clients' memory.
pub(crate) struct Fresh<'s, 'm> {
    pub(crate) storage: &'s Storage<TestPlatform>,
    pub(crate) buffers: &'m BufferArena<TestPlatform>,
    pub(crate) receive: &'m PacketPool<'m>,
    pub(crate) sourcing: &'m BufferArena<TestPlatform>,
    pub(crate) links: Links<'m>,
    /// The boot nonces of the owner and both clients, in that order.
    pub(crate) nonces: [[u8; 16]; 3],
}

/// One incarnation's links: each client's end, each owner end and the
/// networks, and the clients' memory.
pub(crate) struct Links<'m> {
    pub(crate) clients: [LinkEnd<'m>; 2],
    pub(crate) owners: [LinkEnd<'m>; 2],
    pub(crate) nets: [Rc<RefCell<Net<'m>>>; 2],
    pub(crate) pools: &'m [PacketPool<'m>; 2],
    pub(crate) releases: &'m [super::fetch::Releases; 2],
}

/// A nonce supplier handing out `nonce`.
fn fixed(nonce: [u8; 16]) -> impl FnOnce(&mut [u8; 16]) -> Result<(), super::auth::EntropyError> {
    move |bytes| {
        *bytes = nonce;
        Ok(())
    }
}

pub(crate) type Incarnation<'s, 'm> = (
    (TestOwner<'s, 'm, 'm>, SimControl),
    [Rc<RefCell<Net<'m>>>; 2],
    [Client<'m, LinkEnd<'m>>; 2],
);

/// The owner and clients one incarnation starts with: the owner over
/// `device` under `config`, serving both peers, and the two clients over
/// `fresh`'s links, client 0 holding `sources` source slots, every one
/// under `fresh`'s boot nonces. The links' networks come back beside them.
///
/// # Panics
///
/// When the owner does not start over `device`.
pub(crate) fn incarnate<'s, 'm>(
    device: Device<'s, 'm>,
    fresh: Fresh<'s, 'm>,
    (config, sources): (OwnerConfig, u32),
) -> Incarnation<'s, 'm> {
    let Links {
        clients: [end0, end1],
        owners,
        nets,
        pools,
        releases,
    } = fresh.links;
    let [owner, first, second] = fresh.nonces;
    let started = start_on(
        device,
        fresh.storage,
        fresh.receive,
        Vec::from(owners),
        (config, &PRINCIPALS),
        fixed(owner),
    );
    let Ok(owner) = started else {
        panic!("an incarnation's owner starts");
    };
    let budget = &mut EngineBudget::new(1 << 20);
    let sources = super::memory::sources(fresh.sourcing, sources, budget).unwrap();
    let clients = [
        sourced_client(0, &pools[0], &releases[0], end0, sources, fixed(first)),
        sourced_client(
            1,
            &pools[1],
            &releases[1],
            end1,
            Box::default(),
            fixed(second),
        ),
    ];
    (owner, nets, clients)
}

/// Starts an incarnation over `device` from `fresh`: an owner serving both
/// peers with PUT, and clients that open their sessions in order, starting
/// at turn `turn`.
fn launch<'s, 'm>(device: Device<'s, 'm>, fresh: Fresh<'s, 'm>, turn: u64) -> Scene<'s, 'm> {
    let (storage, sourcing) = (fresh.storage, fresh.sourcing);
    let (owner, nets, clients) = incarnate(device, fresh, (OWNER, 4));
    assemble(owner, nets, storage, clients, sourcing, turn)
}

/// A run's incarnations over one media handle.
pub(crate) struct Lifecycle<'s, 'm> {
    manifest: Manifest,
    media: Media,
    dead: Vec<Dead<'s, 'm>>,
    /// The incarnation the living owner belongs to, or the last to die,
    /// which is also how many relaunches ran.
    incarnation: u32,
    living: Option<&'m BufferArena<TestPlatform>>,
    first: FirstFailure,
    /// What clients observed, kept beside every incarnation.
    witness: Witness,
}

impl<'s, 'm> Lifecycle<'s, 'm> {
    /// The lifecycle of a run whose incarnation 0 lives over `media`,
    /// recording an incomplete run into `first`.
    pub(crate) fn new(
        manifest: Manifest,
        media: Media,
        buffers: &'m BufferArena<TestPlatform>,
        first: FirstFailure,
    ) -> Self {
        Self {
            manifest,
            media,
            dead: Vec::new(),
            incarnation: 0,
            living: Some(buffers),
            first,
            witness: Witness::default(),
        }
    }

    /// A read-only view of the run's witness.
    pub(crate) fn witness(&self) -> View<'_> {
        self.witness.view()
    }

    /// The run's witness, for the run's owner to record into.
    pub(super) fn witness_mut(&mut self) -> &mut Witness {
        &mut self.witness
    }

    /// The dead bundles, oldest first.
    pub(crate) fn dead(&self) -> &[Dead<'s, 'm>] {
        &self.dead
    }

    /// Dead bundle `at`, to dispose of or step; its custody stays in it.
    pub(crate) fn dead_mut(&mut self, at: usize) -> &mut Dead<'s, 'm> {
        &mut self.dead[at]
    }

    /// The incarnation that lives, or the last to die.
    pub(crate) fn incarnation(&self) -> u32 {
        self.incarnation
    }

    pub(crate) fn living(&self) -> Option<&'m BufferArena<TestPlatform>> {
        self.living
    }

    /// Kills `scene`'s owner at a stopped boundary: its bundle, transport,
    /// custody, device control, clients and links move to a dead bundle.
    ///
    /// # Errors
    ///
    /// `Bundles` when every dead-bundle place is taken; the scene comes back
    /// unchanged.
    ///
    /// # Panics
    ///
    /// When no incarnation lives, since only the living incarnation's scene
    /// can die, or when a turn unwound and left the scene's owner armed.
    pub(crate) fn die(
        &mut self,
        scene: Scene<'s, 'm>,
    ) -> Result<(), (Refused, Box<Scene<'s, 'm>>)> {
        let Some(buffers) = self.living else {
            panic!("only the living incarnation dies");
        };
        if self.dead.len() == self.manifest.bundles {
            return Err((Refused::Bundles, Box::new(scene)));
        }
        let Scene {
            owner,
            control,
            nets,
            clients,
            ..
        } = scene;
        let Ok(owner) = owner.extract().map_err(drop) else {
            panic!("a scene's owner is extracted between turns only");
        };
        self.dead.push(Dead {
            incarnation: self.incarnation,
            buffers,
            clients,
            nets,
            owner,
            disposition: None,
            control,
        });
        self.living = None;
        Ok(())
    }

    /// Releases dead bundle `at`, dropping its custody and freeing its slot.
    ///
    /// # Errors
    ///
    /// `Withheld` unless its disposition frees writable attach; the bundle
    /// stays.
    pub(crate) fn release(&mut self, at: usize) -> Result<(), Refused> {
        if !self.dead[at].frees() {
            return Err(Refused::Withheld);
        }
        drop(self.dead.remove(at));
        Ok(())
    }

    /// Whether a relaunch would be admitted now.
    ///
    /// # Errors
    ///
    /// `Living` while an incarnation lives, `Restarts` past the restart
    /// bound, `Slots` when the dead bundles leave no slot for the
    /// incarnation the relaunch starts, and `Withheld` when a dead bundle's
    /// disposition does not free writable attach.
    pub(crate) fn relaunch_ready(&self) -> Result<(), Refused> {
        if self.living.is_some() {
            return Err(Refused::Living);
        }
        if self.incarnation as usize >= self.manifest.restarts {
            return Err(Refused::Restarts);
        }
        if self.dead.len() + 1 > self.manifest.slots {
            return Err(Refused::Slots);
        }
        if !self.dead.iter().all(Dead::frees) {
            return Err(Refused::Withheld);
        }
        Ok(())
    }

    /// Starts the next incarnation over the shared media from `fresh`: a
    /// new storage, session and boot nonce, an empty frontier, and fresh
    /// clients that open their sessions in order, starting at turn `turn`.
    ///
    /// # Errors
    ///
    /// As [`relaunch_ready`](Self::relaunch_ready); `fresh` comes back and
    /// nothing starts. A `Slots` refusal that no release can lift, every
    /// dead bundle holding its slot for good under a disposition that
    /// withholds attach, also records the run unsuccessful.
    pub(crate) fn relaunch(
        &mut self,
        fresh: Fresh<'s, 'm>,
        turn: u64,
    ) -> Result<Scene<'s, 'm>, (Refused, Box<Fresh<'s, 'm>>)> {
        self.relaunch_over(fresh, |media, fresh| {
            let device = Device::over(fresh.storage, fresh.buffers, Rc::clone(media));
            launch(device, fresh, turn)
        })
    }

    /// [`relaunch`](Self::relaunch) whose next incarnation `start` builds,
    /// attaching its device itself over the run's one shared media, cold or
    /// warm, so `start` decides what the successor's frontier holds.
    ///
    /// # Errors
    ///
    /// As [`relaunch`](Self::relaunch).
    pub(crate) fn relaunch_over(
        &mut self,
        fresh: Fresh<'s, 'm>,
        start: impl FnOnce(&Media, Fresh<'s, 'm>) -> Scene<'s, 'm>,
    ) -> Result<Scene<'s, 'm>, (Refused, Box<Fresh<'s, 'm>>)> {
        if let Err(refused) = self.relaunch_ready() {
            let stuck = |dead: &Dead<'_, '_>| dead.disposition.is_some_and(|d| !d.frees());
            if refused == Refused::Slots && self.dead.iter().all(stuck) {
                self.first.record(Failure::Unsuccessful(INCOMPLETE));
            }
            return Err((refused, Box::new(fresh)));
        }
        self.incarnation += 1;
        self.living = Some(fresh.buffers);
        Ok(start(&self.media, fresh))
    }
}

/// The failure a relaunch refused for want of a slot no release can free
/// records.
pub(crate) const INCOMPLETE: &str = "no incarnation slot is free: the run is incomplete";

/// A run's living scene, its lifecycle, what its next incarnations need,
/// in launch order, and the run's first-failure cell.
pub(crate) struct Run<'s, 'm> {
    pub(crate) scene: Scene<'s, 'm>,
    pub(crate) life: Lifecycle<'s, 'm>,
    pub(crate) fresh: Vec<Fresh<'s, 'm>>,
    pub(crate) first: FirstFailure,
}

/// Incarnations a run builds resources for: the first and two relaunches.
const INCARNATIONS: usize = 3;

/// Runs `body` over incarnation 0, a scene whose owner publishes key 1
/// over fresh shared media, with the run's lifecycle and the outer-scope
/// resources of incarnations 1 and 2. Every boot nonce is fixed by the
/// incarnation and actor.
pub(crate) fn restart_scene(manifest: Manifest, body: impl FnOnce(Run<'_, '_>)) {
    restart_scene_with(manifest, INCARNATIONS, body);
}

/// [`restart_scene`] with resources for `incarnations` incarnations, the
/// first included.
pub(crate) fn restart_scene_with(
    manifest: Manifest,
    incarnations: usize,
    body: impl FnOnce(Run<'_, '_>),
) {
    restart_scene_keyed(manifest, (incarnations, None), body);
}

/// [`restart_scene_with`], each incarnation's index hashing under the fixed
/// key pair `keys` when one is given, so binding identities repeat between
/// runs.
pub(crate) fn restart_scene_keyed(
    manifest: Manifest,
    (incarnations, keys): (usize, Option<(u64, u64)>),
    body: impl FnOnce(Run<'_, '_>),
) {
    use super::fetch::Releases;
    use super::link::{Faults, network};
    use super::owner_tests::{key, payload};
    use crate::storage::owner_fixture::{MEDIA, arena, publish, storage};

    let media = crate::storage::device::sim::media(MEDIA);
    let storages: Vec<_> = (0..incarnations)
        .map(|_| {
            let mut storage = storage(8);
            if let Some((k0, k1)) = keys {
                storage.install_hasher(crate::index::KeyHasher::with_key_pair(k0, k1));
            }
            storage
        })
        .collect();
    let buffers: Vec<_> = (0..incarnations).map(|_| arena(8)).collect();
    let sourcing: Vec<_> = (0..incarnations).map(|_| arena(4)).collect();
    let packets: Vec<_> = (0..3 * incarnations)
        .map(|_| super::packet::test_arena(32, 16384))
        .collect();
    let view = |arena| PacketPool::new(arena, crate::storage::PoolKind::PacketReceive, 8).unwrap();
    let receive: Vec<_> = (0..incarnations).map(|n| view(&packets[3 * n])).collect();
    let pools: Vec<[PacketPool<'_>; 2]> = (0..incarnations)
        .map(|n| [view(&packets[3 * n + 1]), view(&packets[3 * n + 2])])
        .collect();
    let releases: Vec<[Releases; 2]> = (0..incarnations)
        .map(|_| [0; 2].map(|_| Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap()))
        .collect();
    let mut fresh: Vec<Fresh<'_, '_>> = (0..incarnations)
        .map(|n| {
            let clean = [Faults::default(); 2];
            let seed = 102 + 2 * n as u64;
            let (first, second) = (
                network(64, 8384, seed, clean),
                network(64, 8384, seed + 1, clean),
            );
            let nonce = |actor: usize| [(n * 3 + actor + 1) as u8; 16];
            Fresh {
                storage: &storages[n],
                buffers: &buffers[n],
                receive: &receive[n],
                sourcing: &sourcing[n],
                links: Links {
                    clients: [first.0, second.0],
                    owners: [first.1, second.1],
                    nets: [first.2, second.2],
                    pools: &pools[n],
                    releases: &releases[n],
                },
                nonces: [nonce(0), nonce(1), nonce(2)],
            }
        })
        .collect();
    let zero = fresh.remove(0);
    let mut device = Device::over(zero.storage, zero.buffers, Rc::clone(&media));
    publish(zero.storage, &mut device, &key(1), 0, &payload(1000, 1));
    let scene = launch(device, zero, 0);
    let first = FirstFailure::default();
    body(Run {
        scene,
        life: Lifecycle::new(manifest, media, &buffers[0], first.clone()),
        fresh,
        first,
    });
}
