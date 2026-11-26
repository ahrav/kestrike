//! Process death at a stopped boundary, dead custody, dispositions, and cold
//! relaunch over shared media.

use crate::oracle::{
    ActionKind, Checkpoint, Custodian, KeyId, Label, Obligation, Owner, PutOutcome, Recorder,
    ResourceKind, Row, Verdict, check,
};
use crate::storage::device::sim::QuiesceMode;
use crate::storage::owner_fixture::{MEDIA, SimControl, TestPlatform, reserve};
use crate::storage::{BufferArena, CacheVersion, Crc32c, WritableFill};

use super::adapters::{Attempt, FRAGMENT, LEN, bound, drive, tenures};
use super::client::Client;
use super::datagram::{Datagrams, Received};
use super::fetch::Outcome;
use super::frame::{Kind, Status, parse};
use super::link::{LinkEnd, TxRelease};
use super::observe::{Cuts, Failure};
use super::owner_tests::{key, payload};
use super::put_tests::Scene;
use super::requests::RequestId;
use super::restart::{
    Disposition, Fresh, INCOMPLETE, Lifecycle, MANIFEST, Manifest, Refused, Run, restart_scene,
};
use super::rules::{Chain, Effect, MANIFEST as RULES, Rule, Selector};
use super::upload::UploadOutcome;
use crate::sim::round::{Act, Actor, round};

fn media(control: &SimControl) -> Vec<u8> {
    // Every relaunch rewrites the metadata prefix, so a comparison across incarnations starts past it.
    let prefix = crate::storage::TEST_METADATA_UNITS as usize * crate::storage::IO_UNIT;
    control.device(prefix, MEDIA as usize - prefix)
}

/// Whether `needle`, at least 32 bytes long, appears in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    let probe = &needle[..32];
    haystack
        .windows(probe.len())
        .enumerate()
        .filter(|(_, window)| *window == probe)
        .any(|(at, _)| haystack.get(at..at + needle.len()) == Some(needle))
}

/// Kills `scene`'s owner, which the manifest admits.
pub(super) fn kill<'s, 'm>(life: &mut Lifecycle<'s, 'm>, scene: Scene<'s, 'm>) {
    if life.die(scene).is_err() {
        panic!("death admitted");
    }
}

/// Starts the next incarnation from `fresh`, which the lifecycle admits.
pub(super) fn relaunch<'s, 'm>(
    life: &mut Lifecycle<'s, 'm>,
    fresh: Fresh<'s, 'm>,
) -> Scene<'s, 'm> {
    match life.relaunch(fresh, 0) {
        Ok(scene) => scene,
        Err((refused, _)) => panic!("relaunch admitted: {refused:?}"),
    }
}

/// Polls `scene` `turns` times without ticking its device, so the commands
/// the owner issues stay pending; each turn runs as one controller round,
/// with client `client`'s poll listed first.
fn untick(scene: &mut Scene<'_, '_>, client: usize, turns: u64) {
    for _ in 0..turns {
        let turn = scene.turn;
        let polling = &mut scene.clients[client];
        let [first, second] = &scene.nets;
        let owner = &mut scene.owner;
        round(&mut [
            Act::new(Actor::Client(client as u16), &mut || {
                let _ = polling.poll(turn * 100);
            }),
            Act::new(Actor::Link(0), &mut || first.borrow_mut().advance(turn)),
            Act::new(Actor::Link(1), &mut || second.borrow_mut().advance(turn)),
            Act::new(Actor::Owner(0), &mut || owner.poll(turn * 100)),
        ]);
        scene.turn += 1;
    }
}

/// Source slots of `client` a device reference holds.
fn device_held<'m>(client: &Client<'m, LinkEnd<'m>>) -> usize {
    client
        .sources()
        .iter()
        .filter(|slot| slot.device_held())
        .count()
}

fn charged(buffers: &BufferArena<TestPlatform>) -> u32 {
    buffers.pools().held().iter().map(|(_, held)| held).sum()
}

/// What a death left: the media, the device's pending, executed-unposted
/// and outstanding counts, the link references, and the live requests.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Standing {
    media: Vec<u8>,
    device: (usize, usize, usize),
    nic: usize,
    live: u32,
    /// Buffers held across the pools of the incarnation's buffer arena.
    charge: u32,
}

/// Puts `scene` in the state death preserves, then kills its owner: a GET
/// whose transmit references stay withheld after it completed; a second
/// GET and a local fill of `object` under key 5 whose commands stand
/// pending, one posted, one executed and unposted. Returns what stood just
/// before the death, the dead device's control, and the fill, which the
/// caller holds past the death as the writer of its outstanding writes.
fn die_busy<'s, 'm>(
    mut scene: Scene<'s, 'm>,
    life: &mut Lifecycle<'s, 'm>,
    object: &[u8],
) -> (Standing, SimControl, WritableFill<'s, 'm, TestPlatform>) {
    for net in &scene.nets {
        net.borrow_mut().set_tx_release(TxRelease::Withheld);
    }
    let (outcome, _) = scene.read(1, 1, 0);
    assert_eq!(outcome, Some(Outcome::Complete));
    let fill = start_fill(&mut scene, object);
    scene.clients[1]
        .get(key(1), 0, 1 << 20, scene.turn * 100, 30_000_000)
        .unwrap();
    untick(&mut scene, 1, 8);
    let control = scene.control.clone();
    assert!(control.pending() >= 3, "{}", control.describe());
    control.tick(1);
    let unexecuted = media(&control);
    control.execute_tick(1);
    let nic: usize = scene.nets.iter().map(|net| net.borrow().nic_held()).sum();
    let standing = Standing {
        media: media(&control),
        device: (
            control.pending(),
            control.executed_unposted(),
            control.outstanding(),
        ),
        nic,
        live: scene.owner.census().live(),
        charge: charged(life.living().expect("the scene lives")),
    };
    let (pending, executed, outstanding) = standing.device;
    assert!(
        executed == 1 && pending > executed && outstanding > pending,
        "every work class stands: {standing:?}"
    );
    assert_ne!(
        standing.media, unexecuted,
        "the executed-unposted command is a write"
    );
    assert!(standing.nic > 0 && standing.live > 0, "{standing:?}");
    kill(life, scene);
    (standing, control, fill)
}

/// Streams `object` into a local fill under key 5 through `scene`'s owner,
/// which issues its writes, and returns the fill.
fn start_fill<'s, 'm>(
    scene: &mut Scene<'s, 'm>,
    object: &[u8],
) -> WritableFill<'s, 'm, TestPlatform> {
    let mut fill = reserve(scene.storage, &key(5), 0, object.len()).expect("a fill");
    let io = &mut crate::storage::WorkBudget::with_io(0, usize::MAX, usize::MAX);
    let mut taken = 0;
    while taken < object.len() {
        taken += scene
            .owner
            .receive_fill(&mut fill, &object[taken..], io)
            .unwrap();
    }
    fill
}

/// Kills `scene`'s owner with a local fill of `object` under key 5 whose
/// writes stand pending, and returns the fill, which the caller holds past
/// the death as the writer of those writes.
fn die_writing<'s, 'm>(
    mut scene: Scene<'s, 'm>,
    life: &mut Lifecycle<'s, 'm>,
    object: &[u8],
) -> WritableFill<'s, 'm, TestPlatform> {
    let fill = start_fill(&mut scene, object);
    untick(&mut scene, 1, 2);
    assert!(
        scene.control.pending() > 0,
        "the fill's writes are outstanding"
    );
    kill(life, scene);
    fill
}

/// What a dead bundle stands at now.
fn standing(life: &Lifecycle<'_, '_>, at: usize) -> Standing {
    let dead = &life.dead()[at];
    let control = dead.control();
    Standing {
        media: media(control),
        device: (
            control.pending(),
            control.executed_unposted(),
            control.outstanding(),
        ),
        nic: dead.nets.iter().map(|net| net.borrow().nic_held()).sum(),
        live: dead.owner.custody.requests.census().live(),
        charge: charged(dead.buffers()),
    }
}

/// Death at a stopped boundary with pending, executed-unposted and posted
/// device work, queued and withheld transmit references and live requests
/// changes no media byte and keeps every count in the dead bundle; the dead
/// transport receives nothing of the dead clients' late traffic. Once the
/// dead queue drains, every issued write has landed.
#[test]
fn death_keeps_the_store_and_every_custody() {
    restart_scene(
        MANIFEST,
        |Run {
             scene,
             mut life,
             fresh,
             ..
         }| {
            let object = payload(48_000, 51);
            let (before, control, _fill) = die_busy(scene, &mut life, &object);
            assert_eq!(
                standing(&life, 0),
                before,
                "death changes nothing that stood"
            );
            let dead = life.dead_mut(0);
            let receives = dead.owner.transport.receives;
            for turn in 1_000..1_040 {
                let [first, second] = &dead.nets;
                let client = &mut dead.clients[1];
                round(&mut [
                    Act::new(Actor::Link(0), &mut || first.borrow_mut().advance(turn)),
                    Act::new(Actor::Link(1), &mut || second.borrow_mut().advance(turn)),
                    Act::new(Actor::Client(1), &mut || {
                        let _ = client.poll(turn * 100);
                    }),
                ]);
            }
            let due = dead.nets[1].borrow().receivable(1);
            assert!(due > 0, "late traffic stands due at the dead end, untaken");
            let mut into: Vec<_> = (0..2 * due).map(|_| None).collect();
            let mut meta = vec![Received::default(); 2 * due];
            let taken = dead
                .owner
                .transport
                .receive(fresh[0].receive, &mut into, &mut meta)
                .unwrap();
            assert!(
                taken >= due
                    && dead.owner.transport.receives == receives + 1
                    && dead.nets[1].borrow().receivable(1) == 0,
                "a receive through the dead transport is what would take it"
            );
            assert_eq!(
                dead.dispose(QuiesceMode::AllReturned),
                Ok(Disposition::AllReturned)
            );
            assert_eq!(control.pending(), 0);
            assert!(
                contains(&media(&control), &object),
                "every issued write landed"
            );
            let buffers = dead.buffers();
            let held = charged(buffers);
            assert_eq!(life.release(0), Ok(()));
            assert!(
                charged(buffers) < held,
                "a release returns the dead custody's charge"
            );
        },
    );
}

/// A relaunch after a reset reads the very bytes that stood at death: the
/// media is shared, so the executed-unposted write is there, and the reset
/// dropped the unexecuted ones without moving a byte.
#[test]
fn a_relaunch_reads_the_media_that_stood_at_death() {
    restart_scene(
        MANIFEST,
        |Run {
             scene,
             mut life,
             mut fresh,
             ..
         }| {
            let (before, _, _fill) = die_busy(scene, &mut life, &payload(48_000, 52));
            assert_eq!(
                life.dead_mut(0).dispose(QuiesceMode::Reset),
                Ok(Disposition::Reset)
            );
            assert_eq!(
                life.dead()[0].control().outstanding(),
                0,
                "both queues emptied"
            );
            let scene = relaunch(&mut life, fresh.remove(0));
            assert_eq!(
                media(&scene.control),
                before.media,
                "no copy: the same bytes"
            );
        },
    );
}

/// Kills the scene's owner with a GET of key 1 mid-read, its device
/// commands pending, and returns the dead device's control.
fn die_mid_read<'s, 'm>(mut scene: Scene<'s, 'm>, life: &mut Lifecycle<'s, 'm>) -> SimControl {
    scene.clients[1]
        .get(key(1), 0, 1 << 20, scene.turn * 100, 30_000_000)
        .unwrap();
    untick(&mut scene, 1, 4);
    assert!(scene.control.pending() > 0, "the read is outstanding");
    let control = scene.control.clone();
    kill(life, scene);
    control
}

/// Writable relaunch follows the dead queue's disposition, recorded once:
/// `AllReturned` and `Reset` free it; `Unproven` and `Failed` withhold it,
/// keep the dead incarnation's charge and outstanding work, and refuse a
/// later disposition, so no later stop clears them.
#[test]
fn writable_relaunch_follows_the_disposition() {
    for (mode, disposition) in [
        (QuiesceMode::AllReturned, Disposition::AllReturned),
        (QuiesceMode::Reset, Disposition::Reset),
        (QuiesceMode::Unproven, Disposition::Unproven),
        (QuiesceMode::Failed(Some(5)), Disposition::Failed(Some(5))),
        (QuiesceMode::Failed(None), Disposition::Failed(None)),
    ] {
        restart_scene(
            MANIFEST,
            |Run {
                 scene,
                 mut life,
                 mut fresh,
                 ..
             }| {
                let control = die_mid_read(scene, &mut life);
                assert_eq!(
                    life.relaunch_ready(),
                    Err(Refused::Withheld),
                    "no disposition yet"
                );
                let buffers = life.dead()[0].buffers();
                let charge = charged(buffers);
                assert!(charge > 0, "the dead read holds buffers");
                assert_eq!(life.dead_mut(0).dispose(mode), Ok(disposition));
                for later in [QuiesceMode::Reset, QuiesceMode::AllReturned] {
                    assert_eq!(
                        life.dead_mut(0).dispose(later),
                        Err(Refused::Disposed(disposition))
                    );
                }
                if disposition.frees() {
                    assert_eq!(
                        control.pending(),
                        0,
                        "{disposition:?}: no command waits to land"
                    );
                    relaunch(&mut life, fresh.remove(0));
                } else {
                    assert!(
                        control.pending() > 0,
                        "{disposition:?}: the halted queue keeps its work"
                    );
                    assert_eq!(
                        charged(buffers),
                        charge,
                        "{disposition:?}: the charge stays"
                    );
                    let Err((refused, _)) = life.relaunch(fresh.remove(0), 0) else {
                        panic!("{disposition:?}: attach withheld");
                    };
                    assert_eq!(refused, Refused::Withheld);
                    assert_eq!(life.incarnation(), 0, "{disposition:?}: nothing started");
                    assert_eq!(
                        life.release(0),
                        Err(Refused::Withheld),
                        "its custody cannot be released"
                    );
                    assert_eq!(
                        charged(buffers),
                        charge,
                        "{disposition:?}: a refused release returns nothing"
                    );
                }
            },
        );
    }
}

/// A cold relaunch over the shared media starts with an empty frontier: the
/// old object misses through the new storage while a raw read of the media
/// still finds its record, and an old frame replayed toward the new owner
/// is dropped. A later stop of the new incarnation leaves the dead bundle
/// as it stood.
#[test]
fn a_cold_relaunch_misses_old_bytes_and_rejects_old_traffic() {
    restart_scene(
        MANIFEST,
        |Run {
             mut scene,
             mut life,
             mut fresh,
             ..
         }| {
            let old = scene.storage;
            scene.clients[1]
                .get(key(1), 0, 1 << 20, scene.turn * 100, 30_000_000)
                .unwrap();
            scene.clients[1].poll(scene.turn * 100);
            let late = scene.nets[1]
                .borrow()
                .peek(1)
                .expect("a GET toward the owner");
            untick(&mut scene, 1, 4);
            let old_session = scene.owner.record_session();
            kill(&mut life, scene);
            life.dead_mut(0).dispose(QuiesceMode::AllReturned).unwrap();
            let dead = standing(&life, 0);
            let mut scene = relaunch(&mut life, fresh.remove(0));
            assert_eq!(
                (life.dead()[0].incarnation(), life.incarnation()),
                (0, 1),
                "the dead bundle names its incarnation"
            );
            let (outcome, _) = scene.read(1, 1, 0);
            assert_eq!(
                outcome,
                Some(Outcome::Missing),
                "the new frontier starts empty"
            );
            let (mut bindings, mut facts, mut bytes) = (Vec::new(), Vec::new(), Vec::new());
            old.bindings_into(&mut bindings).unwrap();
            old.slot_facts_into(&mut facts).unwrap();
            let identity = bindings[0].identity;
            let fact = facts[identity.slot as usize];
            assert!(
                scene
                    .control
                    .try_device_into(fact.media().unwrap(), &mut bytes)
            );
            let allocation = u64::from(identity.slot) << 32 | u64::from(fact.incarnation);
            let found = old
                .record_payload(&bytes, allocation, &fact, old_session)
                .expect("the old record on the media");
            assert_eq!(
                found,
                (key(1), 0, &payload(1000, 1)[..]),
                "a raw read sees the old bytes"
            );
            let dropped = scene.owner.report().dropped;
            scene.nets[1].borrow_mut().inject(1, &late);
            drive(&mut scene, 4);
            assert_eq!(
                scene.owner.report().dropped,
                dropped + 1,
                "the new owner drops the old frame"
            );
            scene.owner.close(scene.turn * 100);
            drive(&mut scene, 20);
            assert_eq!(
                standing(&life, 0),
                dead,
                "a later stop leaves the dead bundle as it stood"
            );
        },
    );
}

/// One owner dead with every work class standing and its attach withheld
/// leaves another world's owner serving: turns of the healthy world interleave with the dead world's
/// client polls, link advances and halted device ticks, the healthy GET
/// completes with its exact bytes within its turn bound, and the dead
/// bundle stands as it was.
#[test]
fn a_healthy_peer_serves_beside_a_dead_owner() {
    restart_scene(
        MANIFEST,
        |Run {
             scene, mut life, ..
         }| {
            let (_, _, _fill) = die_busy(scene, &mut life, &payload(48_000, 53));
            life.dead_mut(0).dispose(QuiesceMode::Unproven).unwrap();
            assert_eq!(life.relaunch_ready(), Err(Refused::Withheld));
            let before = standing(&life, 0);
            assert!(before.nic > 0, "the dead links hold transmit references");
            super::put_tests::scene(&super::owner_tests::PRINCIPALS, |mut healthy| {
                let id = healthy.clients[1]
                    .get(key(1), 0, 1 << 20, healthy.turn * 100, 30_000_000)
                    .unwrap();
                let mut bytes = Vec::new();
                for turn in 0..400u64 {
                    let dead = life.dead_mut(0);
                    let control = dead.control().clone();
                    let [first, second] = &dead.nets;
                    let [dead_first, dead_second] = &mut dead.clients;
                    let at = 10_000 + turn;
                    let now = healthy.turn * 100;
                    let reader = &mut healthy.clients[1];
                    // The dead incarnation's actors take indices 0 and 1, the
                    // healthy scene's reader index 2.
                    round(&mut [
                        Act::new(Actor::Link(0), &mut || first.borrow_mut().advance(at)),
                        Act::new(Actor::Link(1), &mut || second.borrow_mut().advance(at)),
                        Act::new(Actor::Client(0), &mut || {
                            let _ = dead_first.poll(at * 100);
                        }),
                        Act::new(Actor::Client(1), &mut || {
                            let _ = dead_second.poll(at * 100);
                        }),
                        Act::new(Actor::Disk(0), &mut || control.tick(64)),
                        Act::new(Actor::Client(2), &mut || {
                            let _ = reader.poll(now);
                        }),
                    ]);
                    healthy.turns(1);
                    while let Some(fragment) = healthy.clients[1].take(id) {
                        bytes.extend_from_slice(fragment.bytes());
                    }
                    if healthy.clients[1].outcome(id).is_some() {
                        break;
                    }
                }
                assert_eq!(
                    healthy.clients[1].outcome(id),
                    Some(Outcome::Complete),
                    "within the bound"
                );
                assert_eq!(bytes, payload(1000, 1));
                healthy.owner.close(healthy.turn * 100);
                healthy.turns(20);
            });
            let after = standing(&life, 0);
            assert_eq!(after, before, "the dead store, queue and custody stand");
            assert!(after.charge > 0, "the dead owner holds buffers");
            let held = after.device.2;
            assert!(held > 0, "the dead owner holds commands");
            let kept = dead_history(held, false);
            assert!(matches!(kept, Verdict::Pass(_)), "{kept:?}");
            assert_eq!(
                dead_history(held, true).violated(),
                Some((
                    Obligation::Resources,
                    "an unproven stop returned retained custody"
                )),
                "the healthy owner's stop clears no dead custody"
            );
        },
    );
}

/// An oracle control sized by the dead device: judges, across one cut, a
/// history of `held` owner buffers under the dead owner's unproven stop
/// and the healthy owner's later stop; with `release`, the first buffer
/// returns after that stop.
fn dead_history(held: usize, release: bool) -> Verdict {
    let mut rec = Recorder::new(1);
    for index in 0..held as u32 {
        rec.take((ResourceKind::Buffer, index, 1), Custodian::Owner, None);
    }
    rec.checkpoint(Checkpoint::Unproven);
    let stopped = rec.checkpoint(Checkpoint::Stopped);
    if release {
        rec.release((ResourceKind::Buffer, 0, 1), Custodian::Owner);
    }
    let rows = rec.rows().to_vec();
    let mut cuts = Cuts::new(Owner(0));
    cuts.cut_by(&rows, &[], |row| Owner(u64::from(row.op == stopped)))
        .unwrap();
    cuts.finish()
}

/// Deaths, restarts and slots stay within the manifest, each refused before
/// it changes the lifecycle. A second death keeps the first bundle whole; past the bundle
/// bound a death leaves the owner serving; a dead bundle holds its slot
/// until released, an unproven one for good, so a relaunch is incomplete,
/// while a bundle a disposition or release can free leaves the run
/// complete;
/// past the restart bound a relaunch is refused.
#[test]
fn incarnations_stay_within_the_manifest() {
    restart_scene(
        MANIFEST,
        |Run {
             scene,
             mut life,
             mut fresh,
             ..
         }| {
            let Err((refused, unused)) = life.relaunch(fresh.remove(0), 0) else {
                panic!("an incarnation lives");
            };
            assert_eq!(refused, Refused::Living);
            fresh.insert(0, *unused);
            die_mid_read(scene, &mut life);
            life.dead_mut(0).dispose(QuiesceMode::AllReturned).unwrap();
            let first = standing(&life, 0);
            let scene = relaunch(&mut life, fresh.remove(0));
            kill(&mut life, scene);
            assert_eq!(life.dead().len(), 2);
            assert_eq!(life.dead()[0].incarnation(), 0);
            assert_eq!(life.dead()[0].disposition(), Some(Disposition::AllReturned));
            assert_eq!(standing(&life, 0), first, "the first bundle stays whole");
        },
    );
    let one = Manifest {
        bundles: 1,
        ..MANIFEST
    };
    restart_scene(
        one,
        |Run {
             scene,
             mut life,
             mut fresh,
             ..
         }| {
            die_mid_read(scene, &mut life);
            life.dead_mut(0).dispose(QuiesceMode::AllReturned).unwrap();
            let first = standing(&life, 0);
            let scene = relaunch(&mut life, fresh.remove(0));
            let Err((refused, scene)) = life.die(scene) else {
                panic!("no bundle place");
            };
            assert_eq!(refused, Refused::Bundles);
            let mut scene = *scene;
            assert_eq!(standing(&life, 0), first, "the first bundle stays whole");
            let object = super::adapters::upload_published(&mut scene, &mut Recorder::new(1), 6);
            let (outcome, bytes) = scene.read(1, 6, 0);
            assert_eq!(
                (outcome, bytes),
                (Some(Outcome::Complete), object),
                "the owner still serves"
            );
        },
    );
    let one = Manifest {
        slots: 1,
        ..MANIFEST
    };
    restart_scene(
        one,
        |Run {
             scene,
             mut life,
             mut fresh,
             first,
         }| {
            die_mid_read(scene, &mut life);
            let Err((refused, early)) = life.relaunch(fresh.remove(0), 0) else {
                panic!("the undisposed bundle holds the only slot");
            };
            assert_eq!(refused, Refused::Slots);
            assert_eq!(first.get(), None, "a disposition can still free the slot");
            life.dead_mut(0).dispose(QuiesceMode::AllReturned).unwrap();
            let Err((refused, again)) = life.relaunch(*early, 0) else {
                panic!("the dead bundle holds the only slot");
            };
            assert_eq!(refused, Refused::Slots);
            assert_eq!(
                (life.incarnation(), life.dead().len()),
                (0, 1),
                "nothing started"
            );
            assert_eq!(first.get(), None, "a release can still free the slot");
            assert_eq!(life.release(0), Ok(()));
            relaunch(&mut life, *again);
        },
    );
    restart_scene(
        one,
        |Run {
             scene,
             mut life,
             mut fresh,
             first,
         }| {
            die_mid_read(scene, &mut life);
            life.dead_mut(0).dispose(QuiesceMode::Unproven).unwrap();
            assert_eq!(life.release(0), Err(Refused::Withheld));
            let Err((refused, _)) = life.relaunch(fresh.remove(0), 0) else {
                panic!("an unproven stop keeps its slot");
            };
            assert_eq!(refused, Refused::Slots);
            assert_eq!(
                first.get(),
                Some(Failure::Unsuccessful(INCOMPLETE)),
                "the run is incomplete"
            );
        },
    );
    let two = Manifest {
        slots: 2,
        ..MANIFEST
    };
    restart_scene(
        two,
        |Run {
             scene,
             mut life,
             mut fresh,
             first,
         }| {
            die_mid_read(scene, &mut life);
            life.dead_mut(0).dispose(QuiesceMode::AllReturned).unwrap();
            let scene = relaunch(&mut life, fresh.remove(0));
            let _fill = die_writing(scene, &mut life, &payload(20_000, 54));
            assert_eq!(
                life.dead_mut(1).dispose(QuiesceMode::Unproven),
                Ok(Disposition::Unproven)
            );
            let Err((refused, again)) = life.relaunch(fresh.remove(0), 0) else {
                panic!("both dead bundles hold the slots");
            };
            assert_eq!(refused, Refused::Slots);
            assert_eq!(first.get(), None, "releasing the first bundle frees a slot");
            assert_eq!(life.release(0), Ok(()));
            let Err((refused, _)) = life.relaunch(*again, 0) else {
                panic!("the unproven bundle withholds attach");
            };
            assert_eq!(refused, Refused::Withheld);
        },
    );
    let once = Manifest {
        restarts: 1,
        ..MANIFEST
    };
    restart_scene(
        once,
        |Run {
             scene,
             mut life,
             mut fresh,
             ..
         }| {
            die_mid_read(scene, &mut life);
            life.dead_mut(0).dispose(QuiesceMode::AllReturned).unwrap();
            let scene = relaunch(&mut life, fresh.remove(0));
            kill(&mut life, scene);
            life.dead_mut(1).dispose(QuiesceMode::AllReturned).unwrap();
            let Err((refused, _)) = life.relaunch(fresh.remove(0), 0) else {
                panic!("past the restart bound");
            };
            assert_eq!(refused, Refused::Restarts);
            assert_eq!(life.incarnation(), 1, "nothing started");
        },
    );
}

/// Polls a dead incarnation's uploading client past its deadline, its links
/// advancing with it, and for 100 rounds after the client decides. Returns
/// the outcome the client then holds: a reply still in a link, which
/// settles an `Unknown`, has arrived by then.
fn dead_outcome(life: &mut Lifecycle<'_, '_>, at: usize, id: RequestId) -> Option<UploadOutcome> {
    let dead = life.dead_mut(at);
    let mut settling = 100;
    for turn in 0..40_000u64 {
        let now = 1_000_000_000 + turn * 1_000;
        let [first, second] = &dead.nets;
        let client = &mut dead.clients[0];
        round(&mut [
            Act::new(Actor::Link(0), &mut || {
                first.borrow_mut().advance(now / 100)
            }),
            Act::new(Actor::Link(1), &mut || {
                second.borrow_mut().advance(now / 100)
            }),
            Act::new(Actor::Client(0), &mut || {
                let _ = client.poll(now);
            }),
        ]);
        if dead.clients[0].put_outcome(id).is_some() {
            if settling == 0 {
                break;
            }
            settling -= 1;
        }
    }
    dead.clients[0].put_outcome(id)
}

/// The fill serial client 0's upload `id` names: 0 until the client holds
/// the owner's authority.
fn fill_serial(scene: &Scene<'_, '_>, id: RequestId) -> Option<u64> {
    scene.clients[0]
        .put_receipt(id)
        .map(|(serial, _, _)| serial)
}

/// Starts an upload of key 6 on client 0 with a 200 ms wait and polls the
/// client once, which hands its BEGIN to the link before any turn of the
/// owner: the client holds no authority.
fn begin_unanswered(scene: &mut Scene<'_, '_>) -> RequestId {
    let now = scene.turn * 100;
    let id = scene.clients[0]
        .put(key(6), CacheVersion(0), now, 200_000)
        .unwrap();
    let report = scene.clients[0].poll(now);
    assert!(
        report.sent >= 1,
        "the poll hands the BEGIN to the transport"
    );
    assert_eq!(
        fill_serial(scene, id),
        Some(0),
        "no owner turn ran, so the client holds no authority"
    );
    id
}

/// A death before the owner granted authority, while the uploading client
/// waits on BEGIN, leaves the client's outcome `Unknown`: the BEGIN reached
/// the transport, so neither publication nor failure is known.
#[test]
fn death_before_authority_leaves_the_upload_unknown() {
    restart_scene(
        MANIFEST,
        |Run {
             mut scene,
             mut life,
             ..
         }| {
            let id = begin_unanswered(&mut scene);
            kill(&mut life, scene);
            assert_eq!(dead_outcome(&mut life, 0, id), Some(UploadOutcome::Unknown));
        },
    );
}

/// The same BEGIN with the owner left alive: the owner grants authority, the
/// client has decided nothing before its deadline, and past the deadline
/// the owner's PUT ERROR settles the upload `Failed(TimedOut)`. The client
/// of `death_before_authority_leaves_the_upload_unknown` still holds
/// `Unknown` 100 rounds after it decided.
#[test]
fn a_living_owner_grants_authority_and_ends_the_upload_timed_out() {
    restart_scene(MANIFEST, |Run { mut scene, .. }| {
        let id = begin_unanswered(&mut scene);
        let granted =
            |scene: &Scene<'_, '_>| fill_serial(scene, id).is_some_and(|serial| serial != 0);
        for _ in 0..600 {
            drive(&mut scene, 1);
            if granted(&scene) {
                break;
            }
        }
        assert!(granted(&scene), "the living owner granted authority");
        assert_eq!(
            scene.clients[0].put_outcome(id),
            None,
            "an upload whose owner answered is undecided before its deadline"
        );
        // The 200 ms wait ends near turn 2,000. The client's own deadline decides first, and the owner's
        // PUT ERROR for its deadline settles that outcome.
        for _ in 0..3_000 {
            drive(&mut scene, 1);
            if let Some(UploadOutcome::Failed(_)) = scene.clients[0].put_outcome(id) {
                break;
            }
        }
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(UploadOutcome::Failed(Status::TimedOut)),
            "a living owner ends the upload at its deadline and its PUT ERROR settles the client's outcome"
        );
    });
}

/// Begins client 0's upload of key 6 under label 1 and supplies every
/// fragment of it.
fn supplied<'t>(
    scene: &mut Scene<'_, '_>,
    rec: &mut Recorder,
    slots: &'t mut [u64],
) -> Attempt<'t> {
    let mut attempt = Attempt::begin(scene, rec, (6, Label(1)), LEN, slots);
    for index in 0..LEN.div_ceil(FRAGMENT as u64) as u32 {
        assert!(attempt.supply(scene, rec, index));
    }
    attempt
}

/// A death with upload DATA accepted by the link and its references
/// withheld keeps every source slot the device holds, and the client's
/// outcome is `Unknown`; the source slots stay held through the decided
/// outcome and the dead queue's stop.
#[test]
fn death_with_data_under_nic_custody_keeps_the_source_slots_held() {
    restart_scene(
        MANIFEST,
        |Run {
             mut scene,
             mut life,
             ..
         }| {
            scene.nets[0]
                .borrow_mut()
                .set_tx_release(TxRelease::Withheld);
            let mut rec = Recorder::new(1);
            let mut slots = tenures(&scene);
            let mut attempt = Attempt::begin(&mut scene, &mut rec, (6, Label(1)), LEN, &mut slots);
            assert!(attempt.supply(&mut scene, &mut rec, 0));
            scene.clients[0].poll(scene.turn * 100);
            attempt.observe(&scene, &mut rec);
            let before = device_held(&scene.clients[0]);
            assert!(before > 0, "the device holds a source slot");
            let id = attempt.id;
            kill(&mut life, scene);
            assert_eq!(
                device_held(&life.dead()[0].clients[0]),
                before,
                "death releases no source custody"
            );
            assert_eq!(dead_outcome(&mut life, 0, id), Some(UploadOutcome::Unknown));
            assert_eq!(
                device_held(&life.dead()[0].clients[0]),
                before,
                "nor does the decided outcome"
            );
            life.dead_mut(0).dispose(QuiesceMode::Unproven).unwrap();
            assert_eq!(
                device_held(&life.dead()[0].clients[0]),
                before,
                "nor does the dead queue's stop"
            );
        },
    );
}

/// A death with the upload's bytes received and its writes outstanding
/// leaves the outcome `Unknown`. Once the dead queue drains the writes land
/// on the shared media, yet the cold relaunch misses the key; the new owner
/// drops the old upload's replayed frame; a fresh upload publishes from its
/// own fragments and reads back exactly, and the drained dead device stays
/// idle. The old attempt's rows, its custody still
/// held, the death's unproven stop, the fresh upload's rows and the new
/// owner's later stop judge as one episode across the relaunch, each under
/// its own owner incarnation.
#[test]
fn death_with_outstanding_writes_lands_them_dead_and_relaunches_cold() {
    restart_scene(
        MANIFEST,
        |Run {
             mut scene,
             mut life,
             mut fresh,
             ..
         }| {
            let mut rec = Recorder::new(1);
            let mut slots = tenures(&scene);
            let attempt = supplied(&mut scene, &mut rec, &mut slots);
            let mut late = None;
            for _ in 0..40 {
                let turn = scene.turn;
                let [uploader, polling] = &mut scene.clients;
                let [first, second] = &scene.nets;
                let owner = &mut scene.owner;
                round(&mut [
                    Act::new(Actor::Client(0), &mut || {
                        let _ = uploader.poll(turn * 100);
                        late = first.borrow().peek(1).or(late.take());
                    }),
                    Act::new(Actor::Client(1), &mut || {
                        let _ = polling.poll(turn * 100);
                    }),
                    Act::new(Actor::Link(0), &mut || first.borrow_mut().advance(turn)),
                    Act::new(Actor::Link(1), &mut || second.borrow_mut().advance(turn)),
                    Act::new(Actor::Owner(0), &mut || owner.poll(turn * 100)),
                ]);
                scene.turn += 1;
            }
            let late = late.expect("the old upload's traffic");
            assert!(
                scene.control.pending() > 0,
                "the upload's writes are outstanding"
            );
            let object = attempt.object.clone();
            let (id, op, serial) = (attempt.id, attempt.op, attempt.serial);
            kill(&mut life, scene);
            assert_eq!(dead_outcome(&mut life, 0, id), Some(UploadOutcome::Unknown));
            rec.put_result(op, (KeyId(6), Label(1)), serial, PutOutcome::Unknown);
            let death = rec.checkpoint(Checkpoint::Unproven);
            assert_eq!(
                life.dead_mut(0).dispose(QuiesceMode::AllReturned),
                Ok(Disposition::AllReturned)
            );
            let mut scene = relaunch(&mut life, fresh.remove(0));
            assert!(
                contains(&media(&scene.control), &object[..FRAGMENT]),
                "the old bytes landed"
            );
            assert!(!bound(&scene, 6), "the new storage binds nothing");
            let (outcome, _) = scene.read(1, 6, 0);
            assert_eq!(
                outcome,
                Some(Outcome::Missing),
                "no cold hit on old upload bytes"
            );
            let dropped = scene.owner.report().dropped;
            scene.nets[0].borrow_mut().inject(1, &late);
            drive(&mut scene, 4);
            assert_eq!(
                scene.owner.report().dropped,
                dropped + 1,
                "the new owner drops the old frame"
            );
            let object = super::adapters::upload_published(&mut scene, &mut rec, 6);
            rec.checkpoint(Checkpoint::Stopped);
            let rows = rec.rows().to_vec();
            let mut cuts = Cuts::new(Owner(0));
            let incarnation = |row: &Row| Owner(u64::from(row.op > death));
            cuts.cut_by(&rows, &[], incarnation).unwrap();
            let episode = cuts.finish();
            assert!(
                matches!(episode, Verdict::Pass(_)),
                "one episode across the relaunch: {episode:?}"
            );
            let published = media(&scene.control);
            for _ in 0..8 {
                life.dead()[0].control().tick(64);
            }
            assert_eq!(
                media(&scene.control),
                published,
                "the drained dead device stays idle"
            );
            let (outcome, bytes) = scene.read(1, 6, 0);
            assert_eq!((outcome, bytes), (Some(Outcome::Complete), object));
        },
    );
}

/// A death after the owner published, its RESULT held in the link, leaves
/// the client `Unknown`. That RESULT replayed toward the new incarnation's
/// client is dropped. The history with the `Unknown` passes the oracle,
/// while the same history with the outcome forced to a failure, and one
/// whose source retention ended before its receipt, each fail by name.
#[test]
fn death_after_publication_with_the_result_lost_stays_unknown() {
    restart_scene(
        MANIFEST,
        |Run {
             mut scene,
             mut life,
             mut fresh,
             ..
         }| {
            let hold = vec![Rule::new(
                Selector::Kind(Kind::PutResult),
                Effect::Delay(1 << 40),
            )];
            scene.nets[0]
                .borrow_mut()
                .set_rules(Chain::new(hold, &[], &RULES).unwrap());
            let mut rec = Recorder::new(1);
            let mut slots = tenures(&scene);
            let mut attempt = supplied(&mut scene, &mut rec, &mut slots);
            for _ in 0..600 {
                drive(&mut scene, 1);
                attempt.observe(&scene, &mut rec);
                if attempt.published {
                    break;
                }
            }
            assert!(attempt.published, "the owner published");
            drive(&mut scene, 4);
            let result = scene.nets[0]
                .borrow()
                .peek(0)
                .expect("the RESULT waits in the link");
            let (id, op, serial) = (attempt.id, attempt.op, attempt.serial);
            let wire = scene.clients[0].put_wire(id);
            assert!(
                parse(Crc32c::detect(), &result, false).is_ok_and(|frame| {
                    let header = frame.header();
                    header.kind == Kind::PutResult && Some(header.request) == wire
                }),
                "the datagram held toward the client is the upload's PUT RESULT"
            );
            assert_eq!(
                scene.clients[0].put_outcome(id),
                None,
                "the held RESULT never reached the client, which has decided nothing"
            );
            kill(&mut life, scene);
            life.dead()[0].nets[0].borrow_mut().clear(0);
            let outcome = dead_outcome(&mut life, 0, id);
            assert_eq!(
                outcome,
                Some(UploadOutcome::Unknown),
                "death proves neither publication nor failure"
            );
            life.dead_mut(0).dispose(QuiesceMode::AllReturned).unwrap();
            let mut scene = relaunch(&mut life, fresh.remove(0));
            scene.nets[0].borrow_mut().inject(0, &result);
            let report = scene.clients[0].poll(scene.turn * 100);
            assert_eq!(
                report.dropped, 1,
                "the old RESULT authorizes nothing in the new session"
            );
            rec.put_result(op, (KeyId(6), Label(1)), serial, PutOutcome::Unknown);
            let rows = rec.rows().to_vec();
            let judged = |rows: Vec<Row>| check(&Recorder::rebuilt(rows));
            let whole = judged(rows.clone());
            assert!(matches!(whole, Verdict::Pass(_)), "{whole:?}");
            let mut failed = rows.clone();
            let last = failed
                .iter_mut()
                .rev()
                .find(|row| row.kind == ActionKind::PutResult)
                .unwrap();
            let mut scratch = Recorder::new(1);
            let code = Status::OwnerUnavailable as u16;
            scratch.put_result(op, (KeyId(6), Label(1)), serial, PutOutcome::Failed(code));
            let again = &scratch.rows()[0];
            last.outcome = again.outcome;
            last.open = again.open;
            assert_eq!(
                judged(failed).violated(),
                Some((
                    Obligation::History,
                    "an attempt that did not publish published"
                )),
                "an Unknown forced to a failure"
            );
            let mut early = rows.clone();
            let release = early
                .iter()
                .position(|row| {
                    row.kind == ActionKind::Release
                        && row.custodian == Some(Custodian::Retransmission)
                })
                .unwrap();
            let moved = early.remove(release);
            let ack = early
                .iter()
                .position(|row| row.kind == ActionKind::Ack)
                .unwrap();
            early.insert(ack, moved);
            Recorder::renumber(&mut early);
            assert_eq!(
                judged(early).violated(),
                Some((
                    Obligation::Custody,
                    "retransmission retention ended before the receipt base passed its fragment"
                )),
                "an early source release"
            );
        },
    );
}

/// The upload of `death_after_publication_with_the_result_lost_stays_unknown`
/// with no rule on the link and no death: the RESULT reaches the client,
/// which decides `Published`, so that test's `Unknown` comes from the lost
/// RESULT and the death.
#[test]
fn a_delivered_result_ends_published() {
    restart_scene(MANIFEST, |Run { mut scene, .. }| {
        let mut rec = Recorder::new(1);
        let mut slots = tenures(&scene);
        let mut attempt = supplied(&mut scene, &mut rec, &mut slots);
        let mut outcome = None;
        for _ in 0..600 {
            drive(&mut scene, 1);
            attempt.observe(&scene, &mut rec);
            outcome = scene.clients[0].put_outcome(attempt.id);
            if outcome.is_some() {
                break;
            }
        }
        assert!(attempt.published, "the owner published");
        assert_eq!(
            outcome,
            Some(UploadOutcome::Published),
            "an upload whose RESULT is delivered ends Published"
        );
    });
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_cold_relaunch_misses_old_bytes_and_rejects_old_traffic,
    a_healthy_peer_serves_beside_a_dead_owner,
    a_relaunch_reads_the_media_that_stood_at_death,
    death_after_publication_with_the_result_lost_stays_unknown,
    death_before_authority_leaves_the_upload_unknown,
    death_keeps_the_store_and_every_custody,
    death_with_data_under_nic_custody_keeps_the_source_slots_held,
    death_with_outstanding_writes_lands_them_dead_and_relaunches_cold,
    incarnations_stay_within_the_manifest,
);

/// Each lifecycle incarnation's volume writes a higher session than the
/// incarnation before it, so a record the dead incarnation wrote fails the
/// relaunched volume's session check on its header.
#[test]
fn each_relaunched_incarnation_writes_a_higher_session() {
    restart_scene(
        MANIFEST,
        |Run {
             scene,
             mut life,
             mut fresh,
             ..
         }| {
            assert_eq!(life.incarnation(), 0);
            let first = scene.owner.record_session();
            kill(&mut life, scene);
            life.dead_mut(0).dispose(QuiesceMode::AllReturned).unwrap();
            let scene = relaunch(&mut life, fresh.remove(0));
            assert_eq!(life.incarnation(), 1);
            assert!(scene.owner.record_session() > first);
        },
    );
}
