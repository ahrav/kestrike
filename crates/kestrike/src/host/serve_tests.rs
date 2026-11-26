use std::cell::Cell;
use std::rc::Rc;

use super::{
    Attachment, Custody, Endpoint, Rising, Unbrought, bring_up, start_up, start_up_with_nonce,
    turn_up,
};
use crate::failover::evidence::Pair;
use crate::failover::fresh::tests as fresh_tests;
use crate::failover::fresh::tests::registrant;
use crate::failover::records::Suffix;
use crate::failover::restart::tests::{own, shard_now};
use crate::failover::retire::Target;
use crate::host::fencer_tests::{Driving, commands, fencer_of, shared_table};
use crate::host::recover::{Role, Tenure};
use crate::host::recover_tests::{fresh_own, own_holds, recovered, tenure};
use crate::host::{Exit, HostGate};
use crate::net::link::{Faults, LinkEnd, network};
use crate::net::owner_tests::{Mux, OWNER, PRINCIPALS, entries, packet_arena};
use crate::net::{Keys, Owner, OwnerConfig, PacketPool};
use crate::storage::device::sim::{Media, SimControl, sim_attached};
use crate::storage::gate_fixture::Ticking;
use crate::storage::gate_fixture::{Control, Reserving, arena_with, foreign};
use crate::storage::portable::scripted::ScriptedClock;
use crate::storage::store::sim::Shared;
use crate::storage::test_platform::TestPlatform;
use crate::storage::volume_fixture::{BUFFER, DEPTH, TICK, config_for, facts};
use crate::storage::warm_sim::{
    block_unit, object_key, region, replacement_unit, shard_store_with, storage, suffix_block,
    tenure_replacing,
};
use crate::storage::{
    BufferArena, EngineBudget, INLINE_RECOVERY, IO_UNIT, MetadataOutcome, Operation, PoolKind,
    Readiness, Storage, WorkBudget,
};

/// The bytes of object `n`: four metadata bytes, then a body of `fill`.
pub(crate) fn content(n: u8, fill: u8) -> Vec<u8> {
    [&object_key(n)[..4], &[fill; 40][..]].concat()
}

/// A volume the record names this host's at `E = 4`, with a named checkpoint of objects `1..=4` and one certified
/// suffix whose one block, on the media, replaces object 2. Returns the shard's store and the media.
pub(super) fn warm_volume() -> (Shared, Media) {
    let (store, media, _) = warm_volume_with(false);
    (store, media)
}

/// [`warm_volume`] whose recorded suffix is certified `certified` blocks past its start.
pub(crate) fn warm_volume_certified(certified: u64) -> (Shared, Media) {
    let (store, media, _) = warm_volume_of(false, certified);
    (store, media)
}

/// [`warm_volume`], with the suffix block's bytes flipped when `damaged`, and the device unit of the replacement's
/// payload.
fn warm_volume_with(damaged: bool) -> (Shared, Media, u32) {
    warm_volume_of(damaged, 1)
}

fn warm_volume_of(damaged: bool, certified: u64) -> (Shared, Media, u32) {
    let capturing = crate::storage::session_at(3, 0);
    let before = capturing.get();
    let (a, replace) =
        tenure_replacing(capturing, 4, |n| content(n, n), Some((2, content(2, 0xee))));
    let replace = replace.expect("the replacement's record");
    let new_unit = replacement_unit(&replace);
    let lap = region();
    let recorded = [Suffix {
        session: before,
        start: lap,
        certified: lap + certified,
        end: lap + 1,
    }];
    let records = shard_store_with(a.named, false, 4, (lap, &recorded));
    let mut block = suffix_block(before, lap, &[replace]);
    if damaged {
        block.iter_mut().for_each(|byte| *byte = !*byte);
    }
    let at = block_unit(lap) as usize * IO_UNIT;
    a.media.borrow_mut()[at..at + IO_UNIT].copy_from_slice(&block);
    (records, a.media, new_unit)
}

/// This host's driver over `media` on `registry`, issuing as `own` from controller 1.
pub(crate) fn host_over(registry: &Control, media: &Media, own: Pair) -> (Reserving, SimControl) {
    let (disk, control) = sim_attached(config_for(7), Rc::clone(media), facts(BUFFER));
    (
        crate::storage::gate_fixture::reserving_as(disk, registry, own, 1),
        control,
    )
}

/// The owner's packet arena and key entries, which an [`Endpoint`] borrows.
pub(super) struct Wire {
    pub(super) packets: BufferArena<TestPlatform>,
    pub(super) entries: [crate::net::KeyEntry<'static>; 2],
}

impl Wire {
    pub(super) fn new() -> Self {
        Self {
            packets: packet_arena(32, 16384),
            entries: entries(),
        }
    }

    pub(super) fn pool(&self) -> PacketPool<'_> {
        PacketPool::new(&self.packets, PoolKind::PacketReceive, 8).expect("a packet pool")
    }
}

pub(super) fn endpoint<'w, 'm>(
    wire: &'w Wire,
    receive: &'m PacketPool<'w>,
) -> Endpoint<'w, 'm, 'w, Mux<'w>> {
    let (_client, owner_end, _net) = network(64, 8384, 21, [Faults::default(); 2]);
    endpoint_on(wire, receive, owner_end)
}

/// The single-peer owner endpoint over `owner_end`, the owner's end of a link. Its one principal holds the PUT grant.
pub(super) fn endpoint_on<'w, 'm>(
    wire: &'w Wire,
    receive: &'m PacketPool<'w>,
    owner_end: LinkEnd<'w>,
) -> Endpoint<'w, 'm, 'w, Mux<'w>> {
    Endpoint {
        config: OWNER,
        keys: Keys {
            principals: &PRINCIPALS[..1],
            entries: &wire.entries[..1],
            epoch: 1,
            put: &PRINCIPALS[..1],
        },
        transport: Mux::new(vec![owner_end]),
        receive,
    }
}

pub(super) fn attachment(storage: &Storage<TestPlatform>) -> Attachment<'_, TestPlatform> {
    Attachment {
        storage,
        clock: ScriptedClock::trusted(),
        depth: DEPTH,
        tick: TICK,
    }
}

/// A turn clock that ticks `control`'s device once per owner poll and fails the test past 4,000 polls.
pub(super) fn turns(control: &SimControl) -> impl FnMut() -> u64 {
    let turn = Cell::new(0_u64);
    move || {
        turn.set(turn.get() + 1);
        assert!(turn.get() < 4_000, "the bootstrap never ended");
        control.tick(64);
        turn.get() * 100
    }
}

/// Runs `body` with the recovery helpers inline, so the bootstrap's ticks do not depend on thread timing.
pub(crate) fn inline<R>(body: impl FnOnce() -> R) -> R {
    let was = INLINE_RECOVERY.with(|inline| inline.replace(true));
    let result = body();
    INLINE_RECOVERY.with(|inline| inline.set(was));
    result
}

fn resident_units(storage: &Storage<TestPlatform>) -> Vec<u64> {
    let mut facts = Vec::new();
    storage.slot_facts_into(&mut facts).expect("a live pool");
    facts
        .iter()
        .filter(|fact| fact.resident)
        .map(|fact| fact.device_unit)
        .collect()
}

/// The device unit of the slot `storage`'s index binds `key` to, through a lookup, or `None` when it misses.
fn bound_unit(storage: &Storage<TestPlatform>, key: &[u8; 32]) -> Option<u64> {
    let mut reader = storage.register().expect("a registration");
    let lease = reader.lookup(key, 4, &mut WorkBudget::new(1 << 16)).ok()?;
    let mut facts = Vec::new();
    storage.slot_facts_into(&mut facts).expect("a live pool");
    Some(facts[lease.id().slot_index()].device_unit)
}

fn live<'a>(
    owner: &Owner<'_, 'a, '_, TestPlatform, Reserving, Mux<'a>>,
) -> (Readiness, MetadataOutcome) {
    (owner.readiness(), owner.volume_metadata_outcome())
}

/// NoEpochReuse: a restart of the volume the record names this host's at `E = 4`, with a named checkpoint and one
/// suffix, bumps to `E = 5` through `recover`; `bring_up` loads the checkpoint and replays the suffix with no device
/// write and reaches `Live` with every retained object restored.
#[test]
fn a_restart_recovers_at_the_next_attempt_and_loads_warm_to_live_with_no_device_write() {
    let (store, media, replacement) = warm_volume_with(false);
    assert_eq!(shard_now(&store).attempts, 4);
    let registry = own_holds();
    let (disk, control) = host_over(&registry, &media, own());
    let arena = arena_with(16, 9);
    let clock = Ticking::default();
    let tenure = tenure(recovered(Role::Restart, &store, disk, &arena, &clock));
    assert_eq!(commands(&registry), ["report", "preempt", "report"]);
    assert_eq!(shard_now(&store).attempts, 5, "the restart's own bump");
    assert_eq!(tenure.authority.session().target().attempts, 5);

    let storage = storage(1);
    let wire = Wire::new();
    let receive = wire.pool();
    let mut budget = EngineBudget::new(1 << 26);
    let owner = inline(|| {
        bring_up(
            &HostGate::qualified(),
            tenure,
            attachment(&storage),
            endpoint(&wire, &receive),
            &mut budget,
            turns(&control),
        )
    })
    .unwrap_or_else(|unbrought| panic!("the bring-up ended {:?}", unbrought.exit));
    assert_eq!(live(&owner), (Readiness::Live, MetadataOutcome::Open));
    assert_eq!(
        control.accepted(Operation::Write),
        0,
        "a warm attach writes nothing"
    );
    let units = resident_units(&storage);
    assert_eq!(
        units.len(),
        4,
        "the checkpoint's objects, one replaced by the suffix"
    );
    assert!(
        units.contains(&u64::from(replacement)),
        "the suffix's replacement of object 2 is resident"
    );
    assert_eq!(
        bound_unit(&storage, &object_key(2)),
        Some(u64::from(replacement)),
        "object 2's key binds the replacement"
    );
    for n in [1, 3, 4] {
        assert!(
            bound_unit(&storage, &object_key(n)).is_some_and(|unit| unit != u64::from(replacement)),
            "object {n} keeps its checkpoint binding"
        );
    }
}

/// FreshIsEmpty: a fresh first acquisition at `E = 0`, with a listing of the own attachment, runs Register, Acquire
/// and Report through `recover` and bumps to `E = 1`; `bring_up` formats the media and reaches `Live` with an empty
/// index.
#[test]
fn a_fresh_acquisition_recovers_at_attempt_one_and_reaches_live_with_an_empty_index() {
    let store = fresh_tests::store(fresh_tests::shard_record(0), fresh_tests::volume_record());
    let registry = shared_table(Vec::new());
    let (disk, control) = crate::host::fencer_tests::host(&registry, fresh_own(), 1);
    let arena = arena_with(16, 9);
    let clock = Driving::new(&control, []);
    let tenure = tenure(recovered(Role::Fresh, &store, disk, &arena, &clock));
    assert_eq!(commands(&registry), ["register", "acquire", "report"]);
    assert_eq!(fresh_tests::shard_now(&store).attempts, 1);

    let storage = storage(1);
    let wire = Wire::new();
    let receive = wire.pool();
    let mut budget = EngineBudget::new(1 << 26);
    let owner = inline(|| {
        bring_up(
            &HostGate::qualified(),
            tenure,
            attachment(&storage),
            endpoint(&wire, &receive),
            &mut budget,
            turns(&control),
        )
    })
    .unwrap_or_else(|unbrought| panic!("the bring-up ended {:?}", unbrought.exit));
    assert_eq!(live(&owner), (Readiness::Live, MetadataOutcome::Open));
    assert!(
        resident_units(&storage).is_empty(),
        "a fresh tenure starts with an empty index"
    );
    assert_eq!(bound_unit(&storage, &object_key(1)), None);
}

/// FENCE-BEFORE-USE: the bring-up's start installs the tenure's coverage and leaves the owner unpolled: the volume
/// still reads `Detached`, which its first poll leaves, and its driver received no command after the sequence's
/// own.
#[test]
fn the_coverage_is_installed_before_the_first_owner_poll() {
    let (store, media) = warm_volume();
    let registry = own_holds();
    let (disk, control) = host_over(&registry, &media, own());
    let arena = arena_with(16, 9);
    let clock = Ticking::default();
    let tenure = tenure(recovered(Role::Restart, &store, disk, &arena, &clock));
    let sequence = commands(&registry);

    let storage = storage(1);
    let wire = Wire::new();
    let receive = wire.pool();
    let mut budget = EngineBudget::new(1 << 26);
    let started = start_up(
        &HostGate::qualified(),
        tenure,
        attachment(&storage),
        endpoint(&wire, &receive),
        &mut budget,
    );
    let mut owner = started.unwrap_or_else(|unbrought| panic!("{:?}", unbrought.exit));
    assert!(owner.coverage_mut().is_some(), "the coverage is installed");
    assert_eq!(
        owner.readiness(),
        Readiness::Detached,
        "no poll ran the bootstrap"
    );
    assert_eq!(
        commands(&registry),
        sequence,
        "no Report after the sequence's"
    );
    assert_eq!(
        control.accepted(Operation::Read) + control.accepted(Operation::Write),
        0,
        "no medium command"
    );
}

/// `start_up` draws the owner's boot nonce from the operating system, so two starts carry two nonces, and
/// `start_up_with_nonce` gives the owner the nonce its caller fills.
#[test]
fn the_start_draws_the_boot_nonce_from_the_os_and_the_nonce_entry_takes_its_callers() {
    let started_with = |scripted: Option<[u8; 16]>| {
        let (store, media) = warm_volume();
        let registry = own_holds();
        let (disk, _control) = host_over(&registry, &media, own());
        let arena = arena_with(16, 9);
        let clock = Ticking::default();
        let tenure = tenure(recovered(Role::Restart, &store, disk, &arena, &clock));
        let storage = storage(1);
        let wire = Wire::new();
        let receive = wire.pool();
        let mut budget = EngineBudget::new(1 << 26);
        let gate = HostGate::qualified();
        let (attachment, endpoint) = (attachment(&storage), endpoint(&wire, &receive));
        let started = match scripted {
            Some(nonce) => {
                let fill = |drawn: &mut [u8; 16]| {
                    *drawn = nonce;
                    Ok(())
                };
                start_up_with_nonce(&gate, tenure, attachment, endpoint, &mut budget, fill)
            }
            None => start_up(&gate, tenure, attachment, endpoint, &mut budget),
        };
        let owner = started.unwrap_or_else(|unbrought| panic!("{:?}", unbrought.exit));
        owner.boot_nonce()
    };
    assert_eq!(started_with(Some([7; 16])), [7; 16]);
    assert_ne!(
        started_with(None),
        started_with(None),
        "each start draws its own nonce"
    );
}

/// The warm restart's tenure over `media` on `registry`, recovered over `arena` on `clock`, and its driver's control.
fn restarted<'a>(
    (store, registry, media): (&Shared, &Control, &Media),
    arena: &'a BufferArena<TestPlatform>,
    clock: &'a Ticking,
) -> (Tenure<'a, TestPlatform, Reserving>, SimControl) {
    let own = crate::host::recover_tests::role_pair(Role::Restart, store);
    let (disk, control) = host_over(registry, media, own);
    (
        tenure(recovered(Role::Restart, store, disk, arena, clock)),
        control,
    )
}

/// Ends `custody` the way its caller must: a driver directly, a volume through its quiesced release, and an owner
/// through its close, polls on `control`'s ticks until nothing blocks it, and its shutdown.
fn release<'a>(
    custody: Custody<'_, 'a, '_, TestPlatform, Reserving, Mux<'a>>,
    control: &SimControl,
) -> Reserving {
    match custody {
        Custody::Driver { disk, .. } => disk,
        Custody::Volume { volume, .. } => {
            let (_, disk) = volume
                .release_driver()
                .unwrap_or_else(|kept| panic!("the volume kept {:?}", kept.1));
            disk
        }
        Custody::Owner(mut owner) => {
            let mut at = 1_000_000;
            owner.close(at);
            while owner.blockers().is_some() {
                assert!(at < 2_000_000, "the owner's teardown never drained");
                control.tick(64);
                at += 100;
                owner.poll(at);
            }
            owner
                .shutdown()
                .unwrap_or_else(|kept| panic!("the owner kept {:?}", kept.1))
                .disk
        }
    }
}

/// `bring_up` of `tenure` over `storage` with `config` and attach `depth`, polled at `now_us`, ending short of `Live`:
/// its exit and the kind of custody it returned. The custody is released through its own teardown before it drops,
/// and a returned driver leaves the engine budget uncharged.
fn unbrought(
    tenure: Tenure<'_, TestPlatform, Reserving>,
    storage: &Storage<TestPlatform>,
    config: (OwnerConfig, u16),
    driven: (&SimControl, impl FnMut() -> u64),
) -> (Exit, &'static str) {
    let (exit, kind, _) = unbrought_reading(tenure, storage, config, driven);
    (exit, kind)
}

/// A same-host restart over `store`'s record, `media` and the reservation table `registry`, over the storage `make`
/// builds, whose bring-up ends short of `Live`: its exit and the volume's metadata outcome, which names a refused
/// warm load's refusal.
pub(crate) fn restart_short_of_live(
    (store, registry, media): (&Shared, &Control, &Media),
    make: fn() -> Storage<TestPlatform>,
) -> (Exit, Option<MetadataOutcome>) {
    let (arena, clock) = (arena_with(16, 9), Ticking::default());
    let (acquired, control) = restarted((store, registry, media), &arena, &clock);
    let volume_storage = make();
    let (exit, _, outcome) = unbrought_reading(
        acquired,
        &volume_storage,
        (OWNER, DEPTH),
        (&control, turns(&control)),
    );
    (exit, outcome)
}

/// [`unbrought`], with the metadata outcome of the returned volume or owner, `None` for a returned driver.
fn unbrought_reading(
    tenure: Tenure<'_, TestPlatform, Reserving>,
    storage: &Storage<TestPlatform>,
    (config, depth): (OwnerConfig, u16),
    (control, now_us): (&SimControl, impl FnMut() -> u64),
) -> (Exit, &'static str, Option<MetadataOutcome>) {
    let wire = Wire::new();
    let receive = wire.pool();
    let mut budget = EngineBudget::new(1 << 26);
    let endpoint = Endpoint {
        config,
        ..endpoint(&wire, &receive)
    };
    let attachment = Attachment {
        depth,
        ..attachment(storage)
    };
    let brought = inline(|| {
        bring_up(
            &HostGate::qualified(),
            tenure,
            attachment,
            endpoint,
            &mut budget,
            now_us,
        )
    });
    let Err(unbrought) = brought else {
        panic!("the bring-up reached Live");
    };
    let Unbrought { exit, custody } = *unbrought;
    let (kind, outcome) = match &custody {
        Custody::Driver { .. } => ("driver", None),
        Custody::Volume { volume, .. } => ("volume", Some(volume.metadata_outcome())),
        Custody::Owner(owner) => ("owner", Some(owner.volume_metadata_outcome())),
    };
    if kind == "driver" {
        assert_eq!(budget.used(), 0, "a returned driver charged nothing");
    }
    drop(release(custody, control));
    (exit, kind, outcome)
}

/// One turn of a bring-up with `turn_up`'s signature: `turn_up` itself, or a control's altered copy.
type Turn = for<'o, 'a> fn(
    &HostGate,
    &mut Owner<'o, 'a, 'o, TestPlatform, Reserving, Mux<'a>>,
    &mut dyn FnMut() -> u64,
) -> Rising;

/// How a differential row drives the bring-up: `bring_up` whole, or `start_up` and then `Turn` until it ends.
#[derive(Clone, Copy)]
enum Drive {
    Whole,
    Turns(Turn),
}

/// What one driven bring-up ended in: its end, the owner's readiness and metadata outcome, the resident device units,
/// the clock reads (one per poll), the device's accepted writes (a format writes, a refused one does not) and the
/// reservation commands of the table after the sequence's.
type Ended = (
    Rising,
    (Readiness, MetadataOutcome),
    Vec<u64>,
    u64,
    usize,
    usize,
);

fn driven(
    tenure: Tenure<'_, TestPlatform, Reserving>,
    control: &SimControl,
    registry: &Control,
    drive: Drive,
) -> Ended {
    let gate = HostGate::qualified();
    let target = tenure.authority.session().target();
    let commands = registry.borrow().log.len();
    let storage = storage(1);
    let wire = Wire::new();
    let receive = wire.pool();
    let mut budget = EngineBudget::new(1 << 26);
    let reads = Cell::new(0_u64);
    let mut now = || {
        reads.set(reads.get() + 1);
        assert!(reads.get() < 4_000, "the bootstrap never ended");
        control.tick(64);
        reads.get() * 100
    };
    let (end, owner) = inline(|| match drive {
        Drive::Whole => {
            let brought = bring_up(
                &gate,
                tenure,
                attachment(&storage),
                endpoint(&wire, &receive),
                &mut budget,
                &mut now,
            );
            match brought {
                Ok(owner) => (Rising::Live, owner),
                Err(unbrought) => match unbrought.custody {
                    Custody::Owner(owner) => (Rising::Short(unbrought.exit), *owner),
                    _ => panic!("a bootstrap's short end returns the owner"),
                },
            }
        }
        Drive::Turns(turn) => {
            let started = start_up(
                &gate,
                tenure,
                attachment(&storage),
                endpoint(&wire, &receive),
                &mut budget,
            );
            let mut owner = started.unwrap_or_else(|unbrought| panic!("{:?}", unbrought.exit));
            assert_eq!(
                owner.tenure().target(),
                target,
                "the started owner holds the tenure's (g, owner, E)"
            );
            assert!(
                std::ptr::eq(owner.storage(), &storage),
                "the started owner holds the attachment's storage"
            );
            loop {
                match turn(&gate, &mut owner, &mut now) {
                    Rising::Initializing => {}
                    end => break (end, owner),
                }
            }
        }
    });
    let ended = (
        end,
        live(&owner),
        resident_units(&storage),
        reads.get(),
        control.accepted(Operation::Write),
        registry.borrow().log.len() - commands,
    );
    drop(release(Custody::Owner(Box::new(owner)), control));
    ended
}

/// `turn_up` over a `&mut dyn` clock, as a [`Turn`].
fn stepped<'o, 'a>(
    gate: &HostGate,
    owner: &mut Owner<'o, 'a, 'o, TestPlatform, Reserving, Mux<'a>>,
    now: &mut dyn FnMut() -> u64,
) -> Rising {
    turn_up(gate, owner, now)
}

/// Control: a turn that formats whenever the bootstrap initializes, ahead of the `Unformatted` reading `turn_up`
/// waits for. The volume rejects a format before that reading, so the bring-up stops on the first turn, before the
/// owner's first poll.
fn formats_early<'o, 'a>(
    gate: &HostGate,
    owner: &mut Owner<'o, 'a, 'o, TestPlatform, Reserving, Mux<'a>>,
    now: &mut dyn FnMut() -> u64,
) -> Rising {
    if owner.readiness().initializing() && owner.format().is_err() {
        return Rising::Short(Exit::Held {
            recovery: owner.tenure().target(),
        });
    }
    turn_up(gate, owner, now)
}

/// Control: a turn that returns `Initializing` from the poll that ended the bootstrap, so the next turn polls once
/// more before its initializing check.
fn polls_past_the_end<'o, 'a>(
    gate: &HostGate,
    owner: &mut Owner<'o, 'a, 'o, TestPlatform, Reserving, Mux<'a>>,
    now: &mut dyn FnMut() -> u64,
) -> Rising {
    let initializing = owner.readiness().initializing();
    owner.poll(now());
    if initializing {
        return Rising::Initializing;
    }
    turn_up(gate, owner, || 0)
}

/// The rows of the differential case: a warm restart to `Live`, a fresh tenure that formats its media to `Live`, a
/// damaged certified suffix that holds at the tenure, and an unrecorded holder at the first Report that retires.
#[derive(Debug, Clone, Copy)]
enum Case {
    Warm,
    Fresh,
    Damaged,
    Unrecorded,
}

/// Recovers `case`'s tenure and drives its bring-up by `drive`: what it ended in, and the tenure's `(g, owner, E)`.
fn bring_up_case(case: Case, drive: Drive) -> (Ended, Target) {
    let arena = arena_with(16, 9);
    let ticking = Ticking::default();
    if let Case::Fresh = case {
        let store = fresh_tests::store(fresh_tests::shard_record(0), fresh_tests::volume_record());
        let registry = shared_table(Vec::new());
        let (disk, control) = crate::host::fencer_tests::host(&registry, fresh_own(), 1);
        let clock = Driving::new(&control, []);
        let acquired = tenure(recovered(Role::Fresh, &store, disk, &arena, &clock));
        let target = acquired.authority.session().target();
        return (driven(acquired, &control, &registry, drive), target);
    }
    let (store, media, _) = warm_volume_with(matches!(case, Case::Damaged));
    let registry = own_holds();
    let (acquired, control) = restarted((&store, &registry, &media), &arena, &ticking);
    if let Case::Unrecorded = case {
        registry.borrow_mut().entries =
            vec![registrant(own(), 1, false), registrant(foreign(), 2, true)];
    }
    let target = acquired.authority.session().target();
    (driven(acquired, &control, &registry, drive), target)
}

/// `bring_up` and a bring-up driven turn by turn through `start_up` and `turn_up` end in the same state for the same
/// inputs: the same end (`Live`, `Held` at the tenure, `Retire` at the tenure), readiness, resident units, clock reads
/// (one per poll), device writes (the fresh case's one format) and reservation commands. The clock reads, device
/// writes and reservation commands of each case are pinned to the counts the single blocking poll loop gave over
/// the same inputs, so a change of `turn_up` that both arms share, such as a second poll in a turn or a poll past the
/// bootstrap's end, changes a pinned count.
#[test]
fn a_bring_up_driven_turn_by_turn_ends_where_bring_up_ends() {
    for (case, pinned) in [
        (Case::Warm, (13, 0, 1)),
        (Case::Fresh, (8, 3, 1)),
        (Case::Damaged, (7, 0, 1)),
        (Case::Unrecorded, (3, 0, 1)),
    ] {
        let (whole, target) = bring_up_case(case, Drive::Whole);
        let (turns, _) = bring_up_case(case, Drive::Turns(stepped));
        assert_eq!(turns, whole, "{case:?}");
        assert_eq!(
            (whole.3, whole.4, whole.5),
            pinned,
            "{case:?}: reads, writes, commands"
        );
        let expected = match case {
            Case::Warm | Case::Fresh => Rising::Live,
            Case::Damaged => Rising::Short(Exit::Held { recovery: target }),
            Case::Unrecorded => Rising::Short(Exit::Retire(target)),
        };
        assert_eq!(turns.0, expected, "{case:?}");
        assert_eq!(
            turns.4 > 0,
            matches!(case, Case::Fresh),
            "{case:?}: only the fresh media formats"
        );
    }
}

/// Control: a turn that formats ahead of the `Unformatted` reading, and one that polls once past the bootstrap's
/// end, each end apart from `bring_up` in the differential case.
#[test]
fn control_a_turn_that_formats_early_or_polls_past_the_end_differs_from_bring_up() {
    let (whole, target) = bring_up_case(Case::Warm, Drive::Whole);
    assert_eq!(whole.0, Rising::Live);

    let (early, _) = bring_up_case(Case::Warm, Drive::Turns(formats_early));
    assert_eq!(
        (&early.0, early.3),
        (&Rising::Short(Exit::Held { recovery: target }), 0),
        "the refused format ends the first turn with no clock read"
    );
    assert_ne!(early, whole);

    let (past, _) = bring_up_case(Case::Warm, Drive::Turns(polls_past_the_end));
    assert_eq!(past.3, whole.3 + 1, "one clock read past bring_up's");
    assert_ne!(past, whole);
}

/// HOST-LOSS-KEEPS-VOLUME, CUSTODY-RETURNS: a certified suffix block that does not decode refuses the warm load; the
/// bring-up holds at the tenure's `(g, owner, E)` with no flip and returns the owner, and the attach wrote nothing.
#[test]
fn a_damaged_suffix_holds_at_the_tenure_and_returns_the_owner() {
    let (store, media, _) = warm_volume_with(true);
    let registry = own_holds();
    let (arena, clock) = (arena_with(16, 9), Ticking::default());
    let (acquired, control) = restarted((&store, &registry, &media), &arena, &clock);
    let target = acquired.authority.session().target();
    let volume_storage = storage(1);
    let (exit, custody) = unbrought(
        acquired,
        &volume_storage,
        (OWNER, DEPTH),
        (&control, turns(&control)),
    );
    assert_eq!((exit, custody), (Exit::Held { recovery: target }, "owner"));
    assert_eq!(control.accepted(Operation::Write), 0);
}

/// The holder the bring-up's first Report finds decides its exit: an unrecorded holder that took the reservation
/// after the restart's Report #2 withdraws the authority with a flip request, which parks as `Retire` at the tenure's
/// `(g, owner, E)`; C's recorded pair holding, and a deposing status on that Report, withdraw it with no flip, which
/// holds there (HOST-LOSS-KEEPS-VOLUME). Each returns the owner, and no medium command follows the withdrawal.
#[test]
fn the_holder_at_the_first_bring_up_report_decides_retire_or_hold() {
    use crate::failover::takeover::tests::c_pair;
    use crate::storage::DeviceStatus;
    type Change = fn(&Control);
    let rows: [(&str, Change, bool); 3] = [
        (
            "unrecorded holder",
            |registry| {
                registry.borrow_mut().entries =
                    vec![registrant(own(), 1, false), registrant(foreign(), 2, true)];
            },
            true,
        ),
        (
            "recorded holder",
            |registry| {
                registry.borrow_mut().entries =
                    vec![registrant(own(), 1, false), registrant(c_pair(), 2, true)];
            },
            false,
        ),
        (
            "deposing status",
            |registry| registry.borrow_mut().report_status = Some(DeviceStatus::Nvme(0x83 << 1)),
            false,
        ),
    ];
    for (row, change, retires) in rows {
        let (store, media) = warm_volume();
        let registry = own_holds();
        let (arena, clock) = (arena_with(16, 9), Ticking::default());
        let (acquired, control) = restarted((&store, &registry, &media), &arena, &clock);
        let target = acquired.authority.session().target();
        change(&registry);
        let medium = registry.borrow().medium;
        let volume_storage = storage(1);
        let (exit, custody) = unbrought(
            acquired,
            &volume_storage,
            (OWNER, DEPTH),
            (&control, turns(&control)),
        );
        let expected = if retires {
            Exit::Retire(target)
        } else {
            Exit::Held { recovery: target }
        };
        assert_eq!((exit, custody), (expected, "owner"), "{row}");
        assert_eq!(registry.borrow().medium, medium, "{row}: no medium command");
    }
}

/// CUSTODY-RETURNS: each refused step before the first poll returns the value that holds the driver, and each ends
/// `Fault` with no flip: a refused attach, and a storage whose facade another holder already issued, return the
/// driver itself and leave the storage's facade and attach as they were; a refused registration and a refused owner
/// start return the volume; a fencing of another tenure returns the owner.
#[test]
fn each_refused_bring_up_step_returns_the_custody_that_holds_the_driver() {
    let fault =
        |exit: &Exit, step: &str| matches!(exit, Exit::Fault(text) if text.starts_with(step));
    let (arena, clock) = (arena_with(16, 9), Ticking::default());
    let warm = || {
        let (store, media) = warm_volume();
        restarted((&store, &own_holds(), &media), &arena, &clock)
    };

    let (acquired, control) = warm();
    let volume_storage = storage(1);
    let (exit, custody) = unbrought(
        acquired,
        &volume_storage,
        (OWNER, 0),
        (&control, turns(&control)),
    );
    assert!(fault(&exit, "volume attach"), "{exit:?}");
    assert_eq!(custody, "driver");
    assert!(
        !volume_storage.is_issued(),
        "a refused attach issues no facade"
    );

    let (acquired, control) = warm();
    let volume_storage = storage(1);
    let held = volume_storage
        .issue_cache()
        .expect("the storage's one facade");
    let (exit, custody) = unbrought(
        acquired,
        &volume_storage,
        (OWNER, DEPTH),
        (&control, turns(&control)),
    );
    assert!(fault(&exit, "storage"), "{exit:?}");
    assert_eq!(custody, "driver");
    assert!(
        held.register().is_ok(),
        "the other holder's facade still registers"
    );
    drop(held);

    let (acquired, control) = warm();
    let volume_storage = storage(1);
    let readers: Vec<_> = std::iter::from_fn(|| volume_storage.register().ok()).collect();
    assert!(!readers.is_empty());
    let (exit, custody) = unbrought(
        acquired,
        &volume_storage,
        (OWNER, DEPTH),
        (&control, turns(&control)),
    );
    drop(readers);
    assert!(fault(&exit, "storage: ReaderLimit"), "{exit:?}");
    assert_eq!(custody, "volume");

    let (acquired, control) = warm();
    let volume_storage = storage(1);
    let refusing = OwnerConfig {
        request_slots: 0,
        ..OWNER
    };
    let (exit, custody) = unbrought(
        acquired,
        &volume_storage,
        (refusing, DEPTH),
        (&control, turns(&control)),
    );
    assert!(fault(&exit, "owner start"), "{exit:?}");
    assert_eq!(custody, "volume");

    let fresh_store =
        fresh_tests::store(fresh_tests::shard_record(0), fresh_tests::volume_record());
    let fresh_registry = shared_table(Vec::new());
    let (disk, fresh_control) = crate::host::fencer_tests::host(&fresh_registry, fresh_own(), 1);
    let fresh_clock = Driving::new(&fresh_control, []);
    let other = tenure(recovered(
        Role::Fresh,
        &fresh_store,
        disk,
        &arena,
        &fresh_clock,
    ));
    let (own_tenure, control) = warm();
    let mismatched = Tenure {
        fencing: other.fencing,
        ..own_tenure
    };
    let volume_storage = storage(1);
    let (exit, custody) = unbrought(
        mismatched,
        &volume_storage,
        (OWNER, DEPTH),
        (&control, turns(&control)),
    );
    assert!(fault(&exit, "coverage"), "{exit:?}");
    assert_eq!(custody, "owner");
}

/// A turn whose clock unwinds after two bootstrap polls ends the bring-up `Rerun(Unwound)` with the owner, whose
/// teardown then drains every read and command it still holds.
#[test]
fn a_turn_that_unwinds_returns_the_owner_for_its_teardown() {
    use crate::host::Rerun;
    let (store, media) = warm_volume();
    let registry = own_holds();
    let (arena, clock) = (arena_with(16, 9), Ticking::default());
    let (acquired, control) = restarted((&store, &registry, &media), &arena, &clock);
    let turn = Cell::new(0_u64);
    let unwinding = || {
        turn.set(turn.get() + 1);
        assert!(turn.get() < 3, "a turn clock that unwinds");
        turn.get() * 100
    };
    let volume_storage = storage(1);
    let (exit, custody) = unbrought(
        acquired,
        &volume_storage,
        (OWNER, DEPTH),
        (&control, unwinding),
    );
    assert_eq!((exit, custody), (Exit::Rerun(Rerun::Unwound), "owner"));
    assert_eq!(turn.get(), 3, "two polls ran before the clock unwound");
}

/// A turn whose clock unwinds with a payload that panics as it drops ends the bring-up `Rerun(Unwound)` with the
/// owner, and that payload is dropped once.
#[test]
fn a_turn_whose_unwind_payload_panics_on_drop_returns_the_owner() {
    use crate::host::Rerun;
    use crate::storage::{Bomb, Dropped};
    let (store, media) = warm_volume();
    let registry = own_holds();
    let (arena, clock) = (arena_with(16, 9), Ticking::default());
    let (acquired, control) = restarted((&store, &registry, &media), &arena, &clock);
    let dropped = Dropped::default();
    let turn = Cell::new(0_u64);
    let unwinding = || {
        turn.set(turn.get() + 1);
        if turn.get() == 3 {
            std::panic::panic_any(Bomb(dropped.clone()));
        }
        turn.get() * 100
    };
    let volume_storage = storage(1);
    let (exit, custody) = unbrought(
        acquired,
        &volume_storage,
        (OWNER, DEPTH),
        (&control, unwinding),
    );
    assert_eq!((exit, custody), (Exit::Rerun(Rerun::Unwound), "owner"));
    assert_eq!(*dropped.lock().unwrap(), ["bomb"]);
}

/// A fresh first acquisition whose Confirm reply is lost after the activation write ends the incarnation at `E = 1`
/// with no tenure, in both commit arms, and returns its driver. The next incarnation reads the same host-local
/// records; its role read finds the restart, whose record names no checkpoint, so its bootstrap reads the media the
/// fresh path left `Unformatted`, and `bring_up` formats it, under the restart's own bump to `E = 2`, and reaches
/// `Live` with an empty index.
#[test]
fn a_cold_restart_after_an_unconfirmed_fresh_tenure_formats_and_reaches_live() {
    use crate::failover::fresh::Refusals;
    use crate::host::fencer::Release;
    use crate::host::recover_tests::{ended, traced_recovery};
    use crate::host::{Rerun, role};
    use crate::storage::device::sim::media;
    use crate::storage::store::sim::Arm;
    use crate::storage::store_tests::{client, shard};
    for commit in [false, true] {
        let store = fresh_tests::store(fresh_tests::shard_record(0), fresh_tests::volume_record());
        let registry = shared_table(Vec::new());
        let shared = media(config_for(7).capacity);
        let log = fresh_tests::Log::default();
        let mut local = fresh_tests::records(&log);
        let (disk, control) = host_over(&registry, &shared, fresh_own());
        let arena = arena_with(16, 9);
        let driving = Driving::new(&control, []);
        for arm in [Arm::Pass, Arm::Pass, Arm::Pass, Arm::Pass] {
            store.schedule(arm);
        }
        store.schedule(Arm::Timeout { commit });
        let fencer = fencer_of(disk, fresh_own(), &arena, &driving);
        let (recovery, _) = traced_recovery(
            Role::Fresh,
            &store,
            fencer,
            (&mut local, &[], &mut Refusals::default()),
        );
        let (exit, device) = ended(recovery);
        assert_eq!(exit, Exit::Rerun(Rerun::Unactivated), "commit {commit}");
        assert!(matches!(device, Release::Driver(_)), "commit {commit}");
        drop(device);
        assert!(!local.refused, "commit {commit}: the retention released");
        assert_eq!(fresh_tests::shard_now(&store).attempts, 1);
        assert!(
            control.accepted(Operation::Write) > 0,
            "the activation write"
        );
        let holder = fresh_tests::holder();
        assert_eq!(
            role(&mut client(&store), shard(), &holder),
            Ok(Role::Restart)
        );

        let (disk, control) = host_over(&registry, &shared, fresh_own());
        let clock = Ticking::default();
        let fencer = fencer_of(disk, fresh_own(), &arena, &clock);
        let (recovery, _) = traced_recovery(
            Role::Restart,
            &store,
            fencer,
            (&mut local, &[], &mut Refusals::default()),
        );
        let acquired = tenure(recovery);
        assert_eq!(acquired.authority.session().target().attempts, 2);
        let volume_storage = storage(1);
        let wire = Wire::new();
        let receive = wire.pool();
        let mut budget = EngineBudget::new(1 << 26);
        let owner = inline(|| {
            bring_up(
                &HostGate::qualified(),
                acquired,
                attachment(&volume_storage),
                endpoint(&wire, &receive),
                &mut budget,
                turns(&control),
            )
        })
        .unwrap_or_else(|unbrought| panic!("the bring-up ended {:?}", unbrought.exit));
        assert_eq!(live(&owner), (Readiness::Live, MetadataOutcome::Open));
        assert!(
            control.accepted(Operation::Write) > 0,
            "the format's RESET writes"
        );
        assert!(resident_units(&volume_storage).is_empty());
        assert_eq!(bound_unit(&volume_storage, &object_key(1)), None);
    }
}
