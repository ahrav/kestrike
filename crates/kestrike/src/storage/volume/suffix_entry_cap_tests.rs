//! Warm takeovers of a volume whose records layout has an entry cap `N_max` below the slot count of the tenure's
//! pool. The property is the retention rule `a retained entry outside every damage set was lost on host loss`
//! (`net/world_tests/narrate/rules.rs`): no recorded publication leaves a stored record whose replay rebuilds a set
//! past the entry cap, which no warm load admits.
//!
//! The volume's records layout holds checkpoint slots of two units, so its entry cap `N_max` is the 41 entries of
//! one data unit, below the 64 slots of the tenure's pool. Each history is a cold first tenure and a chain of warm
//! successors over the same media and the same stored shard record. A tenure lets every write land and is lost; its
//! successor bumps `E` and attaches warm. Each history asserts one thing: every key whose fill a tenure
//! acknowledged, that no tenure removed, that no coverage holds and that no faulted read touched, serves its exact
//! bytes from the last successor, whose warm load ended `Open`. A fill that a tenure refuses is not counted.
//!
//! Each of these histories attempts a fill that would push the record past its entry cap.
//! - In the first tenure: 41 fills, a checkpoint of them, the suffix opens, one more fill.
//! - Replacement in the first tenure: the capture pass starts after 41 fills. The tenure acknowledges the fill of
//!   key 42, publishes the pass's checkpoint and opens the suffix, so the membership is 42 and the checkpoint holds
//!   41 entries. The tenure attempts a replacement of key 42, whose insert would be the record's 42nd entry.
//!   The history judges the keys a record holds: the 41 checkpoint keys, and key 42 when its replacement is
//!   acknowledged.
//! - During a second pass in the first tenure: the first pass starts after 39 fills, the tenure acknowledges the
//!   fills of keys 40 and 41 and publishes the pass's checkpoint of 39 entries, and the suffix opens at a
//!   membership of 41. A second pass starts, the tenure attempts the fill of key 42 while it is in flight, and
//!   publishes the pass, whose checkpoint holds the 41 members at its cut. The insert of key 42 would be that
//!   record's 42nd entry.
//! - In a successor, beside an entry its load omitted: the first tenure publishes a checkpoint of 41 fills. The
//!   second tenure attaches under a fenced coverage that holds version 0 of one checkpoint key, so it serves 40 keys
//!   while a replay of its record rebuilds 41 entries. It opens its suffix and attempts the fill of one new key in a
//!   slot and a unit the omitted entry never held.
//! - The successor runs one suffix store step using the first tenure's starting read. The step returns
//!   `WriteRefused::Tenure`, and the successor then attempts the fill.
//! - In a successor, behind a block its load misread: the first tenure publishes a checkpoint of 40 fills, opens its
//!   suffix and acknowledges the fill of key 41, whose record lands in the first block of the suffix. The second
//!   tenure's read of that block gets the simulated device's `Fault::CorruptSuccess`: the command reports success
//!   with other bytes and the media keep the written bytes. Its load takes the block for the unflushed tail, ends
//!   `Open` with 40 entries and reports no damage. It opens its suffix and attempts the fill of one new key in a
//!   slot and a unit that key 41 never held. The third tenure's load meets no fault. Key 41 is not judged from the
//!   second tenure on, because the faulted read was of its record.
//! - The same, where the misread blocks hold a removal before the insert: the first tenure publishes a checkpoint
//!   of 41 fills, opens its suffix, invalidates key 1 and fills key 42, and the two records land in the first two
//!   blocks. The second tenure's reads of both blocks get the fault. Its load restores keys 1 to 41; the tenure
//!   invalidates key 1, which the record no longer holds, and attempts the fill of one new key at the count it
//!   restored.
//! - In a successor of fewer slots, behind a block its load misread: tenures of 64, 41 and 64 slots. The first
//!   tenure publishes a checkpoint of 40 fills in slots below 40, opens its suffix and acknowledges the fill of one
//!   more key, which takes a slot past 40 and lands in the first block of the suffix. The second tenure, of 41
//!   slots, misreads that block, restores 40 entries and attempts the fill of one new key into its one free slot,
//!   in a unit the misread fill never held. That history is a known defect and expects its assertion to fail:
//!   the second tenure bounds the replayed set by its own slot count and acknowledges the fill, and the third
//!   tenure's load counts 42 entries and refuses `Entries`, which its control pins.
//! - A successor of fewer slots over a wider writer's history, with no fault: a writer of 64 slots under an entry cap
//!   of 82 records a key in a slot past 40, in its checkpoint or through its suffix, and a successor of 41 slots
//!   refuses the load, `Slot` for the checkpoint and `StaleWrite` for the suffix.
//!
//! The last two histories are known defects of pools of different slot counts on one volume. Each breaks
//! ONE-SLOT-COUNT of `storage::recovery::suffix`, the deployment's obligation, and its test pins the outcome.
//!
//! The sibling histories run the same steps and end within the entry cap: 41 fills and none after the checkpoint;
//! 40 fills and one through the suffix; a successor that omits an entry and publishes nothing; a successor that
//! publishes a checkpoint of its own members, runs one store step of its suffix and then fills to the cap; a
//! successor whose load misreads the block and which publishes nothing; and, under a layout whose entry cap of 82
//! covers the 64 slots, a successor that fills before any checkpoint of its own.
//!
//! After 40 fills, the first tenure fills key 41 during capture. Replacing key 41 through the suffix brings the
//! recorded set to the entry cap.
//!
//! After 38 fills, the first tenure fills keys 39 and 40 during capture. The fill of key 41 during the second pass
//! brings that pass's record to the entry cap.

use super::super::sim_tests::{PREFIX, storage, storage_of};
use super::super::tests::{live, tick};
use crate::failover::records::{Layout, NamedCheckpoint, ShardRecord, UNIT_ENTRIES, VolumeRecord};
use crate::failover::restart::tests as restart_tests;
use crate::failover::retire::Target as Own;
use crate::failover::takeover::tests::{c_host, with_c};
use crate::storage::checkpoint::{
    Checkpoint, PossiblyNamed, StagedCheckpoint, SuffixBounds, SuffixLimits, WriteRefused,
    open_suffix, publish, suffix_step,
};
use crate::storage::device::sim::{Fault, Stage};
use crate::storage::device::sim::{Media, media};
use crate::storage::ledger::EngineBudget;
use crate::storage::lookup::LookupError;
use crate::storage::lookup_tests::lookup;
use crate::storage::publication_tests::{publish as fill, reserved};
use crate::storage::publish_tests::key;
use crate::storage::record::Crc32c;
use crate::storage::recovery::capture_tests::{drain, finish};
use crate::storage::recovery::session_at;
use crate::storage::store::Key as StoreKey;
use crate::storage::store::sim::Shared;
use crate::storage::store::{Client, Read, Store, WatermarkLog};
use crate::storage::store_tests::{client, shard};
use crate::storage::test_platform::TestPlatform;
use crate::storage::volume::checkpoint::UnitDone;
use crate::storage::volume_fixture::{
    Device, MEDIA, arena_with, attach_under, bootstrap, fenced, read_back,
};
use crate::storage::{
    MetadataOutcome, ReadStatus, ServingAuthority, Storage, WarmSource, WorkBudget,
};

thread_local! {
    /// The entry cap of the layout of the history that runs: 41 unless a test sets another.
    static ENTRIES: std::cell::Cell<u32> = const { std::cell::Cell::new(UNIT_ENTRIES as u32) };
}

/// The records layout of the volume: three checkpoint slots over the fixture's prefix, each of the units its entry
/// cap needs, so under the cap of 41 a slot holds the entries of one data unit; the rest of the prefix is the delta
/// region.
fn layout() -> Layout {
    let entries = ENTRIES.with(std::cell::Cell::get);
    Layout {
        units: PREFIX,
        slots: 3,
        slot_units: entries.div_ceil(UNIT_ENTRIES as u32) + 1,
        entries,
    }
}

/// The suffix bounds of every tenure: a block seals at the next delta stage, and a tenure reserves eight blocks, so
/// its recorded changes meet the entry cap and not the reservation.
const BOUNDS: SuffixBounds = SuffixBounds {
    limits: SuffixLimits {
        flush_ns: 0,
        queue_blocks: 8,
        oldest_ns: 1 << 40,
        uncertified: 16,
    },
    step: 8,
    margin: 1,
};

/// The body the fill of `key(n)` publishes.
fn body(n: u8) -> [u8; 40] {
    [n; 40]
}

/// Attempts the fill of `key(n)`, services both shards' fill tables and returns whether the fill was acknowledged.
fn acknowledged<'s>(storage: &'s Storage<TestPlatform>, dev: &mut Device<'s, '_>, n: u8) -> bool {
    let published = fill(storage, dev, &key(n), &body(n)).is_ok();
    for shard in 0..2 {
        storage
            .service_fills(
                crate::index::ShardIndex(shard),
                8,
                &mut WorkBudget::new(1 << 20),
            )
            .expect("premise: the fill tables are serviced");
    }
    published
}

/// Starts a capture pass under the layout's entry cap and returns its counter.
fn start_pass(storage: &Storage<TestPlatform>) -> u32 {
    storage
        .start_capture(layout().entries as usize, true, 1024)
        .expect("premise: the capture pass starts under the layout's entry cap");
    storage
        .pool()
        .capture_lock()
        .expect("premise: the capture mutex")
        .counter()
}

/// Publishes pass `counter` as a checkpoint of the tenure of `session` and `possible` over the record `read`, whose named
/// checkpoint is `known`: walks the pass, stages the checkpoint, writes and reads back each unit, publishes and
/// ends the pass. Returns the committed record.
fn publish_pass<'s, S: Store, L: WatermarkLog>(
    storage: &'s Storage<TestPlatform>,
    dev: &mut Device<'s, '_>,
    (host, possible): (&mut Client<S, L>, &mut PossiblyNamed),
    (read, own, known): (&Read<ShardRecord>, Own, Option<NamedCheckpoint>),
    (session, counter): (u64, u32),
) -> Read<ShardRecord> {
    let shard = shard();
    let entries = drain(storage);
    let proof = storage
        .cut_intact((shard, session), counter)
        .expect("premise: the pass is publishable");
    let checkpoint = Checkpoint {
        shard,
        session,
        capture: counter,
    };
    let mut stage = StagedCheckpoint::new(
        Crc32c::detect(),
        possible,
        (checkpoint, &entries),
        &EngineBudget::unlimited(),
    )
    .expect("premise: the checkpoint stages");
    for unit in 0..stage.units().len() as u32 {
        dev.volume
            .stage_unit_write(possible, &mut stage, unit)
            .expect("premise: the unit write stages");
        let done = (0..64).find_map(|_| {
            tick(&mut dev.volume, &dev.control);
            dev.volume.take_unit()
        });
        let slot = stage.slot();
        assert_eq!(
            done,
            Some(UnitDone::Written { slot, unit }),
            "premise: the unit is written"
        );
        dev.volume
            .stage_unit_read(possible, (slot, unit))
            .expect("premise: the read-back stages");
        let done = (0..64).find_map(|_| {
            tick(&mut dev.volume, &dev.control);
            dev.volume.take_unit_for(&mut stage)
        });
        assert_eq!(
            done,
            Some(UnitDone::Read { slot, unit }),
            "premise: the unit reads back"
        );
    }
    let committed = publish(
        host,
        possible,
        read,
        (own, known),
        (&proof, storage.capture_epoch()),
        &mut stage,
    )
    .expect("premise: the pass publishes");
    finish(storage, counter).expect("premise: the published pass ends");
    committed
}

/// Invalidates `key(n)`, services both shards' fill tables and returns whether an entry was removed.
fn invalidated(storage: &Storage<TestPlatform>, n: u8) -> bool {
    let removed = storage
        .invalidate(&key(n), 4, &mut WorkBudget::new(1 << 20))
        .is_ok_and(|done| done.removed.is_some());
    for shard in 0..2 {
        storage
            .service_fills(
                crate::index::ShardIndex(shard),
                8,
                &mut WorkBudget::new(1 << 20),
            )
            .expect("premise: the fill tables are serviced");
    }
    removed
}

fn fresh_records() -> Shared {
    restart_tests::store(
        ShardRecord {
            standby: Some(c_host()),
            ..restart_tests::shard_record(4)
        },
        VolumeRecord {
            layout: layout(),
            ..with_c()
        },
    )
}

/// The first tenure executes these steps in field order around its checkpoint of keys `1..=before`.
#[derive(Clone, Copy, Default)]
struct First {
    /// After the capture cut and before the suffix opens, the tenure acknowledges fills for this many keys
    /// following `before`. Those keys remain in memory only.
    unrecorded: u8,
    /// The tenure invalidates this key once its suffix is open.
    removed: Option<u8>,
    /// Through its open suffix, the tenure attempts fills for this many keys following `before`. The first
    /// `min(after, unrecorded)` attempts target memory-only keys.
    after: u8,
    /// The tenure starts a second capture pass, attempts fills for this many keys following every earlier key
    /// while the pass is in flight, and publishes the pass. Its checkpoint holds every member at its cut, the
    /// memory-only keys among them.
    second: u8,
}

/// The returned keys are the checkpoint keys that survive invalidation plus the keys whose fills the suffix
/// acknowledges, and the memory-only keys once a second pass checkpoints them.
fn first_tenure(before: u8, plan: First) -> (Shared, Media, Vec<u8>) {
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let medium = media(MEDIA);
    let session = session_at(3, 3).get();
    let authority = ServingAuthority::fixture_under(session_at(3, 3));
    let (mut volume, control) =
        attach_under(&storage, &buffers, &medium, authority).expect("premise: the cold attach");
    bootstrap(&mut volume, &control);
    let mut dev = Device { volume, control };
    assert_eq!(
        layout().check_floor(),
        Ok(()),
        "premise: the layout is admitted"
    );
    let records = fresh_records();
    let mut host = client(&records);
    let read = host
        .read::<ShardRecord>(StoreKey::Shard(shard()))
        .expect("premise: the shard record reads");
    assert_eq!(
        read.value().checkpoint,
        None,
        "premise: the record names no checkpoint"
    );
    let own = Own::of(read.value());
    let mut possible = PossiblyNamed::new((shard(), session), layout(), None);

    let mut kept = Vec::new();
    for n in 1..=before {
        assert!(
            acknowledged(&storage, &mut dev, n),
            "premise: the fill of key {n} before the checkpoint is acknowledged"
        );
        kept.push(n);
    }
    let counter = start_pass(&storage);
    for n in before + 1..=before + plan.unrecorded {
        assert!(
            acknowledged(&storage, &mut dev, n),
            "premise: the fill of key {n} while the capture pass is in flight is acknowledged"
        );
    }
    let committed = publish_pass(
        &storage,
        &mut dev,
        (&mut host, &mut possible),
        (&read, own, None),
        (session, counter),
    );
    assert!(
        committed.value().checkpoint.is_some(),
        "premise: the record names the checkpoint"
    );
    let (read, opened) = open_suffix(
        &mut host,
        &mut possible,
        (committed, own),
        (&storage, &[]),
        BOUNDS,
    )
    .expect("premise: the tenure's suffix is recorded");
    assert!(opened, "premise: the tenure's suffix log opens");
    if let Some(n) = plan.removed {
        assert!(
            invalidated(&storage, n),
            "premise: the first tenure's invalidation of key {n} removes its entry"
        );
        kept.retain(|&k| k != n);
    }
    for n in before + 1..=before + plan.after {
        if acknowledged(&storage, &mut dev, n) {
            kept.push(n);
        }
    }
    if plan.second > 0 {
        let named = read.value().checkpoint;
        let counter = start_pass(&storage);
        let last = before + plan.unrecorded.max(plan.after);
        for n in last + 1..=last + plan.second {
            if acknowledged(&storage, &mut dev, n) {
                kept.push(n);
            }
        }
        // The writes of an acknowledged fill land before the pass stages its units.
        landed(&storage, &mut dev);
        publish_pass(
            &storage,
            &mut dev,
            (&mut host, &mut possible),
            (&read, own, named),
            (session, counter),
        );
        let checkpointed: Vec<u8> = (before + 1..=before + plan.unrecorded)
            .filter(|n| !kept.contains(n))
            .collect();
        kept.extend(checkpointed);
    }
    landed(&storage, &mut dev);
    drop(dev);
    (records, medium, kept)
}

/// Ticks the tenure's device until every block of its suffix landed.
fn landed<'s>(storage: &'s Storage<TestPlatform>, dev: &mut Device<'s, '_>) {
    for _ in 0..256 {
        let idle = storage
            .pool()
            .capture_lock()
            .expect("premise: the capture mutex")
            .suffix
            .idle();
        if idle && dev.volume.metadata.delta.is_none() {
            break;
        }
        tick(&mut dev.volume, &dev.control);
    }
    let idle = storage
        .pool()
        .capture_lock()
        .expect("premise: the capture mutex")
        .suffix
        .idle();
    assert!(
        idle && dev.volume.metadata.delta.is_none(),
        "premise: every suffix block of the tenure landed"
    );
}

/// What a warm tenure does: the fault of its load, and its steps once the load ended `Open` and its keys were read.
/// A tenure with a step opens its own suffix first.
#[derive(Clone, Copy, Default)]
struct Warm {
    /// The slot count of the tenure's pool and the keys each of its two index shards holds; the fixture's 64
    /// slots of two 32-key shards when `None`.
    slots: Option<(usize, [usize; 2])>,
    /// The warm load misreads this many blocks from the first block of the first tenure's suffix: the first read
    /// command that covers the device unit of each gets the simulator's `Fault::CorruptSuccess`, so the command
    /// reports success with other bytes and the media keep the written bytes.
    misread: u32,
    /// The tenure publishes a checkpoint of its membership and runs one store step of its suffix.
    checkpoint: bool,
    /// One suffix store step uses the first tenure's starting read and refuses `Tenure`.
    foreign_step: bool,
    /// The tenure invalidates this key.
    remove: Option<u8>,
    /// The tenure attempts the fill of the first key while a fill of the second is reserved and never published,
    /// so the attempted fill takes a slot and a unit the load left free other than the lowest.
    fill: Option<(u8, u8)>,
    /// The tenure attempts the fill of this key with no other fill held, after `fill`.
    alone: Option<u8>,
    /// The suffix damage holes the tenure's load reports.
    damaged: u32,
}

/// How a warm tenure ended: the outcome of its load, the keys it does not serve, the entries its load installed,
/// and whether its invalidation removed an entry and its fill was acknowledged.
struct Tenure {
    outcome: MetadataOutcome,
    lost: Vec<u8>,
    installed: u64,
    removed: bool,
    published: bool,
}

/// The device unit of the first block of the first tenure's suffix: the first unit behind the checkpoint slots.
fn first_block() -> u32 {
    1 + layout().slots * layout().slot_units
}

/// A warm tenure of session `(3, e)`, whose fenced coverage holds version 0 of each key of `covered`: it bumps `E`
/// and attaches a fresh storage over `medium` with the warm source of the stored record, under the read fault of
/// `plan`. `lost` is each of `keys` that misses or serves other bytes than its fill published when the load ended
/// `Open`, every key otherwise. A tenure whose load ended `Open` then runs the steps of `plan` in the order of its
/// fields and lets every write land.
fn warm_tenure(
    records: &Shared,
    medium: &Media,
    (e, covered): (u32, &[u8]),
    keys: &[u8],
    plan: Warm,
) -> Tenure {
    let mut host = client(records);
    let read = host
        .read::<ShardRecord>(StoreKey::Shard(shard()))
        .expect("premise: the shard record reads");
    host.bump(&read)
        .expect("premise: the successor's bump of E");
    let read = host
        .read::<ShardRecord>(StoreKey::Shard(shard()))
        .expect("premise: the shard record reads");
    let covered: Vec<[u8; 32]> = covered.iter().map(|&n| key(n)).collect();
    let mut authority = ServingAuthority::fixture_under(session_at(3, e));
    authority.warm = WarmSource::new(
        read.value(),
        layout(),
        authority.session(),
        &fenced(&covered),
    )
    .map(Box::new);
    assert!(
        authority.warm.is_some(),
        "premise: the record mints a warm source"
    );
    let storage = plan
        .slots
        .map_or_else(|| storage(1), |(slots, shards)| storage_of(slots, shards));
    let buffers = arena_with(4, 9);
    let (mut volume, control) =
        attach_under(&storage, &buffers, medium, authority).expect("premise: the warm attach");
    let mut misread: Vec<u32> = (first_block()..first_block() + plan.misread).collect();
    for _ in 0..1024 {
        if !volume.readiness().initializing() {
            break;
        }
        if !misread.is_empty() {
            let ready = control.ready(Stage::Execute);
            for (candidate, token) in control.candidates(Stage::Execute).iter().zip(ready) {
                // A read command: the opcode, the first unit and the count of 512-byte blocks.
                let bytes = candidate.0;
                let units = u32::from(u16::from_be_bytes([bytes[11], bytes[12]])) / 8;
                let start = u32::from_be_bytes([0, bytes[13], bytes[14], bytes[15]]);
                let covered = |unit: &u32| start <= *unit && *unit < start + units;
                if bytes[10] == 0 && misread.iter().any(covered) {
                    control.fault(token, Fault::CorruptSuccess);
                    misread.retain(|unit| !covered(unit));
                }
            }
        }
        tick(&mut volume, &control);
    }
    assert_eq!(
        misread,
        Vec::<u32>::new(),
        "premise: the warm load read the device units of its faults"
    );
    let outcome = volume.metadata_outcome();
    let report = volume.recovery_report().warm;
    assert_eq!(
        (
            report.failed_units,
            report.unread_units,
            report.suffix_damage,
            report.suffix_unread,
            report.suffix_dropped
        ),
        (0, 0, plan.damaged, 0, 0),
        "premise: the load reports no damage outside the suffix damage the plan expects: {report:?}"
    );
    let mut tenure = Tenure {
        outcome,
        lost: keys.to_vec(),
        installed: report.installed,
        removed: false,
        published: false,
    };
    if outcome != MetadataOutcome::Open {
        return tenure;
    }
    live(&storage, &mut volume);
    let mut reader = storage.register().expect("premise: a reader registers");
    tenure.lost.clear();
    for &n in keys {
        let expected: Vec<u8> = key(n)[..4].iter().chain(&body(n)).copied().collect();
        let served = match lookup(&mut reader, &key(n), 4) {
            Ok(lease) => {
                let delivered = read_back(&mut volume, &control, &lease);
                (delivered.status == ReadStatus::Complete).then_some(delivered.bytes)
            }
            Err(LookupError::Missing) => None,
            Err(other) => panic!("premise: the lookup of key {n} ends {other:?}"),
        };
        if served != Some(expected) {
            tenure.lost.push(n);
        }
    }
    drop(reader);
    let idle = plan.remove.is_none() && plan.fill.is_none() && plan.alone.is_none();
    if !plan.checkpoint && !plan.foreign_step && idle {
        return tenure;
    }
    let named = (read.value().checkpoint).expect("premise: the record names a checkpoint");
    let ends = volume.certified().unwrap_or_default();
    let session = volume.authority.session().get();
    let mut possible = PossiblyNamed::new((shard(), session), layout(), Some(named));
    let own = Own::of(read.value());
    let (read, opened) = open_suffix(
        &mut host,
        &mut possible,
        (read, own),
        (&storage, &ends),
        BOUNDS,
    )
    .expect("premise: the successor's suffix is recorded");
    assert!(opened, "premise: the successor's suffix log opens");
    let mut dev = Device { volume, control };
    if plan.checkpoint {
        let counter = start_pass(&storage);
        let committed = publish_pass(
            &storage,
            &mut dev,
            (&mut host, &mut possible),
            (&read, own, Some(named)),
            (session, counter),
        );
        assert_eq!(
            committed.value().checkpoint.map(|named| named.session),
            Some(session),
            "premise: the record names the successor's checkpoint"
        );
        let (stepped, _) =
            suffix_step(&mut host, &mut possible, (committed, own), &storage, BOUNDS);
        stepped.expect("premise: the suffix's store step");
    }
    if plan.foreign_step {
        let foreign = client(&fresh_records())
            .read::<ShardRecord>(StoreKey::Shard(shard()))
            .expect("premise: the first tenure's starting record reads");
        assert_eq!(
            (
                foreign.value().checkpoint,
                foreign.value().ancestry.as_slice()
            ),
            (None, &[][..]),
            "premise: the foreign read names neither a checkpoint nor a suffix"
        );
        let (stepped, _) = suffix_step(&mut host, &mut possible, (foreign, own), &storage, BOUNDS);
        assert_eq!(
            stepped.err(),
            Some(WriteRefused::Tenure),
            "premise: the store step refuses the read of another tenure"
        );
    }
    if let Some(n) = plan.remove {
        tenure.removed = invalidated(&storage, n);
        landed(&storage, &mut dev);
    }
    if let Some((new, held)) = plan.fill {
        let unpublished =
            reserved(&storage, &key(held), &body(held)).expect("premise: the held fill reserves");
        tenure.published = acknowledged(&storage, &mut dev, new);
        drop(unpublished);
        landed(&storage, &mut dev);
    }
    if let Some(n) = plan.alone {
        tenure.published = acknowledged(&storage, &mut dev, n);
        landed(&storage, &mut dev);
    }
    drop(dev);
    tenure
}

/// The history of an omitted entry: a first tenure that publishes a checkpoint of `before` fills, a second tenure
/// whose coverage holds key 1 and which runs `plan`, and a third tenure under the same coverage. Returns the entry
/// cap, the keys the two tenures acknowledged and the coverage does not hold, and the third tenure.
fn covered_successor(before: u8, plan: Warm) -> (u8, Vec<u8>, Tenure) {
    let cap = layout().entries as u8;
    let (records, medium, kept) = first_tenure(before, First::default());
    assert_eq!(kept.len(), usize::from(before), "premise: {before} fills");
    let mut kept: Vec<u8> = kept.into_iter().filter(|&n| n != 1).collect();
    let second = warm_tenure(&records, &medium, (4, &[1]), &kept, plan);
    assert_eq!(
        (second.outcome, second.lost, second.installed),
        (MetadataOutcome::Open, Vec::new(), u64::from(before) - 1),
        "premise: the second tenure's load omits the covered entry and the tenure serves every checkpoint key its \
         coverage does not hold"
    );
    if second.published {
        kept.extend(plan.fill.map(|(new, _)| new));
    }
    let third = warm_tenure(&records, &medium, (5, &[1]), &kept, Warm::default());
    (cap, kept, third)
}

/// The history of a misread suffix: a first tenure that publishes a checkpoint of `before` fills, opens its suffix,
/// invalidates the key of `removed` and fills one more key, one record in each block of its suffix; a second tenure
/// whose load misreads each of those blocks and which runs `plan`; and a third tenure whose load meets no fault. Returns the keys judged, which are the keys the first tenure's checkpoint holds and did not remove and
/// the key the second tenure's fill published, and the third tenure. The key of the first tenure's last fill is not
/// judged: a faulted read was of its record.
fn misread_successor(before: u8, removed: Option<u8>, plan: Warm) -> (Vec<u8>, Tenure) {
    let (records, medium, kept) = first_tenure(
        before,
        First {
            removed,
            after: 1,
            ..First::default()
        },
    );
    assert!(
        kept.contains(&(before + 1)),
        "premise: the first tenure's fill through its suffix is acknowledged"
    );
    let mut judged: Vec<u8> = kept.into_iter().filter(|&n| n <= before).collect();
    let plan = Warm {
        misread: 1 + u32::from(removed.is_some()),
        ..plan
    };
    let second = warm_tenure(&records, &medium, (4, &[]), &judged, plan);
    assert_eq!(
        (second.outcome, second.lost, second.installed),
        (MetadataOutcome::Open, Vec::new(), u64::from(before)),
        "premise: the second tenure's load misses the block, restores the checkpoint's entries and serves the \
         judged keys"
    );
    assert_eq!(
        second.removed,
        plan.remove.is_some(),
        "premise: the second tenure's invalidation removes its entry"
    );
    judged.retain(|&n| plan.remove != Some(n));
    if second.published {
        judged.extend(plan.fill.map(|(new, _)| new));
    }
    let third = warm_tenure(&records, &medium, (5, &[]), &judged, Warm::default());
    (judged, third)
}

/// A fill of a key no tenure of a history holds, beside a held fill of another such key.
const NEW: Option<(u8, u8)> = Some((50, 51));

/// A first tenure at the entry cap attempts one more fill through its open suffix: every fill it acknowledged is
/// served after host loss, because an acknowledged member the next warm load cannot admit loses every object of the
/// record.
#[test]
fn every_fill_acknowledged_past_the_entry_cap_is_served_after_host_loss() {
    let cap = layout().entries as u8;
    let (records, medium, kept) = first_tenure(
        cap,
        First {
            after: 1,
            ..First::default()
        },
    );
    assert!(
        kept.len() >= usize::from(cap),
        "premise: the fills before the checkpoint were acknowledged"
    );
    let Tenure { outcome, lost, .. } =
        warm_tenure(&records, &medium, (4, &[]), &kept, Warm::default());
    assert!(
        outcome == MetadataOutcome::Open && lost.is_empty(),
        "a retained entry outside every damage set was lost on host loss: the first tenure acknowledged the fills \
         of {} keys under an entry cap of {cap}, removed none and published a checkpoint; the successor's warm \
         load ended {outcome:?} on undamaged media and keys {lost:?} do not serve their bytes",
        kept.len()
    );
}

/// A checkpoint of exactly the entry cap's fills, with none after it, loads warm and serves every key: the cap
/// itself is admitted.
#[test]
fn a_checkpoint_at_the_entry_cap_is_served_after_host_loss() {
    let cap = layout().entries as u8;
    let (records, medium, kept) = first_tenure(cap, First::default());
    assert_eq!(kept.len(), usize::from(cap), "premise: {cap} fills");
    let tenure = warm_tenure(&records, &medium, (4, &[]), &kept, Warm::default());
    assert_eq!(
        (tenure.outcome, tenure.lost),
        (MetadataOutcome::Open, Vec::new())
    );
}

/// A fill through the suffix that brings the membership to the entry cap is acknowledged and served after host
/// loss: the suffix refuses nothing at or below the cap.
#[test]
fn a_suffix_fill_that_reaches_the_entry_cap_is_served_after_host_loss() {
    let cap = layout().entries as u8;
    let (records, medium, kept) = first_tenure(
        cap - 1,
        First {
            after: 1,
            ..First::default()
        },
    );
    assert_eq!(kept.len(), usize::from(cap), "premise: {cap} fills");
    let tenure = warm_tenure(&records, &medium, (4, &[]), &kept, Warm::default());
    assert_eq!(
        (tenure.outcome, tenure.lost),
        (MetadataOutcome::Open, Vec::new())
    );
}

/// Replacing the memory-only key would add a recorded entry when the checkpoint already holds `cap` entries.
#[test]
fn every_recorded_key_is_served_after_a_replacement_of_a_memory_only_fill_past_the_entry_cap() {
    let cap = layout().entries as u8;
    let (records, medium, kept) = first_tenure(
        cap,
        First {
            unrecorded: 1,
            after: 1,
            ..First::default()
        },
    );
    let Tenure { outcome, lost, .. } =
        warm_tenure(&records, &medium, (4, &[]), &kept, Warm::default());
    assert!(
        outcome == MetadataOutcome::Open && lost.is_empty(),
        "a retained entry outside every damage set was lost on host loss: the first tenure published a checkpoint \
         of {cap} fills under an entry cap of {cap}, acknowledged one more fill while its capture pass was in \
         flight and attempted a replacement of that key through its suffix; its records hold {} keys, the \
         successor's warm load ended {outcome:?} on undamaged media and keys {lost:?} do not serve their bytes",
        kept.len()
    );
}

/// Replacing the memory-only key brings the recorded set to the entry cap: the suffix acknowledges it and the
/// successor serves that key with every checkpoint key.
#[test]
fn a_replacement_of_a_memory_only_fill_that_reaches_the_entry_cap_is_served_after_host_loss() {
    let cap = layout().entries as u8;
    let (records, medium, kept) = first_tenure(
        cap - 1,
        First {
            unrecorded: 1,
            after: 1,
            ..First::default()
        },
    );
    assert_eq!(
        kept.len(),
        usize::from(cap),
        "premise: the replacement through the suffix is acknowledged"
    );
    let tenure = warm_tenure(&records, &medium, (4, &[]), &kept, Warm::default());
    assert_eq!(
        (tenure.outcome, tenure.lost),
        (MetadataOutcome::Open, Vec::new())
    );
}

/// A second pass checkpoints the two memory-only fills that brought the membership to the entry cap, so the record
/// it publishes rebuilds every member at its cut beside each insert recorded after it. A fill of a new key while
/// that pass is in flight would be that record's entry past the cap: every fill acknowledged is served after host
/// loss.
#[test]
fn every_fill_acknowledged_during_a_pass_that_checkpoints_memory_only_fills_is_served_after_host_loss()
 {
    let cap = layout().entries as u8;
    let (records, medium, kept) = first_tenure(
        cap - 2,
        First {
            unrecorded: 2,
            second: 1,
            ..First::default()
        },
    );
    assert!(
        kept.len() >= usize::from(cap),
        "premise: the second pass checkpoints the memory-only fills"
    );
    let Tenure { outcome, lost, .. } =
        warm_tenure(&records, &medium, (4, &[]), &kept, Warm::default());
    assert!(
        outcome == MetadataOutcome::Open && lost.is_empty(),
        "a retained entry outside every damage set was lost on host loss: under an entry cap of {cap} the first \
         tenure acknowledged two fills while its first capture pass was in flight, opened its suffix at a \
         membership of {cap}, attempted one more fill while a second pass was in flight and published that pass; \
         its records hold {} keys, the successor's warm load ended {outcome:?} on undamaged media and keys \
         {lost:?} do not serve their bytes",
        kept.len()
    );
}

/// A fill during the second pass that brings the membership to the entry cap is acknowledged, and the successor
/// serves it with every key the second checkpoint holds.
#[test]
fn a_fill_during_a_second_pass_that_reaches_the_entry_cap_is_served_after_host_loss() {
    let cap = layout().entries as u8;
    let (records, medium, kept) = first_tenure(
        cap - 3,
        First {
            unrecorded: 2,
            second: 1,
            ..First::default()
        },
    );
    assert_eq!(
        kept.len(),
        usize::from(cap),
        "premise: the fill during the second pass is acknowledged"
    );
    let tenure = warm_tenure(&records, &medium, (4, &[]), &kept, Warm::default());
    assert_eq!(
        (tenure.outcome, tenure.lost),
        (MetadataOutcome::Open, Vec::new())
    );
}

/// A successor whose load omitted a covered entry of a checkpoint at the entry cap attempts a fill of a new key:
/// every fill acknowledged is served by the third tenure, because the stored record still rebuilds the omitted
/// entry beside any insert the successor records.
#[test]
fn every_fill_a_successor_acknowledges_beside_an_omitted_entry_is_served_after_host_loss() {
    let plan = Warm {
        fill: NEW,
        ..Warm::default()
    };
    let (cap, kept, Tenure { outcome, lost, .. }) = covered_successor(layout().entries as u8, plan);
    assert!(
        outcome == MetadataOutcome::Open && lost.is_empty(),
        "a retained entry outside every damage set was lost on host loss: the first tenure published a checkpoint \
         of {cap} fills under an entry cap of {cap}, the second tenure omitted one covered entry, acknowledged the \
         fills of {} keys in all and removed none; the third tenure's warm load ended {outcome:?} on undamaged media \
         and keys {lost:?} do not serve their bytes",
        kept.len()
    );
}

/// A successor that omits a covered entry and publishes nothing leaves a record the third tenure loads warm, with
/// every uncovered key served.
#[test]
fn a_successor_that_omits_an_entry_and_fills_nothing_is_served_after_host_loss() {
    let (cap, kept, third) = covered_successor(layout().entries as u8, Warm::default());
    assert_eq!(kept.len(), usize::from(cap) - 1, "premise: one key covered");
    assert_eq!(
        (third.outcome, third.lost),
        (MetadataOutcome::Open, Vec::new())
    );
}

/// A successor that published a checkpoint of its own members and ran one store step of its suffix fills to the
/// entry cap: the fill is acknowledged and served after host loss, because the record then names that tenure's
/// checkpoint and suffix alone.
#[test]
fn a_successor_fill_after_its_own_checkpoint_is_served_after_host_loss() {
    let plan = Warm {
        checkpoint: true,
        fill: NEW,
        ..Warm::default()
    };
    let (cap, kept, third) = covered_successor(layout().entries as u8, plan);
    assert_eq!(
        kept.len(),
        usize::from(cap),
        "premise: the successor's fill after its own checkpoint is acknowledged"
    );
    assert_eq!(
        (third.outcome, third.lost),
        (MetadataOutcome::Open, Vec::new())
    );
}

/// After a store step on a foreign read, the stored record still names the first tenure's checkpoint, which
/// contains the entry the successor's load omitted.
#[test]
fn every_fill_a_successor_acknowledges_after_a_store_step_on_a_foreign_read_is_served_after_host_loss()
 {
    let plan = Warm {
        foreign_step: true,
        fill: NEW,
        ..Warm::default()
    };
    let (cap, kept, Tenure { outcome, lost, .. }) = covered_successor(layout().entries as u8, plan);
    assert!(
        outcome == MetadataOutcome::Open && lost.is_empty(),
        "a retained entry outside every damage set was lost on host loss: the first tenure published a checkpoint \
         of {cap} fills under an entry cap of {cap}, the second tenure omitted one covered entry, ran a store step \
         of its suffix over a read of another tenure, acknowledged the fills of {} keys in all and removed none; \
         the third tenure's warm load ended {outcome:?} on undamaged media and keys {lost:?} do not serve their \
         bytes",
        kept.len()
    );
}

/// A successor whose load misread the predecessor's one suffix block, and so restored one entry fewer than the
/// record holds, attempts a fill of a new key: every judged key is served by the third tenure, whose fault-free
/// load reads the block the successor missed.
#[test]
fn every_fill_a_successor_acknowledges_behind_a_misread_suffix_block_is_served_after_host_loss() {
    let cap = layout().entries as u8;
    let plan = Warm {
        fill: NEW,
        ..Warm::default()
    };
    let (judged, Tenure { outcome, lost, .. }) = misread_successor(cap - 1, None, plan);
    assert!(
        outcome == MetadataOutcome::Open && lost.is_empty(),
        "a retained entry outside every damage set was lost on host loss: under an entry cap of {cap} the second \
         tenure's load misread the one suffix block of its predecessor and reported no damage; of the {} keys that \
         block does not hold, which a tenure acknowledged and none removed, the third tenure's warm load, with no \
         fault, ended {outcome:?} and keys {lost:?} do not serve their bytes",
        judged.len()
    );
}

/// A successor whose load misread the predecessor's suffix block and which publishes nothing leaves a record the
/// third tenure loads warm, with every judged key served.
#[test]
fn a_successor_that_misreads_a_suffix_block_and_fills_nothing_is_served_after_host_loss() {
    let cap = layout().entries as u8;
    let (judged, third) = misread_successor(cap - 1, None, Warm::default());
    assert_eq!(
        judged.len(),
        usize::from(cap) - 1,
        "premise: {cap} keys less one"
    );
    assert_eq!(
        (third.outcome, third.lost),
        (MetadataOutcome::Open, Vec::new())
    );
}

/// A successor whose load misread a removal and an insert of the predecessor's suffix removes the same key and
/// attempts a fill at the count it restored: every judged key is served by the third tenure, whose fault-free load
/// replays both misread blocks.
#[test]
fn every_fill_a_successor_acknowledges_behind_a_misread_removal_is_served_after_host_loss() {
    let cap = layout().entries as u8;
    let plan = Warm {
        remove: Some(1),
        fill: NEW,
        ..Warm::default()
    };
    let (judged, Tenure { outcome, lost, .. }) = misread_successor(cap, Some(1), plan);
    assert!(
        outcome == MetadataOutcome::Open && lost.is_empty(),
        "a retained entry outside every damage set was lost on host loss: under an entry cap of {cap} the second \
         tenure's load misread the two suffix blocks of its predecessor, which hold a removal and an insert, and \
         reported no damage; the tenure removed the key those blocks remove and filled at the count it restored; \
         of the {} keys those blocks do not hold, which a tenure acknowledged and none removed, the third \
         tenure's warm load, with no fault, ended {outcome:?} and keys {lost:?} do not serve their bytes",
        judged.len()
    );
}

/// Under a layout whose entry cap covers every slot of the pool, a successor's fill before any checkpoint of its
/// own is acknowledged and served after host loss: the entry-cap refusal applies only below the slot count.
#[test]
fn a_successor_fill_under_an_entry_cap_that_covers_the_slots_is_served_after_host_loss() {
    ENTRIES.with(|entries| entries.set(2 * UNIT_ENTRIES as u32));
    let (records, medium, mut kept) = first_tenure(UNIT_ENTRIES as u8, First::default());
    assert_eq!(kept.len(), UNIT_ENTRIES as usize, "premise: 41 fills");
    let plan = Warm {
        fill: NEW,
        ..Warm::default()
    };
    let second = warm_tenure(&records, &medium, (4, &[]), &kept, plan);
    assert_eq!(
        (second.outcome, second.lost, second.published),
        (MetadataOutcome::Open, Vec::new(), true),
        "premise: under an entry cap of 82 over 64 slots the successor's fill is acknowledged before any \
         checkpoint of its own"
    );
    kept.extend(NEW.map(|(new, _)| new));
    let third = warm_tenure(&records, &medium, (5, &[]), &kept, Warm::default());
    assert_eq!(
        (third.outcome, third.lost),
        (MetadataOutcome::Open, Vec::new())
    );
}

/// The index shard and the first slot of the placement window `key(n)` routes to in `storage`'s pool.
fn placed(storage: &Storage<TestPlatform>, n: u8) -> (usize, usize) {
    let owner = storage.index().expect("premise: an indexed storage");
    let route = (owner.hasher)
        .route_unpaid(&key(n), &owner.geometry, crate::index::Prefetch::NONE)
        .expect("premise: an enabled shard");
    let slots = storage.pool().descriptor().slot_count;
    let window = crate::storage::free::window_of(route.fingerprint(), slots);
    (
        route.shard().0,
        window.expect("premise: the pool holds a window"),
    )
}

/// The keys of a history over pools of 64 and `narrow` slots, `narrow` below 64 and a multiple of the window plus
/// one: `narrow - 1` checkpoint keys, four for each window below `narrow - 1`, in window order, so each takes a slot
/// of its own window in a pool of 64; a key whose window lies past `narrow`; and two more keys of no tenure.
struct Keys {
    checkpoint: Vec<u8>,
    tail: u8,
    held: u8,
    new: u8,
}

fn keys(narrow: usize) -> Keys {
    let storage = storage(1);
    let window = crate::storage::free::WINDOW;
    let mut checkpoint = Vec::new();
    for start in (0..narrow - 1).step_by(window) {
        checkpoint.extend(
            (1..=u8::MAX)
                .filter(|&n| placed(&storage, n).1 == start)
                .take(window),
        );
    }
    let mut unused = (1..=u8::MAX).filter(|n| !checkpoint.contains(n));
    let tail = unused
        .clone()
        .find(|&n| placed(&storage, n).1 >= narrow)
        .expect("premise: a key routes past the narrow pool");
    let mut others = unused.by_ref().filter(|&n| n != tail);
    let (held, new) = (others.next(), others.next());
    Keys {
        checkpoint,
        tail,
        held: held.expect("premise: a held key"),
        new: new.expect("premise: a new key"),
    }
}

/// The keys of `keys` that each of the storage's two index shards holds.
fn routed(storage: &Storage<TestPlatform>, keys: &[u8]) -> [usize; 2] {
    let mut shards = [0; 2];
    for &n in keys {
        shards[placed(storage, n).0] += 1;
    }
    shards
}

/// A first tenure over a pool of 64 slots: it fills the checkpoint keys of `keys`, publishes a checkpoint of them
/// and opens its suffix, then acknowledges through the suffix the fill of the tail key while a fill of the held key
/// is reserved and never published, so the tail takes a slot of its window and the unit above the lowest free one.
/// With `tail` [`Tail::Checkpoint`] the tenure fills the tail key before the checkpoint instead, so the checkpoint
/// holds it. Returns the store's records, the media and the tail's slot.
fn wide_first_tenure(keys: &Keys, tail: Tail) -> (Shared, Media, usize) {
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let medium = media(MEDIA);
    let session = session_at(3, 3).get();
    let authority = ServingAuthority::fixture_under(session_at(3, 3));
    let (mut volume, control) =
        attach_under(&storage, &buffers, &medium, authority).expect("premise: the cold attach");
    bootstrap(&mut volume, &control);
    let mut dev = Device { volume, control };
    let records = fresh_records();
    let mut host = client(&records);
    let read = host
        .read::<ShardRecord>(StoreKey::Shard(shard()))
        .expect("premise: the shard record reads");
    let own = Own::of(read.value());
    let mut possible = PossiblyNamed::new((shard(), session), layout(), None);
    for &n in &keys.checkpoint {
        assert!(
            acknowledged(&storage, &mut dev, n),
            "premise: the fill of key {n} before the checkpoint is acknowledged"
        );
    }
    let mut slot = None;
    if tail == Tail::Checkpoint {
        let lease = fill(&storage, &mut dev, &key(keys.tail), &body(keys.tail))
            .expect("premise: the fill of the tail key before the checkpoint is acknowledged");
        slot = Some(lease.id().slot_index());
    }
    let counter = start_pass(&storage);
    let committed = publish_pass(
        &storage,
        &mut dev,
        (&mut host, &mut possible),
        (&read, own, None),
        (session, counter),
    );
    let (_, opened) = open_suffix(
        &mut host,
        &mut possible,
        (committed, own),
        (&storage, &[]),
        BOUNDS,
    )
    .expect("premise: the tenure's suffix is recorded");
    assert!(opened, "premise: the tenure's suffix log opens");
    if tail == Tail::Suffix {
        let held = reserved(&storage, &key(keys.held), &body(keys.held))
            .expect("premise: the held fill reserves");
        let lease = fill(&storage, &mut dev, &key(keys.tail), &body(keys.tail))
            .expect("premise: the fill through the suffix is acknowledged");
        slot = Some(lease.id().slot_index());
        drop((lease, held));
    }
    for shard in 0..2 {
        storage
            .service_fills(
                crate::index::ShardIndex(shard),
                8,
                &mut WorkBudget::new(1 << 20),
            )
            .expect("premise: the fill tables are serviced");
    }
    landed(&storage, &mut dev);
    drop(dev);
    (
        records,
        medium,
        slot.expect("premise: the tail key was filled"),
    )
}

/// Where a first tenure of 64 slots records its tail key.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tail {
    /// In its checkpoint.
    Checkpoint,
    /// Through its open suffix, after the checkpoint.
    Suffix,
}

/// How a history over pools of differing slot counts ended: the tail key and its slot in the first tenure, the new
/// key and whether the second tenure acknowledged its fill, the keys judged and the third tenure.
struct Narrowed {
    keys: Keys,
    slot: usize,
    published: bool,
    judged: Vec<u8>,
    third: Tenure,
}

/// Tenures of one volume over pools of 64, `narrow` and 64 slots under an entry cap of `narrow`. The first tenure
/// publishes a checkpoint of `narrow - 1` members in slots below `narrow - 1`, opens its suffix and acknowledges the
/// fill of the tail key, which takes a slot at or past `narrow`. The second tenure misreads the suffix block that
/// holds that fill, so its load restores `narrow - 1` entries and reports no damage, and it attempts the fill of the
/// new key into its one free slot. That fill shares neither the slot nor the unit of the misread one, so a replay
/// of the record keeps both once the second tenure acknowledges it. The third tenure's load meets no fault.
fn narrowed_successor(narrow: usize) -> Narrowed {
    let keys = keys(narrow);
    let (records, medium, slot) = wide_first_tenure(&keys, Tail::Suffix);
    assert!(
        slot >= narrow,
        "premise: the tail key takes slot {slot}, past the narrow pool"
    );
    let mut judged = keys.checkpoint.clone();
    let mut held = judged.clone();
    held.push(keys.new);
    let plan = Warm {
        slots: Some((narrow, routed(&storage(1), &held))),
        misread: 1,
        alone: Some(keys.new),
        ..Warm::default()
    };
    let second = warm_tenure(&records, &medium, (4, &[]), &judged, plan);
    assert_eq!(
        (second.outcome, second.lost, second.installed),
        (MetadataOutcome::Open, Vec::new(), narrow as u64 - 1),
        "premise: the second tenure's load misses the block, restores the checkpoint's entries and serves them"
    );
    if second.published {
        judged.push(keys.new);
    }
    let third = warm_tenure(&records, &medium, (5, &[]), &judged, Warm::default());
    Narrowed {
        keys,
        slot,
        published: second.published,
        judged,
        third,
    }
}

/// Tenures of 64, 41 and 64 slots under an entry cap of 41, where the second tenure misread the first tenure's
/// suffix block: every judged key should be served by the third tenure.
///
/// Known defect, pinned: pools of different slot counts on one volume. An inheriting tenure bounds the set a replay
/// rebuilds by its own slot count, 41 here, so the second tenure acknowledges its fill and the third tenure's load
/// refuses `Entries`. The test expects its own assertion, the retention property's, to fail on this history, which
/// breaks ONE-SLOT-COUNT of `storage::recovery::suffix`.
#[test]
#[should_panic(expected = "a retained entry outside every damage set was lost on host loss")]
fn every_fill_a_successor_of_fewer_slots_acknowledges_behind_a_misread_suffix_block_is_served_after_host_loss()
 {
    let cap = layout().entries as usize;
    let Narrowed {
        keys,
        slot,
        published,
        judged,
        third: Tenure { outcome, lost, .. },
    } = narrowed_successor(cap);
    assert!(
        outcome == MetadataOutcome::Open && lost.is_empty(),
        "a retained entry outside every damage set was lost on host loss: under an entry cap of {cap} the first \
         tenure of 64 slots recorded key {} in slot {slot}, the second tenure of {cap} slots misread that block \
         and reported no damage, and its fill of key {} was {}; of the {} judged keys the third tenure of 64 \
         slots, with no fault, ended {outcome:?} and keys {lost:?} do not serve their bytes",
        keys.tail,
        keys.new,
        if published { "acknowledged" } else { "refused" },
        judged.len()
    );
}

/// The control of the history over pools of 64, 41 and 64 slots, which pins the defect's path (pools of different
/// slot counts on one volume): the second tenure's bound is its slot count of 41, so it acknowledges its fill at a
/// membership of 41, and the third tenure's load counts 42 entries and refuses `Entries`.
#[test]
fn a_successor_bounded_by_its_own_slot_count_acknowledges_a_fill_the_next_load_refuses() {
    let narrowed = narrowed_successor(layout().entries as usize);
    assert!(
        narrowed.published,
        "the slot-count bound acknowledges the fill"
    );
    assert_eq!(
        narrowed.third.outcome,
        MetadataOutcome::Unloadable(crate::storage::recovery::LoadRefusal::Entries)
    );
}

/// A body one byte past one extent's payload, which a storage with a sequence arena admits as an object of two
/// extents.
fn two_extents(n: u8) -> Vec<u8> {
    vec![n; crate::storage::EXTENT_PAYLOAD as usize + 1]
}

/// What a tenure over a storage with a sequence arena showed when it attempted a fill of two extents through its
/// open suffix: the fill's outcome, the membership's members and extent rows before and after it, the suffix
/// records before and after it, and, once the fill was acknowledged, how the stage of the next checkpoint of the
/// membership ended.
struct Rows {
    fill: Result<(), crate::storage::FillPublishError>,
    members: (usize, usize),
    rows: (u64, u64),
    records: (u64, u64),
    next: Option<Result<(), crate::storage::checkpoint::StageRefusal>>,
}

/// The membership's members, its extent rows and the suffix's next record sequence.
fn membership(storage: &Storage<TestPlatform>) -> (usize, u64, u64) {
    use std::sync::atomic::Ordering;
    let pool = storage.pool();
    let seq = storage
        .with_suffix(|log| log.next_seq())
        .expect("premise: the capture mutex");
    (
        pool.eligible.load(Ordering::Relaxed),
        pool.member_rows.load(Ordering::Relaxed),
        seq,
    )
}

/// A tenure over the sequence-arena storage, under the layout's entry cap of 3, outside any capturing tenure: it
/// fills key 1 with two extents, publishes a checkpoint of that member, two rows, opens its suffix and attempts the
/// fill of key 2 with two extents, which leaves two members of four rows. A fill it acknowledges is followed by a
/// capture pass whose stage over the membership is attempted.
fn two_extent_tenure() -> Rows {
    ENTRIES.with(|entries| entries.set(3));
    let storage = super::super::sim_tests::sequence_storage();
    let buffers = arena_with(4, 9);
    let medium = media(MEDIA);
    let session = session_at(3, 3).get();
    let authority = ServingAuthority::fixture_under(session_at(3, 3));
    let (mut volume, control) =
        attach_under(&storage, &buffers, &medium, authority).expect("premise: the cold attach");
    bootstrap(&mut volume, &control);
    let mut dev = Device { volume, control };
    let records = fresh_records();
    let mut host = client(&records);
    let read = host
        .read::<ShardRecord>(StoreKey::Shard(shard()))
        .expect("premise: the shard record reads");
    let own = Own::of(read.value());
    let mut possible = PossiblyNamed::new((shard(), session), layout(), None);
    fill(&storage, &mut dev, &key(1), &two_extents(1))
        .expect("premise: the fill of two extents is acknowledged");
    let counter = start_pass(&storage);
    let committed = publish_pass(
        &storage,
        &mut dev,
        (&mut host, &mut possible),
        (&read, own, None),
        (session, counter),
    );
    let (read, opened) = open_suffix(
        &mut host,
        &mut possible,
        (committed, own),
        (&storage, &[]),
        BOUNDS,
    )
    .expect("premise: the tenure's suffix is recorded");
    assert!(opened, "premise: the tenure's suffix log opens");
    let before = membership(&storage);
    assert_eq!(
        (before.0, before.1),
        (1, 2),
        "premise: one member of two rows"
    );
    let fill = fill(&storage, &mut dev, &key(2), &two_extents(2)).map(drop);
    landed(&storage, &mut dev);
    let after = membership(&storage);
    let next = fill.is_ok().then(|| {
        let counter = start_pass(&storage);
        let entries = drain(&storage);
        let checkpoint = Checkpoint {
            shard: shard(),
            session,
            capture: counter,
        };
        let named = read.value().checkpoint;
        let mut possible = PossiblyNamed::new((shard(), session), layout(), named);
        StagedCheckpoint::new(
            Crc32c::detect(),
            &mut possible,
            (checkpoint, &entries),
            &EngineBudget::unlimited(),
        )
        .map(drop)
    });
    drop(dev);
    ENTRIES.with(|entries| entries.set(UNIT_ENTRIES as u32));
    Rows {
        fill,
        members: (before.0, after.0),
        rows: (before.1, after.1),
        records: (before.2, after.2),
        next,
    }
}

/// On a storage with a sequence arena, outside a capturing tenure, the entry-cap guard counts extent rows, as a
/// checkpoint's placement does: a fill of two extents that would leave two members of four rows under an entry cap
/// of 3 is refused `History` before any change, so the membership, its rows and the suffix's records stay as they
/// were.
#[test]
fn a_fill_whose_extent_rows_pass_the_entry_cap_is_refused_before_any_change() {
    let Rows {
        fill,
        members,
        rows,
        records,
        next,
    } = two_extent_tenure();
    assert_eq!(fill, Err(crate::storage::FillPublishError::History));
    assert_eq!(members, (1, 1), "no member was added");
    assert_eq!(rows, (2, 2), "no row was added");
    assert_eq!(records.0, records.1, "no suffix record was appended");
    assert!(next.is_none());
}

/// The control of the guard's row count: with the member count planted as its bound, the fill of two extents is
/// acknowledged at two members, within the cap of 3, and the next checkpoint of the membership's four rows is
/// refused `Entries` at its placement.
#[test]
fn a_guard_that_counts_members_acknowledges_a_fill_whose_checkpoint_is_refused_for_its_rows() {
    use crate::storage::checkpoint::{ReserveRefusal, StageRefusal};
    use crate::storage::publication::MEMBER_COUNT;
    use crate::storage::volume::placement::PlacementRefusal;
    MEMBER_COUNT.with(|plant| plant.set(true));
    let rows = two_extent_tenure();
    MEMBER_COUNT.with(|plant| plant.set(false));
    assert_eq!(rows.fill, Ok(()));
    assert_eq!(rows.members, (1, 2));
    assert_eq!(rows.rows, (2, 4));
    assert_eq!(
        rows.next,
        Some(Err(StageRefusal::Reserve(ReserveRefusal::Placement(
            PlacementRefusal::Entries { entries: 4, cap: 3 }
        ))))
    );
}

/// A writer of 64 slots under an entry cap of 82 records a key in a slot at or past 41, in its checkpoint or through
/// its suffix, with no fault; a successor of 41 slots loads the record.
fn narrower_reader(tail: Tail) -> (usize, Tenure) {
    ENTRIES.with(|entries| entries.set(2 * UNIT_ENTRIES as u32));
    let narrow = UNIT_ENTRIES as usize;
    let keys = keys(narrow);
    let (records, medium, slot) = wide_first_tenure(&keys, tail);
    assert!(
        slot >= narrow,
        "premise: the tail key takes slot {slot}, past the narrow pool"
    );
    let mut loaded = keys.checkpoint.clone();
    loaded.push(keys.tail);
    let plan = Warm {
        slots: Some((narrow, routed(&storage(1), &loaded))),
        damaged: u32::from(tail == Tail::Suffix),
        ..Warm::default()
    };
    (
        slot,
        warm_tenure(&records, &medium, (4, &[]), &loaded, plan),
    )
}

/// Known defect, pinned: pools of different slot counts on one volume. A successor of 41 slots refuses the history
/// of a writer of 64 slots under an entry cap of 82 that holds a key in a slot past 40, with no fault on the media.
/// A key in the checkpoint ends the load `Unloadable(Slot)`, the checkpoint guard's refusal of a slot at or past the
/// reader's slot count. A key recorded through the suffix makes its block a damage hole, which the load reports and
/// refuses as `Unloadable(StaleWrite)`. A smaller reader cannot load a larger writer's history.
#[test]
fn a_successor_of_fewer_slots_refuses_a_wider_writers_history() {
    use crate::storage::recovery::LoadRefusal;
    for (tail, refusal) in [
        (Tail::Checkpoint, LoadRefusal::Slot),
        (Tail::Suffix, LoadRefusal::StaleWrite),
    ] {
        let (slot, tenure) = narrower_reader(tail);
        assert_eq!(
            (tenure.outcome, tenure.installed),
            (MetadataOutcome::Unloadable(refusal), 0),
            "the tail key in slot {slot}"
        );
    }
}
