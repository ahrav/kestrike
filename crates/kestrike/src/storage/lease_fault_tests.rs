//! Lease reads under seeded fault schedules: every read of a published object takes over its lease's right, progresses only through explicit grants, ends with one `Done`, and keeps its right until its record frees, through cancels, deadlines, device faults, held commands, driver unwinds, a gone device, an unproven quiesce, a reset and the volume's release.

use std::panic::{AssertUnwindSafe, catch_unwind};

use super::attempt_tests::service;
use super::device::sim::{Fault, QuiesceMode, Unwind};
use super::device::{DeviceStatus, Operation, PoolKind};
use super::hit_tests::last_read;
use super::lookup_tests::lookup;
use super::publish_tests::{RETRIES, TRIES, budget, key};
use super::record::RecordIdentity;
use super::seeded::SplitMix64;
use super::volume_fixture::{Device, arena};
use super::writable_tests::{bytes, reserve, wide};
use super::{ControlRefusal, ReadEvent, ReadOp, ReadRefusal, ReadStatus};
use crate::index::Key;
use crate::sim::round::{Act, Actor, round};

const FAULTS: [Fault; 4] = [
    Fault::Status(DeviceStatus::Kernel(-5)),
    Fault::Short { units: 1 },
    Fault::CorruptSuccess,
    Fault::PartialReadFailure { sectors: 5 },
];

/// Where a seed loses its volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Loss {
    TickSubmit,
    TickPick,
    ReadSubmit,
    GrantSubmit,
    Gone,
}

/// One published object: its key, allocation, metadata length, payload and slot.
struct Object {
    key: Key,
    allocation: u64,
    metadata: usize,
    payload: Vec<u8>,
    slot: usize,
}

/// What the seeds reached, so the schedule is shown to exercise each path.
#[derive(Debug, Default)]
struct Reached {
    cancelled_undrained: u32,
    timed_out_undrained: u32,
    short: u32,
    stale_grants: u32,
    closed_grants: u32,
    empty_success: u32,
    chunk_mismatch: u32,
    header_mismatch: u32,
    losses: Vec<Loss>,
}

/// Grants `op` one command, with the driver's next call set to unwind when `unwinds`; a grant that submitted at once may meet a fault or a hold on its command, as a tick's submit may.
fn grant(
    dev: &mut Device<'_, '_>,
    rng: &mut SplitMix64,
    reached: &mut Reached,
    held: &mut Vec<super::device::CommandToken>,
    op: ReadOp,
    unwinds: bool,
    at: &str,
) {
    if unwinds {
        dev.control.unwind_next(Some(Unwind::Submit));
    }
    let submitted = dev.volume.report().reads_submitted;
    let granted = catch_unwind(AssertUnwindSafe(|| dev.volume.grant_read(op)));
    dev.control.unwind_next(None);
    match granted {
        Err(_) => {
            assert!(dev.volume.is_lost(), "{at}");
            reached.losses.push(Loss::GrantSubmit);
        }
        Ok(Err(ControlRefusal::Stale)) => reached.stale_grants += 1,
        Ok(Err(ControlRefusal::Closed)) => reached.closed_grants += 1,
        Ok(Ok(_)) => {
            if dev.volume.report().reads_submitted > submitted && rng.below(3) == 0 {
                let token = last_read(&dev.control);
                match FAULTS.get(rng.below(7) as usize) {
                    Some(fault) => dev.control.fault(token, *fault),
                    None => {
                        dev.control.hold(token);
                        held.push(token);
                    }
                }
            }
        }
    }
}

/// Drain proof, verified read information, one `Done` per read and right
/// conservation on the lease path: reads of
/// published objects through `Volume::read`, each later command admitted by
/// a grant that may come at once, late, twice or after the outcome, race
/// cancels, deadlines, device faults on first and later commands, held
/// completions, one loss per seed (a driver unwind in a tick's submit or
/// pick, in a read's first submit or in a grant's submit, or the device
/// going gone), an unproven
/// quiesce, a reset and the release. After every tick the objects' counts
/// above their anchors equal the reads whose records have not freed, so a
/// read's right outlives its `Done` exactly while `read_drained` is false;
/// a tick allocates nothing; every chunk carries its object's bytes under
/// its object's verified identity; and every admitted read ends once.
#[test]
fn seeded_lease_reads_hold_their_rights_and_custody_through_every_fault() {
    let mut reached = Reached::default();
    for seed in 0..32u64 {
        let storage = wide(2, 8);
        let buffers = arena();
        let mut dev = Device::new(&storage, &buffers);
        let session = dev.volume.session();
        let mut rng = SplitMix64::new(0x1EA5E ^ seed);
        let objects: Vec<Object> = (0..3u8)
            .map(|n| {
                let len = if n == 0 {
                    0
                } else {
                    1 + rng.below(5 * 8192) as usize
                };
                let metadata = (rng.below(48) as usize).min(len);
                let payload = bytes(len, seed * 8 + u64::from(n));
                let k = key(n + 1);
                let mut fill = reserve(&storage, &k, metadata, len - metadata).unwrap();
                dev.fill(&mut fill, &payload);
                let lease = fill
                    .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
                    .unwrap();
                service(&storage);
                Object {
                    key: k,
                    allocation: lease.id().record_tag(),
                    metadata,
                    payload,
                    slot: lease.id().slot_index(),
                }
            })
            .collect();
        // Every metadata command settles first, so every command the faults pick is a read.
        dev.persist_journal();
        let refs = |slot: usize| storage.live_pool().unwrap().refs(slot);
        for object in &objects {
            assert_eq!(refs(object.slot), 1, "the anchor alone");
        }
        let mut reader = storage.register().unwrap();
        let mut live: Vec<(ReadOp, usize)> = Vec::new();
        // Reads whose `Done` arrived and whose records have not yet freed.
        let mut undrained: Vec<ReadOp> = Vec::new();
        // Reads admitted by a first submit that unwound, for which the test holds no handle.
        let mut unreceived = 0usize;
        let (mut out, mut chunks, mut held) = (Vec::with_capacity(8), Vec::new(), Vec::new());
        let mut now = 0;
        let loss_at = 60 + rng.below(120);
        let loss = [
            Loss::TickSubmit,
            Loss::TickPick,
            Loss::ReadSubmit,
            Loss::GrantSubmit,
            Loss::Gone,
        ][rng.below(5) as usize];
        for step in 0..300u64 {
            let at = format!("seed {seed} step {step}");
            now += rng.below(3);
            let armed = step >= loss_at && !dev.volume.is_lost();
            if armed && loss == Loss::Gone {
                dev.control.set_gone();
            }
            match rng.below(8) {
                0 | 1 if step < 220 => {
                    let index = rng.below(3) as usize;
                    let lease = lookup(&mut reader, &objects[index].key, RETRIES).unwrap();
                    let deadline = now + 3 + rng.below(30);
                    if armed && loss == Loss::ReadSubmit {
                        dev.control.unwind_next(Some(Unwind::Submit));
                    }
                    let read = catch_unwind(AssertUnwindSafe(|| dev.volume.read(lease, deadline)));
                    dev.control.unwind_next(None);
                    match read {
                        Err(_) => {
                            assert!(dev.volume.is_lost(), "{at}");
                            reached.losses.push(Loss::ReadSubmit);
                            unreceived += 1;
                        }
                        Ok(Ok(op)) => {
                            live.push((op, index));
                            match FAULTS.get(rng.below(8) as usize) {
                                Some(fault) => dev.control.fault(last_read(&dev.control), *fault),
                                None if rng.below(2) == 0 => {
                                    let token = last_read(&dev.control);
                                    dev.control.hold(token);
                                    held.push(token);
                                }
                                None => {}
                            }
                        }
                        Ok(Err(refused)) => assert!(
                            matches!(
                                refused.refusal,
                                ReadRefusal::PoolExhausted
                                    | ReadRefusal::OpsExhausted
                                    | ReadRefusal::Lost
                                    | ReadRefusal::Closed
                                    | ReadRefusal::Submit(_)
                            ),
                            "{refused:?}, {at}"
                        ),
                    }
                }
                // A cancel, or a grant that may find the read busy, already granted or ended.
                2 => {
                    let picked = live
                        .get(rng.below(live.len() as u64 + 1) as usize)
                        .map(|(op, _)| *op)
                        .or_else(|| undrained.first().copied());
                    if let Some(op) = picked {
                        if rng.below(2) == 0 {
                            let _ = dev.volume.cancel_read(op);
                        } else {
                            grant(
                                &mut dev,
                                &mut rng,
                                &mut reached,
                                &mut held,
                                op,
                                armed && loss == Loss::GrantSubmit,
                                &at,
                            );
                        }
                    }
                }
                3 if !held.is_empty() => {
                    dev.control
                        .release(held.swap_remove(rng.below(held.len() as u64) as usize));
                }
                4 => dev.control.execute_tick(1 + rng.below(3) as u32),
                _ => chunks.clear(),
            }
            let unwind = match loss {
                Loss::TickSubmit => Some(Unwind::Submit),
                Loss::TickPick => Some(Unwind::Pick),
                _ => None,
            };
            if armed && unwind.is_some() {
                dev.control.unwind_next(unwind);
            }
            if step == 240 {
                dev.control.set_quiesce(QuiesceMode::Unproven);
                let _ = dev.volume.close();
            }
            if step == 260 {
                dev.control.set_quiesce(QuiesceMode::Reset);
            }
            if step >= 260 {
                let _ = dev.volume.close();
            }
            let budget = 1 + rng.below(4) as u32;
            let mut tick = || dev.control.tick(budget);
            let mut poll = || {
                let allocations = crate::instrument::allocations();
                let ticked =
                    catch_unwind(AssertUnwindSafe(|| dev.volume.poll_storage(now, &mut out)));
                dev.control.unwind_next(None);
                match ticked {
                    Ok(report) => {
                        assert_eq!(crate::instrument::allocations(), allocations, "{at}");
                        if report.submitted > 0 && rng.below(3) == 0 {
                            let token = last_read(&dev.control);
                            match FAULTS.get(rng.below(7) as usize) {
                                Some(fault) => dev.control.fault(token, *fault),
                                None => {
                                    dev.control.hold(token);
                                    held.push(token);
                                }
                            }
                        }
                    }
                    Err(_) => {
                        assert!(dev.volume.is_lost(), "{at}");
                        reached.losses.push(loss);
                    }
                }
            };
            round(&mut [
                Act::new(Actor::Disk(0), &mut tick),
                Act::new(Actor::Volume(0), &mut poll),
            ]);
            for event in out.drain(..) {
                match event {
                    ReadEvent::Chunk {
                        op,
                        info,
                        range,
                        chunk,
                    } => {
                        let Some(&(_, index)) = live.iter().find(|(of, _)| *of == op) else {
                            panic!("a Chunk after its Done, {at}");
                        };
                        let object = &objects[index];
                        let identity = RecordIdentity {
                            key: object.key,
                            allocation: object.allocation,
                            session,
                            version: 0,
                        };
                        assert_eq!(*info.identity(), identity, "{at}");
                        assert_eq!(info.metadata_len() as usize, object.metadata, "{at}");
                        assert_eq!(info.payload_len(), object.payload.len() as u64, "{at}");
                        let expected = &object.payload[range.start as usize..range.end as usize];
                        assert_eq!(chunk.bytes(), expected, "{at}");
                        chunks.push(chunk);
                        // Most grants come with the chunk, some twice, so the second is kept while the command it admitted is outstanding; the rest come late from the schedule.
                        for _ in 0..match rng.below(8) {
                            0 | 1 => 0,
                            2 => 2,
                            _ => 1,
                        } {
                            grant(
                                &mut dev,
                                &mut rng,
                                &mut reached,
                                &mut held,
                                op,
                                armed && loss == Loss::GrantSubmit,
                                &at,
                            );
                        }
                    }
                    ReadEvent::Done { op, info, status } => {
                        let index = match live.iter().position(|(of, _)| *of == op) {
                            Some(position) => Some(live.swap_remove(position).1),
                            None => {
                                assert!(unreceived > 0, "a second Done, {at}");
                                assert!(
                                    matches!(status, ReadStatus::Lost | ReadStatus::TimedOut),
                                    "{status:?}, {at}"
                                );
                                unreceived -= 1;
                                None
                            }
                        };
                        if let (Some(info), Some(index)) = (info, index) {
                            assert_eq!(info.identity().key, objects[index].key, "{at}");
                            assert_eq!(
                                info.payload_len(),
                                objects[index].payload.len() as u64,
                                "{at}"
                            );
                        }
                        match status {
                            ReadStatus::Complete => {
                                assert!(info.is_some(), "{at}");
                                let empty = info.is_some_and(|info| info.payload_len() == 0);
                                reached.empty_success += u32::from(empty);
                            }
                            ReadStatus::HeaderMismatch(_) => {
                                assert_eq!(info, None, "{at}");
                                reached.header_mismatch += 1;
                            }
                            ReadStatus::ChunkMismatch { .. } => {
                                assert!(info.is_some(), "{at}");
                                reached.chunk_mismatch += 1;
                            }
                            ReadStatus::Short => reached.short += 1,
                            _ => {}
                        }
                        if !dev.volume.read_drained(op) {
                            reached.cancelled_undrained +=
                                u32::from(status == ReadStatus::Cancelled);
                            reached.timed_out_undrained +=
                                u32::from(status == ReadStatus::TimedOut);
                            undrained.push(op);
                        }
                    }
                }
            }
            undrained.retain(|op| !dev.volume.read_drained(*op));
            for (op, _) in &live {
                assert!(
                    !dev.volume.read_drained(*op),
                    "a live read holds its record, {at}"
                );
            }
            let rights: usize = objects.iter().map(|object| refs(object.slot) - 1).sum();
            assert_eq!(
                rights,
                live.len() + undrained.len() + unreceived,
                "each undrained read holds one right, {at}"
            );
        }
        if loss == Loss::Gone && dev.volume.is_lost() {
            reached.losses.push(Loss::Gone);
        }
        drop(chunks);
        let Device {
            mut volume,
            control,
        } = dev;
        for _ in 0..8 {
            let _ = volume.close();
            let mut tick = || control.tick(8);
            let mut poll = || {
                let _ = volume.poll_storage(u64::MAX, &mut out);
            };
            round(&mut [
                Act::new(Actor::Disk(0), &mut tick),
                Act::new(Actor::Volume(0), &mut poll),
            ]);
            for event in out.drain(..) {
                if let ReadEvent::Done { op, .. } = event {
                    match live.iter().position(|(of, _)| *of == op) {
                        Some(position) => drop(live.swap_remove(position)),
                        None => unreceived -= 1,
                    }
                }
            }
        }
        assert!(
            live.is_empty() && unreceived == 0,
            "every admitted read ended once, seed {seed}: {live:?}, {unreceived}"
        );
        assert!(volume.release().is_ok(), "seed {seed}");
        for object in &objects {
            assert_eq!(
                refs(object.slot),
                1,
                "every read's right ended, seed {seed}"
            );
        }
        drop(out);
        assert!(
            control.accepted(Operation::Read) > 0,
            "seed {seed} submitted reads"
        );
        assert_eq!(buffers.report(PoolKind::ReadResponse).application, 0);
        drop(reader);
    }
    // Which loss each seed reaches depends on the order of its rounds, so
    // the listed order's seeds reach every kind; a generated order checks
    // the same per-tick invariants over the losses its seeds reach.
    if crate::sim::round::legacy() {
        for kind in [
            Loss::TickSubmit,
            Loss::TickPick,
            Loss::ReadSubmit,
            Loss::GrantSubmit,
            Loss::Gone,
        ] {
            assert!(reached.losses.contains(&kind), "{kind:?}: {reached:?}");
        }
    }
    assert!(reached.cancelled_undrained > 0, "{reached:?}");
    assert!(reached.timed_out_undrained > 0, "{reached:?}");
    assert!(reached.short > 0, "{reached:?}");
    assert!(reached.stale_grants > 0, "{reached:?}");
    assert!(reached.closed_grants > 0, "{reached:?}");
    assert!(reached.empty_success > 0, "{reached:?}");
    assert!(reached.chunk_mismatch > 0, "{reached:?}");
    assert!(reached.header_mismatch > 0, "{reached:?}");
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    seeded_lease_reads_hold_their_rights_and_custody_through_every_fault,
);
