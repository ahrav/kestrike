//! The recovery helpers: their bounds, the stale and panicking terminals, CPU placement, zero limits, and named-slot loads on one, four and many helpers under every completion order, a cancel and a saturated pool.

use super::super::device::sim::media;
use super::super::volume_fixture::{MEDIA, arena_with, attach_over};
use super::super::{AttachError, test_recovery};
use super::CpuSet;
use super::helpers::{Charge, Helpers, Job, Output, PARK, Panicked, WAIT, contain};
use super::journal_tests::storage_with;
use crate::storage::EngineBudget;
use crate::storage::checkpoint::tests::{
    batch_replay, generated, slot_image, slot_reader, suffix_image, suffix_levels, suffix_reader,
};
use crate::storage::checkpoint::{READ_DEPTH, READ_LEN, SlotLoad, SlotReader, UnitDamage, WINDOWS};
use crate::storage::device::DeviceRange;
use crate::storage::recovery::checkpoint::{rows, units};
use crate::storage::recovery::checkpoint_tests::routing;
use crate::storage::recovery::checkpoint_tests::{canon, canonical, damaged, loaded, outside};
use crate::storage::recovery::{GuardedLoad, guarded_load};
use crate::storage::seeded::SplitMix64;

/// The destructors [`Bomb`] and [`Fuse`] ran, in order.
pub(crate) type Dropped = std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>;

/// A panic payload whose destructor records itself and panics with a [`Fuse`].
pub(crate) struct Bomb(pub(crate) Dropped);

impl Drop for Bomb {
    fn drop(&mut self) {
        self.0.lock().unwrap().push("bomb");
        std::panic::panic_any(Fuse(std::sync::Arc::clone(&self.0)));
    }
}

/// The payload of the panic a [`Bomb`]'s destructor raises; its destructor records itself.
struct Fuse(Dropped);

impl Drop for Fuse {
    fn drop(&mut self) {
        self.0.lock().unwrap().push("fuse");
    }
}

/// A free job over nothing, which runs no decode and ends `Freed`.
pub(super) fn job() -> Job {
    Job::Free(Vec::new(), Vec::new())
}

/// Polls `helpers` until no job runs, returning the terminals it adopted.
fn drain(helpers: &mut Helpers) -> Vec<Result<Output, Panicked>> {
    let mut adopted = Vec::new();
    while helpers.busy() {
        let mut taken = 0;
        adopted.extend(helpers.poll(&mut taken));
    }
    adopted
}

/// With `INLINE_RECOVERY` enabled on the calling thread, checks that a live pool starts no helper threads and keeps the threaded pool's charge, adoption, cancellation and panic contracts. Startup errors or a thread count return an error; a broken terminal contract panics.
#[cfg(not(loom))]
pub(crate) fn helpers_run_on_one_thread() -> Result<(), String> {
    let helpers = Helpers::start(test_recovery(), 1).map_err(|error| error.to_string())?;
    let threads = helpers.thread_cpus().len();
    if threads != 0 {
        return Err(format!("recovery helpers started {threads} threads"));
    }
    saturated_pool_bounds();
    bounded_adoption(1);
    stale_terminals();
    panicking_job();
    Ok(())
}

#[test]
#[cfg(not(loom))]
fn inline_helpers_keep_the_terminal_contract() {
    let before = crate::storage::INLINE_RECOVERY.with(|inline| inline.replace(true));
    let checked = crate::storage::helpers_run_on_one_thread();
    crate::storage::INLINE_RECOVERY.with(|inline| inline.set(before));
    checked.unwrap();
}

/// The pool's peak keeps the most live jobs and the largest held charges any reservation reached: a refused
/// reservation, a release, a terminal and a cancel lower the live charge and leave the peak where the largest
/// reservation set it.
#[test]
fn the_peak_keeps_the_high_water_of_every_reservation() {
    let limits = super::RecoveryLimits {
        jobs: 3,
        ..test_recovery()
    };
    let mut helpers = Helpers::start(limits, 1).unwrap();
    let (small, block) = (Charge::decode(1024), Charge::decode(4096));
    assert_eq!(helpers.peak(), (0, Charge::default()));
    assert!(helpers.reserve(block) && helpers.reserve(small));
    let both = Charge {
        input: block.input + small.input,
        output: block.output + small.output,
    };
    assert_eq!(helpers.peak(), (2, both));
    helpers.unreserve(small);
    helpers.dispatch(block, job());
    assert_eq!(drain(&mut helpers).len(), 1);
    assert_eq!(helpers.held(), (0, Charge::default()));
    assert!(helpers.reserve(small));
    assert_eq!(
        helpers.peak(),
        (2, both),
        "a smaller later reservation leaves the peak"
    );
    helpers.cancel();
    assert_eq!(helpers.held(), (0, Charge::default()));
    assert_eq!(helpers.peak(), (2, both), "a cancel leaves the peak");
}

/// The pool reserves until a bound is reached, refuses past it with every charge unchanged, and releases each charge once at its terminal.
#[test]
fn a_saturated_pool_refuses_until_a_terminal_releases_its_charge() {
    saturated_pool_bounds();
}

fn saturated_pool_bounds() {
    let limits = super::RecoveryLimits {
        jobs: 2,
        ..test_recovery()
    };
    let mut helpers = Helpers::start(limits, 1).unwrap();
    let block = Charge::decode(4096);
    assert!(helpers.reserve(block) && helpers.reserve(block));
    assert!(!helpers.reserve(block), "the live-job bound");
    assert_eq!(helpers.held().0, 2);
    helpers.dispatch(block, job());
    assert_eq!(drain(&mut helpers).len(), 1);
    assert_eq!(
        helpers.held(),
        (1, block),
        "the dispatched job's charge released once"
    );
    helpers.unreserve(block);
    assert_eq!(helpers.held(), (0, Charge::default()));
    let wide = super::RecoveryLimits {
        input_bytes: 4096,
        ..test_recovery()
    };
    let mut narrow = Helpers::start(wide, 1).unwrap();
    assert!(narrow.reserve(block));
    assert!(!narrow.reserve(block), "the input-byte bound");
    assert_eq!(narrow.held(), (1, block));
    let tall = super::RecoveryLimits {
        output_bytes: block.output,
        ..test_recovery()
    };
    let mut short = Helpers::start(tall, 1).unwrap();
    assert!(short.reserve(block));
    assert!(!short.reserve(block), "the output-byte bound");
    assert_eq!(short.held(), (1, block));
    short.dispatch(block, job());
    assert_eq!(drain(&mut short).len(), 1);
    assert!(
        short.reserve(block),
        "admission resumes once the terminal drained"
    );
    short.unreserve(block);
}

/// One tick's polls together adopt at most `adopt` terminals; the rest wait for the next tick.
#[test]
fn a_tick_adopts_at_most_the_adoption_bound() {
    bounded_adoption(1);
}

/// The assertions expect one adoption per tick whatever `adopt` the pool starts with.
fn bounded_adoption(adopt: u32) {
    let limits = super::RecoveryLimits {
        adopt,
        ..test_recovery()
    };
    let mut helpers = Helpers::start(limits, 1).unwrap();
    let block = Charge::decode(4096);
    assert!(helpers.reserve(block) && helpers.reserve(block));
    helpers.dispatch(block, job());
    helpers.dispatch(block, job());
    let mut taken = 0;
    assert!(helpers.poll(&mut taken).is_some());
    assert!(helpers.poll(&mut taken).is_none(), "the tick's bound");
    assert!(helpers.busy());
    assert_eq!(drain(&mut helpers).len(), 1);
}

/// Setting `adopt` to two lets the tick adopt both terminals, which the bound of one rejects.
#[test]
#[should_panic(expected = "the tick's bound")]
fn negative_control_a_tick_that_adopts_two_fails_the_bound() {
    bounded_adoption(2);
}

/// A terminal of a cancelled attempt reaches the owner, releases its charge and is adopted by no one.
#[test]
fn a_stale_terminal_publishes_nothing_and_releases_its_charge() {
    stale_terminals();
}

fn stale_terminals() {
    let mut helpers = Helpers::start(test_recovery(), 2).unwrap();
    let block = Charge::decode(4096);
    assert!(helpers.reserve(block));
    helpers.dispatch(block, job());
    helpers.cancel();
    assert!(
        drain(&mut helpers).is_empty(),
        "attempt 2's output reaches attempt 3"
    );
    assert_eq!(helpers.held(), (0, Charge::default()));
    assert!(!helpers.reserve(block), "a cancelled pool reserves nothing");
}

/// A panicking job ends as a `Panicked` terminal and the pool still drops, joining its threads.
#[test]
fn a_panicking_job_becomes_a_typed_terminal() {
    panicking_job();
}

fn panicking_job() {
    let mut helpers = Helpers::start(test_recovery(), 1).unwrap();
    assert!(helpers.reserve(Charge::default()));
    helpers.dispatch(Charge::default(), Job::Panic);
    let adopted = drain(&mut helpers);
    assert!(matches!(adopted[..], [Err(Panicked)]));
    drop(helpers);
}

/// CONTAINED: a run whose panic payload panics again as it drops ends `Panicked`. The first payload's destructor runs
/// once, and the second payload's never runs.
#[test]
fn a_panic_whose_payload_panics_on_drop_is_contained() {
    let dropped = Dropped::default();
    let bomb = Bomb(std::sync::Arc::clone(&dropped));
    let contained = contain(move || -> Output { std::panic::panic_any(bomb) });
    assert!(matches!(contained, Err(Panicked)));
    assert_eq!(*dropped.lock().unwrap(), ["bomb"]);
}

/// Helpers started by a pinned owner run on other CPUs to preserve CPU time for the owner's polling.
#[test]
#[cfg(not(loom))]
fn helpers_of_a_pinned_owner_run_apart_from_its_cpu() {
    let allowed = CpuSet::current().unwrap();
    let mut cpus = allowed.cpus();
    let (Some(owner), Some(_)) = (cpus.next(), cpus.next()) else {
        panic!("the test needs two allowed CPUs, found {allowed:?}");
    };
    let mut apart = allowed;
    apart.remove(owner);
    let limits = super::RecoveryLimits {
        cpus: apart,
        ..test_recovery()
    };
    // SAFETY: `pthread_self` reads the calling thread's handle.
    let this = unsafe { libc::pthread_self() };
    // SAFETY: `this` names the calling thread, which stays live for each call.
    unsafe { CpuSet::from_cpus(&[owner]).unwrap().apply(this) }.unwrap();
    let helpers = Helpers::start(limits, 1);
    // SAFETY: as above.
    unsafe { allowed.apply(this) }.unwrap();
    let placed = helpers.unwrap().thread_cpus();
    assert_eq!(placed.len(), limits.helpers as usize);
    assert!(
        placed
            .iter()
            .all(|set| !set.is_empty() && !set.contains(owner)),
        "the owner runs on {owner}; the helpers on {placed:?}"
    );
    assert!(placed.iter().all(|set| *set == apart), "{placed:?}");
}

#[test]
#[cfg(not(loom))]
fn a_cpu_set_the_kernel_refuses_fails_the_start() {
    let allowed = CpuSet::current().unwrap();
    let outside = (0..super::MAX_CPUS)
        .rev()
        .find(|&cpu| !allowed.contains(cpu))
        .expect("some CPU index lies outside the allowed set");
    let limits = super::RecoveryLimits {
        cpus: CpuSet::from_cpus(&[outside]).unwrap(),
        ..test_recovery()
    };
    let refused = Helpers::start(limits, 1).map(|_| ());
    assert_eq!(
        refused.map_err(|error| error.raw_os_error()),
        Err(Some(libc::EINVAL))
    );
}

/// A recovery I/O share whose owner part holds less than one metadata block plus one suffix block, a zero interval, no
/// owner or more than the most owners refuses the attach, naming the metadata block.
#[test]
fn a_recovery_io_share_below_one_block_or_with_no_interval_refuses_the_attach() {
    let store = media(MEDIA);
    let unit = 4096;
    for (bytes, interval, owners) in [
        (2 * unit - 1, 8, 1),
        (0, 8, 1),
        (2 * unit, 0, 1),
        (2 * unit, 8, 0),
        (
            u64::MAX,
            8,
            crate::storage::recovery::io_share::MAX_OWNERS + 1,
        ),
        (6 * unit, 8, 4),
    ] {
        let storage = storage_with(|volume| {
            volume.recovery.io = super::super::recovery::HostShare {
                bytes,
                interval,
                owners,
            };
        });
        let buffers = arena_with(4, 5);
        let refused = attach_over(&storage, &buffers, &store).map(|_| ());
        assert_eq!(
            refused,
            Err(AttachError::RecoveryLimits { unit: 4096 }),
            "{bytes} bytes per {interval} ticks over {owners} owners"
        );
    }
}

/// A zero count, a byte bound below one metadata block's decode charge, more helpers than jobs or an empty CPU set
/// refuses the attach; bounds of exactly one block's charge attach.
#[test]
fn a_zero_recovery_limit_refuses_at_attach() {
    let store = media(MEDIA);
    let edits: [fn(&mut super::RecoveryLimits); 8] = [
        |limits| limits.cpus = CpuSet::empty(),
        |limits| limits.helpers = 0,
        |limits| limits.helpers = limits.jobs + 1,
        |limits| limits.jobs = 0,
        |limits| limits.adopt = 0,
        |limits| limits.input_bytes = 0,
        |limits| limits.input_bytes = 4095,
        |limits| limits.output_bytes = 4096 * 24 - 1,
    ];
    for edit in edits {
        let storage = storage_with(|volume| edit(&mut volume.recovery));
        let buffers = arena_with(4, 5);
        let refused = attach_over(&storage, &buffers, &store).map(|_| ());
        assert_eq!(refused, Err(AttachError::RecoveryLimits { unit: 4096 }));
    }
    let storage = storage_with(|volume| {
        volume.recovery.input_bytes = 4096;
        volume.recovery.output_bytes = 4096 * 24;
    });
    let buffers = arena_with(4, 5);
    assert!(
        attach_over(&storage, &buffers, &store).is_ok(),
        "one block's bounds attach"
    );
}

/// Adopts every terminal `helpers` holds into `reader`; a `Panicked` terminal fails the decode.
fn adopt(helpers: &mut Helpers, reader: &mut SlotReader) {
    let mut adopted = 0;
    while let Some(output) = helpers.poll(&mut adopted) {
        match output {
            Ok(Output::Slot(done)) => reader.decode().landed(done),
            Ok(_) => unreachable!("only slot jobs run"),
            Err(Panicked) => reader.decode().fail(),
        }
    }
}

/// Drives `reader` over the prefix image `bytes` through `helpers`, as an owner does: it reserves a window's charge
/// before each read, releases it once a suffix read lands in the decode, reserves a destination job's charge before
/// taking each decode job, and completes the read `pick` names. A threaded
/// pool is polled after each dispatch, which sends the job alone, so the jobs spread over the helper threads; a parked
/// pool's terminals are released in the order `pick` names before each loop's poll.
fn slot_load(
    helpers: &mut Helpers,
    mut reader: SlotReader,
    bytes: &[u8],
    mut pick: impl FnMut(usize) -> usize,
) -> Option<SlotLoad> {
    let window = Charge::decode(READ_LEN as usize);
    let threaded = helpers.parked().is_none();
    let mut flight = Vec::new();
    let started = std::time::Instant::now();
    while !reader.done() {
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(120),
            "the reader finishes"
        );
        let guard = Charge {
            input: reader.decode().guard_bytes(),
            output: 0,
        };
        while helpers.reserve(window) {
            let Some(range) = reader.next_read() else {
                helpers.unreserve(window);
                break;
            };
            flight.push(range);
        }
        if !flight.is_empty() {
            let range: DeviceRange = flight.remove(pick(flight.len()));
            let start = range.start() as usize;
            let job = reader.completed(
                range,
                bytes[start..start + range.byte_len() as usize].to_vec(),
            );
            match job {
                Some(job) => {
                    helpers.dispatch(window, Job::Slot(job));
                }
                None => helpers.unreserve(window),
            }
            if threaded {
                adopt(helpers, &mut reader);
            }
        }
        while helpers.reserve(guard) {
            let Some(job) = reader.decode().work() else {
                helpers.unreserve(guard);
                break;
            };
            helpers.dispatch(guard, Job::Slot(job));
            if threaded {
                adopt(helpers, &mut reader);
            }
        }
        if let Some((ran, released)) = helpers.parked() {
            while !ran.is_empty() {
                released.push_back(ran.swap_remove(pick(ran.len())));
            }
        }
        adopt(helpers, &mut reader);
        if threaded {
            std::thread::yield_now();
        }
    }
    reader.finish()
}

/// Limits for `helpers` threads with room for every read a reader keeps outstanding.
fn slot_limits(helpers: u32) -> super::RecoveryLimits {
    let jobs = (READ_DEPTH as u32 + 16).max(helpers);
    let input_bytes = jobs as usize * READ_LEN as usize;
    super::RecoveryLimits {
        helpers,
        jobs,
        input_bytes,
        output_bytes: input_bytes * super::helpers::OUTPUT_PER_BYTE,
        adopt: jobs,
        ..test_recovery()
    }
}

/// A slot decoded on a pool of one, four or sixteen helpers over one, four or sixteen destinations gets the batch
/// guard's verdict and keeps the same entries, for generated checkpoints mixing refusals, and a slot torn in its last
/// unit loses only that unit's entries.
#[test]
fn a_slot_load_gets_the_batch_verdict_at_one_four_and_many_helpers() {
    let mut rng = SplitMix64::new(0x1445);
    let mut refusals = std::collections::BTreeSet::new();
    let mut torn_refused = 0;
    for case in 0..13 {
        let (entries, limits) = match case {
            0 => {
                let entries = crate::storage::checkpoint::tests::entries(41 * 64 * 40);
                let limits = crate::storage::checkpoint::tests::load_limits(entries.len());
                (entries, limits)
            }
            _ => generated(&mut rng),
        };
        let batch = canon(guarded_load(
            entries.clone(),
            limits,
            &EngineBudget::unlimited(),
        ));
        if let GuardedLoad::Cold { refusal, .. } = &batch {
            refusals.insert(format!("{refusal:?}"));
        }
        let last = units(rows(&entries)) as u32 - 1;
        let kept = canonical(outside(&entries, last as usize));
        for ((threads, shards), tear) in [(1, 1), (1, 16), (4, 4), (16, 1), (16, 16)]
            .into_iter()
            .zip([false, true, false, true, false])
        {
            // A pool that waits for no terminal keeps several slot jobs running on its threads at once.
            WAIT.with(|cell| cell.set(false));
            let mut helpers = Helpers::start(slot_limits(threads), 1).unwrap();
            WAIT.with(|cell| cell.set(true));
            let (layout, ck, bytes) = slot_image(&entries, tear);
            let reader = slot_reader(&layout, ck, limits, shards);
            let slot = slot_load(&mut helpers, reader, &bytes, |len| {
                rng.next_u64() as usize % len
            })
            .expect("no helper failed");
            let what = format!("case {case}: {threads} helpers, {shards} shards, torn {tear}");
            if tear {
                let (damage, load) = damaged(slot);
                assert_eq!(damage.failed, [last], "{what}");
                assert_eq!(loaded(load.clone()), kept, "{what}");
                let uncut = rows(&kept) == u64::from(last - 1) * 41;
                if uncut {
                    let over_kept = guarded_load(kept.clone(), limits, &EngineBudget::unlimited());
                    torn_refused += usize::from(matches!(over_kept, GuardedLoad::Cold { .. }));
                    assert_eq!(load, over_kept, "{what}");
                }
                if matches!(batch, GuardedLoad::Warm(_)) {
                    assert_eq!(load, GuardedLoad::Warm(kept.clone()), "{what}");
                }
            } else {
                assert_eq!(slot.damage, None, "{what}");
                assert_eq!(slot.load(), batch, "{what}");
            }
            assert_eq!(helpers.held(), (0, Charge::default()), "{what}");
        }
    }
    assert!(
        refusals.len() >= 4,
        "the cases reach several refusals: {refusals:?}"
    );
    assert!(
        torn_refused > 0,
        "a torn slot's refused verdict is compared"
    );
}

/// Every order in which a parked pool releases a slot load's terminals gives one load: the decode stitches windows
/// in unit order and every guard rule is a predicate over the decoded rows. A slot torn in units 2 and 100, which lie
/// in different windows, names unit 2 as its first damage whatever order the windows land in.
#[test]
fn every_completion_order_of_a_parked_slot_load_gives_one_load() {
    let entries = crate::storage::checkpoint::tests::entries(41 * 140);
    let limits = crate::storage::checkpoint::tests::load_limits(entries.len());
    let (layout, ck, mut bytes) = slot_image(&entries, false);
    let unit = |at: usize| (1 + 2 * layout.slot_units as usize + at) * 4096;
    for at in [2, 100] {
        bytes[unit(at) + 4095] ^= 1;
    }
    PARK.with(|cell| cell.set(true));
    let mut loads = Vec::new();
    for seed in 0..16 {
        let mut rng = SplitMix64::new(seed);
        let mut helpers = Helpers::start(slot_limits(4), 1).unwrap();
        let reader = slot_reader(&layout, ck, limits, 4);
        let slot = slot_load(&mut helpers, reader, &bytes, |len| {
            rng.next_u64() as usize % len
        });
        loads.push(slot.expect("no helper failed"));
    }
    PARK.with(|cell| cell.set(false));
    let first = &loads[0];
    let damage = first.damage.as_ref().unwrap();
    assert_eq!(damage.failed, [2, 100]);
    assert_eq!(damage.first, UnitDamage::Chunk { unit: 2 });
    let kept = entries
        .iter()
        .enumerate()
        .filter(|(at, _)| ![2, 100].contains(&(1 + at / 41)));
    assert_eq!(
        first.load(),
        GuardedLoad::Warm(canonical(kept.map(|(_, entry)| entry.clone()).collect())),
        "every entry outside the torn units loads"
    );
    assert!(loads.iter().all(|load| load == first));
}

/// A slot and suffix load whose window, replay and destination jobs are queued or running when the attempt cancels
/// adopts none of their terminals and releases every charge; a fresh attempt then loads the batch replay's entries.
#[test]
fn a_cancelled_slot_load_adopts_no_terminal_and_releases_every_charge() {
    let entries = crate::storage::checkpoint::tests::entries(41 * 64 * 4);
    let (limits, levels) = suffix_case(&entries);
    let (layout, ck, ancestry, bytes) = suffix_image(&entries, &levels, (&[], false));
    let batch = batch_replay((&layout, &limits), &entries, &ancestry, &bytes);
    let mut helpers = Helpers::start(slot_limits(4), 1).unwrap();
    let mut reader = suffix_reader(&layout, (ck, &ancestry), limits, routing(4));
    let window = Charge::decode(READ_LEN as usize);
    let mut windows = 0;
    while windows < 2 {
        assert!(helpers.reserve(window));
        let range = reader.next_read().unwrap();
        let start = range.start() as usize;
        let job = reader.completed(
            range,
            bytes[start..start + range.byte_len() as usize].to_vec(),
        );
        match job {
            Some(job) => {
                helpers.dispatch(window, Job::Slot(job));
                windows += 1;
            }
            None => helpers.unreserve(window),
        }
    }
    let landed = drain(&mut helpers);
    for output in landed {
        let Ok(Output::Slot(done)) = output else {
            panic!("a slot terminal");
        };
        reader.decode().landed(done);
    }
    let guard = Charge {
        input: reader.decode().guard_bytes(),
        output: 0,
    };
    let mut kinds = Vec::new();
    while let Some(job) = reader.decode().work() {
        kinds.push(matches!(job, crate::storage::checkpoint::Work::Replay(_)));
        assert!(helpers.reserve(guard));
        helpers.dispatch(guard, Job::Slot(job));
    }
    assert!(
        kinds.contains(&true) && kinds.contains(&false),
        "the replay and a destination job run"
    );
    assert!(helpers.reserve(window));
    let range = reader.next_read().unwrap();
    let start = range.start() as usize;
    let job = reader
        .completed(
            range,
            bytes[start..start + range.byte_len() as usize].to_vec(),
        )
        .expect("a slot read");
    helpers.dispatch(window, Job::Slot(job));
    assert!(helpers.reserve(window), "a reservation the cancel releases");
    helpers.cancel();
    assert!(drain(&mut helpers).is_empty(), "every terminal is stale");
    assert_eq!(helpers.held(), (0, Charge::default()));
    let mut again = Helpers::start(slot_limits(4), 2).unwrap();
    let reader = suffix_reader(&layout, (ck, &ancestry), limits, routing(4));
    let slot = slot_load(&mut again, reader, &bytes, |_| 0).expect("no helper failed");
    assert_eq!(slot.load(), GuardedLoad::Warm(canonical(batch.entries)));
}

/// Terminals of slot jobs that land after their attempt's cancel publish nothing: a parked pool holds window jobs, the
/// replay and a destination job that moved its guard past the cancel, and their release reaches no poll's adoption while their
/// charges return.
#[test]
fn a_slot_terminal_landing_after_the_cancel_publishes_nothing() {
    let entries = crate::storage::checkpoint::tests::entries(41 * 64 * 2);
    let limits = crate::storage::checkpoint::tests::load_limits(entries.len());
    let (layout, ck, bytes) = slot_image(&entries, false);
    PARK.with(|cell| cell.set(true));
    let mut helpers = Helpers::start(slot_limits(2), 1).unwrap();
    PARK.with(|cell| cell.set(false));
    let mut reader = slot_reader(&layout, ck, limits, 2);
    let window = Charge::decode(READ_LEN as usize);
    while helpers.reserve(window) {
        let Some(range) = reader.next_read() else {
            helpers.unreserve(window);
            break;
        };
        let start = range.start() as usize;
        let job = reader
            .completed(
                range,
                bytes[start..start + range.byte_len() as usize].to_vec(),
            )
            .expect("a slot read");
        helpers.dispatch(window, Job::Slot(job));
    }
    let (ran, released) = helpers.parked().unwrap();
    released.push_back(ran.remove(0));
    adopt(&mut helpers, &mut reader);
    let guard = Charge {
        input: reader.decode().guard_bytes(),
        output: 0,
    };
    let (before, mut queued) = (helpers.held().1.input, 0);
    while let Some(job) = reader.decode().work() {
        assert!(helpers.reserve(guard));
        helpers.dispatch(guard, Job::Slot(job));
        queued += 1;
    }
    assert!(
        guard.input > 0 && queued >= 2 && helpers.held().1.input == before + queued * guard.input,
        "the queued replay and guard hold the charges their reservations took"
    );
    let (ran, _) = helpers.parked().unwrap();
    assert_eq!(ran.last().map(|(_, charge, _)| *charge), Some(guard));
    assert!(helpers.busy());
    helpers.cancel();
    let (ran, released) = helpers.parked().unwrap();
    assert!(!ran.is_empty(), "the jobs ran before the cancel");
    released.extend(ran.drain(..));
    assert!(
        drain(&mut helpers).is_empty(),
        "a late terminal is adopted by no poll"
    );
    assert_eq!(helpers.held(), (0, Charge::default()));
    assert!(!reader.done(), "the moved guard never returns");
}

/// A slot job that panics on a helper ends as a `Panicked` terminal; the owner fails the decode, whose finish returns
/// no load, so the caller keeps the record for a later read. The reader finishes once its outstanding reads complete,
/// on a slot of more windows than the reader holds, whether a window, replay or destination job panicked, and every
/// charge returns.
#[test]
fn a_panicking_slot_job_fails_the_load() {
    let entries = crate::storage::checkpoint::tests::entries(41 * 64 * (WINDOWS + 8));
    let limits = crate::storage::checkpoint::tests::load_limits(entries.len());
    let (layout, ck, bytes) = slot_image(&entries, false);
    for panics in [
        &crate::storage::recovery::checkpoint::PANIC,
        &crate::storage::recovery::checkpoint::WINDOW_PANIC,
        &crate::storage::recovery::checkpoint::REPLAY_PANIC,
    ] {
        PARK.with(|cell| cell.set(true));
        let mut helpers = Helpers::start(slot_limits(2), 1).unwrap();
        panics.with(|cell| cell.set(true));
        let slot = slot_load(
            &mut helpers,
            slot_reader(&layout, ck, limits, 2),
            &bytes,
            |_| 0,
        );
        panics.with(|cell| cell.set(false));
        PARK.with(|cell| cell.set(false));
        assert_eq!(slot, None, "a helper failure yields no load");
        assert_eq!(helpers.held(), (0, Charge::default()));
    }
    // A window job fails while the suffix's earlier reads are still outstanding: the newest read completes first, and
    // the reader finishes once the suffix reads drain.
    let entries = crate::storage::checkpoint::tests::entries(41 * 64 * 4);
    let (limits, _) = suffix_case(&entries);
    let inserts = (1..6000).map(|serial| {
        let made =
            crate::storage::checkpoint::tests::suffix_entry(serial, entries.len(), 5, 0, &limits);
        crate::storage::recovery::delta::Record::Insert(made)
    });
    let (layout, ck, ancestry, bytes) = suffix_image(&entries, &[inserts.collect()], (&[], false));
    let panics = &crate::storage::recovery::checkpoint::WINDOW_PANIC;
    PARK.with(|cell| cell.set(true));
    let mut helpers = Helpers::start(slot_limits(2), 1).unwrap();
    panics.with(|cell| cell.set(true));
    let reader = suffix_reader(&layout, (ck, &ancestry), limits, routing(2));
    let slot = slot_load(&mut helpers, reader, &bytes, |len| len - 1);
    panics.with(|cell| cell.set(false));
    PARK.with(|cell| cell.set(false));
    assert_eq!(
        slot, None,
        "a helper failure beside outstanding suffix reads yields no load"
    );
    assert_eq!(helpers.held(), (0, Charge::default()));
}

/// A pool whose job or byte bound is reached refuses the next window's reservation, so the owner issues no further
/// slot read; admission resumes once a terminal releases its charge.
#[test]
fn a_saturated_pool_holds_slot_reads_until_a_terminal_releases_its_charge() {
    let entries = crate::storage::checkpoint::tests::entries(41 * 64 * 4);
    let limits = crate::storage::checkpoint::tests::load_limits(entries.len());
    let (layout, ck, bytes) = slot_image(&entries, false);
    let window = Charge::decode(READ_LEN as usize);
    let narrow = super::RecoveryLimits {
        helpers: 1,
        jobs: 2,
        input_bytes: 2 * READ_LEN as usize,
        output_bytes: 2 * window.output,
        adopt: 2,
        ..test_recovery()
    };
    let mut helpers = Helpers::start(narrow, 1).unwrap();
    let mut reader = slot_reader(&layout, ck, limits, 1);
    let mut issued = Vec::new();
    while helpers.reserve(window) {
        issued.push(reader.next_read().unwrap());
    }
    assert_eq!(issued.len(), 2, "the pool holds two windows' charges");
    let range = issued.remove(0);
    let start = range.start() as usize;
    let job = reader
        .completed(
            range,
            bytes[start..start + range.byte_len() as usize].to_vec(),
        )
        .expect("a slot read");
    helpers.dispatch(window, Job::Slot(job));
    assert_eq!(
        helpers.held(),
        (
            2,
            Charge {
                input: 2 * READ_LEN as usize,
                output: 2 * window.output
            }
        ),
        "one running window and one reserved window, each charged its bytes"
    );
    assert!(
        !helpers.reserve(window),
        "a running window still holds its charge"
    );
    assert_eq!(drain(&mut helpers).len(), 1);
    assert!(helpers.reserve(window), "the terminal released its charge");
    helpers.unreserve(window);
    let mut helpers = Helpers::start(narrow, 2).unwrap();
    let slot = slot_load(
        &mut helpers,
        slot_reader(&layout, ck, limits, 1),
        &bytes,
        |_| 0,
    );
    assert_eq!(
        slot.expect("no helper failed").load(),
        canon(guarded_load(entries, limits, &EngineBudget::unlimited())),
        "two jobs on one helper finish the load"
    );
}

/// Limits with room past the checkpoint's slots and units, and one suffix level of fresh inserts, for a load of
/// `entries`.
fn suffix_case(
    entries: &[crate::storage::recovery::CaptureEntry],
) -> (
    crate::storage::LoadLimits,
    Vec<Vec<crate::storage::recovery::delta::Record>>,
) {
    let count = entries.len();
    let mut limits = crate::storage::checkpoint::tests::load_limits(count);
    limits.slot_count = 2 * count + 64;
    (limits.payload_end, limits.n_max) = (8 * limits.slot_count as u64, limits.slot_count);
    let inserts = (1..2000)
        .map(|serial| {
            let made =
                crate::storage::checkpoint::tests::suffix_entry(serial, count, 5, 0, &limits);
            crate::storage::recovery::delta::Record::Insert(made)
        })
        .collect();
    (limits, vec![inserts])
}

/// A slot and an ancestry of suffixes decoded on a pool of one, four or sixteen helpers over one, four or sixteen
/// destinations get the verdict of the checkpoint's guard and, once it passes, of the batch replay followed by the
/// batch guard, with the same final entries, suffix report and counts of superseded and withheld checkpoint entries, for
/// generated checkpoints and suffixes, some with a checkpoint entry of a session the reader does not admit; one case
/// spans 40 windows and three suffix levels.
#[test]
fn a_slot_and_suffix_load_gets_the_batch_verdict_at_one_four_and_many_helpers() {
    let mut rng = SplitMix64::new(0x1445B);
    let (mut warm, mut superseded, mut withheld) = (0, 0, 0);
    for case in 0..8 {
        let (mut entries, mut limits) = match case {
            0 => {
                let entries = crate::storage::checkpoint::tests::entries(41 * 64 * 40);
                let limits = crate::storage::checkpoint::tests::load_limits(entries.len());
                (entries, limits)
            }
            _ => generated(&mut rng),
        };
        if case % 3 == 1 {
            // A checkpoint entry of generation 0, which the suffix reader does not admit.
            let at = case % entries.len();
            entries[at].session = 2;
        }
        let count = entries.len();
        limits.slot_count = 2 * count + 64;
        (limits.payload_end, limits.n_max) = (8 * limits.slot_count as u64, limits.slot_count);
        let levels = match case {
            0 => (0..3)
                .map(|_| suffix_case(&entries).1[0][..600].to_vec())
                .collect(),
            _ => suffix_levels(&mut rng, count, &limits),
        };
        let (layout, ck, ancestry, bytes) = suffix_image(&entries, &levels, (&[], false));
        let base = guarded_load(entries.clone(), limits, &EngineBudget::unlimited());
        let batch = batch_replay((&layout, &limits), &entries, &ancestry, &bytes);
        let expected = match base {
            GuardedLoad::Cold { refusal, .. } => Err(refusal),
            GuardedLoad::Warm(_) => Ok(canon(guarded_load(
                batch.entries.clone(),
                limits,
                &EngineBudget::unlimited(),
            ))),
        };
        // The suffix's own report, and the counts of checkpoint entries it superseded and of those withheld.
        let identities: Vec<_> = entries
            .iter()
            .map(crate::storage::recovery::delta::identity_of)
            .collect();
        let mut report = batch.report.clone();
        report.superseded.retain(|id| !identities.contains(id));
        report.withheld.retain(|id| !identities.contains(id));
        let counts = (
            (batch.report.superseded.len() - report.superseded.len()) as u64,
            (batch.report.withheld.len() - report.withheld.len()) as u64,
        );
        for (threads, shards) in [(1, 1), (1, 16), (4, 4), (16, 1), (16, 16)] {
            WAIT.with(|cell| cell.set(false));
            let mut helpers = Helpers::start(slot_limits(threads), 1).unwrap();
            WAIT.with(|cell| cell.set(true));
            let reader = suffix_reader(&layout, (ck, &ancestry), limits, routing(shards));
            let slot = slot_load(&mut helpers, reader, &bytes, |len| {
                rng.next_u64() as usize % len
            })
            .expect("no helper failed");
            let what = format!("case {case}: {threads} helpers, {shards} shards");
            assert_eq!(slot.damage, None, "{what}");
            match &expected {
                Err(refusal) => assert_eq!(slot.verdict, Err(*refusal), "{what}"),
                Ok(load) => {
                    assert_eq!(&slot.load(), load, "{what}");
                    let slot_counts = (slot.slot_superseded, slot.slot_withheld);
                    assert_eq!((&slot.suffix, slot_counts), (&report, counts), "{what}");
                    warm += 1;
                    (superseded, withheld) = (superseded + counts.0, withheld + counts.1);
                }
            }
            assert_eq!(helpers.held(), (0, Charge::default()), "{what}");
        }
    }
    assert!(
        warm > 5 && superseded > 0 && withheld > 0,
        "the full comparison runs ({warm} loads) over superseded ({superseded}) and withheld ({withheld}) entries"
    );
}

/// A full helper queue holds a slot load at its bounds for as long as no terminal returns: with every job the pool
/// admits run and none adopted, the owner's polls reserve nothing more, issue no read and keep the held jobs and bytes
/// at the limits, however many times it polls. Once the terminals return, the load holds every entry of the slot.
/// Under the `OVER_RESERVE` plant, a reservation that ignores the bounds, the same body issues past two windows and
/// fails its window count.
#[test]
fn a_full_helper_queue_holds_the_load_at_its_bounds_and_loads_every_entry_once_it_drains() {
    a_full_helper_queue_case();
    super::helpers::OVER_RESERVE.with(|plant| plant.set(true));
    let over = std::panic::catch_unwind(a_full_helper_queue_case);
    super::helpers::OVER_RESERVE.with(|plant| plant.set(false));
    PARK.with(|cell| cell.set(false));
    let message = over
        .err()
        .and_then(|payload| payload.downcast::<String>().ok());
    assert!(
        message
            .as_deref()
            .is_some_and(|m| m.contains("the pool admits two windows")),
        "control: a pool that ignores its bounds admits a third window: {message:?}"
    );
}

fn a_full_helper_queue_case() {
    let entries = crate::storage::checkpoint::tests::entries(41 * 64 * 6);
    let limits = crate::storage::checkpoint::tests::load_limits(entries.len());
    let (layout, ck, bytes) = slot_image(&entries, false);
    let window = Charge::decode(READ_LEN as usize);
    let narrow = super::RecoveryLimits {
        helpers: 1,
        jobs: 2,
        input_bytes: 2 * READ_LEN as usize,
        output_bytes: 2 * window.output,
        adopt: 2,
        ..test_recovery()
    };
    PARK.with(|cell| cell.set(true));
    let mut helpers = Helpers::start(narrow, 1).unwrap();
    PARK.with(|cell| cell.set(false));
    let mut reader = slot_reader(&layout, ck, limits, 1);
    let mut issued = 0;
    while issued < 4 && helpers.reserve(window) {
        let range = reader.next_read().expect("the slot spans more windows");
        issued += 1;
        let start = range.start() as usize;
        let read = bytes[start..start + range.byte_len() as usize].to_vec();
        let job = reader.completed(range, read).expect("a slot read");
        helpers.dispatch(window, Job::Slot(job));
    }
    assert_eq!(issued, 2, "the pool admits two windows");
    let full = (
        2,
        Charge {
            input: 2 * READ_LEN as usize,
            output: 2 * window.output,
        },
    );
    for poll in 0..10_000 {
        let mut adopted = 0;
        assert!(
            helpers.poll(&mut adopted).is_none(),
            "poll {poll}: no terminal returned"
        );
        assert!(!helpers.reserve(window), "poll {poll}: the queue is full");
        assert_eq!(helpers.held(), full, "poll {poll}: the charge is the limit");
        assert!(!reader.done());
    }
    let (ran, released) = helpers.parked().expect("a parked pool");
    released.extend(ran.drain(..));
    let slot = slot_load(&mut helpers, reader, &bytes, |_| 0);
    assert_eq!(helpers.held(), (0, Charge::default()));
    assert_eq!(
        slot.expect("no helper failed").load(),
        GuardedLoad::Warm(canonical(entries)),
        "the stalled load lost no entry"
    );
}
