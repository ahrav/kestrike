//! The contract every [`Disk`] implementation meets, checked through the
//! trait alone: the simulated device runs it in every lane, and the SPDK
//! driver runs it on a bound volume as a hardware row.
//!
//! The `fidelity_tests` table lists behavioral differences between the
//! simulated device and the production driver.
//!
//! The contract holds the guarantees a caller can observe from the trait's
//! surface: no completion for a refused command and exactly one for an
//! accepted one (I1, I2), read bytes inside the memory range only (I3),
//! bytes a read returns equal to the bytes a write stored (I4), a pick into
//! a sink with no room that takes nothing and keeps every completion for a
//! later pick (I5), a stop proof after which nothing is reported and every
//! submit is refused `DeviceGone` (I6), a constant geometry (I7), and
//! refusals past the capacity and at the queue depth.
//!
//! For each picked completion, before the next pick, the contract checks
//! that a write's source still equals its pattern (I3) or that a read's
//! buffer holds the block it read (I4), then fills the buffer with a
//! sentinel. Each sentinel stays unchanged through its phase's later picks
//! and the caller's observation interval that follows (I2, I4, I8).
//!
//! A failed check unwinds while the device may still hold commands over the
//! contract's buffers, so the entry point is `unsafe`: a caller over
//! device-accessible memory aborts on that unwind instead of letting the
//! buffers return.

use std::time::{Duration, Instant};

use super::super::os::Platform;
use super::{
    Buffer, BufferArena, Classification, CommandToken, Completion, CompletionSink, DeviceRange,
    Disk, IO_UNIT, PoolKind, QuiesceStatus, RefusalReason,
};

/// Picks or quiesce calls one wait spends before the contract fails.
pub(super) const PICKS: usize = 1 << 20;

/// The byte the contract writes past each read's range, which no read may change.
const GUARD: u8 = 0xC3;

/// The sentinel for the idle buffer at `index`, distinct across 256 consecutive indices.
fn idle(index: usize) -> u8 {
    0x5A ^ index as u8
}

/// The `observe` window lets late device stores land between two rounds of
/// empty picks. Each phase is its tokens, its buffers in token order and the
/// [`idle`] index of its first buffer.
fn stays_idle<D: Disk>(
    disk: &mut D,
    observe: Duration,
    progress: &mut impl FnMut(),
    phases: &[(&[CommandToken], &[Buffer<'_>], usize)],
) {
    silent(disk, progress);
    let start = Instant::now();
    while start.elapsed() < observe {
        progress();
    }
    silent(disk, progress);
    for &(tokens, buffers, first) in phases {
        for (index, (token, buffer)) in tokens.iter().zip(buffers).enumerate() {
            let sentinel = idle(first + index);
            assert!(
                buffer.bytes().iter().all(|&byte| byte == sentinel),
                "{token:?} changed its buffer after its completion"
            );
        }
    }
}

/// The bytes the contract writes to block `index`.
fn pattern(index: usize) -> Vec<u8> {
    (0..IO_UNIT)
        .map(|at| (at % 251) as u8 ^ (index as u8))
        .collect()
}

/// `count` tokens from `base`, each phase's from its own range of 2^32.
fn tokens(base: u64, count: usize) -> Vec<CommandToken> {
    (0..count)
        .map(|index| CommandToken::from_raw((base << 32) + index as u64))
        .collect()
}

/// Picks one completion at a time, calling `progress` before each pick,
/// until `count` arrived.
pub(super) fn drain<D: Disk>(
    disk: &mut D,
    count: usize,
    progress: &mut impl FnMut(),
    what: &str,
    mut each: impl FnMut(&Completion),
) -> Vec<Completion> {
    let mut done = Vec::with_capacity(count);
    for _ in 0..PICKS {
        if done.len() == count {
            return done;
        }
        progress();
        let mut out = Vec::with_capacity(1);
        disk.pick_completions(&mut CompletionSink::new(&mut out, 1));
        out.iter().for_each(&mut each);
        done.extend(out);
    }
    panic!("{what}: {} of {count} completions arrived", done.len());
}

/// `check` runs before the next `progress` call or completion pick.
fn settle<D: Disk>(
    disk: &mut D,
    tokens: &[CommandToken],
    progress: &mut impl FnMut(),
    mut check: impl FnMut(usize),
) {
    let mut checked = vec![false; tokens.len()];
    let done = drain(
        disk,
        tokens.len(),
        progress,
        "the contract's commands",
        |completion| {
            let Some(index) = tokens.iter().position(|&token| token == completion.token) else {
                return;
            };
            if std::mem::replace(&mut checked[index], true) {
                return;
            }
            assert_eq!(
                completion.status.classify(IO_UNIT as u32),
                Classification::Success,
                "{completion:?}"
            );
            check(index);
        },
    );
    each_once(&done, tokens);
}

/// Eight picks, each after `progress`, that find nothing.
fn silent<D: Disk>(disk: &mut D, progress: &mut impl FnMut()) {
    for _ in 0..8 {
        progress();
        let mut out = Vec::with_capacity(1);
        disk.pick_completions(&mut CompletionSink::new(&mut out, 1));
        assert!(out.is_empty(), "no completion without a command: {out:?}");
    }
}

/// Checks that every completion in `done` succeeded and that their tokens
/// are exactly `tokens`, each once.
fn each_once(done: &[Completion], tokens: &[CommandToken]) {
    let mut seen: Vec<u64> = done
        .iter()
        .map(|completion| completion.token.raw())
        .collect();
    let mut expected: Vec<u64> = tokens.iter().map(|token| token.raw()).collect();
    seen.sort_unstable();
    expected.sort_unstable();
    assert_eq!(seen, expected, "each accepted command completes once");
    for completion in done {
        assert_eq!(
            completion.status.classify(IO_UNIT as u32),
            Classification::Success,
            "{completion:?}"
        );
    }
}

/// Asserts `refused` was refused for `reason`; an acceptance is drained
/// with the `outstanding` commands before it, so the contract fails with no
/// command in flight once they all arrive; otherwise `drain` fails under the
/// caller's abort.
fn refused_for<D: Disk>(
    disk: &mut D,
    refused: Result<(), super::SubmitRefusal>,
    reason: RefusalReason,
    outstanding: usize,
    progress: &mut impl FnMut(),
) {
    match refused {
        Err(refusal) => assert_eq!(refusal.reason, reason),
        Ok(()) => {
            drain(
                disk,
                outstanding + 1,
                progress,
                "the accepted submit",
                |_| {},
            );
            panic!("a submit the contract expects refused {reason:?} was accepted");
        }
    }
}

/// Runs the contract on `disk` over `arena`'s buffers, writing the device's
/// first four I/O units at most; `progress` lets the device move between
/// picks and quiesce calls. Each idle-buffer check calls `progress` in a
/// loop for `observe` between two rounds of empty picks, giving a late
/// device store that long to land. The contract ends with the device
/// stopped.
///
/// # Safety
///
/// When `disk` can access `arena`'s memory outside the program, as a
/// controller's DMA can, the caller aborts the process on an unwind out of
/// this call, since a failed check may leave commands over the contract's
/// buffers.
///
/// # Panics
///
/// When a guarantee fails, when an I/O unit is no multiple of the block size
/// or exceeds the transfer limit, when the device holds fewer than
/// `min(queue_depth, 4) + 1` units, when a read-response buffer is no longer
/// than an I/O unit, or when `arena` lacks either `queue_depth`
/// read-response buffers or `min(queue_depth, 4)` receive-write buffers.
pub(crate) unsafe fn meets_the_disk_contract<P: Platform, D: Disk>(
    disk: &mut D,
    arena: &BufferArena<P>,
    observe: Duration,
    mut progress: impl FnMut(),
) {
    let geometry = disk.geometry();
    let len = IO_UNIT as u32;
    assert_eq!(len % geometry.block_size, 0, "a unit is whole blocks");
    assert!(len <= geometry.max_transfer, "a unit fits one transfer");
    let count = (geometry.queue_depth as usize).min(4);
    let usable = geometry.capacity - geometry.capacity % u64::from(len);
    assert!(
        usable >= (count as u64 + 1) * u64::from(len),
        "the device holds the contract's units"
    );
    let block = |index: usize| DeviceRange::new(index as u64 * u64::from(len), len).unwrap();

    // I2, I4 and I5: writes, a pick with no room, then each write once.
    let mut writes: Vec<_> = (0..count)
        .map(|index| {
            let mut buffer = arena.acquire(PoolKind::ReceiveWrite).unwrap();
            buffer.bytes_mut()[..IO_UNIT].copy_from_slice(&pattern(index));
            buffer
        })
        .collect();
    let written = tokens(1, count);
    for (index, buffer) in writes.iter_mut().enumerate() {
        // SAFETY: the contract holds `buffer`, forms no view of it until its completion is picked, and keeps the arena mapped; on a failed check the caller's abort covers the commands in flight.
        unsafe { disk.submit_write(written[index], block(index), buffer.range(len).unwrap()) }
            .unwrap();
    }
    progress();
    let mut none = Vec::new();
    disk.pick_completions(&mut CompletionSink::new(&mut none, 0));
    assert!(none.is_empty(), "a sink with no room takes nothing");
    // I3: a write only reads its memory, so each picked write's source still holds its pattern.
    settle(disk, &written, &mut progress, |index| {
        assert!(
            writes[index].bytes()[..IO_UNIT] == pattern(index),
            "write {:?} changed its source by its completion",
            written[index]
        );
        writes[index].bytes_mut().fill(idle(index));
    });
    stays_idle(disk, observe, &mut progress, &[(&written, &writes, 0)]);

    // I3 and I4: each read returns its block and leaves the guard bytes past its range.
    let mut reads: Vec<_> = (0..count)
        .map(|_| arena.acquire(PoolKind::ReadResponse).unwrap())
        .collect();
    let read = tokens(2, count);
    for (index, buffer) in reads.iter_mut().enumerate() {
        assert!(
            buffer.bytes().len() > IO_UNIT,
            "a read buffer has room for guard bytes"
        );
        buffer.bytes_mut()[..IO_UNIT].fill(0);
        buffer.bytes_mut()[IO_UNIT..].fill(GUARD);
        // SAFETY: as for the writes.
        unsafe { disk.submit_read(read[index], block(index), buffer.range(len).unwrap()) }.unwrap();
    }
    settle(disk, &read, &mut progress, |index| {
        let bytes = reads[index].bytes();
        assert!(
            bytes[..IO_UNIT] == pattern(index),
            "block {index} reads back as written"
        );
        assert!(
            bytes[IO_UNIT..].iter().all(|&byte| byte == GUARD),
            "read {index} wrote past its range"
        );
        reads[index].bytes_mut().fill(idle(count + index));
    });
    // I2, I4 and I8: a picked command's device access ended, so the writes'
    // buffers kept their sentinels through the reads, and every buffer keeps
    // its sentinel through the observation.
    stays_idle(
        disk,
        observe,
        &mut progress,
        &[(&written, &writes, 0), (&read, &reads, count)],
    );
    drop((writes, reads));

    // I1 and the refusals: past the capacity, then at the queue depth.
    let mut spare = arena.acquire(PoolKind::ReceiveWrite).unwrap();
    spare.bytes_mut().fill(GUARD);
    let past = DeviceRange::new(usable, len).unwrap();
    // SAFETY: a refusal ends the obligation at once; `refused_for` drains an acceptance before failing.
    let refused = unsafe { disk.submit_read(tokens(3, 1)[0], past, spare.range(len).unwrap()) };
    refused_for(disk, refused, RefusalReason::InvalidRange, 0, &mut progress);
    let mut full: Vec<_> = (0..geometry.queue_depth)
        .map(|_| arena.acquire(PoolKind::ReadResponse).unwrap())
        .collect();
    let held = tokens(4, full.len());
    for (index, buffer) in full.iter().enumerate() {
        // SAFETY: as for the writes.
        unsafe { disk.submit_read(held[index], block(0), buffer.range(len).unwrap()) }.unwrap();
    }
    // SAFETY: a refusal ends the obligation at once; `refused_for` drains an acceptance with the held reads before failing.
    let refused = unsafe { disk.submit_read(tokens(5, 1)[0], block(0), spare.range(len).unwrap()) };
    refused_for(
        disk,
        refused,
        RefusalReason::QueueFull,
        held.len(),
        &mut progress,
    );
    settle(disk, &held, &mut progress, |index| {
        assert!(
            full[index].bytes()[..IO_UNIT] == pattern(0),
            "read {:?} returned block 0 changed",
            held[index]
        );
        full[index].bytes_mut().fill(idle(2 * count + index));
    });
    // I2, I4 and I8: the drained queue-depth reads' buffers keep their sentinels.
    stays_idle(disk, observe, &mut progress, &[(&held, &full, 2 * count)]);
    assert!(
        spare.bytes().iter().all(|&byte| byte == GUARD),
        "a refused command wrote its memory"
    );

    // I6: a stop proof over an outstanding read, then silence and `DeviceGone`.
    let last = tokens(6, 2);
    full[0].bytes_mut().fill(GUARD);
    // SAFETY: as for the writes; the stop proof below ends the obligation.
    unsafe { disk.submit_read(last[0], block(0), full[0].range(len).unwrap()) }.unwrap();
    // A driver may issue a command at its next poll; one pick issues it before the stop.
    let mut early = Vec::with_capacity(1);
    disk.pick_completions(&mut CompletionSink::new(&mut early, 1));
    assert!(
        early.iter().all(|done| done.token == last[0]),
        "a pick reported a token that is not outstanding: {early:?}"
    );
    let sentinel = idle(2 * count + full.len());
    if let Some(done) = early.first() {
        assert_eq!(
            done.status.classify(IO_UNIT as u32),
            Classification::Success,
            "{done:?}"
        );
        assert!(
            full[0].bytes()[..IO_UNIT] == pattern(0),
            "read {:?} returned block 0 changed",
            last[0]
        );
        assert!(
            full[0].bytes()[IO_UNIT..].iter().all(|&byte| byte == GUARD),
            "read {:?} wrote past its range",
            last[0]
        );
        full[0].bytes_mut().fill(sentinel);
    }
    let stopped = (0..PICKS).any(|_| {
        progress();
        disk.quiesce() == QuiesceStatus::Stopped
    });
    assert!(stopped, "the device proved its stop");
    if !early.is_empty() {
        assert!(
            full[0].bytes().iter().all(|&byte| byte == sentinel),
            "{:?} changed its buffer after its completion",
            last[0]
        );
    }
    let at_stop = full[0].bytes().to_vec();
    silent(disk, &mut progress);
    assert!(
        full[0].bytes() == at_stop,
        "a stopped command wrote its memory"
    );
    // SAFETY: a refusal ends the obligation at once; an acceptance fails the contract under the caller's abort.
    let gone = unsafe { disk.submit_read(last[1], block(0), spare.range(len).unwrap()) };
    assert_eq!(gone.unwrap_err().reason, RefusalReason::DeviceGone);
    assert!(
        spare.bytes().iter().all(|&byte| byte == GUARD),
        "a refused command wrote its memory"
    );
    assert!(
        full[0].bytes() == at_stop,
        "a stopped command wrote its memory"
    );
    assert_eq!(disk.geometry(), geometry, "the geometry is constant");
}
