//! A suffix block's failed write keeps the block queued with its payload for the next stage,
//! which encodes the same bytes (UNIQUE-BLOCK), and only the write's `Written` terminal advances the log's
//! durable prefix, which the tick then publishes to the journal words' prefix word (HOLD-UNTIL-DURABLE).
//!
//! `observe` runs a cold tenure on the simulated device with the suffix log covering LSNs
//! `[0, 16)`, as `storage::volume::warm::suffix_sim_tests::tenure` builds it. One fill is published, which
//! records an INSERT, and the next delta stage seals the block of LSN 0 and submits its write at the first
//! unit of the delta region.
//!
//! - `a_suffix_block_whose_write_failed_stays_queued_and_is_written_again_with_the_same_bytes`: the first
//!   write completes with a device error status (`Fault::Status`, which moves no byte). Once that terminal
//!   was applied and the delta stage that takes its result ran, the durable prefix and the prefix word are
//!   still 0, the block is still queued and the unit on the media is still zero. The volume then submits a
//!   second write at the same unit, whose bytes, read from the pending command, equal the first write's.
//!   The prefix stays 0 while that write is pending and reads 1 after its terminal was delivered, and the
//!   unit on the media then decodes to the one INSERT.
//! - `a_suffix_block_whose_write_succeeded_advances_the_prefix_after_one_write`: the control. The same steps
//!   with no fault: one write, and the prefix reads 1 once its terminal was applied.
//! - `reading_the_words_leaves_the_published_due_time_as_it_was`: `words`, which `observe` calls between
//!   ticks, leaves the pool's published due time unchanged, so the second write follows a due time the delta
//!   stage published.
//!
//! `observe` reads every value before the fixtures drop and asserts nothing about the property, so a failed
//! expectation ends the test with a result line. Its own `expect`s cover only the steps before the fault.
//!
//! `tenure`, `tick` and `fail_first_write` of `warm::suffix_sim_tests` and `warm::tests` are private to
//! `warm`, so the steps are written here from `storage::volume_fixture` and `bootstrap_tests`.

use std::sync::atomic::Ordering;

use super::super::checkpoint::SuffixLimits;
use super::super::device::sim::{Captured, Fault, SimControl, media};
use super::super::device::{BufferArena, DeviceStatus, Operation};
use super::super::publication_tests::publish;
use super::super::publish_tests::key;
use super::super::record::Crc32c;
use super::super::recovery::delta::{Assembler, Block, Record, decode};
use super::super::recovery::delta_tests::fed;
use super::super::recovery::session_at;
use super::super::store_tests::shard;
use super::super::test_platform::TestPlatform;
use super::super::volume_fixture::{Device, MEDIA, arena_with, attach_under, bootstrap};
use super::super::{CommandToken, IO_UNIT, Storage};
use super::bootstrap_tests::{submitted, tick};
use super::metadata::{JOURNAL, Target};
use super::warm::sim_tests::{PREFIX, layout, storage};
use crate::failover::records::Suffix;

/// A block seals at the next delta stage, and under the fixture's one-sample clock no record stalls.
const LIMITS: SuffixLimits = SuffixLimits {
    flush_ns: 0,
    queue_blocks: 8,
    oldest_ns: 1 << 40,
    uncertified: 16,
};

/// The first prefix unit of `layout`'s delta region, `1 + K * S`, which holds the block of LSN 0.
const DELTA: u64 = 1 + 3 * 3;

/// The LSN of the tenure's first block.
const LSN: u64 = 0;

/// The tenure's session.
fn session() -> crate::storage::Session {
    session_at(3, 3)
}

/// The durable prefix, the journal words' prefix word, and whether the log still holds a record.
type Words = (u64, u64, bool);

fn words(storage: &Storage<TestPlatform>, dev: &Device<'_, '_>) -> Words {
    let (durable, idle) = {
        let capture =
            (storage.pool().capture_lock()).expect("the capture mutex is free between ticks");
        (capture.suffix.durable(), capture.suffix.idle())
    };
    let prefix = dev.volume.journal_words.prefix.load(Ordering::Acquire);
    (durable, prefix, !idle)
}

/// The writes `control` accepted inside the delta region, as `(token, prefix unit)`.
fn delta_writes(control: &SimControl) -> Vec<(CommandToken, u64)> {
    (submitted(control, Operation::Write).into_iter())
        .map(|(token, start)| (token, start / IO_UNIT as u64))
        .filter(|(_, unit)| (DELTA..PREFIX).contains(unit))
        .collect()
}

/// Whether the device handed the volume the completion of `token`.
fn delivered(control: &SimControl, token: CommandToken) -> bool {
    (control.capture().events.iter())
        .any(|event| matches!(*event, Captured::Delivered { token: ended, .. } if ended == token))
}

/// The bytes of the block's unit as the media holds them.
fn unit_on_media(control: &SimControl) -> Vec<u8> {
    let media = control.shared_media();
    let media = media.borrow();
    let at = (DELTA + LSN) as usize * IO_UNIT;
    media[at..at + IO_UNIT].to_vec()
}

/// The records `unit` decodes to as the tenure's block of LSN 0, or `None` when it is no such block.
fn records(unit: &[u8]) -> Option<Vec<Record>> {
    let expected = Block {
        shard: shard(),
        session: session().get(),
        lsn: LSN,
    };
    let parts = decode(
        Crc32c::detect(),
        expected,
        expected.session,
        unit,
        Vec::new(),
    )
    .ok()?;
    let mut assembler = Assembler::default();
    assembler.admit(&parts).ok()?;
    let mut records = Vec::new();
    for part in parts {
        if let Some(record) = fed(&mut assembler, part).ok()? {
            records.push(record);
        }
    }
    Some(records)
}

/// What one run showed, each value read while the fixtures lived.
struct Observed {
    /// The words before the fill.
    opened: Words,
    /// The bytes the first write carried while it was pending.
    first: Vec<u8>,
    /// Whether the first write's terminal was applied and the delta stage that takes its result ran.
    first_applied: bool,
    /// The words and the unit on the media after that stage.
    after_first: (Words, Vec<u8>),
    /// The second write's unit, its bytes while it was pending, and the words read beside them.
    second: Option<(u64, Option<Vec<u8>>, Words)>,
    /// Whether the durable prefix or the prefix word was above 0 at a tick before the last write's terminal was
    /// delivered.
    advanced_early: bool,
    /// Whether the log drained inside the test's tick bound.
    drained: bool,
    /// The units of every delta write, the words and the unit on the media once the log drained.
    end: (Vec<u64>, Words, Vec<u8>),
}

/// A cold tenure of [`session`] over fresh media whose suffix log is open over `[0, 16)`.
fn tenure<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    buffers: &'a BufferArena<TestPlatform>,
) -> Device<'s, 'a> {
    let store = media(MEDIA);
    let authority = crate::storage::ServingAuthority::fixture_under(session());
    let (mut volume, control) = attach_under(storage, buffers, &store, authority).expect("attach");
    bootstrap(&mut volume, &control);
    let own = Suffix {
        session: session().get(),
        start: 0,
        certified: 0,
        end: 16,
    };
    let opened = storage
        .with_suffix(|log| log.open((Crc32c::detect(), shard()), (LIMITS, &layout()), own, 0));
    assert_eq!(opened, Ok(true), "the tenure's suffix log opens");
    Device { volume, control }
}

/// Runs the tenure through one sealed block; with `fault`, the block's first write completes with a device error.
fn observe(fault: bool) -> Observed {
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let mut dev = tenure(&storage, &buffers);
    let opened = words(&storage, &dev);

    // The membership change: one published fill records an INSERT in the open block.
    drop(publish(&storage, &mut dev, &key(1), &[1; 40]).expect("the fill publishes"));

    // The next delta stage seals the block and submits its write, which stays pending until the next device tick.
    let mut first = None;
    for _ in 0..8 {
        tick(&mut dev.volume, &dev.control);
        let staged = (dev.volume.metadata.commands[JOURNAL].as_ref()).map(|command| command.target);
        if staged == Some(Target::Delta(LSN)) {
            first = delta_writes(&dev.control).last().copied();
            break;
        }
    }
    let (first, unit) = first.expect("the block of LSN 0 was submitted");
    assert_eq!(unit, DELTA + LSN, "the block's write names its prefix unit");
    let first_bytes = (dev.control.submitted(first)).expect("the first write is pending");
    if fault {
        (dev.control).fault(first, Fault::Status(DeviceStatus::Kernel(-5)));
    }

    // The first write's terminal, then the delta stage that takes its result.
    let mut first_applied = false;
    for _ in 0..8 {
        tick(&mut dev.volume, &dev.control);
        if delivered(&dev.control, first) && dev.volume.metadata.delta.is_none() {
            first_applied = true;
            break;
        }
    }
    let after_first = (words(&storage, &dev), unit_on_media(&dev.control));

    // A second write of the block, if the volume submits one: read while it is pending.
    let mut second = None;
    for _ in 0..8 {
        if let [_, (token, unit)] = delta_writes(&dev.control)[..] {
            second = Some((token, unit, dev.control.submitted(token)));
            break;
        }
        if !fault {
            break;
        }
        tick(&mut dev.volume, &dev.control);
    }
    let second_words = words(&storage, &dev);
    let last = second.as_ref().map_or(first, |(token, ..)| *token);

    // Ticks until the log drained, watching for a prefix that moves before the last write's terminal.
    let (mut advanced_early, mut drained) = (false, false);
    for _ in 0..64 {
        let (durable, prefix, queued) = words(&storage, &dev);
        advanced_early |= (durable > 0 || prefix > 0) && !delivered(&dev.control, last);
        if !queued && dev.volume.metadata.delta.is_none() {
            drained = true;
            break;
        }
        tick(&mut dev.volume, &dev.control);
    }
    let units = (delta_writes(&dev.control).into_iter())
        .map(|(_, unit)| unit)
        .collect();
    let end = (units, words(&storage, &dev), unit_on_media(&dev.control));
    Observed {
        opened,
        first: first_bytes,
        first_applied,
        after_first,
        second: second.map(|(_, unit, bytes)| (unit, bytes, second_words)),
        advanced_early,
        drained,
        end,
    }
}

/// Whether `unit` decodes to the block's one record, the INSERT of the published key.
fn holds_the_insert(unit: &[u8]) -> bool {
    matches!(records(unit).as_deref(), Some([Record::Insert(insert)]) if insert.key == key(1))
}

/// The `u64::MAX` stored in `pool.suffix_due` differs from the log's finite due time, so the word shows
/// whether `words` published that time.
#[test]
fn reading_the_words_leaves_the_published_due_time_as_it_was() {
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let mut dev = tenure(&storage, &buffers);
    drop(publish(&storage, &mut dev, &key(1), &[1; 40]).expect("the fill publishes"));
    let pool = storage.pool();
    let due = (pool.capture_lock())
        .expect("the capture mutex is free between ticks")
        .suffix
        .due();
    pool.suffix_due.store(u64::MAX, Ordering::Relaxed);
    let read = words(&storage, &dev);
    let published = pool.suffix_due.load(Ordering::Relaxed);
    drop(dev);
    assert!(
        due.is_some_and(|due| due != u64::MAX),
        "premise: the log has a due time to publish: {due:?}"
    );
    assert_eq!(
        read,
        (0, 0, true),
        "the open block holds the INSERT and nothing is durable"
    );
    assert_eq!(
        published,
        u64::MAX,
        "reading the words published the log's due time"
    );
}

#[test]
fn a_suffix_block_whose_write_failed_stays_queued_and_is_written_again_with_the_same_bytes() {
    let seen = observe(true);
    assert_eq!(
        seen.opened,
        (0, 0, false),
        "an open log with no record: nothing durable, nothing queued"
    );
    assert!(
        holds_the_insert(&seen.first),
        "the first write carried the block of the INSERT"
    );
    assert!(
        seen.first_applied,
        "the failed terminal was applied and the next delta stage ran"
    );
    let (words_after, media_after) = &seen.after_first;
    assert_eq!(
        *words_after,
        (0, 0, true),
        "a failed write advances neither the durable prefix nor the prefix word, and its block stays queued"
    );
    assert_eq!(
        *media_after,
        vec![0; IO_UNIT],
        "the failed write stored nothing at the block's unit"
    );
    let (unit, bytes, words_beside) = seen.second.expect("the volume submits the block again");
    assert_eq!(
        unit,
        DELTA + LSN,
        "the second write names the same prefix unit"
    );
    assert_eq!(
        bytes.as_ref(),
        Some(&seen.first),
        "the second write carries the bytes of the first"
    );
    assert_eq!(
        words_beside,
        (0, 0, true),
        "the prefix waits while the second write is pending"
    );
    assert!(
        !seen.advanced_early,
        "the prefix moved before the second write's terminal was delivered"
    );
    assert!(seen.drained, "the log drains once the block persisted");
    let (units, words_end, media_end) = seen.end;
    assert_eq!(
        units,
        [DELTA + LSN, DELTA + LSN],
        "the block took two writes, both at its own unit"
    );
    assert_eq!(
        words_end,
        (1, 1, false),
        "the Written terminal advanced the durable prefix over the block and the tick published it"
    );
    assert_eq!(media_end, seen.first, "the media holds the block's bytes");
    assert!(
        holds_the_insert(&media_end),
        "the unit on the media decodes to the block's records"
    );
}

#[test]
fn a_suffix_block_whose_write_succeeded_advances_the_prefix_after_one_write() {
    let seen = observe(false);
    assert_eq!(seen.opened, (0, 0, false));
    assert!(
        holds_the_insert(&seen.first),
        "the first write carried the block of the INSERT"
    );
    assert!(
        seen.first_applied,
        "the Written terminal was applied and the next delta stage ran"
    );
    let (words_after, media_after) = &seen.after_first;
    assert_eq!(
        *words_after,
        (1, 1, false),
        "one Written terminal advances the durable prefix and the prefix word, and the block leaves the queue"
    );
    assert_eq!(
        *media_after, seen.first,
        "the media holds the block's bytes"
    );
    assert!(
        seen.second.is_none(),
        "a written block is not written again"
    );
    assert!(
        !seen.advanced_early,
        "the prefix moved before the write's terminal was delivered"
    );
    assert!(seen.drained);
    let (units, words_end, media_end) = seen.end;
    assert_eq!(units, [DELTA + LSN], "the block took one write");
    assert_eq!(words_end, (1, 1, false));
    assert!(
        holds_the_insert(&media_end),
        "the unit on the media decodes to the block's records"
    );
}
