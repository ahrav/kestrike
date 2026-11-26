//! The fill write path's in-flight right and its write-set array over the simulated device: a set's first command of an interval with nothing outstanding installs the set's one right from a zero count on its `Filling` slot before the driver call, in the set's first interval and again in a second one, and panics before that call when the slot's word refuses the install; and when the array is full while an ended fill's write is still at the device, a new fill's first receive leaves two sets in the array, where it leaves one when that write completed first, and once the held write and the new fill's tail write have reached their terminals the ended fill's slot counts no right and the new fill's progress holds its tail's units as completed.

use std::panic::{AssertUnwindSafe, catch_unwind};

use super::super::attempt_tests::service;
use super::super::device::{IO_UNIT, Operation, PoolKind};
use super::super::grace_tests::refs;
use super::super::owner_fixture::write_tokens;
use super::super::publish_tests::key;
use super::super::volume_fixture::{DEPTH, Device, ample_io, settle, step};
use super::super::word;
use super::super::writable_tests::{bytes, reserve, wide};
use super::volume_tests::{TICK, arena, attach, storage, write, write_set};
use super::write_guard::{self, Guarded};

/// Begins a set with nothing outstanding, replaces its slot's word with `plant` of it, and checks that the set's
/// first submit panics before the driver call with nothing changed.
fn first_submit_panics_on(plant: impl Fn(u64) -> u64) {
    let storage = storage(1);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let (reservation, set) = write_set(&storage, &mut volume, 4);
    let slot = reservation.id().slot_index();
    let pool = storage.live_pool().expect("live");
    let clean = pool.word(slot);
    assert_eq!(word::refs(clean), 0, "a filling slot counts nothing");
    assert_eq!(clean as u32, reservation.id().incarnation());
    assert!(word::well_formed(clean));
    assert_eq!(volume.write_outstanding(set), Some(0));

    pool.edit_word(slot, &plant);
    let planted = pool.word(slot);
    assert_ne!(planted, clean, "the plant changes the word");

    let progress = volume.write_progress(set).expect("live");
    let mapped = volume.tokens.iter().flatten().count();
    let pending = volume.table_report().pending;
    let report = volume.report();
    let counters = (report.writes_submitted, report.writes_refused);
    let held = (volume.write_held, volume.unwound_writes);
    let accepted = control.accepted(Operation::Write);
    let events = control.events().len();

    let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
    assert_eq!(write_guard::take(), Guarded::default());
    let prior = write_guard::arm(true);
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        volume
            .write_at(set, buffer, 0)
            .map_err(|(_, refusal)| refusal)
    }));
    write_guard::arm(prior);
    let guarded = write_guard::take();
    if let Ok(returned) = outcome {
        // A reserved bit left in the word would panic again in the fixture's drop and abort the run.
        pool.edit_word(slot, |current| current & !word::RESERVED);
        panic!(
            "the first submit returned {returned:?} on a slot word {planted:#x} that refuses the install; \
             the device accepted {} write(s)",
            control.accepted(Operation::Write) - accepted
        )
    }

    assert_eq!(
        control.accepted(Operation::Write),
        accepted,
        "no driver call"
    );
    assert_eq!(control.events().len(), events, "the device saw nothing");
    assert_eq!(
        (guarded.first, guarded.checked),
        (None, 1),
        "the guard checked the write before the install panicked"
    );
    assert_eq!(volume.write_progress(set), Some(progress));
    assert_eq!(volume.write_outstanding(set), Some(0));
    assert_eq!(volume.tokens.iter().flatten().count(), mapped);
    assert_eq!(volume.table_report().pending, pending);
    let report = volume.report();
    assert_eq!(
        (report.writes_submitted, report.writes_refused),
        counters,
        "neither a submit nor a refusal was counted"
    );
    assert_eq!((volume.write_held, volume.unwound_writes), held);
    assert_eq!(
        pool.word(slot),
        planted,
        "the refused install wrote nothing"
    );

    // The word goes back to what the reservation left, so the fixture ends as an untouched one does.
    pool.edit_word(slot, |_| clean);
    volume.end_fill(set);
    drop(reservation);
}

/// A set's first submit on a slot whose count is already nonzero panics before the driver call: the device accepts no command, and the set's progress, the token map, the volume's counters and the slot's word stay as they were.
#[test]
fn a_first_submit_on_a_nonzero_count_panics_before_the_driver_call() {
    first_submit_panics_on(|current| current + word::REF);
}

/// The same when the slot's word names another incarnation than the set's object.
#[test]
fn a_first_submit_on_another_incarnation_panics_before_the_driver_call() {
    first_submit_panics_on(|current| {
        current & !word::INCARNATION | u64::from((current as u32).wrapping_add(1))
    });
}

/// The same when the slot's word holds a reserved bit, so it is malformed.
#[test]
fn a_first_submit_on_a_reserved_bit_panics_before_the_driver_call() {
    first_submit_panics_on(|current| current | (1 << 43));
}

/// `word::install` accepts a word that carries the recovered-origin marker, so the first submit returns.
#[test]
#[should_panic(expected = "that refuses the install")]
fn negative_control_a_word_the_install_accepts_fails_the_refusal_check() {
    first_submit_panics_on(|current| current | word::MARKER);
}

/// On an untouched word, the set's first command raises the slot's count from zero to one and changes nothing else in the word, and a second command submitted while the first is outstanding leaves the count at one.
#[test]
fn the_first_command_installs_one_right_and_the_next_command_adds_none() {
    use super::volume_tests::BUFFER;
    let storage = storage(1);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let (reservation, set) = write_set(&storage, &mut volume, 8);
    let slot = reservation.id().slot_index();
    let pool = storage.live_pool().expect("live");
    let clean = pool.word(slot);
    assert_eq!(word::refs(clean), 0);

    let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
    let written = write(&mut volume, set, buffer, 0).map_err(|(_, refusal)| refusal);
    assert_eq!(written, Ok(BUFFER));
    assert_eq!(
        pool.word(slot),
        clean + word::REF,
        "the first command installed the set's one right and changed nothing else"
    );
    assert_eq!(volume.write_outstanding(set), Some(1));
    assert_eq!(control.accepted(Operation::Write), 1);
    assert_eq!(volume.tokens.iter().flatten().count(), 1);

    let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
    let written = write(&mut volume, set, buffer, 4).map_err(|(_, refusal)| refusal);
    assert_eq!(written, Ok(BUFFER));
    assert_eq!(
        pool.word(slot),
        clean + word::REF,
        "a command submitted while another is outstanding installs nothing"
    );
    assert_eq!(volume.write_outstanding(set), Some(2));
    assert_eq!(control.accepted(Operation::Write), 2);
    assert_eq!(volume.tokens.iter().flatten().count(), 2);
}

/// A set's second interval: its first command ended, which released the set's right and left the word at a zero
/// count, so the next command finds nothing outstanding and installs the right again from zero.
#[test]
fn the_first_command_of_a_second_interval_installs_the_right_again_from_zero() {
    use super::volume_tests::BUFFER;
    let storage = storage(1);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let (reservation, set) = write_set(&storage, &mut volume, 8);
    let slot = reservation.id().slot_index();
    let pool = storage.live_pool().expect("live");
    let clean = pool.word(slot);
    assert_eq!(word::refs(clean), 0);

    let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
    let written = write(&mut volume, set, buffer, 0).map_err(|(_, refusal)| refusal);
    assert_eq!(written, Ok(BUFFER));
    assert_eq!(pool.word(slot), clean + word::REF);
    settle(&mut volume, &control);
    assert_eq!(volume.write_outstanding(set), Some(0));
    assert_eq!(
        pool.word(slot),
        clean,
        "the interval's last terminal released the right"
    );

    let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
    let written = write(&mut volume, set, buffer, 4).map_err(|(_, refusal)| refusal);
    assert_eq!(written, Ok(BUFFER));
    assert_eq!(
        pool.word(slot),
        clean + word::REF,
        "the second interval's first command installed the right from zero"
    );
    assert_eq!(volume.write_outstanding(set), Some(1));
    assert_eq!(control.accepted(Operation::Write), 2);
    settle(&mut volume, &control);
    assert_eq!(volume.write_outstanding(set), Some(0));
    assert_eq!(pool.word(slot), clean);
    volume.end_fill(set);
    drop(reservation);
}

/// A count planted between two intervals: the first interval's command ended and released the right, the word then
/// gains a count, and the second interval's first submit panics before the driver call with the word as planted.
#[test]
fn a_first_submit_of_a_second_interval_on_a_nonzero_count_panics_before_the_driver_call() {
    use super::volume_tests::BUFFER;
    let storage = storage(1);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let (reservation, set) = write_set(&storage, &mut volume, 8);
    let slot = reservation.id().slot_index();
    let pool = storage.live_pool().expect("live");
    let clean = pool.word(slot);

    let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
    let written = write(&mut volume, set, buffer, 0).map_err(|(_, refusal)| refusal);
    assert_eq!(written, Ok(BUFFER));
    settle(&mut volume, &control);
    assert_eq!(volume.write_outstanding(set), Some(0));
    assert_eq!(pool.word(slot), clean);

    pool.edit_word(slot, |current| current + word::REF);
    let planted = pool.word(slot);
    let progress = volume.write_progress(set).expect("live");
    let accepted = control.accepted(Operation::Write);
    let events = control.events().len();
    let buffer = arena.acquire(PoolKind::ReceiveWrite).expect("free");
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        volume
            .write_at(set, buffer, 4)
            .map_err(|(_, refusal)| refusal)
    }));
    assert!(
        outcome.is_err(),
        "the second interval's first submit returned on a counted word {planted:#x}"
    );
    assert_eq!(
        control.accepted(Operation::Write),
        accepted,
        "no driver call"
    );
    assert_eq!(control.events().len(), events, "the device saw nothing");
    assert_eq!(volume.write_progress(set), Some(progress));
    assert_eq!(
        pool.word(slot),
        planted,
        "the refused install wrote nothing"
    );

    pool.edit_word(slot, |_| clean);
    volume.end_fill(set);
    drop(reservation);
}

/// One fill record and depth 8 give nine set slots. Eight fills that submitted nothing and fill A, which ended
/// with one write, fill them, so fill B's first receive reclaims. With A's write held at the device, the reclaim
/// leaves two sets in the array, where the control leaves one. Once A's write and the write of B's tail segment
/// have reached their terminals, A's slot counts no right and B's counts one, one set remains, and B's progress
/// holds the units of its tail segment as completed and those of its head segment as outstanding. With A's write
/// completed before A ended, the control, the reclaim takes all nine sets.
#[test]
fn a_full_array_reclaims_around_an_ended_fill_whose_write_is_at_the_device() {
    for held in [true, false] {
        reclaims_around(held, 1 + u32::from(held));
    }
}

/// Runs the scenario with A's write held at the device or completed before A ends, as `held` says, and checks that
/// fill B's first receive leaves `sets` write sets in the array.
fn reclaims_around(held: bool, sets: u32) {
    use super::super::volume_fixture::BUFFER;
    let storage = wide(1, 8);
    let buffers = super::super::volume_fixture::arena();
    let mut dev = Device::new(&storage, &buffers);
    for n in 0..u32::from(DEPTH) {
        let mut idle = reserve(&storage, &key(1), 0, 100).unwrap();
        assert_eq!(
            idle.receive(&mut dev.volume, &[n as u8; 10], &mut ample_io()),
            Ok(10),
            "held {held}: fill {n}"
        );
        idle.abort();
        service(&storage);
    }
    assert_eq!(dev.volume.write_sets(), u32::from(DEPTH), "held {held}");

    let mut a = reserve(&storage, &key(1), 4, 100).unwrap();
    let a_slot = a.id().slot_index();
    assert_eq!(
        a.receive(&mut dev.volume, &bytes(104, 1), &mut ample_io()),
        Ok(104)
    );
    let a_write = *write_tokens(&dev.control).last().unwrap();
    assert_eq!(a.progress(&dev.volume).outstanding_commands, 1);
    if held {
        dev.control.hold(a_write);
    } else {
        settle(&mut dev.volume, &dev.control);
    }
    a.abort();
    service(&storage);
    assert_eq!(refs(&storage, a_slot), usize::from(held), "held {held}");
    assert_eq!(
        dev.volume.write_sets(),
        u32::from(DEPTH) + 1,
        "held {held}: the array is full, and A's set stays whether or not its write reached its terminal"
    );

    let len = BUFFER as usize + 100;
    let mut b = reserve(&storage, &key(2), 4, len - 4).unwrap();
    let b_slot = b.id().slot_index();
    assert_ne!(a_slot, b_slot, "held {held}");
    assert_eq!(
        b.receive(&mut dev.volume, &bytes(len, 2), &mut ample_io()),
        Ok(len)
    );
    assert_eq!(
        dev.volume.write_sets(),
        sets,
        "held {held}: the reclaim takes every ended set with nothing outstanding and no other"
    );
    let tokens = write_tokens(&dev.control);
    let [b_tail, b_head] = tokens[tokens.len() - 2..] else {
        panic!("held {held}: fill B submits two writes");
    };
    assert_ne!(b_tail, a_write);
    let submitted = b.progress(&dev.volume);
    assert_eq!(
        (
            submitted.submitted_units,
            submitted.completed_units,
            submitted.outstanding_commands
        ),
        (submitted.len_units, 0, 2),
        "held {held}"
    );
    // The fill keeps its first segment's buffer for the header until its last byte, so the segment past it
    // is submitted first.
    let tail_units = submitted.len_units - BUFFER / IO_UNIT as u32;
    dev.control.hold(b_tail);
    dev.control.hold(b_head);
    assert_eq!(refs(&storage, b_slot), 1, "held {held}");

    // The terminal of B's tail segment and, when A's write was held, A's late terminal.
    if held {
        dev.control.release(a_write);
    }
    dev.control.release(b_tail);
    let mut out = Vec::with_capacity(16);
    for _ in 0..16 {
        step(&mut dev.volume, &dev.control, &mut out);
        out.clear();
    }
    assert_eq!(dev.control.outstanding(), 1, "held {held}");
    assert_eq!(
        (refs(&storage, a_slot), refs(&storage, b_slot)),
        (0, 1),
        "held {held}: A's terminal releases A's right and leaves B's"
    );
    assert_eq!(dev.volume.write_sets(), 1, "held {held}");
    let progress = b.progress(&dev.volume);
    assert_eq!(
        (
            progress.completed_units,
            progress.outstanding_units,
            progress.outstanding_commands,
            progress.failed
        ),
        (tail_units, BUFFER / IO_UNIT as u32, 1, false),
        "held {held}: B completes its own terminal's units alone"
    );
    assert!(!b.is_ready(&dev.volume), "held {held}");

    dev.control.release(b_head);
    settle(&mut dev.volume, &dev.control);
    assert!(b.is_ready(&dev.volume), "held {held}");
    assert_eq!(refs(&storage, b_slot), 0, "held {held}");
    b.abort();
    service(&storage);
    assert_eq!(
        dev.volume.write_sets(),
        1,
        "held {held}: B ended with nothing outstanding, so its set waits for the next full array"
    );
    assert_eq!(
        (refs(&storage, a_slot), refs(&storage, b_slot)),
        (0, 0),
        "held {held}"
    );
}

/// A's write completes before B's first receive, so `begin_fill` reclaims A's set. The assertion expects both sets
/// to remain, as they do when A's write is held.
#[test]
#[should_panic(expected = "the reclaim takes every ended set with nothing outstanding")]
fn negative_control_a_reclaimed_set_whose_write_the_check_holds_fails_the_set_count() {
    reclaims_around(false, 2);
}
