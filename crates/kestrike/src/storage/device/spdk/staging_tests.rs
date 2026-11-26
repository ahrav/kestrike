//! Completion staging driven through the native callbacks with fabricated completions.

use std::collections::VecDeque;

use spdk_sys as sys;

use super::super::status::{ControllerEvent, DeviceStatus};
use super::staging::{self, Slots, Staging};

fn cpl(status: u16) -> sys::spdk_nvme_cpl {
    let mut cpl = sys::spdk_nvme_cpl::default();
    cpl.__bindgen_anon_1.status_raw = status;
    cpl
}

/// Runs the completion callback for record `index` as SPDK would.
fn callback(slots: &Slots, index: u32, status: Option<u16>) {
    let cpl = status.map(cpl);
    let ptr = cpl.as_ref().map_or(std::ptr::null(), |cpl| cpl as *const _);
    // SAFETY: the slots are alive and no reference into the staging is held across the call.
    unsafe { staging::complete(slots.context(index), ptr) };
}

/// The staging between callbacks.
fn state(slots: &mut Slots) -> &mut Staging {
    // SAFETY: no callback runs while a test holds the reference, and each test drops it before the next callback.
    unsafe { slots.staging() }
}

fn drain(slots: &mut Slots, limit: usize) -> Vec<(u64, u16)> {
    drain_by(slots, limit, production_delivery)
}

/// A delivery step: hands at most `limit` terminals to the sink and returns
/// how many it handed over.
type Delivery = fn(&mut Staging, usize, &mut dyn FnMut(u64, u16)) -> usize;

fn production_delivery(
    staging: &mut Staging,
    limit: usize,
    push: &mut dyn FnMut(u64, u16),
) -> usize {
    staging.deliver(limit, push)
}

fn drain_by(slots: &mut Slots, limit: usize, delivery: Delivery) -> Vec<(u64, u16)> {
    let mut out = Vec::new();
    delivery(state(slots), limit, &mut |token, status| {
        out.push((token, status))
    });
    out
}

fn free(slots: Slots) {
    // SAFETY: no native code holds a pointer into the slots.
    unsafe { slots.free() };
}

#[test]
fn records_are_bounded_by_depth_and_a_refusal_frees_its_record() {
    let mut slots = Slots::new(2);
    let first = state(&mut slots).accept(10).unwrap();
    assert!(state(&mut slots).accept(11).is_some());
    assert_eq!(state(&mut slots).accept(12), None);
    state(&mut slots).refuse(first);
    assert_eq!(state(&mut slots).accepted(), 1);
    assert!(state(&mut slots).accept(12).is_some());
    free(slots);
}

/// Staging takes a free record for each accepted token, so a token
/// accepted while an earlier command with the same token is outstanding
/// takes a record of its own, and each record delivers.
#[test]
fn a_repeated_token_takes_a_record_of_its_own() {
    let mut slots = Slots::new(2);
    let first = state(&mut slots).accept(5).unwrap();
    let second = state(&mut slots).accept(5).unwrap();
    assert_ne!(first, second);
    assert_eq!(state(&mut slots).accepted(), 2);
    callback(&slots, first, Some(0x0001));
    callback(&slots, second, Some(0x0003));
    state(&mut slots).certify();
    assert_eq!(drain(&mut slots, 2), [(5, 0x0001), (5, 0x0003)]);
    assert_eq!(state(&mut slots).accepted(), 0);
    free(slots);
}

#[test]
fn only_certified_terminals_deliver_and_a_burst_past_the_sink_waits() {
    certified_terminals_deliver_oldest_first_and_once(production_delivery);
}

/// A delivery that treats every staged terminal as certified, as one that
/// ignored a failing poll would, hands over a terminal staged before any
/// certification. The record test's own check refuses it. Like every test
/// here, it drives the staging logic through fabricated completions; no SPDK
/// device is exercised.
#[test]
#[should_panic(expected = "uncertified terminals stay held")]
fn negative_control_a_delivery_that_ignores_certification_hands_over_held_terminals() {
    certified_terminals_deliver_oldest_first_and_once(|staging, limit, push| {
        staging.certify();
        staging.deliver(limit, push)
    });
}

/// Drives a failure burst over four records through `delivery`: nothing is
/// delivered before certification, then the certified terminals leave oldest
/// first, once each, in picks bounded by the sink's room.
fn certified_terminals_deliver_oldest_first_and_once(delivery: Delivery) {
    let drain = |slots: &mut Slots, limit| drain_by(slots, limit, delivery);
    let mut slots = Slots::new(4);
    let indices: Vec<u32> = (0..4)
        .map(|token| state(&mut slots).accept(100 + token).unwrap())
        .collect();
    // A failure burst completes every record, more than one pick can take.
    for (n, &index) in indices.iter().enumerate() {
        callback(&slots, index, Some(0x0001 | ((n as u16) << 1)));
    }
    assert_eq!(state(&mut slots).staged(), 4);
    assert!(
        drain(&mut slots, 4).is_empty(),
        "uncertified terminals stay held"
    );
    state(&mut slots).certify();
    assert_eq!(drain(&mut slots, 1), [(100, 0x0001)]);
    assert_eq!(
        drain(&mut slots, 2),
        [(101, 0x0003), (102, 0x0005)],
        "the full 16-bit status, phase bit included"
    );
    assert_eq!(
        state(&mut slots).accepted(),
        1,
        "a record is retained until its terminal is delivered"
    );
    assert_eq!(drain(&mut slots, 8), [(103, 0x0007)]);
    assert_eq!(state(&mut slots).accepted(), 0);
    free(slots);
}

#[test]
fn stray_and_empty_completions_change_no_record() {
    let mut slots = Slots::new(2);
    let index = state(&mut slots).accept(7).unwrap();
    callback(&slots, 1, Some(0));
    callback(&slots, index, None);
    let s = state(&mut slots);
    assert_eq!((s.strays, s.staged(), s.accepted()), (2, 0, 1));
    callback(&slots, index, Some(0));
    callback(&slots, index, Some(0));
    let s = state(&mut slots);
    assert_eq!(
        (s.strays, s.staged()),
        (3, 1),
        "a second terminal for one command is a stray"
    );
    free(slots);
}

#[test]
fn a_proven_stop_discards_held_terminals_and_frees_every_record() {
    let mut slots = Slots::new(3);
    let index = state(&mut slots).accept(1).unwrap();
    let _ = state(&mut slots).accept(2).unwrap();
    callback(&slots, index, Some(0x0002));
    state(&mut slots).discard();
    state(&mut slots).certify();
    assert!(drain(&mut slots, 3).is_empty());
    assert_eq!(
        (state(&mut slots).accepted(), state(&mut slots).staged()),
        (0, 0)
    );
    free(slots);
}

#[test]
fn staging_keeps_the_first_event_any_staged_status_word_shows() {
    for raw in 0..=u16::MAX {
        let mut slots = Slots::new(2);
        let first = state(&mut slots).accept(1).unwrap();
        let second = state(&mut slots).accept(2).unwrap();
        callback(&slots, first, Some(raw));
        let shown = ControllerEvent::of_status(DeviceStatus::Nvme(raw));
        assert_eq!(state(&mut slots).event, shown, "{raw:#06x}");
        callback(&slots, second, Some(0x07 << 1));
        assert_eq!(
            state(&mut slots).event,
            shown.or(Some(ControllerEvent::Abort)),
            "{raw:#06x} then abort requested"
        );
        free(slots);
    }
}

/// Interleaved accepts, terminals, certifications and bounded deliveries
/// wrap the FIFO many times and match a queue model: certified terminals
/// leave oldest first, and no record is lost or delivered twice.
#[test]
fn seeded_histories_match_a_fifo_model() {
    const DEPTH: u32 = 5;
    let mut slots = Slots::new(DEPTH);
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let (mut token, mut accepted, mut model, mut certified) =
        (0u64, Vec::new(), VecDeque::new(), 0usize);
    for _ in 0..10_000 {
        match next() % 4 {
            0 => {
                let taken = state(&mut slots).accept(token);
                assert_eq!(
                    taken.is_some(),
                    accepted.len() + model.len() < DEPTH as usize
                );
                if let Some(index) = taken {
                    accepted.push((index, token));
                    token += 1;
                }
            }
            1 if !accepted.is_empty() => {
                let (index, token) = accepted.swap_remove(next() as usize % accepted.len());
                callback(&slots, index, Some(token as u16));
                model.push_back(token);
            }
            2 => {
                state(&mut slots).certify();
                certified = model.len();
            }
            _ => {
                let limit = next() as usize % 3;
                let expected: Vec<(u64, u16)> = model
                    .drain(..limit.min(certified))
                    .map(|token| (token, token as u16))
                    .collect();
                certified -= expected.len();
                assert_eq!(drain(&mut slots, limit), expected);
            }
        }
        assert_eq!(state(&mut slots).accepted(), accepted.len() + model.len());
        assert_eq!(state(&mut slots).staged(), model.len());
    }
    free(slots);
}

#[test]
fn the_timeout_callback_changes_only_its_counters() {
    let mut slots = Slots::new(2);
    let index = state(&mut slots).accept(5).unwrap();
    callback(&slots, index, Some(0));
    let qpair = std::ptr::without_provenance_mut::<sys::spdk_nvme_qpair>(0x1000);
    // SAFETY: the timeout argument names the live staging and no reference into it is held.
    unsafe {
        staging::timed_out(slots.timeout_arg(), std::ptr::null_mut(), qpair, 9);
        staging::timed_out(slots.timeout_arg(), std::ptr::null_mut(), qpair, 11);
    }
    let s = state(&mut slots);
    assert_eq!((s.timeouts, s.last_timeout), (2, Some((0x1000, 11))));
    assert_eq!(
        (s.accepted(), s.staged(), s.strays),
        (1, 1, 0),
        "no record, terminal or stray changed"
    );
    free(slots);
}

/// The full callback lifetime of each record, with an independent ledger
/// of tokens and FIFO order: accept, the completion callback through the
/// context pointer taken before the owner moved, inspection between native
/// calls, a timeout report through its pointer, certification as a
/// healthy poll's return makes it, bounded delivery whose freed record the
/// next accept reuses, then a proven stop's discard of a held terminal, and one free once native
/// code holds no pointer.
#[test]
fn a_record_goes_from_accept_to_free_through_its_callback_pointers() {
    let mut slots = Slots::new(2);
    let first = state(&mut slots).accept(40).unwrap();
    let second = state(&mut slots).accept(41).unwrap();
    // Native code keeps these across the owner's moves.
    let contexts = [slots.context(first), slots.context(second)];
    let timeout = slots.timeout_arg();
    let mut moved = Box::new(slots);
    let cpl_first = cpl(0x0010);
    let cpl_second = cpl(0x0012);
    // SAFETY: the slots are alive and no reference into the staging is held across the callback.
    unsafe { staging::complete(contexts[1], &raw const cpl_second) };
    // Between native calls, the moved owner reads the staging the callback wrote.
    assert_eq!(state(&mut moved).staged(), 1);
    // SAFETY: as above.
    unsafe {
        staging::complete(contexts[0], &raw const cpl_first);
        staging::timed_out(timeout, std::ptr::null_mut(), std::ptr::null_mut(), 3);
    }
    let mut slots = *moved;
    let mut ledger: VecDeque<(u64, u16)> = VecDeque::from([(41, 0x0012), (40, 0x0010)]);
    let s = state(&mut slots);
    assert_eq!((s.staged(), s.accepted(), s.timeouts), (2, 2, 1));
    assert!(
        drain(&mut slots, 2).is_empty(),
        "uncertified terminals stay held"
    );
    state(&mut slots).certify();
    assert_eq!(drain(&mut slots, 1), [ledger.pop_front().unwrap()]);
    // The delivered record is free again; its next command reuses it.
    let reused = state(&mut slots).accept(42).unwrap();
    assert_eq!(reused, second, "the delivered record is the one reused");
    assert_eq!(drain(&mut slots, 2), [ledger.pop_front().unwrap()]);
    assert!(ledger.is_empty());
    let cpl_reused = cpl(0x0014);
    // SAFETY: the reused record's context is the one native code holds; no reference into the staging is held.
    unsafe { staging::complete(contexts[1], &raw const cpl_reused) };
    let s = state(&mut slots);
    assert_eq!(
        (s.staged(), s.accepted(), s.strays),
        (1, 1, 0),
        "the reused record holds its new terminal"
    );
    // A proven stop supersedes the held, uncertified terminal.
    state(&mut slots).discard();
    let s = state(&mut slots);
    assert_eq!((s.staged(), s.accepted(), s.strays), (0, 0, 0));
    // Native code holds no pointer past the stop, so the one free follows.
    free(slots);
}

/// Miri control: a callback through a context pointer after the free
/// reads freed memory. The Miri lane runs it alone and requires the
/// interpreter's use-after-free report.
#[cfg(miri)]
#[test]
fn negative_control_a_callback_after_the_free_reads_freed_memory() {
    let mut slots = Slots::new(1);
    let index = state(&mut slots).accept(1).unwrap();
    let context = slots.context(index);
    free(slots);
    let cpl = cpl(0);
    // SAFETY: deliberately violated: the context was freed with its slots.
    unsafe { staging::complete(context, &raw const cpl) };
}

/// Miri control: a mutable reference to the staging retained across a
/// callback is invalidated by the callback's own mutable access, so its
/// next use is undefined. The Miri lane runs it alone and requires the
/// borrow tracker's report.
#[cfg(miri)]
#[test]
fn negative_control_a_retained_staging_reference_outlives_a_callback() {
    let mut slots = Slots::new(1);
    let index = state(&mut slots).accept(1).unwrap();
    let retained: *mut Staging = state(&mut slots);
    // SAFETY: deliberately violated: the reference stays live across the callback below.
    let retained = unsafe { &mut *retained };
    callback(&slots, index, Some(0));
    assert_eq!(retained.staged(), 1);
    free(slots);
}
