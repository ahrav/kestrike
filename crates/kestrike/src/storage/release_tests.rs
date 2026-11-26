//! Tests of service's retired pass: it refuses an anchored flag beside a
//! zero count before it judges the anchor's grace.
//!
//! The test retires a published record by replacement, so its slot is
//! Retired and its word holds the retirement's flags and the anchor's one
//! count, and it never certifies an era, so the anchor's grace has not
//! passed. A service pass over that word holds the slot. With the count
//! removed the same pass panics under the pool gate, which poisons it, and
//! the slot's word stays as planted.

use super::evict_tests::generous;
use super::lookup_tests::{body, key, publish, ready, replace, ticks};
use super::slot_tests::poisons;
use super::word::{ABANDONED, ANCHORED, REF, RETIRED};
use super::{SlotIndex, SlotState};

/// A deadline 100 seconds into the engine's nanosecond timeline.
const DEADLINE: u64 = 100 * 1_000_000_000;

/// A retired slot whose anchor still waits for grace is held by service
/// while the anchor is counted; once the word shows the flag beside a zero
/// count, service panics before judging grace or returning the extent, and
/// the pool gate is poisoned with the word unchanged.
#[test]
fn a_retired_anchored_flag_without_its_anchor_poisons_service_before_grace() {
    let storage = ready(8);
    ticks(&storage, &[Some(1)]);
    let id = publish(&storage, key(0x68), DEADLINE, &body(0x68));
    let slot = id.slot_index();
    let replacement = replace(&storage, key(0x68), DEADLINE, &body(0x69));
    assert_eq!(replacement.replaced.map(|(retired, _)| retired), Some(id));
    let live = storage.live_pool().unwrap();
    let retired = Some((SlotState::Retired, id.incarnation()));
    assert_eq!(storage.slot_state(SlotIndex(slot)), retired);
    assert_eq!(live.flags(slot), RETIRED | ABANDONED | ANCHORED);
    assert_eq!(live.refs(slot), 1);

    // No era is certified, so the counted anchor is not released and the
    // slot is held.
    let pass = storage.service(&mut generous()).unwrap();
    assert_eq!(pass.released, 0);
    assert_eq!(live.flags(slot), RETIRED | ABANDONED | ANCHORED);
    assert_eq!(live.refs(slot), 1);
    assert_eq!(storage.slot_state(SlotIndex(slot)), retired);

    live.edit_word(slot, |word| word - REF);
    assert_eq!(live.flags(slot), RETIRED | ABANDONED | ANCHORED);
    assert_eq!(live.refs(slot), 0);
    let planted = live.word(slot);
    poisons(&storage, "anchored flag without its counted anchor", || {
        let _ = storage.service(&mut generous());
    });
    assert_eq!(live.word(slot), planted);
}
