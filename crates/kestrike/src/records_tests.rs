//! Terminal-generation retirement of a records slot through each removal
//! path: a slot started at `u64::MAX - 1` is removed, reused at `u64::MAX`
//! and removed again by `remove`, `take` or `drop_with`, after which it
//! retires. Each old handle stays stale, the retired slot stays empty, and
//! after each step the census of live, free and retired slots equals its
//! expected values. Each successful removal drops or returns its value
//! once, and `drop_with` reads it once.

use std::cell::Cell;
use std::rc::Rc;

use super::records::Records;

/// A value that counts its drops in a shared cell.
struct Counted(Rc<Cell<u32>>);

impl Drop for Counted {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Removal {
    Remove,
    Take,
    DropWith,
}

/// Removes the record `(slot, generation)` names through `removal`,
/// returning whether a record left, the drops during the call and the
/// `drop_with` reader's calls.
fn removed(
    records: &mut Records<Counted>,
    removal: Removal,
    (slot, generation): (u32, u64),
    drops: &Rc<Cell<u32>>,
) -> (bool, u32, u32) {
    let (before, calls) = (drops.get(), Cell::new(0));
    let left = match removal {
        Removal::Remove => {
            let held = records.get(slot, generation).is_some();
            records.remove(slot);
            held
        }
        Removal::Take => records.take(slot, generation).is_some(),
        Removal::DropWith => records
            .drop_with(slot, generation, |_| calls.set(calls.get() + 1))
            .is_some(),
    };
    (left, drops.get() - before, calls.get())
}

/// The live, free and retired slot counts.
fn census(records: &Records<Counted>) -> (u32, u32, u32) {
    let free = records.len() - records.live() - records.retired();
    (records.live(), free, records.retired())
}

/// Each removal path retires the terminal slot, leaves every old handle
/// stale and keeps the census at its expected values. Each successful
/// removal drops or returns its value once, and `drop_with` calls its
/// reader once.
#[test]
fn ib_record_generation_exhaustion_each_removal_path_retires_the_terminal_slot() {
    for removal in [Removal::Remove, Removal::Take, Removal::DropWith] {
        let drops = Rc::new(Cell::new(0));
        let mut records = Records::new(2);
        records.start_slot_at(0, u64::MAX - 1);
        // Slot 0 is the free list's last entry, so the next insert takes it.
        let first = records
            .insert(Counted(Rc::clone(&drops)))
            .ok()
            .expect("a free slot");
        assert_eq!(first, (0, u64::MAX - 1));
        assert_eq!(census(&records), (1, 1, 0));
        let (left, dropped, calls) = removed(&mut records, removal, first, &drops);
        assert!(left, "{removal:?}");
        assert_eq!(
            (dropped, calls),
            match removal {
                Removal::Remove => (1, 0),
                Removal::Take => (1, 0),
                Removal::DropWith => (1, 1),
            },
            "{removal:?}: one drop, one read"
        );
        assert_eq!(census(&records), (0, 2, 0), "{removal:?}");
        let second = records
            .insert(Counted(Rc::clone(&drops)))
            .ok()
            .expect("a free slot");
        assert_eq!(
            second,
            (0, u64::MAX),
            "{removal:?}: reused at the last generation"
        );
        assert_eq!(census(&records), (1, 1, 0), "{removal:?}: reused");
        assert!(
            records.get(first.0, first.1).is_none(),
            "{removal:?}: the old handle"
        );
        let (left, _, _) = removed(&mut records, Removal::Take, first, &drops);
        assert!(
            !left && records.get(second.0, second.1).is_some(),
            "{removal:?}"
        );
        let (left, _, calls) = removed(&mut records, Removal::DropWith, first, &drops);
        assert!(!left && calls == 0 && records.get(second.0, second.1).is_some());
        assert_eq!(
            census(&records),
            (1, 1, 0),
            "{removal:?}: stale calls change nothing"
        );
        let (left, dropped, calls) = removed(&mut records, removal, second, &drops);
        assert!(left && dropped == 1, "{removal:?}");
        assert_eq!(
            calls,
            u32::from(removal == Removal::DropWith),
            "{removal:?}"
        );
        assert_eq!(census(&records), (0, 1, 1), "{removal:?}: the slot retires");
        // Repeated removal of the emptied slot returns `(false, 0, 0)` and
        // keeps one free and one retired slot.
        for again in [Removal::Remove, Removal::Take, Removal::DropWith] {
            assert_eq!(
                removed(&mut records, again, second, &drops),
                (false, 0, 0),
                "{removal:?} then {again:?}"
            );
            assert_eq!(census(&records), (0, 1, 1), "{removal:?} then {again:?}");
        }
        // The retired slot stays empty: slot 1 takes the next insert, and
        // the insert after it hands its value back.
        let other = records
            .insert(Counted(Rc::clone(&drops)))
            .ok()
            .expect("slot 1");
        assert_eq!(other.0, 1);
        assert!(
            records.insert(Counted(Rc::clone(&drops))).is_err(),
            "{removal:?}"
        );
        for handle in [first, second] {
            assert!(records.get(handle.0, handle.1).is_none(), "{removal:?}");
        }
        assert_eq!(records.generation_of(0), None);
        assert_eq!(census(&records), (1, 0, 1), "{removal:?}");
    }
}

/// Slot-only `remove` drops whatever record occupies the slot, the
/// replacement included, while a stale `take` or `drop_with` keeps it.
#[test]
fn ib_record_generation_exhaustion_slot_only_remove_takes_the_replacement() {
    let drops = Rc::new(Cell::new(0));
    let mut records = Records::new(1);
    records.start_slot_at(0, u64::MAX - 1);
    let first = records
        .insert(Counted(Rc::clone(&drops)))
        .ok()
        .expect("a free slot");
    assert!(records.take(first.0, first.1).is_some());
    let second = records
        .insert(Counted(Rc::clone(&drops)))
        .ok()
        .expect("a free slot");
    assert!(records.take(first.0, first.1).is_none());
    assert!(records.drop_with(first.0, first.1, |_| ()).is_none());
    assert_eq!((records.live(), drops.get()), (1, 1));
    records.remove(second.0);
    assert_eq!((records.live(), records.retired(), drops.get()), (0, 1, 2));
}
