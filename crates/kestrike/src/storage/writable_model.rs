//! Loom model with two slots, two owners, and a controller; explores interleavings within preemption bound 2.
//!
//! `pool` and `shard` are loom mutexes standing for the pool and shard gates; `closed` is the admission cutoff, read with `SeqCst` at the reservation's three cutoff reads; the record words run the production `fill` functions on loom atomics.
//! `disposed` is one flag per serial that an owner sets under the pool gate as its block is returned or abandoned, before it departs: the block's fate, which the departure's `Release` must publish to the pass's `Acquire`.
//! An owner that unwinds during disposal sets no flag and never departs, so its record stays occupied and its slot stays filling; the model runs that owner as a variant instead of a panic.
//!
//! The negative control weakens the departure to `Relaxed` and is matched on its own assertion: the pass then observes a departed record whose disposal flag it cannot yet see.
//! Loom does not model the cross-location `SeqCst` total order, so the cutoff reads are checked only through the model's own state: a refusal leaves no slot claimed.
//! Run with `RUSTFLAGS="--cfg loom" cargo test -p kestrike --lib --release writable_model`.

use std::sync::atomic::Ordering;

use loom::sync::atomic::{AtomicBool, AtomicU64};
use loom::sync::{Arc, Mutex};
use loom::thread;

use super::fill::{self, FIRST_SERIAL, FillSerial, Record};

const RECORDS: usize = 2;
const SLOTS: usize = 2;
const KEY_A: u64 = 0xA;
const KEY_B: u64 = 0xB;
const SERIALS: usize = 3;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ending {
    Abort,
    Unwind,
}

#[derive(Clone, Copy)]
enum Departure {
    Production,
    Relaxed,
}

struct Weakened<'w>(&'w AtomicU64);

impl fill::FillWord for Weakened<'_> {
    fn load(&self, order: Ordering) -> u64 {
        self.0.load(order)
    }

    fn acquire_fence() {
        loom::sync::atomic::fence(Ordering::Acquire);
    }

    fn store(&self, value: u64, order: Ordering) {
        self.0.store(value, order)
    }

    fn fetch_or(&self, value: u64, order: Ordering) -> u64 {
        self.0.fetch_or(value, order)
    }

    fn compare_exchange(
        &self,
        current: u64,
        new: u64,
        _: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64> {
        self.0
            .compare_exchange(current, new, Ordering::Relaxed, failure)
    }
}

struct PoolState {
    free: Vec<usize>,
    filling: usize,
    retired: usize,
}

struct Table {
    keys: [u64; RECORDS],
    next_serial: u64,
}

struct Model {
    pool: Mutex<PoolState>,
    shard: Mutex<Table>,
    states: [AtomicU64; RECORDS],
    closed: AtomicBool,
    disposed: [AtomicBool; SERIALS],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Reserved,
    Closed,
    Superseded,
    InProgress,
}

struct Fill {
    record: usize,
    serial: FillSerial,
    slot: usize,
    written: bool,
}

impl Model {
    fn new() -> Self {
        Self {
            pool: Mutex::new(PoolState {
                free: (0..SLOTS).collect(),
                filling: 0,
                retired: 0,
            }),
            shard: Mutex::new(Table {
                keys: [0; RECORDS],
                next_serial: FIRST_SERIAL,
            }),
            states: [AtomicU64::new(fill::FREE), AtomicU64::new(fill::FREE)],
            closed: AtomicBool::new(false),
            disposed: [
                AtomicBool::new(false),
                AtomicBool::new(false),
                AtomicBool::new(false),
            ],
        }
    }

    fn begin(&self, key: u64) -> Result<(usize, FillSerial), Outcome> {
        let mut table = self.shard.lock().unwrap();
        if self.closed.load(Ordering::SeqCst) {
            return Err(Outcome::Closed);
        }
        let mut free = None;
        for (position, state) in self.states.iter().enumerate() {
            let record = fill::decode(state.load(Ordering::Relaxed), table.next_serial)
                .expect("the model writes only encoded words");
            match record {
                Record::Free => {
                    free.get_or_insert(position);
                }
                occupied if occupied.is_associated() && table.keys[position] == key => {
                    return Err(Outcome::InProgress);
                }
                Record::Occupied { .. } => {}
            }
        }
        let record = free.expect("two records for two owners");
        let serial = FillSerial::new(table.next_serial).expect("valid model fill serial");
        table.keys[record] = key;
        self.states[record].store(fill::occupied(serial), Ordering::Relaxed);
        table.next_serial = serial.get() + 1;
        Ok((record, serial))
    }

    fn reserve(&self, record: usize, serial: FillSerial) -> Result<Fill, Outcome> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Outcome::Closed);
        }
        let slot = {
            let mut pool = self.pool.lock().unwrap();
            if self.closed.load(Ordering::SeqCst) {
                return Err(Outcome::Closed);
            }
            let slot = pool.free.pop().expect("two slots for two owners");
            pool.filling += 1;
            slot
        };
        let revalidated = {
            let table = self.shard.lock().unwrap();
            if self.closed.load(Ordering::SeqCst) {
                Err(Outcome::Closed)
            } else {
                let word = self.states[record].load(Ordering::Relaxed);
                let decoded = fill::decode(word, table.next_serial).expect("encoded");
                let current = matches!(
                    decoded,
                    Record::Occupied {
                        serial: current,
                        departed: false,
                        revoked: false,
                    } if current == serial
                );
                if current {
                    Ok(())
                } else {
                    Err(Outcome::Superseded)
                }
            }
        };
        match revalidated {
            Ok(()) => Ok(Fill {
                record,
                serial,
                slot,
                written: false,
            }),
            Err(outcome) => {
                let mut pool = self.pool.lock().unwrap();
                pool.free.push(slot);
                pool.filling -= 1;
                Err(outcome)
            }
        }
    }

    fn end(&self, fill: Fill, ending: Ending, departure: Departure) {
        if ending == Ending::Unwind {
            return;
        }
        {
            let mut pool = self.pool.lock().unwrap();
            pool.filling -= 1;
            if fill.written {
                pool.retired += 1;
            } else {
                pool.free.push(fill.slot);
            }
            self.disposed[fill.serial.get() as usize].store(true, Ordering::Relaxed);
        }
        let state = &self.states[fill.record];
        let departed = match departure {
            Departure::Production => fill::depart(state, fill.serial),
            Departure::Relaxed => fill::depart(&Weakened(state), fill.serial),
        };
        assert!(
            departed,
            "protection violated: an owner could not depart its own record"
        );
    }

    fn revoke(&self, key: u64) {
        let table = self.shard.lock().unwrap();
        for (position, state) in self.states.iter().enumerate() {
            let record =
                fill::decode(state.load(Ordering::Relaxed), table.next_serial).expect("encoded");
            if record.is_associated() && table.keys[position] == key {
                fill::revoke(state);
            }
        }
    }

    fn service(&self) -> usize {
        let table = self.shard.lock().unwrap();
        let mut released = 0;
        for state in &self.states {
            let record = fill::observe(state, table.next_serial).expect("encoded");
            if let Record::Occupied {
                serial,
                departed: true,
                ..
            } = record
            {
                assert!(
                    self.disposed[serial.get() as usize].load(Ordering::Relaxed),
                    "protection violated: a departed record whose block was not disposed of"
                );
                fill::release(state);
                released += 1;
            }
        }
        released
    }
}

fn owner(
    model: &Model,
    key: u64,
    write: bool,
    ending: Ending,
    departure: Departure,
) -> (Outcome, bool) {
    let (record, serial) = match model.begin(key) {
        Ok(granted) => granted,
        Err(outcome) => return (outcome, false),
    };
    match model.reserve(record, serial) {
        Ok(mut fill) => {
            fill.written = write;
            model.end(fill, ending, departure);
            (Outcome::Reserved, ending == Ending::Unwind)
        }
        Err(outcome) => {
            model.disposed[serial.get() as usize].store(true, Ordering::Relaxed);
            assert!(fill::depart(&model.states[record], serial));
            (outcome, false)
        }
    }
}

fn model(ending: Ending, departure: Departure, bound: usize) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(bound);
    builder.check(move || {
        let model = Arc::new(Model::new());
        let first = {
            let model = Arc::clone(&model);
            thread::spawn(move || owner(&model, KEY_A, true, ending, departure))
        };
        let second = {
            let model = Arc::clone(&model);
            thread::spawn(move || owner(&model, KEY_B, false, Ending::Abort, departure))
        };
        model.revoke(KEY_A);
        model.closed.store(true, Ordering::SeqCst);
        model.service();
        let (first_outcome, first_unwound) = first.join().unwrap();
        let (second_outcome, second_unwound) = second.join().unwrap();
        assert!(!second_unwound);
        let freed = model.service();
        let pool = model.pool.lock().unwrap();
        let unwound = usize::from(first_unwound);
        assert_eq!(pool.filling, unwound);
        assert_eq!(pool.free.len() + pool.retired + pool.filling, SLOTS);
        let occupied = model
            .states
            .iter()
            .filter(|state| state.load(Ordering::Relaxed) != fill::FREE)
            .count();
        assert_eq!(occupied, unwound);
        let granted = [first_outcome, second_outcome]
            .iter()
            .filter(|outcome| **outcome != Outcome::InProgress)
            .count();
        assert!(freed <= granted);
        assert!(first_outcome != Outcome::InProgress && second_outcome != Outcome::InProgress);
    });
}

#[test]
fn two_owners_close_revocation_and_service() {
    model(Ending::Abort, Departure::Production, 2);
}

#[test]
fn an_unwound_disposal_keeps_its_record_and_slot_charged() {
    model(Ending::Unwind, Departure::Production, 2);
}

#[test]
#[should_panic(expected = "a departed record whose block was not disposed of")]
fn negative_control_a_relaxed_departure_hides_the_disposal() {
    model(Ending::Abort, Departure::Relaxed, 2);
}
