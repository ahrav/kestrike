//! Loom kernel for the fill authority and departure seam: two keys, a table
//! of two records, a tiny serial maximum and up to three participants,
//! exploring every interleaving of the grant under the gate, the owner's
//! departure without it, and the service pass that frees the record, within
//! the recorded preemption bound.
//!
//! Model substitutions, each replacing a mapped word or code the storage owns
//! with a loom primitive:
//!
//! - `gate` is the shard gate, a loom mutex holding the gate-owned table
//!   state the root mapping keeps as plain words under the gate: the keys,
//!   the next serial and the service cursor. The production grant and pass
//!   are spelled out over it in their order; the protocol words themselves
//!   are the production `fill` module's `decode`, `occupied`, `depart`,
//!   `revoke`, `observe`, `load_run` and `release`, called unchanged on loom
//!   atomics.
//! - `states` are the two record words. `ended` is one flag per issuable
//!   serial that an owner sets, without the gate, before it departs: it
//!   stands for any owner-side state a departing owner records last, and it
//!   makes the departure's `Release` observable, since the pass asserts the
//!   flag after the production `observe` found the record departed.
//! - The pass observes the records either as production's under-funded
//!   pass does, one `observe` per record, or as its funded pass does, one
//!   `load_run` over the table's words with the run's acquire fence, so the
//!   fence-based ordering is checked against the same departures.
//! - The two-participant kernel's main thread is an invalidation: under the
//!   gate it revokes the key's current association, if any, while the owners
//!   begin and depart around it, so the departure's retry past a concurrent
//!   revocation is explored.
//! - The serial maximum is the model's own, [`TINY_MAX`], applied where the
//!   production grant applies [`SERIAL_MAX`](super::fill::SERIAL_MAX); the
//!   word encoding is untouched.
//!
//! Properties, each an assertion in the model: a key never has two current
//! associations; a granted serial is never granted twice and never exceeds
//! the maximum, and once the maximum is passed no grant follows; a record is
//! freed only when its word is departed and its owner's flag is set; a
//! revoked record keeps its serial and its departure; every owner departs
//! its own record exactly once, revoked or not; after every participant has
//! ended, one funded pass frees every record and the serial counter equals
//! the grants made plus one.
//!
//! Negative controls, each matched on its own assertion so a different
//! failure cannot stand in for it: a `Relaxed` departure, run through the
//! production `depart` with only its success ordering weakened, lets the
//! pass free a record whose owner's flag it cannot yet see, under either
//! observation, which is the
//! bridge the `Release` supplies for owner-side state outside the gate; a
//! release that ignores the departed flag frees a live owner's record, which
//! a later grant then reissues under the owner. The departure's serial check has no
//! control here: with every owner departing once and every release checked,
//! no interleaving lets a departure reach a record another serial occupies,
//! so a check-free departure passes this kernel and the check is defence for
//! owners that end late, which the kernel does not model.
//!
//! The follower kernel adds each record's row: its terminal word, encoded by
//! the production `row` module, its observer count and the count of rights
//! its publication retained. One producer is granted, marks its row
//! upload-granted under the gate, then either records a failure without the
//! gate and departs, or publishes under the gate, attaching the row's right
//! when a follower is joined. One follower joins under the gate, observes
//! with the production `observe`, acquires a published version's own right,
//! and detaches with a `Release` subtraction.
//! The main thread services once while both run and once after.
//! Properties: a follower that observes the departure
//! sees the producer's terminal; a follower's record is never freed or
//! reissued under it; a retained right is returned exactly once, by the
//! pass that frees its record, and only after the last observer detached.
//! The published object's count of rights is modeled beside the record: the
//! publication installs the publisher's right and, with a follower joined,
//! the row's; the publisher drops its right at once; the follower takes its
//! own with a retain that admits only a positive count and drops it after
//! detaching; the pass returns the row's right as it frees the record. The
//! main thread regrants between its passes, so a freed record can be
//! reissued while the follower runs. Further properties: a follower of a
//! retained publication always takes its right, no right is returned on an
//! idle count, and every right returns. Its controls: a failure recorded
//! after the departure lets a follower see the departure without its
//! terminal, and a pass that frees a departed record with a follower joined
//! lets the follower observe its record freed, or meets the regrant's
//! refusal of that Free record.
//!
//! Bounds: loom `0.7.2`, preemption bound 2 for the three-participant kernel
//! and 3 for the two-participant kernel, the follower kernel and their
//! controls, exhaustive within them. Loom does not model the cross-location
//! `SeqCst` total order. The model orders threads with the gate and with
//! `Release`-`Acquire` pairs, which loom models. Run with
//! `RUSTFLAGS="--cfg loom" cargo test -p kestrike --lib --release fill_model`.

use std::sync::atomic::Ordering;

use loom::sync::atomic::{AtomicBool, AtomicU64};
use loom::sync::{Arc, Mutex};
use loom::thread;

use super::fill::{self, FIRST_SERIAL, FillSerial, Record};
use super::row::{self, FillFailure, Terminal};

const RECORDS: usize = 2;
const KEY_A: u64 = 0xA;
const KEY_B: u64 = 0xB;
/// The largest serial the model issues; production's is `SERIAL_MAX`.
const TINY_MAX: u64 = 2;

/// Which departure the owners run.
#[derive(Clone, Copy)]
enum Departure {
    /// The production `Release` compare-exchange with the serial check.
    Production,
    /// The same exchange at `Relaxed`.
    Relaxed,
}

/// The record word with its departure's success ordering weakened to
/// `Relaxed`: the production `depart`, retry loop included, runs over it
/// unchanged, so the control removes only the release.
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

/// How the pass observes the records.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Observe {
    /// One `Acquire` load per record: the under-funded pass.
    Single,
    /// `Relaxed` loads of the whole table and one `Acquire` fence when any
    /// word is occupied: the funded pass's run.
    Run,
}

/// Which release the pass runs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Release {
    /// The production store, made only for a departed word with no
    /// follower joined.
    Production,
    /// Frees any occupied record, departed or not.
    Unchecked,
    /// Frees a departed record whatever its observer count.
    IgnoresObservers,
}

struct Table {
    keys: [u64; RECORDS],
    next_serial: u64,
    cursor: usize,
    /// Serials granted so far, for the uniqueness check.
    granted: Vec<FillSerial>,
    /// Serials the invalidation revoked.
    revoked: Vec<FillSerial>,
}

struct Shard {
    gate: Mutex<Table>,
    states: [AtomicU64; RECORDS],
    /// One flag per issuable serial, indexed by serial.
    ended: [AtomicBool; TINY_MAX as usize + 1],
    /// Each record's row terminal word.
    terminals: [AtomicU64; RECORDS],
    /// Each record's joined followers.
    observers: [AtomicU64; RECORDS],
    /// Each record's object rights its publication retained, at most one.
    retained: [AtomicU64; RECORDS],
    /// The published object's count of rights, the slot word's count: the
    /// publisher's, the row's retained one and the follower's own.
    object: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refused {
    InProgress,
    FillSlotsFull,
    AttemptExhausted,
    /// A Free record with a follower joined, which the production grant
    /// refuses as a malformed table.
    Corrupt,
}

impl Shard {
    fn new() -> Self {
        Self {
            gate: Mutex::new(Table {
                keys: [0; RECORDS],
                next_serial: FIRST_SERIAL,
                cursor: 0,
                granted: Vec::new(),
                revoked: Vec::new(),
            }),
            states: [AtomicU64::new(fill::FREE), AtomicU64::new(fill::FREE)],
            ended: [
                AtomicBool::new(false),
                AtomicBool::new(false),
                AtomicBool::new(false),
            ],
            terminals: [AtomicU64::new(row::GRANTED), AtomicU64::new(row::GRANTED)],
            observers: [AtomicU64::new(0), AtomicU64::new(0)],
            retained: [AtomicU64::new(0), AtomicU64::new(0)],
            object: AtomicU64::new(0),
        }
    }

    /// The production grant over the model table: the exhaustion check, the
    /// scan for a Free record and a current association, the write.
    fn begin(&self, key: u64) -> Result<(usize, FillSerial), Refused> {
        let mut table = self.gate.lock().unwrap();
        if table.next_serial > TINY_MAX {
            return Err(Refused::AttemptExhausted);
        }
        let mut free = None;
        let mut associated = 0;
        for (position, state) in self.states.iter().enumerate() {
            let record = fill::decode(state.load(Ordering::Relaxed), table.next_serial)
                .expect("the model writes only encoded words");
            match record {
                Record::Free => {
                    free.get_or_insert(position);
                }
                occupied if occupied.is_associated() && table.keys[position] == key => {
                    associated += 1;
                }
                Record::Occupied { .. } => {}
            }
        }
        assert!(
            associated <= 1,
            "protection violated: two associations for one key"
        );
        if associated == 1 {
            return Err(Refused::InProgress);
        }
        let record = free.ok_or(Refused::FillSlotsFull)?;
        let serial = FillSerial::new(table.next_serial).expect("valid model fill serial");
        assert!(
            !table.granted.contains(&serial) && serial.get() <= TINY_MAX,
            "protection violated: serial reissued or past the maximum"
        );
        if self.observers[record].load(Ordering::Acquire) != 0 {
            return Err(Refused::Corrupt);
        }
        table.granted.push(serial);
        table.keys[record] = key;
        self.terminals[record].store(row::GRANTED, Ordering::Relaxed);
        self.states[record].store(fill::occupied(serial), Ordering::Relaxed);
        table.next_serial = serial.get() + 1;
        Ok((record, serial))
    }

    /// An owner's end: its flag, then its departure.
    fn depart(&self, record: usize, serial: FillSerial, departure: Departure) {
        self.ended[serial.get() as usize].store(true, Ordering::Relaxed);
        let state = &self.states[record];
        let departed = match departure {
            Departure::Production => fill::depart(state, serial),
            Departure::Relaxed => fill::depart(&Weakened(state), serial),
        };
        assert!(
            departed,
            "protection violated: an owner could not depart its own record"
        );
    }

    /// The invalidation's revocation under the gate: the current association
    /// of `key`, if any, loses its association and nothing else.
    fn revoke(&self, key: u64) {
        let mut table = self.gate.lock().unwrap();
        for (position, state) in self.states.iter().enumerate() {
            let record = fill::decode(state.load(Ordering::Relaxed), table.next_serial)
                .expect("the model writes only encoded words");
            if let Record::Occupied { serial, .. } = record
                && record.is_associated()
                && table.keys[position] == key
            {
                fill::revoke(state);
                table.revoked.push(serial);
            }
        }
    }

    /// One production pass over the table under the gate.
    fn service(&self, observe: Observe, release: Release) -> usize {
        let mut table = self.gate.lock().unwrap();
        let mut released = 0;
        let mut position = table.cursor;
        let run = match observe {
            Observe::Single => None,
            Observe::Run => Some(fill::load_run(&self.states)),
        };
        for _ in 0..RECORDS {
            let state = &self.states[position];
            let record = match run {
                None => fill::observe(state, table.next_serial),
                Some(words) => fill::decode(words[position], table.next_serial),
            }
            .expect("encoded");
            let joined = self.observers[position].load(Ordering::Acquire) != 0;
            match (record, release) {
                (Record::Occupied { departed: true, .. }, Release::Production) if joined => {}
                (
                    Record::Occupied {
                        serial,
                        departed: true,
                        revoked,
                    },
                    _,
                ) => {
                    assert!(
                        self.ended[serial.get() as usize].load(Ordering::Relaxed),
                        "protection violated: a departed record whose owner had not ended"
                    );
                    assert_eq!(
                        revoked,
                        table.revoked.contains(&serial),
                        "protection violated: a revocation was lost or invented"
                    );
                    // The occupant's serial must be the one that departed.
                    assert!(
                        table.granted.contains(&serial),
                        "protection violated: a departed word names an ungranted serial"
                    );
                    // The production pass returns the row's retained right
                    // before the release store.
                    if let Ok(Terminal::Published { retained: true, .. }) =
                        row::decode(self.terminals[position].load(Ordering::Relaxed))
                    {
                        let rights = self.retained[position].fetch_sub(1, Ordering::Relaxed);
                        assert_eq!(
                            rights, 1,
                            "protection violated: a retained right returned twice"
                        );
                        let count = self.object.fetch_sub(1, Ordering::Release);
                        assert!(
                            count >= 1,
                            "protection violated: a retained right returned on an idle object"
                        );
                        self.terminals[position].store(row::GRANTED, Ordering::Relaxed);
                    }
                    fill::release(state);
                    released += 1;
                }
                (Record::Occupied { .. }, Release::Unchecked) => {
                    state.store(fill::FREE, Ordering::Relaxed);
                    released += 1;
                }
                _ => {}
            }
            position = (position + 1) % RECORDS;
        }
        table.cursor = position;
        released
    }
}

/// One participant: begins `key`, and on a grant ends the attempt with
/// `departure`. Returns whether it was granted.
fn owner(shard: &Shard, key: u64, departure: Departure) -> bool {
    match shard.begin(key) {
        Ok((record, serial)) => {
            // The word an owner holds carries its serial until it departs;
            // another owner's departure never changes it.
            let word = shard.states[record].load(Ordering::Relaxed);
            assert_eq!(
                word >> 2,
                serial.get(),
                "protection violated: a live record lost its serial"
            );
            assert_eq!(
                word & 1,
                0,
                "protection violated: a live record marked departed"
            );
            shard.depart(record, serial, departure);
            true
        }
        Err(_) => false,
    }
}

/// How the producer of the follower kernel ends.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Records a failure without the gate, then departs: production order.
    Fail,
    /// Departs, then records the failure: the control.
    FailAfterDeparture,
    /// Publishes under the gate.
    Publish,
}

const FAILURE: FillFailure = FillFailure::TimedOut;

impl Shard {
    /// The producer: a grant, the reservation's upload grant under the gate,
    /// then its end.
    fn produce(&self, outcome: Outcome) {
        let Ok((record, serial)) = self.begin(KEY_A) else {
            return;
        };
        {
            let _hold = self.gate.lock().unwrap();
            self.terminals[record].store(row::READY, Ordering::Relaxed);
        }
        match outcome {
            Outcome::Fail => {
                self.terminals[record].store(row::failed(FAILURE), Ordering::Relaxed);
                self.depart(record, serial, Departure::Production);
            }
            Outcome::FailAfterDeparture => {
                self.depart(record, serial, Departure::Production);
                self.terminals[record].store(row::failed(FAILURE), Ordering::Relaxed);
            }
            Outcome::Publish => {
                // The publisher's own revocation, which the pass's ledger of
                // revoked serials records as it records an invalidation's.
                let mut table = self.gate.lock().unwrap();
                table.revoked.push(serial);
                let retained = self.observers[record].load(Ordering::Acquire) != 0;
                if retained {
                    self.retained[record].fetch_add(1, Ordering::Relaxed);
                }
                // The install on the idle count: the publisher's right and,
                // with a follower joined, the row's.
                self.object
                    .fetch_add(1 + u64::from(retained), Ordering::Release);
                self.terminals[record].store(row::published(7, retained), Ordering::Relaxed);
                self.ended[serial.get() as usize].store(true, Ordering::Relaxed);
                let state = &self.states[record];
                fill::revoke(state);
                assert!(
                    fill::depart(state, serial),
                    "the publisher departs its own record"
                );
                drop(table);
                // The publisher's lease ends at once.
                self.object.fetch_sub(1, Ordering::Release);
            }
        }
    }

    /// The follower: the production join rule under the gate, two
    /// observations, then an acquisition of a published version or a
    /// `Release` detach. Returns whether it acquired a version's own right,
    /// which it then drops.
    fn follow(&self, outcome: Outcome) -> bool {
        let joined = {
            let table = self.gate.lock().unwrap();
            let mut joined = None;
            for (position, state) in self.states.iter().enumerate() {
                let word = state.load(Ordering::Relaxed);
                let Ok(Record::Occupied {
                    serial,
                    departed,
                    revoked,
                }) = fill::decode(word, table.next_serial)
                else {
                    continue;
                };
                let terminal = row::decode(self.terminals[position].load(Ordering::Relaxed))
                    .expect("the model writes only encoded terminals");
                let joinable = match terminal {
                    Terminal::Ready => !departed && !revoked,
                    Terminal::Published { .. } => departed,
                    Terminal::Granted | Terminal::Failed(_) => false,
                };
                if joinable && table.keys[position] == KEY_A {
                    joined = Some((position, serial));
                }
            }
            if let Some((position, _)) = joined {
                self.observers[position].fetch_add(1, Ordering::Relaxed);
            }
            joined
        };
        let Some((record, serial)) = joined else {
            return false;
        };
        for _ in 0..2 {
            let observed = fill::observe(&self.states[record], serial.get() + 1).expect("encoded");
            let Record::Occupied {
                serial: seen,
                departed,
                ..
            } = observed
            else {
                panic!("protection violated: a follower's record was freed under it");
            };
            assert_eq!(
                seen, serial,
                "protection violated: a follower's record was reissued"
            );
            if !departed {
                continue;
            }
            let terminal = row::decode(self.terminals[record].load(Ordering::Relaxed))
                .expect("the model writes only encoded terminals");
            match (outcome, terminal) {
                (Outcome::Publish, Terminal::Published { retained, .. }) => {
                    // A retained right keeps the object's count positive
                    // for the follower's own retain.
                    let mut count = self.object.load(Ordering::Relaxed);
                    let took = loop {
                        if count == 0 {
                            break false;
                        }
                        match self.object.compare_exchange(
                            count,
                            count + 1,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        ) {
                            Ok(_) => break true,
                            Err(seen) => count = seen,
                        }
                    };
                    assert!(
                        took || !retained,
                        "protection violated: a retained version lost its right"
                    );
                    self.observers[record].fetch_sub(1, Ordering::Release);
                    if took {
                        let count = self.object.fetch_sub(1, Ordering::Release);
                        assert!(
                            count >= 1,
                            "protection violated: a follower's right on an idle object"
                        );
                    }
                    return took;
                }
                (Outcome::Fail | Outcome::FailAfterDeparture, Terminal::Failed(failure)) => {
                    assert_eq!(failure, FAILURE);
                    break;
                }
                (_, terminal) => panic!(
                    "protection violated: a follower saw the departure without its terminal: {terminal:?}"
                ),
            }
        }
        self.observers[record].fetch_sub(1, Ordering::Release);
        false
    }
}

fn follower_model(outcome: Outcome, release: Release) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder.check(move || {
        let shard = Arc::new(Shard::new());
        let producer = {
            let shard = Arc::clone(&shard);
            thread::spawn(move || shard.produce(outcome))
        };
        let follower = {
            let shard = Arc::clone(&shard);
            thread::spawn(move || shard.follow(outcome))
        };
        shard.service(Observe::Single, release);
        // A regrant races the follower: a record the pass freed is reissued
        // to another key, whose owner ends at once.
        match shard.begin(KEY_B) {
            Ok((record, serial)) => shard.depart(record, serial, Departure::Production),
            // The grant's refusal of a Free record with a follower joined is
            // the second place the defect shows.
            Err(Refused::Corrupt) => {
                panic!("protection violated: a follower's record was freed while joined")
            }
            Err(_) => {}
        }
        producer.join().unwrap();
        follower.join().unwrap();
        shard.service(Observe::Single, release);
        assert_eq!(
            shard.object.load(Ordering::Relaxed),
            0,
            "protection violated: an object right never returned"
        );
        for position in 0..RECORDS {
            assert_eq!(shard.states[position].load(Ordering::Relaxed), fill::FREE);
            assert_eq!(shard.observers[position].load(Ordering::Relaxed), 0);
            assert_eq!(
                shard.retained[position].load(Ordering::Relaxed),
                0,
                "protection violated: a retained right never returned"
            );
        }
    });
}

#[test]
fn a_follower_sees_a_failed_producers_terminal_at_its_departure() {
    follower_model(Outcome::Fail, Release::Production);
}

#[test]
fn a_follower_of_a_publication_keeps_its_record_until_it_detaches() {
    follower_model(Outcome::Publish, Release::Production);
}

#[test]
#[should_panic(expected = "a follower saw the departure without its terminal")]
fn negative_control_a_terminal_recorded_after_the_departure_is_missed() {
    follower_model(Outcome::FailAfterDeparture, Release::Production);
}

#[test]
#[should_panic(expected = "a follower's record was freed")]
fn negative_control_a_release_that_ignores_followers_frees_a_joined_record() {
    follower_model(Outcome::Fail, Release::IgnoresObservers);
}

fn model(departure: Departure, observe: Observe, release: Release, bound: usize, three: bool) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(bound);
    builder.check(move || {
        let shard = Arc::new(Shard::new());
        let first = {
            let shard = Arc::clone(&shard);
            thread::spawn(move || owner(&shard, KEY_A, departure))
        };
        let second = {
            let shard = Arc::clone(&shard);
            thread::spawn(move || owner(&shard, KEY_A, departure))
        };
        // The main thread invalidates the first key, or in the
        // three-participant kernel contends for the second, then services
        // once while the owners run.
        let mut granted = 0;
        if three {
            granted += usize::from(owner(&shard, KEY_B, departure));
        } else {
            shard.revoke(KEY_A);
        }
        shard.service(observe, release);
        granted += usize::from(first.join().unwrap()) + usize::from(second.join().unwrap());
        // Every owner has ended: one funded pass frees every record, the
        // table is empty, and the counter is the grants plus one.
        let freed = shard.service(observe, release);
        let table = shard.gate.lock().unwrap();
        assert!(granted <= TINY_MAX as usize);
        assert_eq!(table.granted.len(), granted);
        assert_eq!(table.next_serial, FIRST_SERIAL + granted as u64);
        for state in &shard.states {
            assert_eq!(state.load(Ordering::Relaxed), fill::FREE);
        }
        assert!(freed <= granted);
        // With the maximum reached, no further grant: the counter is past it
        // and stays there through the empty table.
        if granted == TINY_MAX as usize {
            drop(table);
            assert_eq!(shard.begin(KEY_B).err(), Some(Refused::AttemptExhausted));
            assert_eq!(shard.begin(KEY_A).err(), Some(Refused::AttemptExhausted));
        }
    });
}

#[test]
fn two_owners_on_one_key_and_a_servicer() {
    model(
        Departure::Production,
        Observe::Single,
        Release::Production,
        3,
        false,
    );
}

#[test]
fn two_owners_on_one_key_and_a_servicer_observing_the_run() {
    model(
        Departure::Production,
        Observe::Run,
        Release::Production,
        3,
        false,
    );
}

#[test]
fn three_participants_over_two_keys_reach_the_serial_maximum() {
    model(
        Departure::Production,
        Observe::Single,
        Release::Production,
        2,
        true,
    );
}

#[test]
fn three_participants_over_two_keys_observing_the_run() {
    model(
        Departure::Production,
        Observe::Run,
        Release::Production,
        2,
        true,
    );
}

#[test]
#[should_panic(expected = "a departed record whose owner had not ended")]
fn negative_control_a_relaxed_departure_loses_the_owners_last_write() {
    model(
        Departure::Relaxed,
        Observe::Single,
        Release::Production,
        3,
        false,
    );
}

#[test]
#[should_panic(expected = "a departed record whose owner had not ended")]
fn negative_control_a_relaxed_departure_escapes_the_runs_fence() {
    model(
        Departure::Relaxed,
        Observe::Run,
        Release::Production,
        3,
        false,
    );
}

#[test]
#[should_panic(expected = "protection violated: a live record")]
fn negative_control_an_unchecked_release_frees_a_live_owner() {
    model(
        Departure::Production,
        Observe::Single,
        Release::Unchecked,
        3,
        false,
    );
}
