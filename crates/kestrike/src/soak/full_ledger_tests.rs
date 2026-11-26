//! A soak ledger at its capacity and the next action that would add an entry.
//!
//! A soak ledger at its capacity refuses the next operation as inconclusive, drops nothing
//! and cuts the window; `Soak::step` then fails the soak as `SoakFailure::Inconclusive`.
//!
//! Each case runs one soak over the simulated device with capacity 2 and pressure 1, publishes key 0, and
//! fills the ledger with reads of key 0 whose device commands it holds, so no entry settles by itself.
//!
//! - `refused_actions`: two held reads bring the ledger to exactly its capacity. The case then calls each
//!   action that would add an entry, as `Soak::step` calls it: a read and an acquire of the published key,
//!   a fill of an unpublished key, and a pressure. Each must return `Err(Inconclusive::Ledger)` and leave
//!   the ledger's identities as they were.
//! - `refused_step`: from the same full ledger the case runs `Soak::step`, whose action the seeded chooser
//!   draws, until a step is refused. A step that returns `Ok` must add nothing. The refused step must
//!   return `Err(Inconclusive::Ledger)`, leave the ledger at its capacity with the same identities, cut
//!   exactly one window and record `SoakFailure::Inconclusive`, with no failure before it.
//! - `admitted_read`, the counterpart: one held read leaves the ledger one entry below its capacity. The same
//!   read is admitted, adds exactly one identity and records no failure.
//!
//! A case decides nothing while its fixtures live: it records a premise that failed to form, releases every
//! held device command, closes the soak, and returns. The assertions run afterwards.

use std::num::NonZeroU8;
use std::time::Duration;

use super::monitor_tests::{SimSoak, fixture};
use super::*;
use crate::storage::owner_fixture::{Device, SimControl, TestPlatform, last_read};
use crate::storage::{BufferArena, CommandToken};

/// The soak's clock, which no case moves, so no read passes its deadline.
const NOW: u64 = 10;

const CAPACITY: usize = 2;

const CONFIG: SoakConfig = SoakConfig {
    seed: 0x5eed,
    keys: NonZeroU8::new(4).unwrap(),
    body_cap: 100,
    capacity: CAPACITY,
    pressure: 1,
    cut_every: 8,
    patience: Duration::from_secs(10),
};

/// Steps a case gives the seeded workload to draw an action the full ledger refuses.
const STEPS: usize = 2_000;

/// One action's result and the ledger's identities after it.
type Acted = (&'static str, Result<(), Inconclusive>, Vec<u64>);

/// What the refused step left, and what the steps before it did.
#[derive(Debug, PartialEq, Eq)]
struct Refused {
    result: Inconclusive,
    /// A step before it returned `Ok` and changed the ledger's identities.
    added_before: bool,
    /// The soak's failure before the refused step.
    failure_before: Option<SoakFailure>,
    /// `windows()` before the refused step and after it.
    windows: (u64, u64),
    unsettled: usize,
    unresolved: Vec<u64>,
    failure: Option<SoakFailure>,
}

/// What one case returns once its fixtures are gone.
#[derive(Debug, Default)]
struct Witness {
    /// Premises that failed to form; a case with one has no verdict.
    premises: Vec<&'static str>,
    /// `unsettled()` and `unresolved()` once the case's reads were held.
    held: (usize, Vec<u64>),
    acted: Vec<Acted>,
    refused: Option<Refused>,
    /// The soak's failure after the case's actions, before the close.
    failure: Option<SoakFailure>,
}

/// One soak with key 0 published, its device, the commands the case holds and what it witnessed.
struct Run<'s, 'a> {
    soak: SimSoak<'s, 'a>,
    control: SimControl,
    tokens: Vec<CommandToken>,
    witness: Witness,
}

/// The witness of a case whose storage refused the soak's reader.
fn unregistered() -> Witness {
    Witness {
        premises: vec!["the storage registers the soak's reader"],
        ..Witness::default()
    }
}

impl<'s, 'a> Run<'s, 'a> {
    /// A soak with key 0 published and `reads` reads of it held at the device, or `None` when the
    /// storage refused the soak's reader.
    fn start(
        storage: &'s Storage<TestPlatform>,
        arena: &'a BufferArena<TestPlatform>,
        reads: usize,
    ) -> Option<Self> {
        let Device { volume, control } = Device::new(storage, arena);
        let reader = storage.register().ok()?;
        let mut soak = Soak::new(storage, volume, reader, CONFIG, Vec::new());
        soak.device = Some(control.clone());
        soak.clock = Some(NOW);
        let mut run = Self {
            soak,
            control,
            tokens: Vec::new(),
            witness: Witness::default(),
        };
        if run.soak.fill(0).is_err() {
            run.witness
                .premises
                .push("the soak begins the fill of key 0");
        }
        for _ in 0..100 {
            run.control.tick(64);
            let mut events = Vec::with_capacity(8);
            run.soak.volume.poll_storage(NOW, &mut events);
            run.soak.advance();
            if run.soak.published[0].is_some() {
                break;
            }
        }
        let published = run.soak.published[0].is_some() && run.soak.published[1].is_none();
        run.require(published, "key 0 is published and key 1 is not");
        let empty = run.soak.unsettled() == 0;
        run.require(empty, "the ledger is empty before the case's reads");
        for _ in 0..reads {
            run.hold();
        }
        let quiet = run.soak.failure().is_none();
        run.require(quiet, "the soak has no failure before the case starts");
        run.witness.held = (run.soak.unsettled(), run.soak.unresolved());
        Some(run)
    }

    fn require(&mut self, holds: bool, premise: &'static str) {
        if !holds {
            self.witness.premises.push(premise);
        }
    }

    /// Admits a read of key 0 and holds its device command, so no terminal arrives by itself.
    fn hold(&mut self) {
        let (before, last) = (self.soak.reads.len(), last_read(&self.control));
        if self.soak.read(0).is_err() || self.soak.reads.len() != before + 1 {
            self.witness
                .premises
                .push("the volume admits the held read");
            return;
        }
        let Some(token) = last_read(&self.control).filter(|token| Some(*token) != last) else {
            self.witness.premises.push("the read reached the device");
            return;
        };
        if self.control.try_hold(token).is_err() {
            self.witness
                .premises
                .push("the device holds the read's command");
            return;
        }
        self.tokens.push(token);
    }

    /// Records `result` of the action `name` and the ledger after it.
    fn acted(&mut self, name: &'static str, result: Result<(), Inconclusive>) {
        self.witness
            .acted
            .push((name, result, self.soak.unresolved()));
    }

    /// Releases the held commands, closes the soak and returns the case's witness.
    fn end(mut self) -> Witness {
        self.witness.failure = self.soak.failure();
        for token in self.tokens.drain(..) {
            self.control.release(token);
        }
        self.soak.config.patience = Duration::from_secs(1);
        let _ = self.soak.close();
        self.witness
    }
}

/// The ledger at its capacity, and each action that would add an entry called as `Soak::step` calls it.
fn refused_actions() -> Witness {
    let (storage, arena) = fixture();
    let Some(mut run) = Run::start(&storage, &arena, CAPACITY) else {
        return unregistered();
    };
    let result = run.soak.read(0);
    run.acted("read", result);
    let result = run.soak.acquire(0);
    run.acted("acquire", result);
    let result = run.soak.fill(1);
    run.acted("fill", result);
    let result = run.soak.pressure(0);
    run.acted("pressure", result);
    run.end()
}

/// The ledger at its capacity, and the seeded workload's steps up to the first one refused.
fn refused_step() -> Witness {
    let (storage, arena) = fixture();
    let Some(mut run) = Run::start(&storage, &arena, CAPACITY) else {
        return unregistered();
    };
    let mut added_before = false;
    for _ in 0..STEPS {
        let (failure_before, windows, ledger) = (
            run.soak.failure(),
            run.soak.windows(),
            run.soak.unresolved(),
        );
        match run.soak.step() {
            Ok(()) => added_before |= run.soak.unresolved() != ledger,
            Err(result) => {
                run.witness.refused = Some(Refused {
                    result,
                    added_before,
                    failure_before,
                    windows: (windows, run.soak.windows()),
                    unsettled: run.soak.unsettled(),
                    unresolved: run.soak.unresolved(),
                    failure: run.soak.failure(),
                });
                break;
            }
        }
    }
    run.end()
}

/// The counterpart: the ledger one entry below its capacity, and the same read.
fn admitted_read() -> Witness {
    let (storage, arena) = fixture();
    let Some(mut run) = Run::start(&storage, &arena, CAPACITY - 1) else {
        return unregistered();
    };
    let result = run.soak.read(0);
    run.acted("read", result);
    run.end()
}

/// The case formed: every premise held, and its held reads brought the ledger to `entries`.
fn formed(witness: &Witness, entries: usize) {
    assert!(witness.premises.is_empty(), "{witness:?}");
    assert_eq!(witness.held.0, entries, "{witness:?}");
    assert_eq!(witness.held.1.len(), entries, "{witness:?}");
}

#[test]
fn a_full_ledger_refuses_each_adding_action_and_keeps_every_entry() {
    let witness = refused_actions();
    formed(&witness, CAPACITY);
    let expected: Vec<Acted> = ["read", "acquire", "fill", "pressure"]
        .into_iter()
        .map(|name| (name, Err(Inconclusive::Ledger), witness.held.1.clone()))
        .collect();
    assert_eq!(witness.acted, expected, "{witness:?}");
}

#[test]
fn the_step_a_full_ledger_refuses_cuts_the_window_and_fails_the_soak_inconclusive() {
    let witness = refused_step();
    formed(&witness, CAPACITY);
    let refused = witness.refused.as_ref().expect("a step was refused");
    assert_eq!(
        *refused,
        Refused {
            result: Inconclusive::Ledger,
            added_before: false,
            failure_before: None,
            windows: (refused.windows.0, refused.windows.0 + 1),
            unsettled: CAPACITY,
            unresolved: witness.held.1.clone(),
            failure: Some(SoakFailure::Inconclusive),
        },
        "{witness:?}"
    );
}

#[test]
fn a_ledger_one_entry_below_its_capacity_admits_the_same_read() {
    let witness = admitted_read();
    formed(&witness, CAPACITY - 1);
    let [(_, result, ledger)] = &witness.acted[..] else {
        panic!("one action: {witness:?}");
    };
    assert_eq!(*result, Ok(()), "{witness:?}");
    assert_eq!(
        ledger.len(),
        CAPACITY,
        "the read added one entry: {witness:?}"
    );
    assert_eq!(ledger[..CAPACITY - 1], witness.held.1[..], "{witness:?}");
    assert!(
        !witness.held.1.contains(&ledger[CAPACITY - 1]),
        "{witness:?}"
    );
    assert_eq!(witness.failure, None, "{witness:?}");
}
