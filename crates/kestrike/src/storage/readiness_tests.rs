//! The readiness machine's closed table, every `(state, event)` cell, and the word's compare-and-swap writes.

use super::readiness::{Event, ReadinessError, State, Word, next};
use super::reserve::ReserveError;
use crate::failover::serving::State as Serving;

const EVENTS: [Event; 9] = [
    Event::Attach,
    Event::LoadComplete,
    Event::BeginReplay {
        matches: true,
        rows: 0,
    },
    Event::BeginReplay {
        matches: true,
        rows: 3,
    },
    Event::BeginReplay {
        matches: false,
        rows: 0,
    },
    Event::BeginReplay {
        matches: false,
        rows: 3,
    },
    Event::CompleteReplay,
    Event::Withhold,
    Event::Withdraw,
];

/// Every cell of the table, listed independently of `next`: each state, then the outcome of each event in `EVENTS` order and of `Close`.
#[test]
fn every_cell_of_the_table_holds() {
    use ReadinessError::{AlreadyLive, Ended, Invariant, NotReady};
    use State::{Closed, Detached, Live, Loaded, Loading, Replaying, Withheld};
    let table: [(State, [Result<State, ReadinessError>; 10]); 7] = [
        (
            Detached,
            [
                Ok(Loading),
                Err(NotReady),
                Err(NotReady),
                Err(NotReady),
                Err(NotReady),
                Err(NotReady),
                Err(NotReady),
                Err(Invariant),
                Ok(Withheld),
                Ok(Closed),
            ],
        ),
        (
            Loading,
            [
                Err(Invariant),
                Ok(Loaded),
                Err(NotReady),
                Err(NotReady),
                Err(NotReady),
                Err(NotReady),
                Err(NotReady),
                Ok(Withheld),
                Ok(Withheld),
                Ok(Closed),
            ],
        ),
        (
            Loaded,
            [
                Err(Invariant),
                Err(Invariant),
                Ok(Live),
                Ok(Replaying),
                Ok(Withheld),
                Ok(Withheld),
                Err(NotReady),
                Ok(Withheld),
                Ok(Withheld),
                Ok(Closed),
            ],
        ),
        (
            Replaying,
            [
                Err(Invariant),
                Err(Invariant),
                Err(AlreadyLive),
                Err(AlreadyLive),
                Err(AlreadyLive),
                Err(AlreadyLive),
                Ok(Live),
                Ok(Withheld),
                Ok(Withheld),
                Ok(Closed),
            ],
        ),
        (
            Live,
            [
                Err(Invariant),
                Err(Invariant),
                Err(AlreadyLive),
                Err(AlreadyLive),
                Err(AlreadyLive),
                Err(AlreadyLive),
                Err(AlreadyLive),
                Ok(Withheld),
                Ok(Withheld),
                Ok(Closed),
            ],
        ),
        (
            Withheld,
            [
                Ok(Withheld),
                Ok(Withheld),
                Err(Ended(Withheld)),
                Err(Ended(Withheld)),
                Err(Ended(Withheld)),
                Err(Ended(Withheld)),
                Err(Ended(Withheld)),
                Ok(Withheld),
                Ok(Withheld),
                Ok(Closed),
            ],
        ),
        (
            Closed,
            [
                Err(Invariant),
                Ok(Closed),
                Err(Ended(Closed)),
                Err(Ended(Closed)),
                Err(Ended(Closed)),
                Err(Ended(Closed)),
                Err(Ended(Closed)),
                Ok(Closed),
                Ok(Closed),
                Ok(Closed),
            ],
        ),
    ];
    assert_eq!(
        table.map(|(state, _)| state),
        State::ALL_STATES,
        "the table lists every state once, in discriminant order"
    );
    for (at, event) in EVENTS.iter().enumerate() {
        assert!(
            !EVENTS[at + 1..].contains(event),
            "each column names a distinct event: {event:?}"
        );
    }
    for (state, outcomes) in table {
        for (event, outcome) in EVENTS.iter().chain([&Event::Close]).zip(outcomes) {
            assert_eq!(next(state, *event), outcome, "{state:?} on {event:?}");
        }
    }
}

/// Only `Detached` and `Live` admit fills, and no state leaves `Withheld` or `Closed` for a serving state.
#[test]
fn fills_open_only_at_live_and_ended_attempts_stay_ended() {
    use super::ReserveError::{Bootstrapping, Closed};
    for state in State::ALL_STATES {
        let expected = match state {
            State::Detached | State::Live => None,
            State::Loading | State::Loaded | State::Replaying => Some(Bootstrapping),
            State::Withheld | State::Closed => Some(Closed),
        };
        assert_eq!(state.fill_refusal(), expected, "{state:?}");
    }
    for state in [State::Withheld, State::Closed] {
        for event in EVENTS.iter().chain([&Event::Close]) {
            assert!(
                !matches!(
                    next(state, *event),
                    Ok(State::Detached
                        | State::Loading
                        | State::Loaded
                        | State::Replaying
                        | State::Live)
                ),
                "{state:?} on {event:?}"
            );
        }
    }
}

/// The word moves through the RESET path's states by compare-and-swap, a withdrawal wins over a later begin, and a second attach refuses.
#[test]
fn the_word_follows_the_reset_path_and_a_withdrawal_ends_it() {
    let word = Word::default();
    assert_eq!(word.state(), State::Detached);
    assert_eq!(word.apply(Event::Attach), Ok(State::Loading));
    assert_eq!(word.apply(Event::Attach), Err(ReadinessError::Invariant));
    assert_eq!(word.apply(Event::LoadComplete), Ok(State::Loaded));
    assert_eq!(word.apply(Event::Withdraw), Ok(State::Withheld));
    assert_eq!(
        word.apply(Event::BeginReplay {
            matches: true,
            rows: 0
        }),
        Err(ReadinessError::Ended(State::Withheld))
    );
    assert_eq!(word.state(), State::Withheld);
    let live = Word::default();
    live.apply(Event::Attach).unwrap();
    live.apply(Event::LoadComplete).unwrap();
    assert_eq!(
        live.apply(Event::BeginReplay {
            matches: true,
            rows: 0
        }),
        Ok(State::Live)
    );
    assert_eq!(live.state(), State::Live);
}

/// A begin racing a withdrawal from `Loaded` on two threads always ends `Withheld`: the begin either reached `Live` first, which the withdrawal then leaves, or found `Withheld` and changed nothing.
#[test]
fn a_begin_racing_a_withdrawal_always_ends_withheld() {
    for _ in 0..2000 {
        let word = std::sync::Arc::new(Word::default());
        word.apply(Event::Attach).unwrap();
        word.apply(Event::LoadComplete).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let racer = {
            let (word, barrier) = (word.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                let _ = word.apply(Event::BeginReplay {
                    matches: true,
                    rows: 0,
                });
            })
        };
        barrier.wait();
        assert!(word.apply(Event::Withdraw).is_ok());
        racer.join().unwrap();
        assert_eq!(word.state(), State::Withheld);
    }
}

#[test]
fn below_live_and_stops_metadata_hold_in_their_states_only() {
    for state in State::ALL_STATES {
        assert_eq!(
            state.below_live(),
            matches!(state, State::Loading | State::Loaded | State::Replaying),
            "{state:?}"
        );
        assert_eq!(
            state.stops_metadata(),
            matches!(state, State::Withheld),
            "{state:?}"
        );
    }
}

fn live(storage: &super::Storage<super::test_platform::TestPlatform>) {
    storage.readiness.apply(Event::LoadComplete).unwrap();
    storage
        .readiness
        .apply(Event::BeginReplay {
            matches: true,
            rows: 0,
        })
        .unwrap();
}

/// Storage admission stays open to isolate readiness-word refusals.
#[test]
fn a_direct_reservation_refuses_bootstrapping_below_live_and_closed_once_ended() {
    use super::ReserveError::{Bootstrapping, Closed};
    const BEGIN: Event = Event::BeginReplay {
        matches: true,
        rows: 0,
    };
    const REPLAY: Event = Event::BeginReplay {
        matches: true,
        rows: 3,
    };
    let paths: [(&[Event], State, Option<super::ReserveError>); 7] = [
        (&[Event::Attach], State::Loading, Some(Bootstrapping)),
        (
            &[Event::Attach, Event::LoadComplete],
            State::Loaded,
            Some(Bootstrapping),
        ),
        (
            &[Event::Attach, Event::LoadComplete, REPLAY],
            State::Replaying,
            Some(Bootstrapping),
        ),
        (
            &[Event::Attach, Event::LoadComplete, BEGIN],
            State::Live,
            None,
        ),
        (
            &[Event::Attach, Event::LoadComplete, BEGIN, Event::Withdraw],
            State::Withheld,
            Some(Closed),
        ),
        (
            &[Event::Attach, Event::Withhold],
            State::Withheld,
            Some(Closed),
        ),
        (&[Event::Attach, Event::Close], State::Closed, Some(Closed)),
    ];
    for (events, state, refusal) in paths {
        let storage = super::owner_fixture::storage(8);
        for event in events {
            storage.readiness.apply(*event).unwrap();
        }
        assert_eq!(storage.readiness.state(), state);
        let mut budget = super::budget::WorkBudget::new(1 << 20);
        let reserved = storage.reserve(Some(0), Some(100), &mut budget);
        assert!(!storage.is_closed(), "{state:?}");
        assert_eq!(reserved.err(), refusal, "{state:?}");
    }
}

#[test]
fn coverage_advances_only_between_begin_and_withdrawal() {
    use super::coverage::{Advance, CoverageError};
    let storage = super::owner_fixture::storage(8);
    storage.readiness.apply(Event::Attach).unwrap();
    assert_eq!(storage.advance_coverage(1), Err(CoverageError::NotReady));
    live(&storage);
    assert_eq!(storage.advance_coverage(1), Ok(Advance::Advanced));
    assert_eq!(storage.withdraw(), State::Withheld);
    assert!(!storage.is_closed());
    assert_eq!(storage.advance_coverage(2), Err(CoverageError::Closed));
}

#[test]
fn withdraw_waits_for_an_open_gate_hold() {
    let storage = super::owner_fixture::storage(8);
    storage.readiness.apply(Event::Attach).unwrap();
    live(&storage);
    let held = storage.live_pool().unwrap().lock().unwrap();
    std::thread::scope(|scope| {
        let waiter = scope.spawn(|| storage.withdraw());
        while storage.readiness.state() != State::Withheld {
            std::hint::spin_loop();
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(
            !waiter.is_finished(),
            "withdraw returned during a gate hold"
        );
        held.release();
        assert_eq!(waiter.join().unwrap(), State::Withheld);
    });
}

/// `withdraw` returns `Closed` when a close lands while the call waits for the gate.
#[test]
fn withdraw_returns_the_word_after_its_gate_pass() {
    let storage = super::owner_fixture::storage(8);
    storage.readiness.apply(Event::Attach).unwrap();
    live(&storage);
    let held = storage.live_pool().unwrap().lock().unwrap();
    std::thread::scope(|scope| {
        let waiter = scope.spawn(|| storage.withdraw());
        while storage.readiness.state() != State::Withheld {
            std::hint::spin_loop();
        }
        assert_eq!(storage.readiness.apply(Event::Close), Ok(State::Closed));
        held.release();
        assert_eq!(waiter.join().unwrap(), State::Closed);
    });
}

#[test]
fn recovering_authority_at_live_refuses_transiently_and_closed_overrides_withdrawn() {
    let word = super::readiness::Word::default();
    word.apply(super::readiness::Event::Attach).unwrap();
    word.set_authority(crate::failover::serving::State::Recovering, 1);
    word.apply(super::readiness::Event::LoadComplete).unwrap();
    word.apply(super::readiness::Event::BeginReplay {
        matches: true,
        rows: 0,
    })
    .unwrap();
    assert_eq!(
        word.fill_refusal(),
        Some(super::reserve::ReserveError::Bootstrapping)
    );
    word.set_authority(crate::failover::serving::State::Serving, 1);
    assert_eq!(word.fill_refusal(), None);
    word.set_authority(crate::failover::serving::State::Withdrawn, 1);
    assert_eq!(
        word.fill_refusal(),
        Some(super::reserve::ReserveError::Withdrawn)
    );
    assert!(word.authority_withdrawn());
    word.apply(super::readiness::Event::Close).unwrap();
    assert_eq!(
        word.fill_refusal(),
        Some(super::reserve::ReserveError::Closed)
    );
    assert!(word.authority_withdrawn(), "a close keeps the withdrawal");
}

/// An unattached `Detached` word admits fills. With `Withdrawn` authority it refuses fills with `Withdrawn`; with any other authority it refuses fills with `Bootstrapping` and awaits its gate. `initializing` holds exactly in `Detached` and `Loading`.
#[test]
fn an_attached_word_at_detached_refuses_fills_until_its_gate() {
    use crate::failover::serving::State as Serving;
    let unattached = Word::default();
    assert_eq!(unattached.fill_refusal(), None);
    assert_eq!(unattached.state_and_attach_gate(), (State::Detached, false));
    for (authority, refusal) in [
        (
            Serving::PreBoundary,
            super::reserve::ReserveError::Bootstrapping,
        ),
        (
            Serving::Serving,
            super::reserve::ReserveError::Bootstrapping,
        ),
        (
            Serving::Recovering,
            super::reserve::ReserveError::Bootstrapping,
        ),
        (Serving::Closed, super::reserve::ReserveError::Bootstrapping),
        (Serving::Withdrawn, super::reserve::ReserveError::Withdrawn),
    ] {
        let word = Word::default();
        word.set_authority(authority, 1);
        assert_eq!(
            word.state_and_attach_gate(),
            (State::Detached, true),
            "{authority:?}"
        );
        assert_eq!(word.fill_refusal(), Some(refusal), "{authority:?}");
        word.apply(Event::Attach).unwrap();
        assert_eq!(
            word.state_and_attach_gate(),
            (State::Loading, false),
            "{authority:?}"
        );
    }
    for state in State::ALL_STATES {
        assert_eq!(
            state.initializing(),
            matches!(state, State::Detached | State::Loading),
            "{state:?}"
        );
    }
}

/// Every production write of the readiness word, by source file and event: one `apply` per transition its owner
/// makes, so the `LoadComplete` writers are the RESET completion in `metadata.rs` and the warm bootstrap's commit in
/// `warm.rs`; the owner's attach, metadata and tick paths, the tick's unwind guard, and `Storage::withdraw` and
/// `try_withdraw` apply `Withdraw`. A call counts by its `readiness` receiver, or by a readiness `Event` literal argument
/// through any receiver, such as the unwind guard's alias; a variable argument through an alias is outside the scan.
/// Test files, loom models and test modules are skipped.
#[test]
fn every_production_readiness_word_writer_is_named() {
    let root = std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
    let mut found = Vec::new();
    let mut dirs = vec![root.clone()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if !name.ends_with(".rs") || name.ends_with("_tests.rs") || name.ends_with("_model.rs")
            {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let end = ["#[cfg(test)]\nmod ", "#[cfg(all(test, loom))]\nmod "]
                .iter()
                .filter_map(|marker| source.find(marker))
                .min()
                .unwrap_or(source.len());
            let flat: String = source[..end]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let file = path
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            // A call names the readiness word by its receiver, or by a readiness event literal through any alias.
            for pattern in [".apply(", "readiness.set_authority("] {
                for (at, _) in flat.match_indices(pattern) {
                    let argument = &flat[at + pattern.len()..];
                    let event = argument
                        .split(|c: char| !(c.is_alphanumeric() || c == ':' || c == '_'))
                        .next()
                        .unwrap();
                    let event = event.rsplit("readiness::").next().unwrap();
                    let receiver = flat[..at].ends_with(".readiness") || pattern != ".apply(";
                    if receiver || event.starts_with("Event::") {
                        found.push((file.clone(), event.to_string()));
                    }
                }
            }
        }
    }
    found.sort();
    let expected = [
        ("storage/volume/attach.rs", "Event::Close"),
        ("storage/volume/attach.rs", "Event::Withdraw"),
        ("storage/volume/authority.rs", "state"),
        ("storage/volume/fence.rs", "Event::Attach"),
        ("storage/volume/metadata.rs", "Event::LoadComplete"),
        ("storage/volume/metadata.rs", "Event::Withdraw"),
        ("storage/volume/metadata.rs", "event"),
        ("storage/volume/readiness.rs", "Event::BeginReplay"),
        ("storage/volume/readiness.rs", "Event::CompleteReplay"),
        ("storage/volume/readiness.rs", "Event::Withdraw"),
        ("storage/volume/readiness.rs", "Event::Withdraw"),
        ("storage/volume/tick.rs", "Event::Withdraw"),
        ("storage/volume/tick.rs", "Event::Withdraw"),
        ("storage/volume/tick.rs", "Event::Withdraw"),
        ("storage/volume/warm.rs", "Event::Close"),
        ("storage/volume/warm.rs", "Event::LoadComplete"),
    ];
    let expected: Vec<(String, String)> = expected
        .iter()
        .map(|(file, event)| (file.to_string(), event.to_string()))
        .collect();
    assert_eq!(found, expected);
}

/// The serving states whose authority `set_authority` writes as one code.
const INACTIVE: [Serving; 2] = [Serving::PreBoundary, Serving::Closed];
/// A matching replay that admits zero bindings, which takes a `Loaded` word to `Live`.
const REPLAY: Event = Event::BeginReplay {
    matches: true,
    rows: 0,
};

/// A word that reached `Live` through Attach, LoadComplete and a matching replay that admits zero bindings, with no
/// authority published.
fn live_word() -> Word {
    let word = Word::default();
    assert_eq!(word.apply(Event::Attach), Ok(State::Loading));
    assert_eq!(word.apply(Event::LoadComplete), Ok(State::Loaded));
    assert_eq!(word.apply(REPLAY), Ok(State::Live));
    word
}

/// A `Live` word refuses `Closed` once it holds the authority of `PreBoundary` or of `Closed`, whether it held no
/// authority or `Serving` before, and whether the authority came after `Live` or before the attach; the same word
/// under `Serving` admits the fill, so the refusal is the authority's.
#[test]
fn a_live_word_under_pre_boundary_or_closed_authority_refuses_closed() {
    let word = live_word();
    assert_eq!(word.fill_refusal(), None, "no authority published");
    for authority in INACTIVE {
        word.set_authority(authority, 1);
        assert_eq!(word.state(), State::Live, "{authority:?}");
        assert_eq!(
            word.fill_refusal(),
            Some(ReserveError::Closed),
            "{authority:?}"
        );
    }
    word.set_authority(Serving::Serving, 1);
    assert_eq!(word.fill_refusal(), None, "Serving at Live admits");
    for authority in INACTIVE {
        word.set_authority(authority, 2);
        assert_eq!(
            word.fill_refusal(),
            Some(ReserveError::Closed),
            "{authority:?} after Serving"
        );
        word.set_authority(Serving::Serving, 2);
        assert_eq!(word.fill_refusal(), None);
    }
    for authority in INACTIVE {
        let word = Word::default();
        word.set_authority(authority, 1);
        word.apply(Event::Attach).unwrap();
        word.apply(Event::LoadComplete).unwrap();
        assert_eq!(word.apply(REPLAY), Ok(State::Live));
        assert_eq!(
            word.fill_refusal(),
            Some(ReserveError::Closed),
            "{authority:?} published before the attach"
        );
    }
}

/// Each readiness state under each of the two authorities: the gate, the load and the replay refuse
/// `Bootstrapping`, and `Live`, `Withheld` and `Closed` refuse `Closed`; no state admits.
#[test]
fn no_readiness_state_admits_a_fill_under_pre_boundary_or_closed_authority() {
    use ReserveError::{Bootstrapping, Closed};
    for authority in INACTIVE {
        let word = Word::default();
        word.set_authority(authority, 1);
        let mut seen = vec![(word.state_and_attach_gate(), word.fill_refusal())];
        for event in [
            Event::Attach,
            Event::LoadComplete,
            Event::BeginReplay {
                matches: true,
                rows: 1,
            },
            Event::CompleteReplay,
            Event::Withdraw,
            Event::Close,
        ] {
            word.apply(event).unwrap();
            seen.push((word.state_and_attach_gate(), word.fill_refusal()));
        }
        assert_eq!(
            seen,
            [
                ((State::Detached, true), Some(Bootstrapping)),
                ((State::Loading, false), Some(Bootstrapping)),
                ((State::Loaded, false), Some(Bootstrapping)),
                ((State::Replaying, false), Some(Bootstrapping)),
                ((State::Live, false), Some(Closed)),
                ((State::Withheld, false), Some(Closed)),
                ((State::Closed, false), Some(Closed)),
            ],
            "{authority:?}"
        );
    }
}
