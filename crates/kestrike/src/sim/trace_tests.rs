//! Bundle records, digest, checkpoints, capacity, failure evidence and the
//! terminal taxonomy.

use std::io::{self, Read, Write};

use crate::oracle::Obligation;

use super::choice_tests::{ROOT, launched, sequence};
use super::trace::{
    Capacity, Event, Field, Infrastructure, LoadError, Outcome, PAYLOAD, RECORD, Recorder,
    Terminal, Work, bit, load, read,
};

/// Record tags as the format codes them.
const FIELD: u8 = 2;
const TURN: u8 = 4;
const VIOLATION: u8 = 7;
const TERMINAL: u8 = 8;
const CHECKPOINT: u8 = 9;
const DIAGNOSTIC: u8 = 10;

const BOTH: u8 = 0b11;

fn capacity(records: u64) -> Capacity {
    Capacity::new(8, 4, records, 4).expect("a capacity")
}

fn pass() -> Terminal {
    Terminal::Complete {
        outcome: Outcome::Pass,
        fired: BOTH,
        required: BOTH,
    }
}

/// A recorded choice tape of `count` decision pairs from the pinned root.
fn tape(count: usize) -> Vec<u8> {
    let mut chooser = launched(ROOT);
    sequence(&mut chooser, count);
    chooser.finish().expect("a tape")
}

fn event(kind: u8, byte: u8) -> Event {
    let mut payload = [0; PAYLOAD];
    payload[0] = byte;
    Event { kind, payload }
}

const WORK: Work = Work {
    turns: 6,
    decisions: 6,
    progress: 3,
    virtual_us: 700,
    skipped_us: 100,
};

/// Records a small run into a bundle: fields, choices, turns, clock moves
/// and events, with `noise` as its diagnostic text, then `tamper`'s
/// records, and returns its terminal, digest and bytes.
fn recorded(
    noise: &str,
    tamper: impl FnOnce(&mut Recorder<Vec<u8>>),
) -> (Terminal, [u8; 32], Vec<u8>) {
    let mut recorder = Recorder::new(Vec::new(), capacity(10_000));
    recorder.field(Field::Manifest, b"version = 1\nprofile = upload\n");
    recorder.field(Field::Config, &[7; 64]);
    recorder.diagnostic(noise);
    recorder.choices(&tape(3));
    for turn in 0..6u64 {
        recorder.turn(turn * 100, &[turn as u8; 16], turn, &[0; 12]);
        recorder.event(&event(1, turn as u8));
    }
    recorder.clock(700);
    tamper(&mut recorder);
    let closed = recorder.finish(pass(), WORK);
    (closed.terminal, closed.digest, closed.sink)
}

fn plain() -> (Terminal, [u8; 32], Vec<u8>) {
    recorded("wall 1ms", |_| {})
}

/// Rewrites the record at `at` with `edit`.
fn edited(bytes: &[u8], at: usize, edit: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let mut out = bytes.to_vec();
    edit(&mut out[at * RECORD..(at + 1) * RECORD]);
    out
}

/// `bytes` without the record at `at`.
fn without(bytes: &[u8], at: usize) -> Vec<u8> {
    [&bytes[..at * RECORD], &bytes[(at + 1) * RECORD..]].concat()
}

fn tags(bytes: &[u8]) -> Vec<u8> {
    bytes.chunks(RECORD).map(|record| record[0]).collect()
}

/// The index of the first record tagged `tag`.
fn first(bytes: &[u8], tag: u8) -> usize {
    tags(bytes)
        .iter()
        .position(|&found| found == tag)
        .expect("a record of the tag")
}

/// A recorded bundle loads to the digest, terminal and work its recorder
/// closed with, its decisions, fields, choice tape and events, and its pass
/// counts.
#[test]
fn a_recorded_bundle_loads_to_its_digest_and_result() {
    let (terminal, digest, bytes) = plain();
    let loaded = load(&bytes, 10_000).unwrap();
    assert_eq!(loaded.digest, digest);
    assert_eq!(loaded.terminal, terminal);
    assert!(loaded.terminal.counts());
    assert_eq!(loaded.work, WORK);
    assert_eq!(loaded.decisions, 6);
    assert_eq!(loaded.tape, tape(3));
    assert_eq!(
        loaded.fields[0],
        (Field::Manifest, b"version = 1\nprofile = upload\n".to_vec())
    );
    assert_eq!(loaded.fields[1], (Field::Config, vec![7; 64]));
    assert_eq!(loaded.events.len(), 6);
    assert_eq!(loaded.violation, None);
}

/// Swapping two records or changing one payload byte changes the digest;
/// diagnostics, such as a timing or a Debug rendering, leave it unchanged.
#[test]
fn a_reorder_or_byte_change_alters_the_digest_and_diagnostics_do_not() {
    let (_, digest, _) = plain();
    let (_, noisy, _) = recorded("Some(Pass(Activations([1, 0, 0])))", |_| {});
    assert_eq!(noisy, digest, "a diagnostic leaves the digest");
    let (_, reordered, _) = recorded("wall 1ms", |recorder| {
        recorder.event(&event(1, 9));
        recorder.clock(800);
    });
    let (_, swapped, _) = recorded("wall 1ms", |recorder| {
        recorder.clock(800);
        recorder.event(&event(1, 9));
    });
    assert_ne!(reordered, swapped, "a reorder moves the digest");
    let (_, changed, _) = recorded("wall 1ms", |recorder| recorder.event(&event(1, 8)));
    let (_, original, _) = recorded("wall 1ms", |recorder| recorder.event(&event(1, 9)));
    assert_ne!(changed, original, "one payload byte moves the digest");
}

/// A changed byte of a semantic record or of a checkpoint makes a
/// checkpoint disagree and the load rejects the bundle; so does a
/// checkpoint removed where one is due, wherever it stood, and one added
/// where none is.
#[test]
fn checkpoints_reject_alterations_and_misplacement() {
    let (_, _, bytes) = plain();
    let turn = first(&bytes, TURN);
    let changed = edited(&bytes, turn, |record| record[10] ^= 1);
    assert!(matches!(
        load(&changed, 10_000),
        Err(LoadError::Checkpoint { .. })
    ));
    let checkpoint = first(&bytes, CHECKPOINT);
    for byte in [1, 2, 3, 4, 36, 4 + 40, RECORD - 1] {
        let altered = edited(&bytes, checkpoint, |record| record[byte] ^= 1);
        assert_eq!(
            load(&altered, 10_000),
            Err(LoadError::Checkpoint { at: checkpoint }),
            "byte {byte}"
        );
    }
    let last = tags(&bytes).len() - 1;
    let closing = edited(&bytes, last, |record| record[RECORD - 1] ^= 1);
    assert_eq!(
        load(&closing, 10_000),
        Err(LoadError::Checkpoint { at: last })
    );
    let stripped = without(&bytes, checkpoint);
    assert_eq!(
        load(&stripped, 10_000),
        Err(LoadError::Checkpoint { at: checkpoint })
    );
    let extra = [
        &bytes[..(checkpoint + 1) * RECORD],
        &bytes[checkpoint * RECORD..],
    ]
    .concat();
    assert_eq!(
        load(&extra, 10_000),
        Err(LoadError::Checkpoint { at: checkpoint + 1 })
    );
}

/// A terminal edited to a pass with its checkpoint removed, and a stream
/// cut anywhere before its terminal's checkpoint, a partial record
/// included, load as `Truncated` incomplete evidence that never counts; a
/// violation bundle so edited is rejected, its violation record beside a
/// pass.
#[test]
fn a_stream_cut_before_its_last_checkpoint_never_claims_success() {
    let failed = Terminal::Complete {
        outcome: Outcome::Inconclusive,
        fired: BOTH,
        required: BOTH,
    };
    let mut recorder = Recorder::new(Vec::new(), capacity(10_000));
    recorder.turn(0, &[0; 16], 0, &[0; 12]);
    let bytes = recorder.finish(failed, Work::default()).sink;
    let mut recorder = Recorder::new(Vec::new(), capacity(10_000));
    recorder.violation(&[1; PAYLOAD]);
    let violated = Terminal::Complete {
        outcome: Outcome::Violation,
        fired: BOTH,
        required: BOTH,
    };
    let evidence = recorder.finish(violated, Work::default()).sink;
    let at = first(&evidence, TERMINAL);
    let forged = edited(&evidence, at, |record| record[5] = Outcome::Pass as u8);
    let stripped = &forged[..forged.len() - RECORD];
    assert_eq!(load(stripped, 10_000), Err(LoadError::Violation { at }));
    let terminal = first(&bytes, TERMINAL);
    let promoted = edited(&bytes, terminal, |record| record[5] = Outcome::Pass as u8);
    let headless = &promoted[..promoted.len() - RECORD];
    let loaded = load(headless, 10_000).unwrap();
    assert_eq!(
        loaded.terminal,
        Terminal::Infrastructure(Infrastructure::Truncated)
    );
    assert!(!loaded.terminal.counts());
    for cut in 1..bytes.len() {
        let loaded = load(&bytes[..cut], 10_000).unwrap();
        assert_eq!(
            loaded.terminal,
            Terminal::Infrastructure(Infrastructure::Truncated),
            "cut at {cut}"
        );
    }
    let mut torn = bytes.clone();
    torn.extend_from_slice(&[1; 7]);
    assert_eq!(
        load(&torn, 10_000),
        Err(LoadError::Torn { len: torn.len() })
    );
}

/// Each malformed bundle rejects with its own error: more records than the
/// maximum, a chunk past its width, padding past a chunk or a choice, an
/// unknown tag or field, a terminal of an unknown class or code, another
/// version, a record after the terminal, a terminal whose decision count
/// differs, a choice in the reserved persistence domain, and a second
/// violation or a complete terminal other than a violation that carries
/// one.
#[test]
fn malformed_bundles_reject_with_their_own_errors() {
    let (_, _, bytes) = plain();
    let records = bytes.len() / RECORD;
    assert_eq!(
        load(&bytes, records as u64 - 1),
        Err(LoadError::TooMany {
            count: records,
            max: records as u64 - 1
        })
    );
    let field = first(&bytes, FIELD);
    let wide = edited(&bytes, field, |record| record[4] = PAYLOAD as u8);
    assert_eq!(load(&wide, 10_000), Err(LoadError::Oversized { at: field }));
    let padded = edited(&bytes, field, |record| record[RECORD - 1] = 1);
    assert_eq!(load(&padded, 10_000), Err(LoadError::Padding { at: field }));
    let diagnostic = first(&bytes, DIAGNOSTIC);
    for byte in [1, 2, 3] {
        let marked = edited(&bytes, diagnostic, |record| record[byte] = 1);
        assert_eq!(
            load(&marked, 10_000),
            Err(LoadError::Padding { at: diagnostic }),
            "byte {byte}"
        );
    }
    let unnamed = edited(&bytes, field, |record| record[1] = 99);
    assert_eq!(load(&unnamed, 10_000), Err(LoadError::Field { at: field }));
    let choice = first(&bytes, 3);
    let spilled = edited(&bytes, choice, |record| record[RECORD - 1] = 1);
    assert_eq!(
        load(&spilled, 10_000),
        Err(LoadError::Padding { at: choice })
    );
    let terminal = first(&bytes, TERMINAL);
    for byte in [4, 5] {
        let strange = edited(&bytes, terminal, |record| record[byte] = 9);
        assert_eq!(
            load(&strange, 10_000),
            Err(LoadError::Terminal { at: terminal })
        );
    }
    let unknown = edited(&bytes, 3, |record| record[0] = 0x7f);
    assert_eq!(
        load(&unknown, 10_000),
        Err(LoadError::Tag { at: 3, tag: 0x7f })
    );
    let version = edited(&bytes, 0, |record| record[4] = 2);
    assert_eq!(load(&version, 10_000), Err(LoadError::Version { at: 0 }));
    let rebegun = edited(&bytes, 3, |record| record.copy_from_slice(&bytes[..RECORD]));
    assert_eq!(load(&rebegun, 10_000), Err(LoadError::Version { at: 3 }));
    let mut late = bytes.clone();
    late.extend_from_slice(&bytes[terminal * RECORD..(terminal + 1) * RECORD]);
    assert_eq!(
        load(&late, 10_000),
        Err(LoadError::AfterTerminal { at: records })
    );
    let (_, _, miscounted) = recorded("wall 1ms", |recorder| recorder.choices(&tape(1)[..32]));
    assert_eq!(
        load(&miscounted, 10_000),
        Err(LoadError::Decisions {
            recorded: 6,
            counted: 7
        })
    );
    let (_, _, reserved) = recorded("wall 1ms", |recorder| {
        let mut identity = [0; 32];
        identity[0] = 1;
        identity[3] = super::choice::Domain::Persistence as u8;
        recorder.choices(&identity);
    });
    assert!(matches!(
        load(&reserved, 10_000),
        Err(LoadError::Reserved { .. })
    ));
    assert_eq!(
        load(&bytes[RECORD..], 10_000),
        Err(LoadError::Version { at: 0 })
    );
    let mut recorder = Recorder::new(Vec::new(), capacity(10_000));
    recorder.violation(&[1; PAYLOAD]);
    let violated = recorder.finish(pass(), Work::default()).sink;
    let at = first(&violated, TERMINAL);
    assert_eq!(load(&violated, 10_000), Err(LoadError::Violation { at }));
    let mut recorder = Recorder::new(Vec::new(), capacity(10_000));
    recorder.violation(&[1; PAYLOAD]);
    let unsuccessful = Terminal::Complete {
        outcome: Outcome::Unsuccessful,
        fired: BOTH,
        required: BOTH,
    };
    let mislabeled = recorder.finish(unsuccessful, Work::default()).sink;
    let at = first(&mislabeled, TERMINAL);
    assert_eq!(load(&mislabeled, 10_000), Err(LoadError::Violation { at }));
    let failed = Terminal::Complete {
        outcome: Outcome::Violation,
        fired: BOTH,
        required: BOTH,
    };
    let bare = Recorder::new(Vec::new(), capacity(10_000))
        .finish(failed, Work::default())
        .sink;
    let at = first(&bare, TERMINAL);
    assert_eq!(load(&bare, 10_000), Err(LoadError::Violation { at }));
    let violation = first(&violated, VIOLATION);
    let doubled = [
        &violated[..(violation + 2) * RECORD],
        &violated[violation * RECORD..],
    ]
    .concat();
    assert_eq!(
        load(&doubled, 10_000),
        Err(LoadError::Violation { at: violation + 2 })
    );
}

/// A sink that refuses writes past `limit` bytes, or every flush.
struct Failing {
    written: Vec<u8>,
    limit: usize,
    flushes: bool,
}

impl Write for Failing {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written.len() + buf.len() > self.limit {
            return Err(io::Error::other("sink full"));
        }
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.flushes {
            Ok(())
        } else {
            Err(io::Error::other("flush refused"))
        }
    }
}

/// A failed write or a failed final flush closes the recorder with a
/// `Sink` terminal; what reached the sink loads as `Truncated` incomplete
/// evidence or, with every record written, as the complete bundle.
#[test]
fn a_sink_failure_keeps_incomplete_evidence() {
    let sink = Failing {
        written: Vec::new(),
        limit: 8 * RECORD,
        flushes: true,
    };
    let mut recorder = Recorder::new(sink, capacity(10_000));
    for turn in 0..40u64 {
        recorder.turn(turn, &[0; 16], turn, &[0; 12]);
    }
    let closed = recorder.finish(pass(), Work::default());
    assert_eq!(
        closed.terminal,
        Terminal::Infrastructure(Infrastructure::Sink)
    );
    let loaded = load(&closed.sink.written, 10_000).unwrap();
    assert_eq!(
        loaded.terminal,
        Terminal::Infrastructure(Infrastructure::Truncated)
    );
    let unflushed = Failing {
        written: Vec::new(),
        limit: usize::MAX,
        flushes: false,
    };
    let closed = Recorder::new(unflushed, capacity(10_000)).finish(pass(), Work::default());
    assert_eq!(
        closed.terminal,
        Terminal::Infrastructure(Infrastructure::Sink)
    );
}

/// Past the record maximum the recorder takes no more records and closes
/// with a `Cap` terminal; with a full diagnostic ring and a violation
/// pushed after the cap, the bundle still fits the maximum and loads under
/// it with that terminal, which never counts. The pending buffer keeps its
/// allocation across a long run, and warm records allocate nothing.
#[test]
fn the_cap_keeps_incomplete_evidence_and_capacity_stays_fixed() {
    for every in [1, 4, 7] {
        let capped = Capacity::new(8, 4, 64, every).unwrap();
        let mut recorder = Recorder::new(Vec::with_capacity(1 << 16), capped);
        let reserved = recorder.pending_capacity();
        for turn in 0..10_000u64 {
            recorder.turn(turn, &[1; 16], turn, &[0; 12]);
            recorder.diagnostic("filling the ring");
        }
        recorder.violation(&[1; PAYLOAD]);
        assert_eq!(recorder.pending_capacity(), reserved);
        let closed = recorder.finish(pass(), Work::default());
        assert_eq!(
            closed.terminal,
            Terminal::Infrastructure(Infrastructure::Cap)
        );
        assert!(
            closed.sink.len() / RECORD <= 64,
            "every {every}: {}",
            closed.sink.len() / RECORD
        );
        let loaded = load(&closed.sink, 64).unwrap();
        assert_eq!(loaded.terminal, closed.terminal, "every {every}");
        assert!(!loaded.terminal.counts());
        assert_eq!(
            loaded.violation, None,
            "a violation after the cap records nothing"
        );
    }
    let mut kept = 0;
    for turns in 40..60u64 {
        let capped = Capacity::new(8, 4, 64, 4).unwrap();
        let mut recorder = Recorder::new(Vec::new(), capped);
        for turn in 0..turns {
            recorder.turn(turn, &[1; 16], turn, &[0; 12]);
            recorder.diagnostic("filling the ring");
        }
        recorder.violation(&[1; PAYLOAD]);
        let failed = Terminal::Complete {
            outcome: Outcome::Violation,
            fired: BOTH,
            required: BOTH,
        };
        let closed = recorder.finish(failed, Work::default());
        assert!(closed.sink.len() / RECORD <= 64, "{turns} turns");
        let loaded = load(&closed.sink, 64).unwrap();
        if loaded.terminal != Terminal::Infrastructure(Infrastructure::Cap) {
            assert_eq!(loaded.violation, Some([1; PAYLOAD]), "{turns} turns");
            kept += 1;
        }
    }
    assert!(
        kept > 0,
        "some turn count admits the violation below the cap"
    );
    let mut warm = Recorder::new(Vec::with_capacity(1 << 20), capacity(10_000));
    let reserved = warm.pending_capacity();
    for turn in 0..64u64 {
        warm.turn(turn, &[2; 16], turn, &[0; 12]);
        warm.diagnostic("warm");
    }
    let before = crate::instrument::allocations();
    for turn in 0..1_000u64 {
        warm.turn(turn, &[2; 16], turn, &[0; 12]);
        warm.event(&event(3, turn as u8));
        warm.diagnostic("warm");
    }
    assert_eq!(
        crate::instrument::allocations(),
        before,
        "warm records allocate nothing"
    );
    assert_eq!(warm.pending_capacity(), reserved);
}

/// Once the cap or a defect closes the recorder, the records the run keeps
/// emitting are dropped, so the prefix omits later evidence; the recorder
/// reports unflushed even after a flush empties the buffer.
#[test]
fn a_closed_recorder_is_never_flushed() {
    let mut recorder = Recorder::new(Vec::new(), capacity(10_000));
    recorder.turn(1, &[1; 16], 1, &[0; 12]);
    assert!(!recorder.flushed(), "a pending record");
    recorder.flush();
    assert!(recorder.flushed(), "open and empty");
    let (semantic, prefix) = recorder.prefix();

    let mut capped = Recorder::new(Vec::new(), Capacity::new(8, 4, 64, 4).unwrap());
    for turn in 0..10_000u64 {
        capped.turn(turn, &[1; 16], turn, &[0; 12]);
    }
    capped.flush();
    assert!(!capped.flushed(), "closed at the cap");
    assert!(
        capped.prefix().0 < 10_000,
        "the prefix stops where the cap closed the recorder"
    );
    assert_eq!(
        capped.finish(pass(), Work::default()).terminal,
        Terminal::Infrastructure(Infrastructure::Cap)
    );

    let mut defective = Recorder::new(Vec::new(), capacity(10_000));
    defective.turn(1, &[1; 16], 1, &[0; 12]);
    defective.enter();
    defective.turn(2, &[1; 16], 2, &[0; 12]);
    defective.flush();
    assert!(!defective.flushed(), "closed by a defect");
    assert_eq!(
        defective.prefix(),
        (semantic, prefix),
        "the prefix stops where the recorder closed"
    );
}

/// Capacities a recorder cannot honor are refused: a zero count, a record
/// maximum leaving no room beside the ring, and a pending buffer whose
/// bytes overflow.
/// A field past the chunk index's 65536 chunks closes the recorder at
/// its cap: the bundle keeps the chunks that fit and records incomplete
/// evidence.
#[test]
fn a_field_past_the_chunk_index_closes_at_the_cap() {
    let chunk = PAYLOAD - 1;
    let roomy = Capacity::new(8, 4, 1 << 20, 1 << 16).unwrap();
    let mut recorder = Recorder::new(Vec::new(), roomy);
    recorder.field(Field::Manifest, &vec![b'a'; chunk * ((1 << 16) + 1)]);
    recorder.turn(1, &[1; 16], 1, &[0; 12]);
    let closed = recorder.finish(pass(), Work::default());
    assert_eq!(
        closed.terminal,
        Terminal::Infrastructure(Infrastructure::Cap)
    );
    let loaded = load(&closed.sink, 1 << 20).unwrap();
    assert_eq!(loaded.terminal, closed.terminal);
    let [(Field::Manifest, bytes)] = loaded.fields.as_slice() else {
        panic!("one manifest field: {:?}", loaded.fields.len());
    };
    assert_eq!(bytes.len(), chunk << 16);
}

#[test]
fn capacities_without_room_are_refused() {
    assert!(Capacity::new(0, 4, 1_000, 4).is_none());
    assert!(Capacity::new(8, 0, 1_000, 4).is_none());
    assert!(Capacity::new(8, 4, 1_000, 0).is_none());
    assert!(Capacity::new(8, 4, 9, 4).is_none());
    assert!(Capacity::new(8, 4, 10, 4).is_some());
    assert!(Capacity::new(8, 4, 10, 1).is_none());
    for every in [1, 2] {
        let least = (10..20)
            .find(|&records| Capacity::new(8, 4, records, every).is_some())
            .unwrap();
        let mut recorder = Recorder::new(Vec::new(), Capacity::new(8, 4, least, every).unwrap());
        recorder.turn(0, &[0; 16], 0, &[0; 12]);
        let closed = recorder.finish(pass(), Work::default());
        assert_eq!(
            closed.terminal,
            pass(),
            "every {every}: the least maximum admits a record"
        );
        assert!(closed.sink.len() / RECORD <= least as usize);
    }
    assert!(Capacity::new(usize::MAX, 4, 1_000, 4).is_none());
}

/// A record pushed while an action runs closes the recorder as a harness
/// defect; the bundle loads with that terminal, which never counts, and
/// keeps a violation recorded before it.
#[test]
fn a_record_pushed_inside_an_action_is_a_defect() {
    let mut recorder = Recorder::new(Vec::new(), capacity(10_000));
    recorder.turn(0, &[0; 16], 0, &[0; 12]);
    recorder.enter();
    recorder.turn(1, &[0; 16], 1, &[0; 12]);
    recorder.leave();
    recorder.turn(2, &[0; 16], 2, &[0; 12]);
    let closed = recorder.finish(pass(), Work::default());
    assert_eq!(
        closed.terminal,
        Terminal::Infrastructure(Infrastructure::Defect)
    );
    let loaded = load(&closed.sink, 10_000).unwrap();
    assert_eq!(loaded.terminal, closed.terminal);
    assert_eq!(
        tags(&closed.sink)
            .iter()
            .filter(|&&tag| tag == TURN)
            .count(),
        1
    );
    let mut recorder = Recorder::new(Vec::new(), capacity(10_000));
    recorder.violation(&[1; PAYLOAD]);
    recorder.enter();
    recorder.turn(1, &[0; 16], 1, &[0; 12]);
    let kept = recorder.finish(pass(), Work::default()).sink;
    let loaded = load(&kept, 10_000).unwrap();
    assert_eq!(
        loaded.terminal,
        Terminal::Infrastructure(Infrastructure::Defect)
    );
    assert_eq!(
        loaded.violation,
        Some([1; PAYLOAD]),
        "a defect keeps its evidence"
    );
    assert!(!loaded.terminal.counts());
}

/// A sink whose bytes the test reads while the recorder holds it.
#[derive(Clone, Default)]
struct Shared(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);

impl Write for Shared {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The first violation record and its checkpoint reach the sink before any
/// later record is pushed, a violation on a checkpoint's cadence takes that
/// one checkpoint, and a later violation records nothing.
#[test]
fn the_first_violation_flushes_with_its_checkpoint() {
    for turns in 0..5u64 {
        let shared = Shared::default();
        let mut recorder = Recorder::new(shared.clone(), capacity(10_000));
        for turn in 0..turns {
            recorder.turn(turn, &[0; 16], turn, &[0; 12]);
        }
        let mut violation = [0; PAYLOAD];
        violation[0] = 1;
        recorder.violation(&violation);
        let flushed = tags(&shared.0.borrow());
        assert_eq!(
            flushed[flushed.len() - 2..],
            [VIOLATION, CHECKPOINT],
            "after {turns} turns"
        );
        let mut later = [0; PAYLOAD];
        later[0] = 2;
        recorder.violation(&later);
        recorder.turn(9, &[0; 16], 9, &[0; 12]);
        let failed = Terminal::Complete {
            outcome: Outcome::Violation,
            fired: BOTH,
            required: BOTH,
        };
        let closed = recorder.finish(failed, Work::default());
        let loaded = load(&shared.0.borrow(), 10_000).unwrap();
        assert_eq!(loaded.violation, Some(violation));
        assert_eq!(
            tags(&shared.0.borrow())
                .iter()
                .filter(|&&tag| tag == VIOLATION)
                .count(),
            1
        );
        assert!(!closed.terminal.counts());
    }
}

/// Only a complete pass whose every required obligation fired counts: a
/// pass missing one, a pass with nothing required, every other outcome and
/// every infrastructure class do not.
#[test]
fn only_a_complete_pass_with_every_obligation_fired_counts() {
    let required = bit(Obligation::Bytes) | bit(Obligation::History);
    let complete = |outcome, fired, required| Terminal::Complete {
        outcome,
        fired,
        required,
    };
    assert!(complete(Outcome::Pass, required, required).counts());
    assert!(!complete(Outcome::Pass, bit(Obligation::Bytes), required).counts());
    assert!(!complete(Outcome::Pass, required, 0).counts());
    for outcome in [
        Outcome::Violation,
        Outcome::Inconclusive,
        Outcome::Unsuccessful,
    ] {
        assert!(!complete(outcome, required, required).counts());
    }
    for class in [
        Infrastructure::Sink,
        Infrastructure::Cap,
        Infrastructure::Truncated,
        Infrastructure::Defect,
    ] {
        assert!(!Terminal::Infrastructure(class).counts());
    }
}

/// The diagnostic ring keeps its newest entries and drops the oldest past
/// its capacity, outside the digest.
#[test]
fn the_diagnostic_ring_is_lossy_by_declaration() {
    let mut recorder = Recorder::new(Vec::new(), capacity(10_000));
    for n in 0..10 {
        recorder.diagnostic(&format!("entry {n}"));
    }
    let bytes = recorder.finish(pass(), Work::default()).sink;
    let kept: Vec<String> = bytes
        .chunks(RECORD)
        .filter(|record| record[0] == DIAGNOSTIC)
        .map(|record| String::from_utf8_lossy(&record[5..5 + usize::from(record[4])]).into_owned())
        .collect();
    assert_eq!(kept, ["entry 6", "entry 7", "entry 8", "entry 9"]);
}

/// Reading a bundle of at most `max` records takes the whole of a source
/// within that size, and from a larger one only the first `max + 1`
/// records, which load as `TooMany`.
#[test]
fn a_bundle_read_stops_one_record_past_its_maximum() {
    let (_, _, bytes) = plain();
    let records = (bytes.len() / RECORD) as u64;
    assert_eq!(read(bytes.as_slice(), records).unwrap(), bytes);
    let mut torn = bytes.clone();
    torn.extend_from_slice(&[0; RECORD - 1]);
    assert_eq!(read(torn.as_slice(), records).unwrap(), torn);
    let mut source = io::repeat(1).take(64 << 20);
    let taken = read(&mut source, records).unwrap();
    assert_eq!(taken.len(), (records as usize + 1) * RECORD);
    assert_eq!(
        load(&taken, records),
        Err(LoadError::TooMany {
            count: records as usize + 1,
            max: records
        })
    );
}

/// A recorder dropped while its thread panics writes its pending records,
/// so the stream holds every record before the panic and loads as
/// truncated, while a recorder dropped without a panic writes nothing it
/// still holds.
#[test]
fn a_panic_writes_the_pending_records() {
    let mut sink = Vec::new();
    let panicked = super::unwind::caught(|| {
        let mut recorder = Recorder::new(&mut sink, capacity(10_000));
        recorder.field(Field::Manifest, b"version = 1\nprofile = upload\n");
        recorder.turn(0, &[1; 16], 0, &[0; 12]);
        panic!("a panic inside the run");
    });
    assert!(panicked.is_err());
    let loaded = load(&sink, u64::MAX).unwrap();
    assert_eq!(
        loaded.terminal,
        Terminal::Infrastructure(Infrastructure::Truncated)
    );
    assert_eq!(loaded.turns.len(), 1);
    let mut quiet = Vec::new();
    drop(Recorder::new(&mut quiet, capacity(10_000)));
    assert!(quiet.is_empty());
}
