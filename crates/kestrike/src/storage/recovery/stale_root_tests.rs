//! The bootstrap decision refuses `StaleSession` when a valid root holds a generation at or above the session,
//! so the roots it writes stay the highest.
//!
//! Every test probes both root slots and hands the probes to `root::decide` under a tenure's session `s`, the
//! session of an acknowledged bump over the simulated store. A slot's probe is the root codec's decode of the
//! block a write left there, so a valid root is one the decoder accepts, and an invalid slot is the decode of a
//! zeroed block. The refusing tests place a root at `s` or above it in slot A, in slot B, beside an invalid
//! slot, beside a lower valid root and in both slots. The same probes with every valid root below `s`, `s - 1`
//! included, decide the RESET under `s`.

use crate::storage::record::Crc32c;

use super::MetadataOutcome;
use super::block::{FormatId, Layout, Undecodable};
use super::layout::Slot;
use super::root::{Decision, Probed, Root, decide, decode, encode};
use super::session::Session;
use super::session_tests::session_at;

const LAYOUT: Layout = Layout {
    unit: 4096,
    metadata_units: 2,
};
const FORMAT: FormatId = FormatId([0x5A; 16]);

/// What a slot holds before its probe: a zeroed block, or a root of `(generation, root sequence)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    Blank,
    Root(u64, u64),
}

/// The tenures every test decides under, as `(generation, attempts)` of the shard record before the bump: the first
/// session of generation 1, a later attempt of it, and a later generation.
const TENURES: [(u64, u32); 3] = [(1, 0), (1, 7), (4, 2)];

/// The probe of `slot` holding `held`: the decode of the encoded root, or of a zeroed block.
///
/// # Errors
///
/// The premise that failed to form: a written root that does not decode to itself, or a zeroed block that does not
/// decode `Invalid`.
fn probe(slot: Slot, held: Held) -> Result<Probed, String> {
    let crc = Crc32c::detect();
    let mut block = vec![0; LAYOUT.unit as usize];
    let Held::Root(generation, sequence) = held else {
        let decoded = decode(crc, LAYOUT, &block, slot);
        return match decoded {
            Err(Undecodable::Invalid) => Ok(Some(decoded)),
            other => Err(format!("premise: a zeroed slot {slot:?} decodes {other:?}")),
        };
    };
    let root = Root {
        sequence,
        ..Root::reset(
            generation,
            crate::storage::TEST_CLOCK.encode(),
            crate::storage::TEST_FEED.encode(),
        )
    };
    encode(crc, LAYOUT, FORMAT, &root, slot, &mut block);
    let decoded = decode(crc, LAYOUT, &block, slot);
    match &decoded {
        Ok((format, read)) if *format == FORMAT && *read == root => Ok(Some(decoded)),
        other => Err(format!(
            "premise: the root {held:?} written to slot {slot:?} decodes {other:?}"
        )),
    }
}

/// The decision over slots holding `a` and `b` under `session`.
fn decided(a: Held, b: Held, session: &Session) -> Result<Decision, String> {
    Ok(decide(&probe(Slot::A, a)?, &probe(Slot::B, b)?, session))
}

/// Every case of `cases(s)` whose decision under a tenure's session `s` differs from the one the case expects, one
/// line each, over every tenure of [`TENURES`]. The sessions and probes are dropped before the caller asserts.
fn failures(cases: impl Fn(u64) -> Vec<(Held, Held, Decision)>) -> Vec<String> {
    let mut failed = Vec::new();
    for (generation, attempts) in TENURES {
        let session = session_at(generation, attempts);
        let s = session.get();
        if s == u64::MAX || s < 3 {
            failed.push(format!(
                "premise: session {s} leaves no root above or below it"
            ));
            continue;
        }
        for (a, b, expected) in cases(s) {
            match decided(a, b, &session) {
                Ok(decision) if decision == expected => {}
                Ok(decision) => failed.push(format!(
                    "session {s}, slot A {a:?}, slot B {b:?}: decided {decision:?}, expected {expected:?}"
                )),
                Err(premise) => failed.push(premise),
            }
        }
    }
    failed
}

const STALE: Decision = Decision::Refused(MetadataOutcome::StaleSession);

fn reset(session: u64, first: Slot) -> Decision {
    Decision::Reset {
        format: FORMAT,
        session,
        first,
    }
}

/// The placements of the root `high` the refusing tests share: alone beside an invalid slot, beside each lower valid
/// root, and in both slots, with `high` in slot A and in slot B.
fn placements(high: Held, s: u64) -> Vec<(Held, Held, Decision)> {
    let mut cases = vec![(high, high, STALE)];
    for beside in [
        Held::Blank,
        Held::Root(s - 1, 0),
        Held::Root(s - 1, 9),
        Held::Root(1, 0),
    ] {
        cases.push((high, beside, STALE));
        cases.push((beside, high, STALE));
    }
    cases
}

/// A valid root whose generation equals the session refuses `StaleSession` wherever it lies: a RESET under `s` would
/// reissue the generation that root already holds.
#[test]
fn a_valid_root_at_the_session_refuses_stale_session() {
    let failed = failures(|s| {
        let mut cases = placements(Held::Root(s, 0), s);
        cases.extend(placements(Held::Root(s, 3), s));
        cases
    });
    assert!(failed.is_empty(), "{failed:#?}");
}

/// A valid root whose generation lies above the session, by one or at the largest generation, refuses `StaleSession`
/// wherever it lies, and so does a pair of roots at and above the session.
#[test]
fn a_valid_root_above_the_session_refuses_stale_session() {
    let failed = failures(|s| {
        let mut cases = placements(Held::Root(s + 1, 0), s);
        cases.extend(placements(Held::Root(s + 1, 3), s));
        cases.extend(placements(Held::Root(u64::MAX, 0), s));
        cases.push((Held::Root(s, 0), Held::Root(s + 1, 0), STALE));
        cases.push((Held::Root(s + 1, 0), Held::Root(s, 0), STALE));
        cases
    });
    assert!(failed.is_empty(), "{failed:#?}");
}

/// With every valid root below the session, `s - 1` included, the same probes decide the RESET under `s` and the
/// format the roots share, writing first to the slot without the highest root and to A when both slots hold one root.
#[test]
fn valid_roots_below_the_session_reset_under_the_session() {
    let failed = failures(|s| {
        let (near, later, low) = (Held::Root(s - 1, 0), Held::Root(s - 1, 9), Held::Root(1, 0));
        vec![
            (near, Held::Blank, reset(s, Slot::B)),
            (Held::Blank, near, reset(s, Slot::A)),
            (later, Held::Blank, reset(s, Slot::B)),
            (Held::Blank, later, reset(s, Slot::A)),
            (low, Held::Blank, reset(s, Slot::B)),
            (Held::Blank, low, reset(s, Slot::A)),
            (near, low, reset(s, Slot::B)),
            (low, near, reset(s, Slot::A)),
            (later, near, reset(s, Slot::B)),
            (near, later, reset(s, Slot::A)),
            (near, near, reset(s, Slot::A)),
            (later, later, reset(s, Slot::A)),
            (low, low, reset(s, Slot::A)),
        ]
    });
    assert!(failed.is_empty(), "{failed:#?}");
}

/// Over every pair of slots drawn from an invalid slot and roots around the session, a RESET is ordered only under a
/// generation above every valid root read, and a pair holding a valid root is refused `StaleSession` exactly when one
/// of its roots is at or above the session.
#[test]
fn every_reset_carries_a_generation_above_every_valid_root_read() {
    let mut failed = Vec::new();
    let mut resets = 0;
    let mut refusals = 0;
    for (generation, attempts) in TENURES {
        let session = session_at(generation, attempts);
        let s = session.get();
        let held = [
            Held::Blank,
            Held::Root(1, 0),
            Held::Root(s - 2, 0),
            Held::Root(s - 1, 0),
            Held::Root(s - 1, 9),
            Held::Root(s, 0),
            Held::Root(s, 9),
            Held::Root(s + 1, 0),
            Held::Root(u64::MAX, 0),
        ];
        for a in held {
            for b in held {
                if a == Held::Blank && b == Held::Blank {
                    continue;
                }
                let highest = [a, b]
                    .into_iter()
                    .filter_map(|held| match held {
                        Held::Blank => None,
                        Held::Root(generation, _) => Some(generation),
                    })
                    .max();
                let Some(highest) = highest else {
                    failed.push(format!("premise: {a:?} and {b:?} hold no root"));
                    continue;
                };
                let line = match decided(a, b, &session) {
                    Err(premise) => Some(premise),
                    Ok(Decision::Reset { session: under, .. }) => {
                        resets += 1;
                        (under != s || under <= highest).then(|| {
                            format!(
                                "session {s}, slot A {a:?}, slot B {b:?}: RESET under {under} over a valid root of generation {highest}"
                            )
                        })
                    }
                    Ok(STALE) => {
                        refusals += 1;
                        (highest < s).then(|| {
                            format!(
                                "session {s}, slot A {a:?}, slot B {b:?}: refused StaleSession with every valid root below the session"
                            )
                        })
                    }
                    Ok(other) => Some(format!(
                        "session {s}, slot A {a:?}, slot B {b:?}: decided {other:?}"
                    )),
                };
                failed.extend(line);
            }
        }
    }
    // Per tenure, 80 pairs hold a root: the 24 drawn from the invalid slot and the four roots below the session reset,
    // and the 56 with a root at or above it refuse.
    assert_eq!((resets, refusals), (72, 168), "{failed:#?}");
    assert!(failed.is_empty(), "{failed:#?}");
}
