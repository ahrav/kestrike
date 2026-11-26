//! Choice schema checks: pinned derivation vectors, stream isolation and
//! fresh-start reproduction, explicit replay failures before any effect,
//! harness defects, byte fills and PUT action descriptors.

use super::choice::{
    Candidate, ChoiceError, Chooser, Defect, Domain, Draw, EventKind, IDENTITY_LEN, Identity,
    Opens, PutAction, RECORD_LEN, Site, draws, opens,
};
use crate::storage::seeded::SplitMix64;

pub(crate) const ROOT: u64 = 0x0123_4567_89AB_CDEF;

pub(crate) const WORKLOAD: Site = Site {
    domain: Domain::Workload,
    actor: 0,
    site: 0,
};
pub(crate) const DISK: Site = Site {
    domain: Domain::Disk,
    actor: 1,
    site: 3,
};
pub(crate) const UPLOAD: Site = Site {
    domain: Domain::Put,
    actor: 2,
    site: 4,
};
pub(crate) const SUPPLIER: Site = Site {
    domain: Domain::Put,
    actor: 2,
    site: 5,
};
const PERSISTENCE: Site = Site {
    domain: Domain::Persistence,
    actor: 3,
    site: 0,
};

pub(crate) const TOPOLOGY: [Site; 5] = [WORKLOAD, DISK, UPLOAD, SUPPLIER, PERSISTENCE];

/// An identity's domain, actor, incarnation, site and occurrence.
type Named = (Domain, u16, u32, u16, u32);

/// A derivation vector: an identity, its seed and its first three draws.
type Vector = (Named, u64, [u64; 3]);

/// Seeds and first draws derived outside the crate with Python's `hashlib`
/// and a reference SplitMix64: SHA-256 over `b"image-cache cv1\0"`, the root
/// little-endian and the identity's canonical bytes, whose first eight bytes
/// little-endian seed the generator. Each row is the identity's domain,
/// actor, incarnation, site and occurrence, its seed and its first three
/// outputs.
pub(crate) const VECTORS: [Vector; 4] = [
    (
        (Domain::Workload, 0, 0, 0, 0),
        0x5774_D0D8_CB1D_68FE,
        [
            0x82E9_7B80_8373_77CD,
            0xCBDF_CBB0_BBDF_D257,
            0x48F2_618B_CCD5_C3E0,
        ],
    ),
    (
        (Domain::Workload, 0, 0, 0, 1),
        0xF80F_ABC8_B9EA_A1A5,
        [
            0x41C7_4973_5B99_B136,
            0x6503_3E63_9A77_5EC3,
            0x33A3_79F9_ECD7_838C,
        ],
    ),
    (
        (Domain::Disk, 1, 0, 3, 0),
        0x4DD5_540E_E4EB_3D58,
        [
            0x7628_9F97_2549_13B7,
            0x3674_0EC2_D3FC_D421,
            0x30AD_EECF_7519_1501,
        ],
    ),
    (
        (Domain::Put, 2, 1, 4, 0),
        0x6D44_AD03_ACA9_8438,
        [
            0x6BDD_5DE5_9125_FDC1,
            0xB21A_1B90_09A8_3C47,
            0x937B_A84A_CC7E_A9E2,
        ],
    ),
];

/// Whether every vector's seed and first draws match the pinned values.
pub(crate) fn vectors_hold() -> Result<(), String> {
    for ((domain, actor, incarnation, site, occurrence), seed, draws) in VECTORS {
        let identity = Identity {
            site: Site {
                domain,
                actor,
                site,
            },
            incarnation,
            occurrence,
        };
        let derived = identity.seed(ROOT);
        if derived != seed {
            return Err(format!("{identity:?}: seed {derived:#x}, pinned {seed:#x}"));
        }
        let mut stream = SplitMix64::new(derived);
        let first = [stream.next_u64(), stream.next_u64(), stream.next_u64()];
        if first != draws {
            return Err(format!("{identity:?}: draws {first:x?}, pinned {draws:x?}"));
        }
    }
    Ok(())
}

/// Ordered candidates `0..n` of the workload domain.
fn candidates(n: u8) -> Vec<Candidate> {
    (0..n)
        .map(|n| {
            let mut bytes = [0; 16];
            bytes[0] = Domain::Workload as u8;
            bytes[15] = n;
            Candidate(bytes)
        })
        .collect()
}

/// Actors of `TOPOLOGY`, numbered from 0.
const ACTORS: u16 = 4;

/// A recording chooser with every actor's first incarnation launched.
pub(crate) fn launched(root: u64) -> Chooser {
    first_incarnations(Chooser::record(root, &TOPOLOGY))
}

/// A chooser replaying `tape` with every actor's first incarnation
/// launched.
pub(crate) fn replaying(tape: Vec<u8>) -> Chooser {
    first_incarnations(Chooser::replay(&TOPOLOGY, tape))
}

fn first_incarnations(mut chooser: Chooser) -> Chooser {
    for actor in 0..ACTORS {
        chooser.launch(actor);
    }
    chooser
}

/// `sequence(&mut launched(ROOT), 4)`, derived outside the crate as the
/// vectors are: each workload index is the draw modulo 5, each disk value
/// the draw modulo 2^20.
pub(crate) const SEQUENCE: [u64; 8] = [4, 594_871, 2, 941_362, 1, 161_913, 0, 598_786];

/// Whether the chooser's sequence from `ROOT` equals the pinned one.
pub(crate) fn sequence_holds() -> Result<(), String> {
    let drawn = sequence(&mut launched(ROOT), 4);
    if drawn == SEQUENCE {
        Ok(())
    } else {
        Err(format!("{drawn:?}, pinned {SEQUENCE:?}"))
    }
}

/// `count` workload index draws and `count` disk bounded draws, interleaved.
pub(crate) fn sequence(chooser: &mut Chooser, count: usize) -> Vec<u64> {
    let set = candidates(5);
    (0..count)
        .flat_map(|_| {
            let index = chooser.index(WORKLOAD, 0, &set).expect("a draw") as u64;
            let bound = chooser.bounded(DISK, 0, 1 << 20).expect("a draw");
            [index, bound]
        })
        .collect()
}

#[test]
fn derivation_vectors_match_the_pinned_values() {
    assert_eq!(vectors_hold(), Ok(()));
    assert_eq!(sequence_holds(), Ok(()));
}

/// The records of one index decision over one candidate and of a five-byte
/// fill, assembled outside the crate from the layout: a tag byte, then the
/// identity, kind and size; each candidate; the selection and its bound;
/// and each entropy piece with its length, every record zero-padded to 32
/// bytes.
#[test]
fn records_hold_their_pinned_bytes() {
    let mut chooser = launched(ROOT);
    chooser.index(WORKLOAD, 0, &candidates(1)).expect("a draw");
    let mut fill = [0; 5];
    chooser.bytes(SUPPLIER, 0, &mut fill).expect("a fill");
    let tape = chooser.finish().expect("a tape");
    let pinned = [
        "0101000100000000000000000000000001010000000000000000000000000000",
        "0201000000000000000000000000000000000000000000000000000000000000",
        "0300000000000000000100000000000000000000000000000000000000000000",
        "0101000602000000000005000000000003050000000000000000000000000000",
        "0405e7e060381400000000000000000000000000000000000000000000000000",
    ];
    let records: Vec<String> = tape
        .chunks(RECORD_LEN)
        .map(|record| record.iter().map(|byte| format!("{byte:02x}")).collect())
        .collect();
    assert_eq!(records, pinned);
}

/// Two choosers from the same root make the same decisions, and a decision's
/// value is the first output of its identity's stream.
#[test]
fn a_fresh_start_reproduces_every_sequence() {
    let first = sequence(&mut launched(ROOT), 16);
    assert_eq!(sequence(&mut launched(ROOT), 16), first);
    assert_ne!(sequence(&mut launched(ROOT + 1), 16), first);
    let mut chooser = launched(ROOT);
    let value = chooser.bounded(DISK, 0, u64::MAX).expect("a draw");
    let identity = Identity {
        site: DISK,
        incarnation: 0,
        occurrence: 0,
    };
    assert_eq!(
        value,
        SplitMix64::new(identity.seed(ROOT)).next_u64() % u64::MAX
    );
}

/// An extra decision on one site leaves every other site's sequence as it
/// was, whatever the interleaving.
#[test]
fn one_extra_draw_leaves_other_streams_unchanged() {
    let disk = |extra: usize| {
        let mut chooser = launched(ROOT);
        let mut values = Vec::new();
        for step in 0..8 {
            if step == 3 {
                for _ in 0..extra {
                    chooser.index(WORKLOAD, 0, &candidates(3)).expect("a draw");
                }
            }
            values.push(chooser.bounded(DISK, 0, 1 << 30).expect("a draw"));
        }
        values
    };
    assert_eq!(disk(1), disk(0));
    assert_eq!(disk(5), disk(0));
}

/// A relaunch starts the actor's next incarnation, whose occurrences
/// restart and whose stream differs from the earlier incarnation's; a
/// decision for an incarnation the actor is not in is a harness defect.
#[test]
fn a_relaunch_starts_a_fresh_incarnation() {
    let mut chooser = launched(ROOT);
    let first = chooser.bounded(UPLOAD, 0, 1 << 40).expect("a draw");
    assert_eq!(chooser.launch(2), 1);
    let relaunched = chooser.bounded(UPLOAD, 1, 1 << 40).expect("a draw");
    assert_ne!(first, relaunched);
    assert_eq!(
        chooser.bounded(UPLOAD, 0, 1 << 40),
        Err(ChoiceError::HarnessDefect(Defect::Incarnation {
            actor: 2,
            incarnation: 0
        }))
    );
    let identity = Identity {
        site: UPLOAD,
        incarnation: 1,
        occurrence: 0,
    };
    assert_eq!(
        relaunched,
        SplitMix64::new(identity.seed(ROOT)).next_u64() % (1 << 40)
    );
}

/// Replay of a recorded tape makes the recorded decisions, steps every site
/// as the recording did and consumes the whole tape; a fill returns its
/// recorded bytes even where they differ from its stream's.
#[test]
fn a_recorded_tape_replays_every_decision() {
    let mut recorder = launched(ROOT);
    let recorded = sequence(&mut recorder, 6);
    let mut fill = [0; 40];
    recorder.bytes(SUPPLIER, 0, &mut fill).expect("a fill");
    let decisions = recorder.decisions();
    let mut tape = recorder.finish().expect("a tape");
    assert_eq!(tape.len() % RECORD_LEN, 0);
    let entropy = tape.len() - 2 * RECORD_LEN + 2;
    tape[entropy] ^= 0xFF;
    fill[0] ^= 0xFF;
    let mut replayer = replaying(tape);
    assert_eq!(sequence(&mut replayer, 6), recorded);
    let mut replayed = [0; 40];
    replayer.bytes(SUPPLIER, 0, &mut replayed).expect("a fill");
    assert_eq!(
        replayed, fill,
        "the recorded bytes replay, not the stream's"
    );
    assert_eq!(replayer.decisions(), decisions);
    assert!(replayer.finish().is_ok());
}

/// A replay that diverges to another root after k decisions keeps
/// counting identities from the prefix: its tape starts with the replayed
/// prefix, a strict replay of the whole tape checks every identity, and the
/// first decision after the divergence takes the value the new root
/// derives at the site's next occurrence, not at its first.
#[test]
fn a_divergence_keeps_counting_occurrences_from_the_prefix() {
    let mut recorder = launched(ROOT);
    let prefix = sequence(&mut recorder, 3);
    let tape = recorder.finish().expect("a tape");
    let other = ROOT ^ 0x5555;
    let mut branch = replaying(tape.clone());
    assert_eq!(sequence(&mut branch, 3), prefix);
    branch.diverge(other);
    let after = branch.bounded(DISK, 0, 1 << 20).expect("a draw");
    let derived = |occurrence| {
        let identity = Identity {
            site: DISK,
            incarnation: 0,
            occurrence,
        };
        SplitMix64::new(identity.seed(other)).below(1 << 20)
    };
    assert_eq!(after, derived(3));
    assert_ne!(after, derived(0));
    assert_eq!(branch.decisions(), 7);
    let diverged = branch.finish().expect("a tape");
    assert!(diverged.starts_with(&tape));
    let mut strict = replaying(diverged);
    assert_eq!(sequence(&mut strict, 3), prefix);
    assert_eq!(strict.bounded(DISK, 0, 1 << 20), Ok(after));
    assert!(strict.finish().is_ok());
}

/// A forced index is the next index decision's selection, recorded so a
/// strict replay reproduces it, and leaves every later decision derived; a
/// forced index outside the candidates is refused before any effect.
#[test]
fn a_forced_index_is_recorded_and_replays() {
    let set = candidates(5);
    let mut recorder = launched(ROOT);
    recorder.force(3);
    assert_eq!(recorder.index(WORKLOAD, 0, &set), Ok(3));
    let mut plain = launched(ROOT);
    plain.index(WORKLOAD, 0, &set).expect("a draw");
    assert_eq!(
        recorder.bounded(DISK, 0, 1 << 20),
        plain.bounded(DISK, 0, 1 << 20)
    );
    let tape = recorder.finish().expect("a tape");
    let mut replayer = replaying(tape);
    assert_eq!(replayer.index(WORKLOAD, 0, &set), Ok(3));
    let mut refused = launched(ROOT);
    refused.force(5);
    assert_eq!(
        refused.index(WORKLOAD, 0, &set),
        Err(ChoiceError::Index { index: 5, len: 5 })
    );
    assert_eq!(refused.decisions(), 0);
}

/// A fed chooser reads each value from its input in decision order: an
/// index takes one byte for at most 256 candidates, a bounded value the
/// bytes its bound needs, a fill its length; the tape it records replays
/// strictly; one input gives one tape; a decision past the input's end is
/// refused as short before its effect and consumes nothing.
#[test]
fn a_fed_chooser_reads_its_input_in_decision_order() {
    let fed = |input: Vec<u8>| first_incarnations(Chooser::fed(&TOPOLOGY, input));
    let set = candidates(5);
    let input = vec![7, 0x34, 0x12, 0x0f, 1, 2, 3];
    let mut chooser = fed(input.clone());
    assert_eq!(chooser.index(WORKLOAD, 0, &set), Ok(2));
    assert_eq!(chooser.bounded(DISK, 0, 1 << 20), Ok(0x0f_1234));
    let mut fill = [0; 3];
    chooser.bytes(SUPPLIER, 0, &mut fill).expect("a fill");
    assert_eq!(fill, [1, 2, 3]);
    assert_eq!(chooser.bounded(DISK, 0, 2), Err(ChoiceError::Short));
    assert_eq!(chooser.decisions(), 3);
    let tape = chooser.finish().expect("a tape");
    let mut again = fed(input);
    again.index(WORKLOAD, 0, &set).expect("a draw");
    again.bounded(DISK, 0, 1 << 20).expect("a draw");
    again.bytes(SUPPLIER, 0, &mut [0; 3]).expect("a fill");
    assert_eq!(again.finish().expect("a tape"), tape);
    let mut replayer = replaying(tape);
    assert_eq!(replayer.index(WORKLOAD, 0, &set), Ok(2));
    assert_eq!(replayer.bounded(DISK, 0, 1 << 20), Ok(0x0f_1234));
    let mut replayed = [0; 3];
    replayer.bytes(SUPPLIER, 0, &mut replayed).expect("a fill");
    assert_eq!(replayed, [1, 2, 3]);
    assert!(replayer.finish().is_ok());
    let mut short = fed(vec![1]);
    assert_eq!(
        short.bytes(SUPPLIER, 0, &mut [0; 2]),
        Err(ChoiceError::Short)
    );
    assert_eq!(short.index(WORKLOAD, 0, &set), Ok(1));
}

/// The decisions of `chooser`, whose every actor is launched: an index
/// among one candidate, values below `bounds` in order, a forced index
/// among five, forced to 3 when `force` holds, and fills of 0, 30, 61 and
/// 70,000 bytes; returns the tape and every value drawn.
fn decide(mut chooser: Chooser, bounds: &[u64], force: bool) -> (Vec<u8>, Vec<u64>, Vec<Vec<u8>>) {
    let mut values = vec![chooser.index(WORKLOAD, 0, &candidates(1)).unwrap() as u64];
    for &bound in bounds {
        values.push(chooser.bounded(DISK, 0, bound).unwrap());
    }
    if force {
        chooser.force(3);
    }
    values.push(chooser.index(WORKLOAD, 0, &candidates(5)).unwrap() as u64);
    let fills = [0, 30, 61, 70_000].map(|len| {
        let mut fill = vec![0; len];
        chooser.bytes(SUPPLIER, 0, &mut fill).unwrap();
        fill
    });
    (chooser.finish().unwrap(), values, fills.to_vec())
}

/// A recorded tape splits into one draw per decision: a selection in the
/// fewest little-endian bytes that hold its bound less one, one byte for a
/// bound of 1 and at each width's edge, a forced index as a derived one,
/// and a fill's pieces joined, past 64 KiB whole. A fed chooser reading
/// those bytes, forcing nothing and ignoring zeros past them, records the
/// same tape. The same bytes under bounds that
/// changed width record a tape whose draws split by the new bounds, and a
/// tape cut inside a decision, with a selection past its bound, nonzero
/// padding or an unknown record, splits into none.
#[test]
fn a_recorded_tape_splits_into_the_draws_a_fed_chooser_reads() {
    const BOUNDS: [u64; 7] = [1, 256, 257, 65_536, 65_537, 1 << 32, u64::MAX];
    let (tape, values, fills) = decide(launched(ROOT), &BOUNDS, true);
    let split = draws(&tape).expect("a recorded tape splits");
    let widths: Vec<usize> = split.iter().map(|draw| draw.bytes.len()).collect();
    assert_eq!(widths, [1, 1, 1, 2, 2, 3, 4, 8, 1, 0, 30, 61, 70_000]);
    assert_eq!(split[8].bytes, [3], "the forced index converts as drawn");
    for (draw, value) in split.iter().zip(&values) {
        let mut word = [0; 8];
        word[..draw.bytes.len()].copy_from_slice(&draw.bytes);
        assert_eq!((u64::from_le_bytes(word), draw.fill), (*value, false));
    }
    for (draw, fill) in split[9..].iter().zip(&fills) {
        assert_eq!((&draw.bytes, draw.fill), (fill, true));
    }
    let input: Vec<u8> = split.iter().flat_map(|draw| &draw.bytes).copied().collect();
    assert!(input.len() > 65_536);
    let fed = |bounds: &[u64]| {
        decide(
            first_incarnations(Chooser::fed(&TOPOLOGY, [&input[..], &[0; 8]].concat())),
            bounds,
            false,
        )
    };
    assert_eq!(fed(&BOUNDS), (tape.clone(), values.clone(), fills.clone()));
    let wider = [1, 257, 257, 65_536, 65_537, 1 << 32, u64::MAX];
    let (resplit, ..) = fed(&wider);
    let draws_of = |tape: &[u8]| draws(tape).expect("a fed tape splits");
    assert_eq!(
        draws_of(&resplit)[2].bytes.len(),
        2,
        "the widened bound reads two bytes"
    );
    let again: Vec<u8> = draws_of(&resplit)
        .iter()
        .flat_map(|draw| &draw.bytes)
        .copied()
        .collect();
    assert_eq!(
        fed(&wider).0,
        decide(
            first_incarnations(Chooser::fed(&TOPOLOGY, again)),
            &wider,
            false
        )
        .0
    );
    assert_eq!(draws(&tape[..tape.len() - RECORD_LEN]), None);
    assert_eq!(draws(&tape[..tape.len() - 1]), None);
    let mut past = tape.clone();
    let selection = 2 * RECORD_LEN;
    past[selection + 1..selection + 9].copy_from_slice(&5u64.to_le_bytes());
    assert_eq!(draws(&past), None, "a selection past its bound");
    let mut padded = tape.clone();
    padded[selection + 20] = 1;
    assert_eq!(draws(&padded), None, "nonzero padding after a selection");
    let mut unknown = tape.clone();
    unknown[0] = 9;
    assert_eq!(draws(&unknown), None);
    assert_eq!(draws(&[]), Some(Vec::<Draw>::new()));
    // Each refusal edits one record the recorder wrote, found by tag: an
    // identity at 1, a selection at 3 and an entropy piece at 4.
    let tape = &tape[..];
    let records = |tag: u8| {
        (0..tape.len() / RECORD_LEN)
            .map(|at| at * RECORD_LEN)
            .filter(move |&at| tape[at] == tag)
    };
    let refused = |at: usize, edit: &dyn Fn(&mut [u8])| {
        let mut edited = tape.to_vec();
        edit(&mut edited[at..at + RECORD_LEN]);
        draws(&edited)
    };
    let selection = records(3).next().unwrap();
    let at_bound = |record: &mut [u8]| {
        let bound: [u8; 8] = record[9..17].try_into().unwrap();
        record[1..9].copy_from_slice(&bound);
    };
    assert_eq!(
        refused(selection, &at_bound),
        None,
        "a value equal to its bound"
    );
    let kind = 1 + IDENTITY_LEN;
    let of_kind = |code: u8| records(1).find(|&at| tape[at + kind] == code).unwrap();
    let sized = |record: &mut [u8]| record[kind + 1] = 1;
    assert_eq!(
        refused(of_kind(2), &sized),
        None,
        "a bounded identity with a size"
    );
    assert_eq!(
        refused(of_kind(2), &|record| record[kind] = 9),
        None,
        "an unknown kind"
    );
    let index = of_kind(1);
    let after = (index..tape.len())
        .step_by(RECORD_LEN)
        .find(|&at| tape[at] == 3)
        .unwrap();
    let wider = |record: &mut [u8]| {
        let bound = u64::from_le_bytes(record[9..17].try_into().unwrap());
        record[9..17].copy_from_slice(&(bound + 1).to_le_bytes());
    };
    assert_eq!(
        refused(after, &wider),
        None,
        "an index bound past its candidates"
    );
    let short = records(4)
        .find(|&at| usize::from(tape[at + 1]) < 30)
        .unwrap();
    let width = usize::from(tape[short + 1]);
    let padding = |record: &mut [u8]| record[2 + width] = 1;
    assert_eq!(
        refused(short, &padding),
        None,
        "nonzero padding after a short piece"
    );
    let full = records(4).find(|&at| tape[at + 1] == 30).unwrap();
    for length in [29, 31] {
        let split = |record: &mut [u8]| record[1] = length;
        assert_eq!(refused(full, &split), None, "a piece of {length} bytes");
    }
}

/// A replay whose decision runs `effect` only on success: short input, a
/// different candidate set and an index outside the set each fail by their
/// own error without running the effect, and trailing input fails at
/// `finish` after the last decision.
#[test]
fn malformed_replays_fail_explicitly_before_any_effect() {
    let mut recorder = launched(ROOT);
    let set = candidates(4);
    recorder.index(WORKLOAD, 0, &set).expect("a draw");
    let tape = recorder.finish().expect("a tape");
    let replay = |tape: Vec<u8>, set: &[Candidate]| {
        let mut chooser = replaying(tape);
        let mut effects = 0;
        let result = chooser.index(WORKLOAD, 0, set).inspect(|_| effects += 1);
        if result.is_err() {
            assert_eq!(chooser.decisions(), 0, "a failed decision counts nothing");
        }
        (result, effects, chooser)
    };
    let (short, effects, _) = replay(tape[..tape.len() - 1].to_vec(), &set);
    assert_eq!((short, effects), (Err(ChoiceError::Short), 0));
    let (changed, effects, mut chooser) = replay(tape.clone(), &candidates(3));
    assert_eq!((changed, effects), (Err(ChoiceError::Candidates), 0));
    assert!(
        chooser.index(WORKLOAD, 0, &set).is_ok(),
        "the failed decision consumed no record"
    );
    let mut elsewhere = replaying(tape.clone());
    assert_eq!(
        elsewhere.bounded(DISK, 0, 4),
        Err(ChoiceError::Identity),
        "another site's decision"
    );
    let mut swapped = set.clone();
    swapped[3].0[15] = 9;
    let (differs, effects, _) = replay(tape.clone(), &swapped);
    assert_eq!((differs, effects), (Err(ChoiceError::Candidates), 0));
    let mut outside = tape.clone();
    let selection = outside.len() - RECORD_LEN;
    outside[selection + 1..selection + 9].copy_from_slice(&7u64.to_le_bytes());
    let (invalid, effects, _) = replay(outside, &set);
    assert_eq!(
        (invalid, effects),
        (Err(ChoiceError::Index { index: 7, len: 4 }), 0)
    );
    let mut recorder = launched(ROOT);
    recorder.bounded(DISK, 0, 8).expect("a draw");
    let mut over = recorder.finish().expect("a tape");
    let selection = over.len() - RECORD_LEN;
    over[selection + 1..selection + 9].copy_from_slice(&8u64.to_le_bytes());
    assert_eq!(
        replaying(over).bounded(DISK, 0, 8),
        Err(ChoiceError::Index { index: 8, len: 8 })
    );
    let mut longer = tape.clone();
    longer.extend_from_slice(&tape[..RECORD_LEN]);
    let (accepted, effects, chooser) = replay(longer, &set);
    assert!(accepted.is_ok() && effects == 1);
    assert_eq!(
        chooser.finish(),
        Err(ChoiceError::Trailing { bytes: RECORD_LEN })
    );
}

/// A site the topology never registered, the reserved persistence and crash
/// domain, the reserved crash event, unordered or repeated candidates and an
/// empty choice are harness defects.
#[test]
fn harness_defects_are_named() {
    let mut chooser = launched(ROOT);
    let stray = Site {
        site: 9,
        ..WORKLOAD
    };
    assert_eq!(
        chooser.bounded(stray, 0, 2),
        Err(ChoiceError::HarnessDefect(Defect::Unregistered(stray)))
    );
    assert_eq!(
        chooser.bounded(PERSISTENCE, 0, 2),
        Err(ChoiceError::HarnessDefect(Defect::ReservedDomain))
    );
    assert_eq!(
        EventKind::Crash.admit(None),
        Err(ChoiceError::HarnessDefect(Defect::ReservedEvent))
    );
    assert_eq!(EventKind::Delivery.admit(None), Ok(EventKind::Delivery));
    let mut reversed = candidates(3);
    reversed.reverse();
    assert_eq!(
        chooser.index(WORKLOAD, 0, &reversed),
        Err(ChoiceError::HarnessDefect(Defect::Unordered))
    );
    let repeated = [candidates(1)[0], candidates(1)[0]];
    assert_eq!(
        chooser.index(WORKLOAD, 0, &repeated),
        Err(ChoiceError::HarnessDefect(Defect::Unordered))
    );
    assert_eq!(
        chooser.index(WORKLOAD, 0, &[]),
        Err(ChoiceError::HarnessDefect(Defect::Empty))
    );
    assert_eq!(
        chooser.bounded(WORKLOAD, 0, 0),
        Err(ChoiceError::HarnessDefect(Defect::Empty))
    );
    assert_eq!(chooser.decisions(), 0, "no defect made a decision");
}

/// A registry of hundreds of scattered sites, some registered twice,
/// decides at each site with that site's own occurrence count, restarts
/// only the relaunched actor's sites, and refuses every unregistered site.
/// The 600 scattered keys fill a 2048-entry index, where 102 of them sit
/// past their first probe entry. Each decision's value is the one its
/// identity derives.
#[test]
fn a_large_registry_finds_every_site_and_refuses_the_rest() {
    let domains = [Domain::Workload, Domain::Disk, Domain::Link, Domain::Put];
    let mut stream = SplitMix64::new(ROOT);
    let mut scattered = |actors: u64| Site {
        domain: domains[stream.below(4) as usize],
        actor: stream.below(actors) as u16,
        site: stream.below(1 << 16) as u16,
    };
    let mut sites: Vec<Site> = (0..600).map(|_| scattered(24)).collect();
    let strays: Vec<Site> = (0..600)
        .map(|_| scattered(24))
        .filter(|stray| !sites.contains(stray))
        .collect();
    let mut registered = sites.clone();
    registered.extend_from_slice(&sites[..100]);
    sites.sort();
    sites.dedup();
    let mut chooser = Chooser::record(ROOT, &registered);
    assert_eq!(chooser.displaced(), 102);
    for actor in 0..24 {
        assert_eq!(chooser.launch(actor), 0);
    }
    let derived = |site, incarnation, occurrence| {
        let identity = Identity {
            site,
            incarnation,
            occurrence,
        };
        SplitMix64::new(identity.seed(ROOT)).below(1 << 40)
    };
    for occurrence in 0..2 {
        for &site in &sites {
            let drawn = chooser.bounded(site, 0, 1 << 40);
            assert_eq!(drawn, Ok(derived(site, 0, occurrence)), "{site:?}");
        }
    }
    assert_eq!(chooser.launch(7), 1);
    for &site in &sites {
        let (incarnation, occurrence) = if site.actor == 7 { (1, 0) } else { (0, 2) };
        let drawn = chooser.bounded(site, incarnation, 1 << 40);
        assert_eq!(
            drawn,
            Ok(derived(site, incarnation, occurrence)),
            "{site:?}"
        );
    }
    let decisions = chooser.decisions();
    assert!(strays.len() > 500);
    for stray in strays {
        assert_eq!(
            chooser.bounded(stray, 0, 2),
            Err(ChoiceError::HarnessDefect(Defect::Unregistered(stray)))
        );
    }
    assert_eq!(chooser.decisions(), decisions, "no refusal made a decision");
}

/// Every domain but the reserved persistence and crash domain decides at a
/// registered site, and every event kind but the reserved crash kind is
/// admitted.
#[test]
fn only_the_reserved_domain_and_event_kind_are_refused() {
    use Domain::{Chaos, Clock, Disk, Entropy, Link, Persistence, Put, Workload};
    let domains = [
        Workload,
        Disk,
        Link,
        Clock,
        Entropy,
        Put,
        Persistence,
        Chaos,
    ];
    let sites: Vec<Site> = domains
        .iter()
        .map(|&domain| Site {
            domain,
            actor: 0,
            site: domain as u16,
        })
        .collect();
    let mut chooser = Chooser::record(ROOT, &sites);
    chooser.launch(0);
    for site in sites {
        let decided = chooser.bounded(site, 0, 4);
        if site.domain == Persistence {
            assert_eq!(
                decided,
                Err(ChoiceError::HarnessDefect(Defect::ReservedDomain))
            );
        } else {
            assert!(decided.is_ok(), "{site:?}");
        }
    }
    use EventKind::{Action, Advance, Completion, Crash, Delivery, Release};
    for kind in [Action, Delivery, Completion, Release, Advance] {
        assert_eq!(kind.admit(None), Ok(kind));
    }
    assert_eq!(
        Crash.admit(None),
        Err(ChoiceError::HarnessDefect(Defect::ReservedEvent))
    );
}

/// Candidates gathered in a hash container's iteration order are refused
/// until sorted into their total order.
#[test]
fn a_candidate_set_in_hash_order_is_refused() {
    let all = candidates(32);
    let runnable: std::collections::HashSet<usize> = (0..all.len()).collect();
    let hashed: Vec<Candidate> = runnable.into_iter().map(|n| all[n]).collect();
    assert!(
        hashed.windows(2).any(|pair| pair[0] > pair[1]),
        "hash order"
    );
    let mut chooser = launched(ROOT);
    assert_eq!(
        chooser.index(WORKLOAD, 0, &hashed),
        Err(ChoiceError::HarnessDefect(Defect::Unordered))
    );
    let mut sorted = hashed;
    sorted.sort();
    assert!(chooser.index(WORKLOAD, 0, &sorted).is_ok());
}

/// A byte fill is one decision: it advances only its own site, its bytes
/// come from its identity's stream, and replay returns them verbatim.
#[test]
fn a_byte_fill_is_one_recorded_decision() {
    let mut chooser = launched(ROOT);
    let mut fill = [0; 13];
    chooser.bytes(SUPPLIER, 0, &mut fill).expect("a fill");
    assert_eq!(chooser.decisions(), 1);
    let identity = Identity {
        site: SUPPLIER,
        incarnation: 0,
        occurrence: 0,
    };
    let mut stream = SplitMix64::new(identity.seed(ROOT));
    let words = [stream.next_u64(), stream.next_u64()];
    let expected: Vec<u8> = words
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .take(13)
        .collect();
    assert_eq!(fill.to_vec(), expected);
    let mut next = [0; 13];
    chooser.bytes(SUPPLIER, 0, &mut next).expect("a fill");
    assert_ne!(next, fill, "the second fill is the site's next occurrence");
    let undisturbed = launched(ROOT).bounded(DISK, 0, 1 << 30);
    assert_eq!(chooser.bounded(DISK, 0, 1 << 30), undisturbed);
}

/// PUT actions are canonical descriptors in a total order. A different
/// fragment choice changes only the supplier's stream, a different
/// supplier readiness changes only the upload decision's candidate bytes,
/// and replay refuses that changed PUT candidate set before effect.
#[test]
fn put_actions_are_canonical_and_their_choices_stay_in_their_stream() {
    let actions = |ready_us: u32| {
        let mut set: Vec<Candidate> = [
            PutAction::Begin { key: 7, attempt: 1 },
            PutAction::Prepare { key: 7, attempt: 1 },
            PutAction::Supply {
                key: 7,
                attempt: 1,
                fragment: 0,
            },
            PutAction::Defer {
                key: 7,
                attempt: 1,
                ready_us,
            },
            PutAction::Cancel { key: 7, attempt: 1 },
            PutAction::Abandon { key: 7, attempt: 1 },
            PutAction::Outcome { key: 7, attempt: 1 },
            PutAction::Retry { key: 7, attempt: 1 },
        ]
        .map(PutAction::candidate)
        .to_vec();
        set.sort();
        set
    };
    let run = |ready_us: u32, fragments: u64| {
        let mut chooser = launched(ROOT);
        let upload = chooser
            .index(UPLOAD, 0, &actions(ready_us))
            .expect("a draw");
        let supply = chooser.bounded(SUPPLIER, 0, fragments).expect("a draw");
        let workload = chooser.bounded(WORKLOAD, 0, 1 << 30).expect("a draw");
        (upload, supply, workload, chooser.finish().expect("a tape"))
    };
    let supplier = |fragments: u64| {
        let identity = Identity {
            site: SUPPLIER,
            incarnation: 0,
            occurrence: 0,
        };
        SplitMix64::new(identity.seed(ROOT)).next_u64() % fragments
    };
    let (upload, supply, workload, tape) = run(500, 4);
    assert_eq!(supply, supplier(4));
    let (other_upload, other_supply, other_workload, _) = run(900, 4);
    assert_eq!(
        (other_upload, other_supply, other_workload),
        (upload, supply, workload),
        "a readiness changes candidate bytes only"
    );
    let (fragment_upload, fragment_supply, fragment_workload, _) = run(500, 9);
    assert_eq!(
        fragment_supply,
        supplier(9),
        "the supplier's stream decides"
    );
    assert_eq!((fragment_upload, fragment_workload), (upload, workload));
    let mut replayer = replaying(tape);
    assert_eq!(
        replayer.index(UPLOAD, 0, &actions(900)),
        Err(ChoiceError::Candidates)
    );
}

/// A fill replayed at another length, a tape cut inside its entropy, a
/// changed entropy length byte, a bounded decision replayed under another
/// bound and a nonzero padding byte in any record each fail before any
/// effect, and a correct decision still replays after a wrong fill length
/// or bound.
#[test]
fn changed_fills_bounds_and_padding_fail_before_any_effect() {
    let mut recorder = launched(ROOT);
    let mut fill = [0; 40];
    recorder.bytes(SUPPLIER, 0, &mut fill).expect("a fill");
    recorder.bounded(DISK, 0, 8).expect("a draw");
    recorder.index(WORKLOAD, 0, &candidates(2)).expect("a draw");
    let tape = recorder.finish().expect("a tape");
    for len in [41, 70, 39] {
        let mut chooser = replaying(tape.clone());
        let mut out = vec![0; len];
        assert_eq!(
            chooser.bytes(SUPPLIER, 0, &mut out),
            Err(ChoiceError::Identity),
            "{len}"
        );
        assert!(out.iter().all(|&byte| byte == 0) && chooser.decisions() == 0);
        let mut again = [0; 40];
        assert_eq!(chooser.bytes(SUPPLIER, 0, &mut again), Ok(()));
        assert_eq!(again, fill);
    }
    let mut cut = replaying(tape[..2 * RECORD_LEN + 7].to_vec());
    let mut out = [0; 40];
    assert_eq!(cut.bytes(SUPPLIER, 0, &mut out), Err(ChoiceError::Short));
    assert_eq!(out, [0; 40]);
    for (record, length) in [(1, 29u8), (2, 9), (2, 11), (2, 0)] {
        let mut tampered = tape.clone();
        tampered[record * RECORD_LEN + 1] = length;
        let mut chooser = replaying(tampered);
        let mut out = [0; 40];
        assert_eq!(
            chooser.bytes(SUPPLIER, 0, &mut out),
            Err(ChoiceError::Identity),
            "record {record} length {length}"
        );
        assert_eq!((out, chooser.decisions()), ([0; 40], 0));
    }
    let mut wider = replaying(tape.clone());
    wider.bytes(SUPPLIER, 0, &mut out).expect("a fill");
    assert_eq!(wider.bounded(DISK, 0, 1000), Err(ChoiceError::Identity));
    assert!(wider.bounded(DISK, 0, 8).is_ok());
    // Record 1, the fill's first entropy record, carries 30 bytes and no
    // padding.
    let records = tape.len() / RECORD_LEN;
    for record in (0..records).filter(|&record| record != 1) {
        let mut padded = tape.clone();
        padded[(record + 1) * RECORD_LEN - 1] = 1;
        let mut chooser = replaying(padded);
        let mut out = [0; 40];
        let replayed = chooser.bytes(SUPPLIER, 0, &mut out).and_then(|()| {
            chooser.bounded(DISK, 0, 8)?;
            chooser.index(WORKLOAD, 0, &candidates(2)).map(|_| ())
        });
        assert_eq!(replayed, Err(ChoiceError::Identity), "record {record}");
    }
}

/// The choice contract, the entropy modules with the owner and volume
/// fixtures the identity case builds on, the bundle and manifest modules
/// with the mixed world's bundle run and the choice fixtures spell no
/// environment, file system or clock API; the worker spells no clock API
/// and reads one environment variable, the library search path its
/// reducer reads once for its fresh processes to keep; and all of them but
/// the choice fixtures spell no hash-container type. The turn loop's wall
/// time enters only diagnostics, and the worker's file, executable and
/// library search path reads stay outside every decision, which the pinned
/// vectors, fresh-process reproduction and strict replay cases check by
/// behavior.
#[test]
fn choices_read_no_environment_clock_or_hash_order() {
    let choice = include_str!("choice.rs");
    let worker = include_str!("../worker.rs");
    let fixtures = include_str!("choice_tests.rs");
    let entropy = [
        include_str!("entropy.rs"),
        include_str!("entropy_tests.rs"),
        include_str!("../net/entropy_tests.rs"),
        include_str!("../net/owner_tests.rs"),
        include_str!("../storage/entropy_tests.rs"),
        include_str!("../storage/owner_fixture.rs"),
        include_str!("../storage/volume_fixture.rs"),
        include_str!("trace.rs"),
        include_str!("manifest.rs"),
        include_str!("../net/world_tests/bundle.rs"),
    ];
    // Spelled in pieces, so this file names none of them whole.
    let environment = [
        concat!("std::", "env"),
        concat!("env::", "var"),
        concat!("vars", "_os"),
        concat!("std::", "fs"),
        concat!("Inst", "ant"),
        concat!("System", "Time"),
    ];
    let hashing = [
        concat!("Hash", "Map"),
        concat!("Hash", "Set"),
        concat!("Random", "State"),
    ];
    for banned in environment {
        assert!(!choice.contains(banned), "choice.rs uses {banned}");
        assert!(!fixtures.contains(banned), "choice_tests.rs uses {banned}");
        for source in entropy {
            assert!(!source.contains(banned), "an entropy module uses {banned}");
        }
    }
    for banned in hashing {
        assert!(!choice.contains(banned), "choice.rs uses {banned}");
        assert!(!worker.contains(banned), "worker.rs uses {banned}");
        for source in entropy {
            assert!(!source.contains(banned), "an entropy module uses {banned}");
        }
    }
    // The reducer's fresh processes keep the library search path, which
    // directs their library lookup and feeds no decision; it is read once.
    let library_path = concat!("std::", "env::", "var", "_os(\"LD_LIBRARY_PATH\")");
    assert_eq!(
        worker.matches(library_path).count(),
        1,
        "worker.rs reads the library search path once"
    );
    assert_eq!(
        worker.matches(concat!("std::", "env::")).count(),
        worker.matches(concat!("std::", "env::args()")).count()
            + worker
                .matches(concat!("std::", "env::current_exe()"))
                .count()
            + worker.matches(concat!("std::", "env::consts::")).count()
            + worker.matches(library_path).count(),
        "no other process environment"
    );
    assert_eq!(
        worker.matches(concat!("env::", "var")).count(),
        worker.matches(library_path).count(),
        "worker.rs reads no other environment variable"
    );
    let worker_banned = [
        concat!("vars", "_os"),
        concat!("Inst", "ant"),
        concat!("System", "Time"),
    ];
    for banned in worker_banned {
        assert!(!worker.contains(banned), "worker.rs uses {banned}");
    }
}

/// Every PUT action decodes from its own candidate, and a candidate of
/// another domain decodes to none.
#[test]
fn put_actions_decode_from_their_candidates() {
    let actions = [
        PutAction::Begin { key: 7, attempt: 1 },
        PutAction::Prepare { key: 7, attempt: 2 },
        PutAction::Supply {
            key: 7,
            attempt: 1,
            fragment: 3,
        },
        PutAction::Defer {
            key: 7,
            attempt: 1,
            ready_us: 9,
        },
        PutAction::Cancel { key: 8, attempt: 1 },
        PutAction::Abandon { key: 7, attempt: 1 },
        PutAction::Outcome { key: 7, attempt: 1 },
        PutAction::Retry { key: 7, attempt: 4 },
    ];
    for action in actions {
        assert_eq!(PutAction::from_candidate(&action.candidate()), Some(action));
    }
    let mut other = PutAction::Begin { key: 7, attempt: 1 }.candidate();
    other.0[0] = Domain::Workload as u8;
    assert_eq!(PutAction::from_candidate(&other), None);
}

/// Each identity record of a recorded tape opens one decision, and an
/// identity in the reserved persistence and crash domain opens a reserved
/// one; candidate, selection and entropy records open nothing.
#[test]
fn identity_records_open_decisions() {
    let mut chooser = launched(ROOT);
    sequence(&mut chooser, 3);
    let decisions = chooser.decisions();
    let tape = chooser.finish().expect("a tape");
    let opened: Vec<Opens> = tape.as_chunks::<RECORD_LEN>().0.iter().map(opens).collect();
    let counted = opened
        .iter()
        .filter(|&&kind| kind == Opens::Decision)
        .count();
    assert_eq!(counted as u64, decisions);
    assert!(opened.contains(&Opens::Nothing));
    assert!(!opened.contains(&Opens::Reserved));
    let reserved = Identity {
        site: PERSISTENCE,
        incarnation: 0,
        occurrence: 0,
    };
    let mut record = [0; RECORD_LEN];
    record[0] = tape[0];
    record[1..1 + IDENTITY_LEN].copy_from_slice(&reserved.canonical());
    assert_eq!(opens(&record), Opens::Reserved);
}

/// A site whose occurrence counter reached its end refuses its next
/// decision instead of reusing an identity.
#[test]
fn an_exhausted_occurrence_counter_refuses_the_next_decision() {
    use super::choice::{ChoiceError, Defect};
    let site = Site {
        domain: Domain::Workload,
        actor: 0,
        site: 1,
    };
    let mut chooser = Chooser::record(9, &[site]);
    let incarnation = chooser.launch(0);
    chooser.skip_to(site, u32::MAX - 1);
    assert!(chooser.bounded(site, incarnation, 4).is_ok());
    assert_eq!(
        chooser.bounded(site, incarnation, 4),
        Err(ChoiceError::HarnessDefect(Defect::Occurrences(site)))
    );
}

/// A recording chooser that releases its tape after each decision makes
/// the same decisions as one that keeps it, and the released pieces in
/// order are the kept tape.
#[test]
fn releasing_a_recording_keeps_its_decisions() {
    let site = Site {
        domain: Domain::Workload,
        actor: 0,
        site: 1,
    };
    let (mut kept, mut streamed) = (Chooser::record(9, &[site]), Chooser::record(9, &[site]));
    let (a, b) = (kept.launch(0), streamed.launch(0));
    let mut emitted = streamed.recorded().to_vec();
    assert!(streamed.release());
    for _ in 0..8 {
        assert_eq!(kept.bounded(site, a, 1000), streamed.bounded(site, b, 1000));
        emitted.extend_from_slice(streamed.recorded());
        assert!(streamed.release());
        assert!(streamed.recorded().is_empty());
    }
    assert_eq!(emitted, kept.finish().unwrap());
}
