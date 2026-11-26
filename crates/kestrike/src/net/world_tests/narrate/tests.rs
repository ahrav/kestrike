//! The narrative form over fixed-byte and recorded bundles: record layouts
//! that re-encode through their fields, names checked against the
//! producers that write each code, windows and context, and the refusals
//! and incomplete outcomes of malformed input and failed output.

use crate::oracle::{KeyId, Label, Obligation};
use crate::sim::action::ActionKind;
use crate::sim::choice::{Candidate, ChoiceError, Domain, PutAction, Site as ChoiceSite};
use crate::sim::manifest::Manifest;
use crate::sim::trace::{
    Capacity, Event, Field, Infrastructure, Outcome, PAYLOAD, RECORD, Recorder, Tag, Terminal, Work,
};
use crate::sim::turn::{End, Limit};

use super::super::super::audit::{Class, Reason, Record, Source};
use super::super::super::observe::Failure;
use super::super::super::rules::{Bound, Corruption};
use super::super::super::witness::{Change, Effect, Tuple, Witness};
use super::super::bundle::{
    Composed, Site, Violated, act_events, admit, audit_event, entropy_event, event_put,
    failure_event, reason_code, stop_event, traced,
};
use super::super::cluster::{Reached, Topology, WINDOW, coverage_event, window_words};
use super::{Decoded, Form, MAX_RECORDS, Pins, Value, Window, World, decode, kind_name, run};

const EXECUTABLE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// The decoder pins of a worker built as the sample manifests pin it.
pub(super) fn here() -> Pins {
    (Ok(EXECUTABLE.into()), "x86_64-linux".into())
}

/// A sample manifest of `profile` at `root`, pinned to [`EXECUTABLE`].
pub(super) fn manifest(profile: &str, root: u64) -> Manifest {
    let text = crate::sim::manifest_tests::sample(profile, EXECUTABLE, "x86_64-linux")
        .replace("root = 3", &format!("root = {root}"));
    Manifest::parse(&text).unwrap()
}

/// `profile` at `root` run into a bundle by this build.
pub(super) fn recorded(profile: &str, root: u64) -> Vec<u8> {
    let manifest = manifest(profile, root);
    traced(admit(&manifest).unwrap(), Vec::new()).sink
}

/// A record of `tag` and sub-tag `sub` whose payload bytes all differ from
/// zero, then hold `set`'s bytes at their payload offsets.
pub(super) fn patterned(tag: Tag, sub: u8, set: &[(usize, u8)]) -> [u8; RECORD] {
    let mut out = [0; RECORD];
    out[0] = tag as u8;
    out[1] = sub;
    out[2..4].copy_from_slice(&[0x31, 0x32]);
    for (at, byte) in out[4..].iter_mut().enumerate() {
        *byte = (at as u8).wrapping_mul(29).wrapping_add(7) | 1;
    }
    for &(at, byte) in set {
        out[4 + at] = byte;
    }
    out
}

/// The record of `tag`, an event's `kind`, that `decoded`'s fields and
/// spare runs encode, written field by field from each decoded value.
pub(super) fn encode(tag: Tag, kind: u8, decoded: &Decoded) -> [u8; RECORD] {
    let mut out = [0; RECORD];
    let mut written = [false; RECORD];
    out[0] = tag as u8;
    if tag == Tag::Event {
        out[1] = kind;
    }
    let mut put = |at: usize, bytes: &[u8]| {
        for (offset, &byte) in bytes.iter().enumerate() {
            assert!(
                !written[at + offset],
                "two fields hold byte {}",
                at + offset
            );
            written[at + offset] = true;
            out[at + offset] = byte;
        }
    };
    for (spec, value) in &decoded.fields {
        match (spec.form, value) {
            (Form::Int { big: true }, Value::Int(value)) => {
                put(spec.at, &value.to_be_bytes()[8 - spec.len..]);
            }
            (Form::Int { big: false }, Value::Int(value)) => {
                assert!(spec.len == 8 || *value < 1 << (8 * spec.len));
                put(spec.at, &value.to_le_bytes()[..spec.len]);
            }
            (Form::Hex | Form::Text, Value::Bytes(bytes)) => put(spec.at, bytes),
            _ => panic!("{} decoded as another form", spec.name),
        }
    }
    for (at, bytes) in &decoded.spare {
        put(*at, bytes);
    }
    out
}

/// Every record layout the narrative names, for each world, its
/// candidate domains and codes, every event kind with each sub-variant,
/// and kinds and codes outside the vocabulary.
fn fixtures() -> Vec<(World, Tag, [u8; RECORD])> {
    let worlds = [
        World::Mixed,
        World::Cluster,
        World::Recovery,
        World::Unknown,
    ];
    let mut out = Vec::new();
    for world in worlds {
        for (domain, code) in (1..=7).flat_map(|domain| (0..=20).map(move |code| (domain, code))) {
            out.push((
                world,
                Tag::Turn,
                patterned(Tag::Turn, 0, &[(8, domain), (9, code)]),
            ));
        }
        for request in 0..=11 {
            let set = [(8, 1), (9, 4), (32, request)];
            out.push((world, Tag::Turn, patterned(Tag::Turn, 0, &set)));
        }
        out.push((world, Tag::Clock, patterned(Tag::Clock, 0, &[])));
        for variant in [0, 1, 2, 3, 4, 0x81, 0x83, 9] {
            let violation = patterned(Tag::Violation, 0, &[(0, variant), (2, 41)]);
            out.push((world, Tag::Violation, violation));
        }
        for class in [1, 2, 3] {
            out.push((
                world,
                Tag::Terminal,
                patterned(Tag::Terminal, 0, &[(0, class)]),
            ));
        }
        for kind in 0..=16 {
            for first in 0..=7 {
                for words in [0, 1, 2, 3, 4, 9] {
                    let set = [(0, first), (10, words)];
                    out.push((world, Tag::Event, patterned(Tag::Event, kind, &set)));
                }
            }
        }
        for tag in [
            Tag::Begin,
            Tag::Field,
            Tag::Choice,
            Tag::Checkpoint,
            Tag::Diagnostic,
        ] {
            out.push((world, tag, patterned(tag, 3, &[])));
        }
    }
    out
}

/// Every fixture record decodes to fields and spare runs that write it
/// back byte for byte, with no byte held by two fields and no field past
/// the record, and its line names a table for every field it decodes.
/// This proves each layout lossless and free of overlap, and every table
/// token known; it holds for a layout that names a field at the wrong
/// offset or leaves one out, which the producer-built name checks reject.
#[test]
fn whole_records_reencode_through_their_fields() {
    let fixtures = fixtures();
    assert!(fixtures.len() > 2000);
    for (world, tag, record) in fixtures {
        let decoded = decode(world, &record);
        decoded.line();
        assert_eq!(
            encode(tag, record[1], &decoded),
            record,
            "{world:?} {}",
            decoded.line()
        );
    }
}

/// A changed byte inside a named field changes that field's value, and
/// one outside every field shows as spare, so no byte of a record is
/// silently dropped from its line.
#[test]
fn a_changed_byte_shows_in_its_field_or_as_spare() {
    let record = patterned(Tag::Clock, 0, &[]);
    let mut edited = record;
    edited[5] ^= 0x40;
    assert_ne!(
        decode(World::Mixed, &record).fields,
        decode(World::Mixed, &edited).fields
    );
    let mut spare = clock(0);
    spare[47] = 9;
    spare[2] = 1;
    let line = decode(World::Mixed, &spare).line();
    assert_eq!(line, "now_us=0 spare@2=01 spare@47=09");
}

/// The line of the turn whose candidate is `candidate` and outcome
/// `outcome`, at time 600, in `world`.
fn raw_turn_line(world: World, candidate: [u8; 16], outcome: u64) -> String {
    let mut record = turn(600, 0);
    record[12..28].copy_from_slice(&candidate);
    record[28..36].copy_from_slice(&outcome.to_le_bytes());
    decode(world, &record).line()
}

/// `line` when it names every byte: no spare run and no code outside its
/// table, as a producer-written record's line must.
#[track_caller]
pub(crate) fn clean(line: String) -> String {
    assert!(
        !line.contains("spare@") && !line.contains("unknown("),
        "{line}"
    );
    line
}

/// [`raw_turn_line`] of a candidate a producer wrote, checked [`clean`].
#[track_caller]
pub(crate) fn turn_line(world: World, candidate: [u8; 16], outcome: u64) -> String {
    clean(raw_turn_line(world, candidate, outcome))
}

fn raw_event_line(event: &Event) -> String {
    decode(World::Mixed, &event_record(event)).line()
}

/// [`raw_event_line`] of an event a producer wrote, checked [`clean`].
#[track_caller]
fn event_line(event: &Event) -> String {
    clean(raw_event_line(event))
}

/// The mixed world's candidates, built by the world's own constructors,
/// name their code, actor and argument; its turn outcomes name a refused
/// action, a script step that stays, a held update's delivery and a client
/// poll's packed received and sent counts; PUT descriptors name their
/// action and fields, and a link release its link and reference. A second
/// owner's poll, client poll and disk service name the peer, and its
/// client poll's outcome splits as the scripted owner's client's does.
#[test]
fn mixed_candidates_name_their_producers_meaning() {
    use super::super::{
        CLIENT_POLL, DELIVER, OWNER_POLL, PEER_CLIENT_POLL, PEER_OWNER_POLL, PEER_SERVICE, SCRIPT,
        action, candidate, nic_return,
    };
    let lines = [
        (
            candidate(PEER_OWNER_POLL, 0, 0).0,
            12,
            "code=peer-owner-poll actor=0 arg=0 outcome=12",
        ),
        (
            candidate(PEER_CLIENT_POLL, 1, 0).0,
            3 | 5 << 32,
            "code=peer-client-poll actor=1 arg=0 received=3 sent=5",
        ),
        (
            candidate(PEER_SERVICE, 0, 0).0,
            2,
            "code=peer-service actor=0 arg=0 outcome=2",
        ),
        (
            candidate(OWNER_POLL, 0, 0).0,
            12,
            "code=owner-poll actor=0 arg=0 outcome=12",
        ),
        (
            candidate(CLIENT_POLL, 1, 0).0,
            3 | 5 << 32,
            "code=client-poll actor=1 arg=0 received=3 sent=5",
        ),
        (
            candidate(SCRIPT, 0, 4).0,
            super::super::histories::STAY,
            "code=script actor=0 step=4 outcome=stay",
        ),
        (
            candidate(SCRIPT, 0, 5).0,
            2,
            "code=script actor=0 step=5 outcome=2",
        ),
        (
            action(ActionKind::Get, 1, 7).0,
            0,
            "code=Get actor=1 arg=7 outcome=refused",
        ),
        (
            action(ActionKind::Close, 0, 0).0,
            1,
            "code=Close actor=0 arg=0 outcome=1",
        ),
        (
            nic_return(1, 258).0,
            259,
            "event=release net=1 nth=258 outcome=259",
        ),
        (
            PutAction::Supply {
                key: 6,
                attempt: 2,
                fragment: 1,
            }
            .candidate()
            .0,
            0,
            "action=supply key=6 attempt=2 fragment=1 outcome=refused",
        ),
        (
            PutAction::Defer {
                key: 6,
                attempt: 1,
                ready_us: 5600,
            }
            .candidate()
            .0,
            1,
            "action=defer key=6 attempt=1 ready_us=5600 outcome=1",
        ),
    ];
    for (candidate, outcome, named) in lines {
        let line = turn_line(World::Mixed, candidate, outcome);
        assert!(line.starts_with("now_us=600 domain="), "{line}");
        assert!(line.ends_with(named), "{line} names other than {named}");
    }
    let mut delivered = candidate(DELIVER, 1, 0).0;
    delivered[7] = ActionKind::Rekey as u8;
    let line = turn_line(World::Mixed, delivered, super::super::REKEY_BUSY);
    assert!(line.ends_with("code=deliver actor=1 update=0 kind=Rekey outcome=rekey-busy"));
}

/// One candidate code names a different operation in each world: code 5
/// is the mixed world's script step, the cluster world's PREPARE and the
/// recovery world's hold, and a world this decoder does not list leaves
/// the workload bytes spare. A cluster disk candidate carries its cell in
/// its ordinal's top byte, which the mixed world reads as its second
/// owner's device and an unlisted world leaves spare with the ordinal.
/// Each world's own test module checks every code its producer writes.
#[test]
fn colliding_codes_take_their_worlds_meaning() {
    let mut five = [0; 16];
    five[..3].copy_from_slice(&[Domain::Workload as u8, 5, 1]);
    let named = |world| raw_turn_line(world, five, 0);
    assert!(named(World::Mixed).contains("code=script actor=1 step=0"));
    assert!(named(World::Cluster).contains("code=prepare cell=1 client=0 arg=0 key=0 slot=0"));
    assert!(named(World::Recovery).contains("code=hold operation=1"));
    assert_eq!(
        named(World::Unknown),
        "now_us=600 domain=Workload outcome=0 spare@13=0501"
    );
    for (world, wrong) in [(World::Mixed, "prepare"), (World::Cluster, "script")] {
        assert!(!named(world).contains(wrong), "{world:?} names {wrong}");
    }
    let mut cluster;
    cluster = [2, 2, 1, 0, 0, 0, 0, 0, 0, 7, 1, 0, 8, 0, 0, 3];
    let line = turn_line(World::Cluster, cluster, 0);
    assert!(
        line.contains("stage=post cell=1 ordinal=7 op=write sectors=8 start_unit=3"),
        "{line}"
    );
    let line = turn_line(World::Mixed, cluster, 0);
    assert!(
        line.contains("stage=post owner=peer ordinal=7 op=write"),
        "{line}"
    );
    assert_eq!(
        raw_turn_line(World::Unknown, cluster, 0),
        "now_us=600 domain=Disk stage=post op=write sectors=8 start_unit=3 outcome=0 \
            spare@14=01 spare@21=07"
    );
    cluster[1] = 9;
    assert!(raw_turn_line(World::Cluster, cluster, 0).contains("stage=unknown(9)"));
}

/// Events built by their producers name each field as the producer wrote
/// it: actions and witnesses, a PUT's packed fields, an audit record's
/// class, reason and link or device source, a failure's variant of each
/// kind, obligation and rule, truncation and a cut rule, identities of both
/// sites and of an audit, an entropy refusal, each stop with distinct
/// fields, coverage and window counts with saturation and both verdicts,
/// and every witness change, effect and acknowledgment, each list checked
/// whole against its enum.
#[test]
fn events_name_their_producers_meaning() {
    let mut acts = Vec::new();
    act_events(&mut acts, ActionKind::Read, 3, true);
    assert_eq!(event_line(&acts[0]), "event ACT action=Read outcome=3");
    assert_eq!(event_line(&acts[1]), "event WITNESS action=Read outcome=3");
    let put = event_put(ActionKind::Supply, 2, 9, 1, &[0xab; 16], 77, 1 << 32 | 5);
    assert_eq!(
        event_line(&put),
        format!(
            "event PUT action=Supply attempt=2 session=9 fragment=1 supplied={} held_until_us=77 outcome=5 (outcome holds the low 32 bits of the action's outcome)",
            "ab".repeat(16)
        )
    );
    for (reason, name) in [
        (Reason::Lost, "Lost"),
        (Reason::Corrupted(Corruption::Tag), "Corrupted reason_arg=1"),
        (Reason::Full(Bound::Captures), "Full reason_arg=2"),
        (Reason::Unattributed, "Unattributed"),
        (
            Reason::DeviceOmitted(crate::storage::device::sim::Omission::Episode),
            "DeviceOmitted",
        ),
        (Reason::DeviceFalseStopped, "DeviceFalseStopped"),
        (Reason::LostBurst, "LostBurst"),
        (Reason::LostResend, "LostResend"),
    ] {
        let record = Record {
            class: Class::Production,
            reason,
            source: Source::Link {
                actor: 0x0305,
                toward: 1,
            },
        };
        let line = event_line(&audit_event(1, &record));
        let expected = format!("event AUDIT net=1 class=Production reason={name}");
        assert!(line.starts_with(&expected), "{line}");
        assert!(
            line.contains("place=link actor_low=5 toward_xor_actor_high=31 ("),
            "{line}"
        );
        let word = name.split(' ').next().unwrap();
        assert!(format!("{reason:?}").starts_with(word), "{reason:?} {word}");
        let code = u64::from(reason_code(reason)[0]);
        assert_eq!(super::named("REASONS", code, 1).as_deref(), Some(word));
        let violation = violation_record(&Violated::Audit(record).code());
        let line = decode(World::Mixed, &violation).line();
        assert!(line.starts_with(&format!(
            "violation variant=audit class=Production reason={name}"
        )));
    }
    let failures = [
        (
            Failure::Violation(Obligation::Custody, "short rule"),
            "event FAILURE variant=violation obligation=Custody length=10 rule=\"short rule\"",
        ),
        (
            Failure::Unsuccessful("probe"),
            "event OBSERVED variant=unsuccessful obligation=none length=5 rule=\"probe\"",
        ),
        (
            Failure::Truncated(Box::new(Failure::Unsuccessful("probe"))),
            "event OBSERVED variant=unsuccessful+truncated obligation=none length=5 rule=\"probe\"",
        ),
    ];
    for (failure, line) in failures {
        assert_eq!(event_line(&failure_event(&failure)), line);
    }
    let oracle = Failure::Oracle(crate::oracle::Verdict::Inconclusive(
        crate::oracle::Inconclusive::SearchBound { limit: 1 },
    ));
    assert_eq!(
        event_line(&failure_event(&oracle)),
        "event OBSERVED variant=oracle obligation=none length=12 rule=\"inconclusive\""
    );
    let rule = "a rule longer than the forty-one bytes a record holds";
    let long = Failure::Violation(Obligation::Bytes, rule);
    let cut = format!(
        "rule=\"{}\" (the rule may continue past its 41 recorded bytes)",
        &rule[..41]
    );
    assert!(event_line(&failure_event(&long)).ends_with(&cut));
    let identity = Violated::Observed(long).identity(Site::Settled);
    let line = event_line(&identity);
    let prefix = format!(
        "event IDENTITY version=2 variant=violation obligation=Bytes class=none site=settled length={} hash=",
        rule.len()
    );
    assert!(line.starts_with(&prefix), "{line}");
    let device = Record {
        class: Class::Harness,
        reason: Reason::Lost,
        source: Source::Device(4),
    };
    let audit = Violated::Audit(device).identity(Site::Run);
    assert!(event_line(&audit).starts_with("event IDENTITY version=2 variant=audit obligation=none class=Harness site=settled length=15"));
    let run = Violated::Observed(Failure::Violation(Obligation::Bytes, "x")).identity(Site::Run);
    assert!(
        event_line(&run).contains(" site=run "),
        "{}",
        event_line(&run)
    );
    let line = event_line(&audit_event(1, &device));
    assert!(line.contains(" place=device actor_low=4 "), "{line}");
    let mut saturated = identity;
    saturated.payload[5..7].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(event_line(&saturated).contains("length=65535(saturated)"));
    let refusal = crate::sim::entropy::DrawRefusal {
        site: ChoiceSite {
            domain: Domain::Entropy,
            actor: 3,
            site: 2,
        },
        incarnation: 1,
        error: ChoiceError::Trailing { bytes: 123_456_789 },
    };
    assert_eq!(
        event_line(&entropy_event(refusal)),
        "event ENTROPY actor=3 site=2 incarnation=1 error=\"Trailing { bytes: 123456789 }\" (error holds at most the first 36 bytes of the refusal)"
    );
    let composed = Composed {
        checked: 4,
        owners: 2,
        clients: 5,
    };
    assert_eq!(
        event_line(&stop_event(
            End::Inconclusive(Limit::NoProgress),
            Some(composed)
        )),
        "event STOP class=2 detail=3 composed=yes checked=4 owners=2 clients=5 (stop limit no_progress)"
    );
    assert_eq!(
        event_line(&stop_event(End::Halted, None)),
        "event STOP class=4 detail=0 composed=no checked=0 owners=0 clients=0 (stop halted)"
    );
    let mut reached = Reached {
        published: 1,
        hits: 2,
        misses: 3,
        refused: 4,
        invalidated: 5,
        cancelled: 6,
        cross: 7,
        reused: 8,
        healthy: 9,
        ..Reached::default()
    };
    reached.faults = 1 << 40;
    let topology = Topology {
        owners: 2,
        keys: 5,
        hot: 1,
    };
    assert_eq!(
        event_line(&coverage_event(topology, &reached)),
        "event COVERAGE owners=2 keys=5 hot=1 published=1 hits=2 misses=3 refused=4 invalidated=5 cancelled=6 cross=7 reused=8 healthy=9 faults=4294967295(saturated)"
    );
    let mut window = Event {
        kind: WINDOW,
        payload: [0; PAYLOAD],
    };
    for n in 0..10u32 {
        let at = if n == 0 { 0 } else { 5 + 4 * (n as usize - 1) };
        window.payload[at..at + 4].copy_from_slice(&(100 + n).to_le_bytes());
    }
    window.payload[4] = 1;
    let words = window_words(&window.payload);
    let names = [
        "index",
        "carried",
        "registry",
        "outstanding",
        "kept",
        "published",
        "hits",
        "faults",
        "reused",
        "healed",
    ];
    let line = event_line(&window);
    assert!(line.contains("verdict=passed"));
    let mut inconclusive = window;
    inconclusive.payload[4] = 0;
    assert!(event_line(&inconclusive).contains(" verdict=not-passed "));
    for (name, word) in names.iter().zip(words) {
        assert!(
            line.contains(&format!(" {name}={word}")),
            "{line} lacks {name}={word}"
        );
    }
    let tuple = Tuple {
        peer: 1,
        slot: 2,
        generation: 3,
        epoch: 4,
    };
    let mut witness = Witness::default();
    for change in [
        Change::Began {
            op: 7,
            tuple,
            effect: Effect::Exclusion {
                key: KeyId(1),
                label: Label(2),
                frozen: 3,
            },
        },
        Change::Emitted { op: 7 },
        Change::Consumed {
            tuple,
            acknowledged: true,
        },
        Change::Intended {
            op: 7,
            digest: [0xcd; 32],
        },
    ] {
        // A change this list leaves out fails to compile here.
        match change {
            Change::Began { .. }
            | Change::Emitted { .. }
            | Change::Consumed { .. }
            | Change::Intended { .. } => (),
        }
        witness.apply(change);
    }
    assert_eq!(
        super::CHANGES.split(',').count(),
        witness.events().len() + 1
    );
    let freshness = Effect::Freshness {
        cursor: 1,
        caller: true,
    };
    // An effect this list, with the exclusion above, leaves out fails to
    // compile here.
    let effects = [(Effect::Live, "live"), (freshness, "freshness")];
    for (effect, _) in effects {
        match effect {
            Effect::Live | Effect::Exclusion { .. } | Effect::Freshness { .. } => (),
        }
    }
    for (effect, name) in effects {
        let mut began = Witness::default();
        began.apply(Change::Began {
            op: 8,
            tuple,
            effect,
        });
        began.apply(Change::Consumed {
            tuple,
            acknowledged: false,
        });
        let named: Vec<String> = began.events().iter().map(event_line).collect();
        assert!(named[0].contains(&format!(" effect={name} ")), "{named:?}");
        assert!(named[1].ends_with(" acknowledged=no"), "{named:?}");
    }
    let lines: Vec<String> = witness.events().iter().map(event_line).collect();
    assert_eq!(
        lines,
        [
            format!(
                "event OBSERVATION change=began op=7 peer=1 slot=2 generation=3 epoch=4 effect=exclusion effect_fields=01{}{}",
                hex_le(2),
                hex_le(3)
            ),
            "event OBSERVATION change=emitted op=7".into(),
            "event OBSERVATION change=consumed peer=1 slot=2 generation=3 epoch=4 acknowledged=yes"
                .into(),
            format!(
                "event OBSERVATION change=intended op=7 digest={}",
                "cd".repeat(32)
            ),
        ]
    );
}

fn hex_le(value: u64) -> String {
    value
        .to_le_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Each ledger stage names its fields as the ledger writes them: a
/// reach's queue, every activation class with each drained bit and
/// evidence, its counts and landing words, a count past four leaving its
/// bytes spare, and both check verdicts; a capture's sentinel index and
/// delay name none, a value one below a sentinel prints as a number, and
/// packed flags name both decisions.
#[test]
fn ledger_and_rule_fields_name_their_producers_meaning() {
    use crate::sim::ledger::{Activation, Checked, Entry, Evidence, event};
    let activation = Activation {
        landing: vec![5, 6],
        drained: true,
        held: 2,
        class: crate::sim::cut::Class::ControllerReset,
        queue: 3,
        evidence: Evidence::Unmatched,
    };
    for class in crate::sim::cut::Class::ALL {
        for (evidence, name) in [
            (Evidence::Attributed, "attributed"),
            (Evidence::Ambiguous, "ambiguous"),
            (Evidence::Unmatched, "unmatched"),
        ] {
            for (drained, flag) in [(false, "no"), (true, "yes")] {
                let activation = Activation {
                    landing: Vec::new(),
                    drained,
                    held: 0,
                    class,
                    queue: 0,
                    evidence,
                };
                let line = event_line(&event(1, &Entry::Activated(activation)));
                assert!(line.contains(&format!(" class={class:?} ")), "{line}");
                assert!(
                    line.ends_with(&format!(" drained_evidence={flag}/{name}")),
                    "{line}"
                );
            }
        }
    }
    assert_eq!(
        event_line(&event(4, &Entry::Checked(Checked::Pass))),
        "event LEDGER stage=checked cut=4 verdict=pass"
    );
    let mut wide = patterned(Tag::Event, crate::sim::ledger::LEDGER, &[(0, 3), (10, 9)]);
    wide[4 + 11] = 0;
    let line = decode(World::Mixed, &wide).line();
    assert!(
        line.contains(" words=9 ") && line.contains(" spare@16="),
        "{line}"
    );
    assert!(!line.contains("landing="), "{line}");
    for (entry, line) in [
        (Entry::Planned, "event LEDGER stage=planned cut=4"),
        (
            Entry::Reached { queue: 9 },
            "event LEDGER stage=reached cut=4 queue=9",
        ),
        (
            Entry::Activated(activation),
            "event LEDGER stage=activated cut=4 class=ControllerReset queue=3 held=2 words=2 drained_evidence=yes/unmatched landing=5 landing=6",
        ),
        (Entry::Recovered, "event LEDGER stage=recovered cut=4"),
        (
            Entry::Checked(Checked::Fail),
            "event LEDGER stage=checked cut=4 verdict=fail",
        ),
        (Entry::Skipped, "event LEDGER stage=skipped cut=4"),
    ] {
        assert_eq!(event_line(&event(4, &entry)), line);
    }
    let mut rule = Event {
        kind: crate::net::world_tests::bundle::RULE,
        payload: [0; PAYLOAD],
    };
    rule.payload[14] = super::super::super::frame::Kind::PutData as u8;
    rule.payload[15..19].copy_from_slice(&u32::MAX.to_le_bytes());
    rule.payload[19] = 2;
    rule.payload[23..31].copy_from_slice(&u64::MAX.to_le_bytes());
    rule.payload[31] = 2 | 1 << 2;
    rule.payload[32] = 2;
    assert_eq!(
        event_line(&rule),
        "event RULE net=0 tap=0 link=0 toward=0 ordinal=0 message=PutData index=none dropped=rule rule_at=0 duplicate=no delay=none reorder_truncate=true/false corrupt=Tag (rule_at holds the low 16 bits of the rule index; index and delay print none at their largest value, which their encoder also writes for absent)"
    );
    let unknown = Event {
        kind: 16,
        payload: [0; PAYLOAD],
    };
    assert_eq!(raw_event_line(&unknown), "event unknown(16)");
    assert_eq!(kind_name(16), None);
    for (table, len) in [
        ("max:none", 4),
        ("max:none", 8),
        ("max:stay", 8),
        ("sat", 2),
        ("sat", 4),
    ] {
        let max = u64::MAX >> (64 - 8 * len);
        assert!(super::named(table, max, len).is_some(), "{table}/{len}");
        assert_eq!(super::named(table, max - 1, len), None, "{table}/{len}");
    }
    let mut ledger = event(1, &Entry::Planned);
    ledger.payload[0] = 7;
    assert_eq!(
        raw_event_line(&ledger),
        "event LEDGER stage=unknown(7) cut=1"
    );
}

/// The event kinds the narrative names are the bundle's kinds, each by
/// the name of the constant its producer records it under.
#[test]
fn every_event_kind_has_its_producers_name() {
    use super::super::bundle::{
        ACT, AUDIT, ENTROPY, FAILURE, IDENTITY, OBSERVED, PUT, RULE, STOP, UPLOAD, WITNESS,
    };
    let kinds = [
        (ACT, "ACT"),
        (WITNESS, "WITNESS"),
        (PUT, "PUT"),
        (UPLOAD, "UPLOAD"),
        (AUDIT, "AUDIT"),
        (FAILURE, "FAILURE"),
        (RULE, "RULE"),
        (OBSERVED, "OBSERVED"),
        (crate::sim::ledger::LEDGER, "LEDGER"),
        (super::super::super::witness::OBSERVATION, "OBSERVATION"),
        (ENTROPY, "ENTROPY"),
        (STOP, "STOP"),
        (super::super::cluster::COVERAGE, "COVERAGE"),
        (WINDOW, "WINDOW"),
        (IDENTITY, "IDENTITY"),
    ];
    for (kind, name) in kinds {
        assert_eq!(kind_name(kind), Some(name));
    }
    assert_eq!(kind_name(0), None);
}

/// A narrative run: its exit code, the narrative file, stdout and stderr.
pub(super) struct Narrated {
    pub(super) code: i32,
    pub(super) text: Option<String>,
    pub(super) out: String,
    pub(super) err: String,
}

/// Runs the form over `bytes`, written to a scratch bundle, with `flags`
/// after `BUNDLE --output FILE`.
pub(super) fn narrate(name: &str, bytes: &[u8], flags: &[&str], decoder: &Pins) -> Narrated {
    let dir = super::super::scratch(&format!("narrate-{name}")).unwrap();
    let (bundle, output) = (dir.join("bundle"), dir.join("narrative"));
    std::fs::write(&bundle, bytes).unwrap();
    let mut args = vec![
        bundle.display().to_string(),
        "--output".into(),
        output.display().to_string(),
    ];
    args.extend(flags.iter().map(|flag| (*flag).to_owned()));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = run(&args, || decoder.clone(), &mut out, &mut err);
    let narrated = Narrated {
        code,
        text: std::fs::read_to_string(&output).ok(),
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    };
    assert_eq!(std::fs::read(&bundle).unwrap(), bytes, "the input changed");
    std::fs::remove_dir_all(&dir).unwrap();
    narrated
}

pub(super) fn body(text: &str) -> Vec<&str> {
    text.lines().filter(|line| line.starts_with('#')).collect()
}

/// A bundle recorded by hand under the upload manifest at its capacity,
/// holding `records` between the manifest field and the terminal.
pub(super) fn handmade(records: &[[u8; RECORD]], terminal: Terminal) -> Vec<u8> {
    let manifest = manifest("upload", 3);
    let mut recorder = Recorder::new(Vec::new(), manifest.capacity());
    recorder.field(Field::Manifest, manifest.canonical().as_bytes());
    recorder.diagnostic("cpu fixture");
    for record in records {
        recorder.raw(record);
    }
    recorder.finish(terminal, Work::default()).sink
}

pub(super) fn clock(now: u64) -> [u8; RECORD] {
    let mut record = [0; RECORD];
    record[0] = Tag::Clock as u8;
    record[4..12].copy_from_slice(&now.to_le_bytes());
    record
}

pub(super) fn turn(now: u64, code: u8) -> [u8; RECORD] {
    let mut record = [0; RECORD];
    record[0] = Tag::Turn as u8;
    record[4..12].copy_from_slice(&now.to_le_bytes());
    record[12..15].copy_from_slice(&[Domain::Workload as u8, code, 0]);
    record
}

pub(super) fn event_record(event: &Event) -> [u8; RECORD] {
    let mut record = [0; RECORD];
    record[0] = Tag::Event as u8;
    record[1] = event.kind;
    record[4..].copy_from_slice(&event.payload);
    record
}

pub(super) fn violation_record(payload: &[u8; PAYLOAD]) -> [u8; RECORD] {
    let mut record = [0; RECORD];
    record[0] = Tag::Violation as u8;
    record[4..].copy_from_slice(payload);
    record
}

pub(super) const PASS: Terminal = Terminal::Complete {
    outcome: Outcome::Pass,
    fired: 3,
    required: 3,
};

pub(super) const VIOLATING: Terminal = Terminal::Complete {
    outcome: Outcome::Violation,
    fired: 3,
    required: 3,
};

const VIOLATED: Terminal = Terminal::Complete {
    outcome: Outcome::Violation,
    fired: 0,
    required: 0,
};

/// An upload bundle whose manifest allows 70 records, holding `turns`
/// turns at the upload capacity.
fn capped(turns: u64) -> Vec<u8> {
    let small = manifest("upload", 3).with("records", 70);
    let mut recorder = Recorder::new(Vec::new(), manifest("upload", 3).capacity());
    recorder.field(Field::Manifest, small.canonical().as_bytes());
    for at in 0..turns {
        recorder.raw(&turn(at, 3));
    }
    recorder.finish(PASS, Work::default()).sink
}

/// Two turns at the first clock, a later clock, a third turn and its
/// event, a violation and the settlement's stop event.
fn timeline() -> Vec<[u8; RECORD]> {
    let mut acts = Vec::new();
    act_events(&mut acts, ActionKind::Get, 1, false);
    let violated =
        violation_record(&failure_event(&Failure::Violation(Obligation::Bytes, "x")).payload);
    vec![
        clock(600),
        turn(600, 1),
        event_record(&acts[0]),
        turn(600, 2),
        clock(700),
        turn(700, 3),
        event_record(&acts[0]),
        violated,
        event_record(&stop_event(End::Done, None)),
    ]
}

fn timeline_bundle() -> Vec<u8> {
    handmade(&timeline(), VIOLATING)
}

/// Every one of the ten record tags loads, the header names its format,
/// counts each tag and prints the bundle's digest, pins, profile and
/// window, and the default tier renders the turns in stream order, numbered from zero,
/// each at its own recorded time, then the violation in its turn and the
/// terminal at settlement: a complete violating bundle renders with exit 0.
#[test]
fn a_bundle_renders_its_turns_violation_and_terminal_in_order() {
    let mut records = timeline();
    let mut choice = [0; RECORD];
    choice[0] = Tag::Choice as u8;
    choice[4] = 2;
    records.insert(0, choice);
    let bytes = handmade(&records, VIOLATING);
    let narrated = narrate("order", &bytes, &[], &here());
    assert_eq!(narrated.code, 0, "{}", narrated.err);
    let text = narrated.text.unwrap();
    let loaded = crate::sim::trace::load(&bytes, MAX_RECORDS).unwrap();
    let recorded = super::super::replay::manifest_of(&loaded).unwrap();
    assert!(text.starts_with("narrative: 1\nrecords: 32 whole, 0 trailing bytes; "));
    let digest = super::super::branch::hex(&loaded.digest);
    let pins = format!(
        "pins: executable={EXECUTABLE} platform=\"x86_64-linux\" build={} toolchain={:?}\n",
        recorded.build, recorded.toolchain
    );
    let profile = format!(
        "profile: \"upload\" root=3 scenario={:?}\n",
        recorded.scenario
    );
    for header in [format!("digest: {digest}\n"), pins, profile] {
        assert!(text.contains(&header), "{header} {text}");
    }
    assert!(
        text.contains("window: turns 0..3 of 3, tier turns\n"),
        "{text}"
    );
    assert!(text.contains(
        "begin=1 field=17 choice=1 turn=3 clock=2 event=3 violation=1 terminal=1 checkpoint=2 diagnostic=1"
    ), "{text}");
    assert!(
        text.contains("evidence: complete\nterminal: complete violation fired=03 required=03\n")
    );
    assert!(text.contains(
        "names: this decoder's tables, built into the executable the bundle pins; the mixed world"
    ));
    let lines = body(&text);
    let places: Vec<&str> = lines
        .iter()
        .map(|line| line.split(':').next().unwrap().split_once(' ').unwrap().1)
        .collect();
    assert_eq!(
        places,
        ["turn 0", "turn 1", "turn 2", "turn 2", "settle context"],
        "{text}"
    );
    assert!(lines[0].contains("now_us=600 domain=Workload code=owner-poll"));
    assert!(lines[1].contains("now_us=600 domain=Workload code=client-poll"));
    assert!(lines[2].contains("now_us=700 domain=Workload code=service"));
    assert!(lines[3].contains("violation variant=violation obligation=Bytes length=1 rule=\"x\""));
    assert!(lines[4].contains("terminal class=complete outcome=violation"));
    let at = |line: &str| {
        line[1..]
            .split(' ')
            .next()
            .unwrap()
            .parse::<usize>()
            .unwrap()
    };
    assert!(lines.windows(2).all(|pair| at(pair[0]) < at(pair[1])));
    assert_eq!(narrated.out.lines().count(), 1);
    assert!(
        narrated.out.ends_with("5 of 32 records, complete\n"),
        "{}",
        narrated.out
    );
}

/// The events tier adds the clocks and events inside the window, the last
/// clock before boundary `from` as context when no clock at `from` opens
/// it, and the settlement's stop event as context; an empty window
/// `[N,N)` shows the last clock strictly before `N`, and it and the window
/// at the end hold no turns and keep the context and the terminal. A clock
/// after `N` turns belongs to boundary `N`, inside `from..to` alone.
#[test]
fn windows_hold_their_turns_and_mark_context() {
    let bytes = timeline_bundle();
    let lines = |flags: &[&str]| {
        let narrated = narrate("window", &bytes, flags, &here());
        assert_eq!(narrated.code, 0, "{}", narrated.err);
        body(&narrated.text.unwrap())
            .into_iter()
            .map(|line| line.split_once(' ').unwrap().1.to_owned())
            .collect::<Vec<String>>()
    };
    let all = lines(&["--events"]);
    assert_eq!(all.len(), 10, "{all:#?}");
    assert!(all[0].starts_with("clock 0: now_us=600"));
    assert!(all[4].starts_with("clock 2: now_us=700"));
    assert!(all[8].starts_with("settle context: event STOP"));
    let one = lines(&["--events", "--from", "1", "--to", "2"]);
    assert_eq!(
        one.iter()
            .map(|line| line.split(':').next().unwrap())
            .collect::<Vec<_>>(),
        [
            "clock 0 context",
            "turn 1",
            "turn 2 context",
            "settle context",
            "settle context"
        ],
        "{one:#?}"
    );
    let opened = lines(&["--events", "--from", "2", "--to", "3"]);
    assert!(opened[0].starts_with("clock 2: now_us=700"), "{opened:#?}");
    assert!(opened[1].starts_with("turn 2: now_us=700"));
    let header = narrate(
        "window-header",
        &bytes,
        &["--from", "1", "--to", "2"],
        &here(),
    );
    assert!(
        header
            .text
            .unwrap()
            .contains("window: turns 1..2 of 3, tier turns\n")
    );
    for (from, to, clock) in [
        ("1", "1", "clock 0 context: now_us=600"),
        ("2", "2", "clock 0 context: now_us=600"),
        ("3", "3", "clock 2 context: now_us=700"),
    ] {
        let empty = lines(&["--events", "--from", from, "--to", to]);
        assert!(empty[0].starts_with(clock), "{empty:#?}");
        assert!(
            empty.iter().all(|line| line.contains("context")),
            "{empty:#?}"
        );
        assert!(
            !empty
                .iter()
                .any(|line| line.starts_with("turn") && line.contains("now_us"))
        );
        assert!(empty.last().unwrap().contains("terminal"));
    }
    let end = lines(&["--from", "3"]);
    assert_eq!(end.len(), 2, "{end:#?}");
    for refused in [["--from", "2", "--to", "1"], ["--from", "0", "--to", "4"]] {
        let narrated = narrate("window-refused", &bytes, &refused, &here());
        assert_eq!(
            (narrated.code, narrated.text),
            (2, None),
            "{}",
            narrated.err
        );
        assert!(narrated.err.contains("outside the 3 turns"));
    }
}

/// A violation whose next semantic record is an identity of the settled
/// site belongs to the settlement; one with a run-site identity stays in
/// the turn it followed. Neither notes an unrecorded site.
#[test]
fn a_settled_violation_renders_at_settlement() {
    let failure = Failure::Violation(Obligation::Restart, "x");
    for (site, place) in [(Site::Settled, "settle context"), (Site::Run, "turn 0")] {
        let violated = Violated::Observed(failure.clone());
        let violation = violation_record(&violated.code());
        let records = [
            clock(5),
            turn(5, 1),
            violation,
            event_record(&violated.identity(site)),
        ];
        let bytes = handmade(&records, VIOLATED);
        let text = narrate("settled", &bytes, &[], &here()).text.unwrap();
        assert!(text.contains(&format!("{place}: violation")), "{text}");
        assert!(!text.contains("site unrecorded"), "{text}");
    }
}

/// Malformed input is refused with exit 2 and no narrative: a reordered
/// or edited semantic record, a changed or missing checkpoint, a partial
/// record after a complete bundle, an unknown tag, a field chunk out of
/// order, a manifest that does not parse, more records than
/// `--max-records` or than the recorded manifest's maximum, an oversized
/// manifest value, whose reason is cut, a missing bundle, a directory, a
/// socket and a FIFO no writer holds; each refusal occurs, as the reason
/// shows.
#[test]
fn malformed_input_is_refused() {
    let bytes = timeline_bundle();
    let records = bytes.len() / RECORD;
    let at = |kind: Tag| {
        bytes
            .chunks(RECORD)
            .position(|record| record[0] == kind as u8)
            .unwrap()
    };
    let edit = |edit: &dyn Fn(&mut Vec<u8>)| {
        let mut edited = bytes.clone();
        edit(&mut edited);
        edited
    };
    let (first, checkpoint, diagnostic) = (at(Tag::Turn), at(Tag::Checkpoint), at(Tag::Diagnostic));
    let cases: Vec<(&str, Vec<u8>, &[&str], &str)> = vec![
        (
            "reordered",
            edit(&|bytes| {
                let (left, right) = bytes.split_at_mut((first + 1) * RECORD);
                left[first * RECORD..].swap_with_slice(&mut right[..RECORD]);
            }),
            &[],
            "Checkpoint",
        ),
        (
            "edited",
            edit(&|bytes| bytes[first * RECORD + 5] ^= 1),
            &[],
            "Checkpoint",
        ),
        (
            "checkpoint",
            edit(&|bytes| bytes[checkpoint * RECORD + 9] ^= 1),
            &[],
            "Checkpoint",
        ),
        (
            "missing",
            edit(&|bytes| drop(bytes.drain(checkpoint * RECORD..(checkpoint + 1) * RECORD))),
            &[],
            "Checkpoint",
        ),
        ("torn", edit(&|bytes| bytes.extend([1; 7])), &[], "Torn"),
        (
            "tag",
            edit(&|bytes| bytes[diagnostic * RECORD] = 11),
            &[],
            "Tag",
        ),
        (
            "capped",
            bytes.clone(),
            &["--max-records", "30"],
            "more than 30 records",
        ),
        (
            "zero",
            bytes.clone(),
            &["--max-records", "0"],
            "not a readable bound",
        ),
        (
            "overflow",
            bytes.clone(),
            &["--max-records", "18446744073709551615"],
            "not a readable bound",
        ),
    ];
    for (name, input, flags, reason) in cases {
        let narrated = narrate(name, &input, flags, &here());
        assert_eq!(
            (narrated.code, narrated.text.is_some()),
            (2, false),
            "{name}: {}",
            narrated.err
        );
        assert!(narrated.err.contains(reason), "{name}: {}", narrated.err);
    }
    assert_eq!(records, 31);
    let wide = manifest("upload", 3).capacity();
    let narrated = narrate("manifest-cap", &capped(80), &[], &here());
    assert_eq!(narrated.code, 2);
    assert!(
        narrated.err.contains("records past the manifest's maximum"),
        "{}",
        narrated.err
    );
    let canonical = manifest("upload", 3).canonical();
    for (name, text) in [
        (
            "version",
            canonical.replacen(
                "version = 2",
                &format!("version = {}", "9".repeat(20_000)),
                1,
            ),
        ),
        ("key", format!("{canonical}{} = 1\n", "k".repeat(20_000))),
    ] {
        let mut recorder = Recorder::new(Vec::new(), wide);
        recorder.field(Field::Manifest, text.as_bytes());
        let narrated = narrate(
            name,
            &recorder.finish(PASS, Work::default()).sink,
            &[],
            &here(),
        );
        assert_eq!((narrated.code, narrated.text), (2, None), "{name}");
        assert!(narrated.err.len() < 4200, "{name}: {}", narrated.err.len());
        assert!(
            narrated.err.ends_with(" [cut]\n"),
            "{name}: {}",
            narrated.err
        );
    }
    let mut recorder = Recorder::new(Vec::new(), wide);
    recorder.field(Field::Manifest, b"version = 2\nprofile = upload\n");
    let unparsed = recorder.finish(PASS, Work::default()).sink;
    let narrated = narrate("manifest", &unparsed, &[], &here());
    assert_eq!((narrated.code, narrated.text), (2, None));
    assert!(narrated.err.contains("Input(\"Missing"), "{}", narrated.err);
    let mut chunk = [0; RECORD];
    chunk[..4].copy_from_slice(&[Tag::Field as u8, Field::Manifest as u8, 5, 0]);
    let out_of_order = handmade(&[chunk], PASS);
    let narrated = narrate("chunk", &out_of_order, &[], &here());
    assert_eq!((narrated.code, narrated.text), (2, None));
    assert!(narrated.err.contains("Field { at: "), "{}", narrated.err);
    let dir = super::super::scratch("narrate-irregular").unwrap();
    // A socket path must fit sun_path's 108 bytes wherever the scratch
    // directory lies, so it names the directory through its descriptor.
    let handle = std::fs::File::open(&dir).unwrap();
    let fd = std::os::fd::AsRawFd::as_raw_fd(&handle);
    let socket = std::path::PathBuf::from(format!("/proc/self/fd/{fd}/socket"));
    #[expect(
        clippy::disallowed_methods,
        reason = "the CLI fixture supplies a socket path to check refusal of nonregular files"
    )]
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let fifo = dir.join("fifo");
    let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: `name` is a NUL-terminated path that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    for (input, reason) in [
        (dir.join("absent"), "No such file"),
        (dir.clone(), "not a regular file"),
        (socket.clone(), "not a regular file"),
        (fifo, "not a regular file"),
    ] {
        let args = [
            input.display().to_string(),
            "--output".into(),
            dir.join("out").display().to_string(),
        ];
        // A FIFO with no writer blocks an open that waits, so the run
        // has a deadline.
        let (sent, received) = std::sync::mpsc::channel();
        #[expect(
            clippy::disallowed_methods,
            reason = "the CLI fixture bounds a potentially blocking FIFO open outside simulation"
        )]
        std::thread::spawn(move || {
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let code = run(&args, here, &mut out, &mut err);
            sent.send((code, String::from_utf8_lossy(&err).into_owned()))
        });
        let (code, err) = received
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("the open does not block");
        assert_eq!(code, 2, "{input:?}: {err}");
        assert!(err.contains(reason), "{input:?}: {err}");
        assert!(!dir.join("out").exists());
    }
    drop(handle);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Each command-line refusal exits 2 before any output exists: no bundle,
/// no output, a flag of another form, a repeated flag, a value missing or
/// not canonical, and the failure tier beside `--events` or a turn window.
#[test]
fn malformed_command_lines_are_refused() {
    let bytes = timeline_bundle();
    for (flags, reason) in [
        (&["--events", "--events"][..], "unknown or repeated"),
        (&["--from", "1", "--from", "1"], "given twice"),
        (&["--from", "01"], "not a canonical count"),
        (&["--to", "+1"], "not a canonical count"),
        (&["--to"], "needs a value"),
        (&["--milestone", "x"], "unknown or repeated"),
        (&["--output", "again"], "unknown or repeated"),
        (&["--failure", "--failure"], "unknown or repeated"),
        (&["--failure", "--events"], "whole bundle: no --events"),
        (&["--events", "--failure"], "whole bundle: no --events"),
        (&["--failure", "--from", "0"], "whole bundle: no --events"),
        (&["--to", "1", "--failure"], "whole bundle: no --events"),
    ] {
        let narrated = narrate("flags", &bytes, flags, &here());
        assert_eq!((narrated.code, narrated.text), (2, None), "{flags:?}");
        assert!(narrated.err.contains(reason), "{flags:?}: {}", narrated.err);
    }
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(run(&[], here, &mut out, &mut err), 2);
    assert_eq!(run(&["bundle".into()], here, &mut out, &mut err), 2);
    assert!(String::from_utf8_lossy(&err).contains("--output is required"));
    assert!(out.is_empty());
}

/// A stream that ends before its terminal's checkpoint, a partial record
/// at its end included, and a run that ended in an infrastructure class
/// with its violation kept, render annotated narratives and exit 3; the
/// kept violation renders.
#[test]
fn incomplete_evidence_renders_annotated_with_exit_3() {
    let bytes = timeline_bundle();
    for (name, cut) in [
        ("truncated", bytes.len() - RECORD),
        ("partial", bytes.len() - RECORD - 20),
    ] {
        let narrated = narrate(name, &bytes[..cut], &[], &here());
        assert_eq!(narrated.code, 3, "{name}: {}", narrated.err);
        let text = narrated.text.unwrap();
        assert!(
            text.contains("evidence: incomplete: the stream ends before its terminal's checkpoint")
        );
        assert!(text.contains("terminal: infrastructure truncated"));
        assert!(text.contains(": violation variant=violation"));
        assert!(narrated.out.ends_with("incomplete\n"));
        if name == "partial" {
            assert!(text.contains(", 28 trailing bytes;"), "{text}");
        }
    }
    let capped = handmade(&timeline(), Terminal::Infrastructure(Infrastructure::Cap));
    let narrated = narrate("capped-violation", &capped, &[], &here());
    assert_eq!(narrated.code, 3);
    let text = narrated.text.unwrap();
    assert!(text.contains("evidence: incomplete: the run ended in an infrastructure class"));
    assert!(
        text.contains("turn 2: violation variant=violation obligation=Bytes"),
        "{text}"
    );
    assert!(text.contains("terminal class=infrastructure infrastructure=cap"));
}

/// The header names the recorded pins beside the decoder's: a decoder of
/// another executable says the bundle pins another, one that cannot read
/// itself renders with exit 3 and says the pin may differ, and a profile
/// outside the catalog leaves its workload candidates as spare bytes; each
/// free-text manifest value prints quoted with its control bytes escaped.
#[test]
fn the_header_names_pins_and_naming_provenance() {
    let bytes = timeline_bundle();
    let foreign = (Ok("b".repeat(64)), "x86_64-linux".to_owned());
    let narrated = narrate("foreign", &bytes, &[], &foreign);
    assert_eq!(narrated.code, 0);
    let text = narrated.text.unwrap();
    assert!(text.contains(&format!(
        "pins: executable={EXECUTABLE} platform=\"x86_64-linux\""
    )));
    assert!(text.contains(&format!(
        "decoder: executable={} platform=x86_64-linux",
        "b".repeat(64)
    )));
    assert!(
        text.contains(
            "names: this decoder's tables; the bundle pins another executable or platform"
        )
    );
    let blind = (Err("denied".to_owned()), "x86_64-linux".to_owned());
    let narrated = narrate("blind", &bytes, &[], &blind);
    assert_eq!(narrated.code, 3);
    let text = narrated.text.unwrap();
    assert!(text.contains("decoder: executable=unreadable (denied)"));
    assert!(
        text.contains("the bundle pins another executable or platform, or the decoder cannot read"),
        "{text}"
    );
    assert!(text.contains("evidence: incomplete: the decoder cannot read its own executable"));
    let elsewhere = (Ok(EXECUTABLE.to_owned()), "aarch64-linux".to_owned());
    let text = narrate("platform", &bytes, &[], &elsewhere).text.unwrap();
    assert!(
        text.contains("the bundle pins another executable or platform"),
        "{text}"
    );
    let text = narrate("same", &bytes, &[], &here()).text.unwrap();
    assert!(
        text.contains("built into the executable the bundle pins"),
        "{text}"
    );
    let unlisted = manifest("upload", 3);
    let text = unlisted
        .canonical()
        .replace("profile = upload", "profile = re\u{1b}[2J\rtired")
        .replace(
            &format!("platform = {}", unlisted.platform),
            "platform = x86\u{1b}64 build=forged",
        )
        .replace(
            &format!("scenario = {}", unlisted.scenario),
            "scenario = s\u{7}x",
        )
        .replace(
            &format!("toolchain = {}", unlisted.toolchain),
            "toolchain = t\u{8}c",
        );
    let mut recorder = Recorder::new(Vec::new(), unlisted.capacity());
    recorder.field(Field::Manifest, text.as_bytes());
    recorder.raw(&clock(1));
    recorder.raw(&turn(1, 1));
    let bytes = recorder.finish(PASS, Work::default()).sink;
    let narrated = narrate("unlisted", &bytes, &[], &here());
    let text = narrated.text.unwrap();
    assert!(text.contains("a profile outside this catalog"), "{text}");
    for escaped in [
        "profile: \"re\\u{1b}[2J\\rtired\" root=3 scenario=\"s\\u{7}x\"\n",
        " platform=\"x86\\u{1b}64 build=forged\" build=",
        " toolchain=\"t\\u{8}c\"\n",
    ] {
        assert!(text.contains(escaped), "{escaped} {text}");
    }
    assert!(!text.contains(['\u{1b}', '\r', '\u{7}', '\u{8}']), "{text}");
    assert!(
        text.contains("turn 0: now_us=1 domain=Workload outcome=0 spare@13=01"),
        "{text}"
    );
}

/// An output path that exists, the input's own path included, is refused
/// and left as it was; one in a missing directory, and an input the host
/// cannot read, are host failures with no narrative; a write or flush that
/// fails mid-narrative exits 3 and names the partial file, and a failed
/// write or flush of the status line exits 3 and names the whole file.
#[test]
fn output_failures_have_their_outcomes() {
    let bytes = timeline_bundle();
    let dir = super::super::scratch("narrate-output").unwrap();
    let bundle = dir.join("bundle");
    std::fs::write(&bundle, &bytes).unwrap();
    std::fs::write(dir.join("taken"), b"kept").unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let args = |output: &std::path::Path| {
        [
            bundle.display().to_string(),
            "--output".into(),
            output.display().to_string(),
        ]
    };
    assert_eq!(run(&args(&dir.join("taken")), here, &mut out, &mut err), 2);
    assert_eq!(std::fs::read(dir.join("taken")).unwrap(), b"kept");
    assert_eq!(run(&args(&bundle), here, &mut out, &mut err), 2);
    assert_eq!(std::fs::read(&bundle).unwrap(), bytes);
    assert_eq!(
        run(
            &args(&dir.join("absent/narrative")),
            here,
            &mut out,
            &mut err
        ),
        3
    );
    // A regular file whose first read fails for every user: this
    // process's memory at address 0, which no mapping covers.
    let unread = [
        "/proc/self/mem".to_owned(),
        "--output".into(),
        dir.join("unread").display().to_string(),
    ];
    assert_eq!(run(&unread, here, &mut out, &mut err), 3);
    assert!(!dir.join("unread").exists());
    assert!(String::from_utf8_lossy(&err).contains("bundle /proc/self/mem: "));
    // An open that fails for every user: a path through a regular file.
    let through = [
        bundle.join("x").display().to_string(),
        "--output".into(),
        dir.join("through").display().to_string(),
    ];
    assert_eq!(run(&through, here, &mut out, &mut err), 3);
    assert!(!dir.join("through").exists());
    assert!(String::from_utf8_lossy(&err).contains("Not a directory"));
    assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));
    std::fs::remove_dir_all(&dir).unwrap();
    struct Full;
    impl std::io::Write for Full {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("no space"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let loaded = crate::sim::trace::load(&bytes, MAX_RECORDS).unwrap();
    let manifest = super::super::replay::manifest_of(&loaded).unwrap();
    let window = Window {
        from: 0,
        to: 3,
        tier: super::Tier::Events,
    };
    // A sink that takes every write and fails its flush, as a buffered
    // file does on a full disk when the narrative fits its buffer.
    struct Unflushed;
    impl std::io::Write for Unflushed {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("no space"))
        }
    }
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let input = (bytes.as_slice(), &loaded, &manifest);
    for code in [
        super::emit((Full, "FILE"), input, window, &here(), &mut out, &mut err),
        super::emit(
            (Unflushed, "FILE"),
            input,
            window,
            &here(),
            &mut out,
            &mut err,
        ),
    ] {
        assert_eq!(code, 3);
    }
    let failed = "error: output FILE: no space; FILE holds a partial narrative\n";
    assert_eq!(
        (String::from_utf8(err).unwrap(), out.len()),
        (failed.repeat(2), 0)
    );
    let mut err = Vec::new();
    for mut out in [&mut Full as &mut dyn std::io::Write, &mut Unflushed] {
        let mut sink = Vec::new();
        let code = super::emit(
            (&mut sink, "FILE"),
            input,
            window,
            &here(),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 3);
        assert!(!sink.is_empty());
    }
    let whole = "error: stdout: no space; FILE holds the whole narrative\n";
    assert_eq!(String::from_utf8(err).unwrap(), whole.repeat(2));
}

/// A narrative of many records stays in its file, past a megabyte there,
/// while the form's own stdout holds one line and stderr nothing: the
/// in-process witness the module's tests select, beside the worker's
/// fresh-process case over the same bundle.
#[test]
fn a_large_narrative_stays_in_its_file() {
    let narrated = narrate("large", &large_bundle(), &["--events"], &here());
    assert_eq!((narrated.code, narrated.err.as_str()), (0, ""));
    assert!(narrated.text.unwrap().len() > 1 << 20);
    assert_eq!(narrated.out.lines().count(), 1, "{}", narrated.out);
}

/// A complete bundle of 12,000 turns, each with a `PUT` event, whose
/// events-tier narrative passes a megabyte.
pub(crate) fn large_bundle() -> Vec<u8> {
    let capacity = Capacity::new(64, 64, 100_000, 256).unwrap();
    let mut recorder = Recorder::new(Vec::new(), capacity);
    let text = manifest("upload", 3).with("records", 100_000).canonical();
    recorder.field(Field::Manifest, text.as_bytes());
    recorder.raw(&clock(0));
    for at in 0..12_000u64 {
        let put = event_put(ActionKind::Supply, 1, at, 2, &[7; 16], 0, 1);
        recorder.raw(&turn(at, 3));
        recorder.raw(&event_record(&put));
    }
    recorder.finish(PASS, Work::default()).sink
}

/// A recorded two-owner history names every turn, and names the peer in
/// exactly the turns [`Peer::owns`](super::super::peer::Peer::owns): a
/// workload turn by a peer code, a disk turn as `owner=peer` beside every
/// field its device's own candidate reads as, and a link turn by a link
/// index past the scripted owner's two. The run holds a peer turn of each
/// domain.
#[test]
fn a_two_owner_history_names_the_peers_turns() {
    use super::super::peer::{NETS, Peer};
    let bytes = recorded("h6-get", 3);
    let mut peers = [0; 3];
    for record in bytes.as_chunks::<RECORD>().0 {
        if Tag::from_code(record[0]) != Some(Tag::Turn) {
            continue;
        }
        let line = clean(decode(World::Mixed, record).line());
        let field = |name: &str| line.split(' ').find_map(|field| field.strip_prefix(name));
        let named = [
            field("code=").is_some_and(|code| code.starts_with("peer-")),
            field("owner=") == Some("peer"),
            field("net=").is_some_and(|net| net.parse::<u8>().unwrap() >= NETS),
        ];
        let candidate = Candidate(record[12..28].try_into().unwrap());
        assert_eq!(named.contains(&true), Peer::owns(&candidate), "{line}");
        if named[1] {
            let mut own = *record;
            own[14] = 0;
            let own = decode(World::Mixed, &own).line();
            assert_eq!(line.replace(" owner=peer", ""), own, "{line}");
        }
        for (turns, named) in peers.iter_mut().zip(named) {
            *turns += u32::from(named);
        }
    }
    assert!(peers.iter().all(|&turns| turns > 0), "{peers:?}");
}

/// Bundles this build records name every record in their world: no
/// rendered or hidden record of the mixed, faulted, history, cluster or
/// recovery runs prints an unknown code or a spare byte, each turn's time is the nearest
/// clock's before it, every turn renders as a turn counted from zero, so
/// settlement opens after the last, each run's event kinds occur as its
/// producers emit them, and a recorded violation renders as its violation
/// record with no `FAILURE` event and no unrecorded-site note, as the
/// stream records it; a history's script turns name their steps.
#[test]
fn recorded_bundles_name_every_record_in_their_world() {
    let cases: [(&str, u64, &str, &[&str]); 6] = [
        (
            "upload",
            3,
            "the mixed world",
            &["ACT", "WITNESS", "PUT", "UPLOAD", "STOP"],
        ),
        (
            "planted",
            3,
            "the mixed world",
            &["PUT", "UPLOAD", "IDENTITY", "STOP"],
        ),
        (
            "faulted",
            3,
            "the mixed world",
            &["AUDIT", "RULE", "UPLOAD", "STOP"],
        ),
        (
            "i3-put-hole",
            2_946_512_557_381_983_801,
            "the mixed world",
            &["RULE", "STOP"],
        ),
        (
            "cluster-broad",
            7,
            "the cluster world",
            &["ACT", "WITNESS", "COVERAGE", "STOP"],
        ),
        ("recovery-512", 3, "the recovery world", &["LEDGER", "STOP"]),
    ];
    for (profile, root, world, kinds) in cases {
        let bytes = recorded(profile, root);
        let narrated = narrate(profile, &bytes, &["--events"], &here());
        assert_eq!(narrated.code, 0, "{profile}: {}", narrated.err);
        let text = narrated.text.unwrap();
        assert!(text.contains(world), "{profile}");
        let (mut now, mut turns) = (None, 0);
        for line in body(&text) {
            let (place, record) = line.split_once(": ").unwrap();
            clean(record.to_owned());
            let time = record
                .strip_prefix("now_us=")
                .map(|rest| rest.split(' ').next().unwrap());
            if place.contains(" clock ") && time.is_some() {
                now = time;
            }
            if place.ends_with(&format!(" turn {turns}")) && time.is_some() {
                assert_eq!(time, now, "{profile}: {line}");
                turns += 1;
            }
            assert!(!record.contains("event FAILURE"), "{profile}: {line}");
        }
        let loaded = crate::sim::trace::load(&bytes, MAX_RECORDS).unwrap();
        assert_eq!(turns, loaded.turns.len(), "{profile}");
        let vocabulary = World::of(&manifest(profile, root));
        for record in bytes.as_chunks::<RECORD>().0 {
            if matches!(
                Tag::from_code(record[0]),
                Some(Tag::Turn | Tag::Clock | Tag::Event | Tag::Violation | Tag::Terminal)
            ) {
                clean(decode(vocabulary, record).line());
            }
        }
        assert!(!text.contains("site unrecorded"), "{profile}");
        assert_eq!(
            text.contains("(step "),
            world == "the mixed world" && profile.starts_with('i')
        );
        let script = super::super::bundle::named(profile, root).unwrap().1.script;
        let steps: Vec<&str> = body(&text)
            .into_iter()
            .filter(|line| line.contains(" code=script "))
            .collect();
        assert_eq!(steps.is_empty(), script.is_empty(), "{profile}");
        for line in steps {
            let step = line
                .split(" step=")
                .nth(1)
                .unwrap()
                .split(' ')
                .next()
                .unwrap();
            let name = script[step.parse::<usize>().unwrap()].name;
            assert!(line.ends_with(&format!(" (step {name})")), "{line}");
        }
        assert!(turns > 0 && text.contains(&format!("of {turns}, tier events")));
        for kind in kinds {
            assert!(
                text.contains(&format!(": event {kind} ")),
                "{profile} lacks {kind}"
            );
        }
        let violations = body(&text)
            .iter()
            .filter(|line| line.contains(": violation "))
            .count();
        let violating = text.contains("terminal: complete violation");
        assert_eq!(violations, usize::from(violating), "{profile}");
        assert_eq!(violating, profile == "planted", "{profile}");
    }
}

/// Every `UPLOAD` event a recorded upload, planted or faulted run holds
/// names each field as [`UploadState::of`](super::super::bundle::UploadState::of),
/// the decoder beside its encoder, reads it, with the collected outcome
/// its producer's code names, every outcome listed, and an upload run
/// collects one published.
#[test]
fn upload_events_name_the_state_their_producer_recorded() {
    use super::super::super::upload::UploadOutcome;
    use super::super::bundle::UploadState;
    let outcomes = [
        (UploadOutcome::Published, "published"),
        (
            UploadOutcome::Failed(super::super::super::frame::Status::Missing),
            "failed",
        ),
        (UploadOutcome::NotStarted, "not-started"),
        (UploadOutcome::Unknown, "unknown"),
    ];
    // An outcome this list leaves out fails to compile here.
    let listed = |outcome: UploadOutcome| match outcome {
        UploadOutcome::Published
        | UploadOutcome::Failed(_)
        | UploadOutcome::NotStarted
        | UploadOutcome::Unknown => (),
    };
    outcomes.iter().for_each(|(outcome, _)| listed(*outcome));
    assert_eq!(super::UPLOADS.split(',').count(), outcomes.len() + 2);
    let name = |code: u8| {
        let mut named = outcomes
            .iter()
            .filter(|(outcome, _)| UploadState::code(*outcome) == code)
            .map(|(_, name)| *name);
        if code == 0 {
            Some("uncollected")
        } else {
            named.next()
        }
    };
    let mut published = false;
    for profile in ["upload", "planted", "faulted"] {
        let bytes = recorded(profile, 3);
        let loaded = crate::sim::trace::load(&bytes, MAX_RECORDS).unwrap();
        let uploads: Vec<&Event> = loaded
            .events
            .iter()
            .filter(|event| event.kind == super::super::bundle::UPLOAD)
            .collect();
        assert!(!uploads.is_empty(), "{profile}");
        for event in uploads {
            let state = UploadState::of(event).unwrap();
            let expected = format!(
                "event UPLOAD attempt={} serial={} base={} grant={} held_slots={} outcome={} bound={}",
                state.attempt,
                state.serial,
                state.base,
                state.grant,
                state.held,
                name(state.outcome).unwrap(),
                if state.bound { "yes" } else { "no" },
            );
            assert_eq!(event_line(event), expected, "{profile}");
            published |= state.outcome == UploadState::code(UploadOutcome::Published);
        }
    }
    assert!(published);
    let mut event = Event {
        kind: super::super::bundle::UPLOAD,
        payload: [0; PAYLOAD],
    };
    event.payload[..22].copy_from_slice(&[
        2, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 1,
    ]);
    for (outcome, named) in outcomes {
        event.payload[20] = UploadState::code(outcome);
        let state = UploadState::of(&event).unwrap();
        let line = event_line(&event);
        let fields = format!(
            "attempt={} serial={} base={} grant={} held_slots={} outcome={named} bound=yes",
            state.attempt, state.serial, state.base, state.grant, state.held
        );
        assert!(line.ends_with(&fields), "{line}");
    }
}

/// A `RULE` event carries its capture's canonical code: every field of a
/// capture with distinct values names the value the capture held, its
/// sentinel index and delay name none, and every drop, corruption and
/// reorder and truncation decision names the variant the capture held.
#[test]
fn rule_events_name_the_capture_their_producer_encoded() {
    use super::super::super::frame::Kind;
    use super::super::super::rules::{Capture, Decision, Dropped};
    let capture = |index, delay| Capture {
        tap: 3,
        link: 0x0105,
        toward: 1,
        ordinal: 0x01_0203_0405,
        kind: Some(Kind::PutAck),
        index,
        grant: Some(77),
        decision: Decision {
            drop: Some(Dropped::Isolated(9)),
            duplicate: true,
            delay,
            reorder: Some(false),
            truncate: Some(true),
            corrupt: Some(Corruption::PutBody),
        },
    };
    let event = |capture: &Capture| {
        let mut payload = [0; PAYLOAD];
        payload[0] = 1;
        payload[1..33].copy_from_slice(&super::super::bundle::capture_code(capture));
        Event {
            kind: crate::net::world_tests::bundle::RULE,
            payload,
        }
    };
    let line = event_line(&event(&capture(Some(7), Some(300))));
    let fields = "event RULE net=1 tap=3 link=261 toward=1 ordinal=4328719365 message=PutAck \
        index=7 dropped=isolated rule_at=9 duplicate=yes delay=300 reorder_truncate=false/true \
        corrupt=PutBody";
    assert!(line.starts_with(fields), "{line}");
    let line = event_line(&event(&capture(None, None)));
    assert!(
        line.contains(" index=none ") && line.contains(" delay=none "),
        "{line}"
    );
    let drops = [
        (None, "no rule_at=0"),
        (Some(Dropped::Fault), "fault rule_at=0"),
        (Some(Dropped::Rule(4)), "rule rule_at=4"),
        (Some(Dropped::Isolated(5)), "isolated rule_at=5"),
        (Some(Dropped::Burst), "burst rule_at=0"),
        (Some(Dropped::Resend), "resend rule_at=0"),
    ];
    for (drop, named) in drops {
        let mut dropped = capture(None, None);
        dropped.decision.drop = drop;
        let line = event_line(&event(&dropped));
        assert!(line.contains(&format!(" dropped={named} ")), "{line}");
    }
    let corruptions = [
        (None, "none"),
        (Some(Corruption::Header), "Header"),
        (Some(Corruption::Tag), "Tag"),
        (Some(Corruption::GetBody), "GetBody"),
        (Some(Corruption::PutBody), "PutBody"),
        (Some(Corruption::Unsupported), "Unsupported"),
    ];
    for (corrupt, named) in corruptions {
        let mut corrupted = capture(None, None);
        corrupted.decision.corrupt = corrupt;
        let line = event_line(&event(&corrupted));
        assert!(line.contains(&format!(" corrupt={named} (")), "{line}");
    }
    for (reorder, truncate, named) in [
        (None, None, "none/none"),
        (Some(true), Some(false), "true/false"),
    ] {
        let mut flagged = capture(None, None);
        (flagged.decision.reorder, flagged.decision.truncate) = (reorder, truncate);
        let line = event_line(&event(&flagged));
        assert!(
            line.contains(&format!(" reorder_truncate={named} ")),
            "{line}"
        );
    }
}

/// The terminal record [`Recorder::finish`] writes names its class, each
/// tested outcome or infrastructure class, its masks and each work field.
#[test]
fn terminals_name_the_class_and_work_their_recorder_wrote() {
    let work = Work {
        turns: 11,
        decisions: 12,
        progress: 13,
        virtual_us: 14,
        skipped_us: 15,
    };
    let lines = [
        (
            Terminal::Complete {
                outcome: Outcome::Unsuccessful,
                fired: 5,
                required: 7,
            },
            "terminal class=complete outcome=unsuccessful fired=05 required=07",
        ),
        (
            Terminal::Complete {
                outcome: Outcome::Inconclusive,
                fired: 0,
                required: 1,
            },
            "terminal class=complete outcome=inconclusive fired=00 required=01",
        ),
        (
            Terminal::Complete {
                outcome: Outcome::Pass,
                fired: 3,
                required: 2,
            },
            "terminal class=complete outcome=pass fired=03 required=02",
        ),
        (
            Terminal::Infrastructure(Infrastructure::Defect),
            "terminal class=infrastructure infrastructure=defect",
        ),
        (
            Terminal::Infrastructure(Infrastructure::Sink),
            "terminal class=infrastructure infrastructure=sink",
        ),
    ];
    for (terminal, named) in lines {
        let capacity = manifest("upload", 3).capacity();
        let sink = Recorder::new(Vec::new(), capacity)
            .finish(terminal, work)
            .sink;
        let record = sink
            .as_chunks::<RECORD>()
            .0
            .iter()
            .find(|record| record[0] == Tag::Terminal as u8)
            .unwrap();
        let line = clean(decode(World::Mixed, record).line());
        let expected =
            format!("{named} turns=11 decisions=12 progress=13 virtual_us=14 skipped_us=15");
        assert_eq!(line, expected);
    }
}

/// Each name list matches its producer's whole enumeration: every
/// obligation through a failure's code, every audit class through an audit
/// record and its identity, every reason through its canonical code, every
/// action kind, every PUT descriptor and every held-update delivery
/// outcome, each list checked whole against its enum; a delivery outcome
/// past the closed table prints unknown.
#[test]
fn every_vocabulary_matches_its_producer_enumeration() {
    for obligation in Obligation::ALL {
        let line = event_line(&failure_event(&Failure::Violation(obligation, "r")));
        assert!(
            line.contains(&format!(" obligation={obligation:?} ")),
            "{line}"
        );
        let identity = Violated::Observed(Failure::Violation(obligation, "r")).identity(Site::Run);
        assert!(event_line(&identity).contains(&format!(" obligation={obligation:?} ")));
    }
    for class in Class::ALL {
        let record = Record {
            class,
            reason: Reason::Lost,
            source: Source::Device(2),
        };
        assert!(event_line(&audit_event(0, &record)).contains(&format!(" class={class:?} ")));
        let identity = Violated::Audit(record).identity(Site::Settled);
        assert!(event_line(&identity).contains(&format!(" class={class:?} ")));
    }
    use crate::storage::device::sim::Omission;
    let reasons = [
        Reason::Lost,
        Reason::RuleDrop,
        Reason::Isolated,
        Reason::Duplicated,
        Reason::Stale,
        Reason::Delayed,
        Reason::Reordered,
        Reason::Truncated,
        Reason::Corrupted(Corruption::Tag),
        Reason::Inapplicable(Corruption::Header),
        Reason::WouldBlock,
        Reason::CallFailed,
        Reason::DeadEnd,
        Reason::Missed,
        Reason::Full(Bound::Captures),
        Reason::ForeignPeer,
        Reason::Oversize,
        Reason::NotHoldable,
        Reason::PrematureReturn,
        Reason::Altered,
        Reason::DeviceRefused(
            crate::storage::device::sim::Origin::Model,
            crate::storage::RefusalReason::QueueFull,
        ),
        Reason::DeviceInjected(crate::storage::device::sim::Injection::Foreign),
        Reason::DeviceLost,
        Reason::Unattributed,
        Reason::DeviceOmitted(Omission::Episode),
        Reason::DeviceFalseStopped,
        Reason::LostBurst,
        Reason::LostResend,
    ];
    // A reason this list leaves out fails to compile here.
    let listed = |reason: Reason| match reason {
        Reason::Lost
        | Reason::RuleDrop
        | Reason::Isolated
        | Reason::Duplicated
        | Reason::Stale
        | Reason::Delayed
        | Reason::Reordered
        | Reason::Truncated
        | Reason::Corrupted(_)
        | Reason::Inapplicable(_)
        | Reason::WouldBlock
        | Reason::CallFailed
        | Reason::DeadEnd
        | Reason::Missed
        | Reason::Full(_)
        | Reason::ForeignPeer
        | Reason::Oversize
        | Reason::NotHoldable
        | Reason::PrematureReturn
        | Reason::Altered
        | Reason::DeviceRefused(..)
        | Reason::DeviceInjected(_)
        | Reason::DeviceLost
        | Reason::Unattributed
        | Reason::DeviceOmitted(_)
        | Reason::DeviceFalseStopped
        | Reason::LostBurst
        | Reason::LostResend => (),
    };
    reasons.iter().copied().for_each(listed);
    assert_eq!(super::REASONS.split(',').count(), reasons.len() + 1);
    let mut codes: Vec<u8> = reasons
        .iter()
        .map(|reason| reason_code(*reason)[0])
        .collect();
    codes.sort_unstable();
    assert_eq!(
        codes,
        (1..=28).collect::<Vec<u8>>(),
        "every reason code once"
    );
    for reason in reasons {
        let record = Record {
            class: Class::Injected,
            reason,
            source: Source::Device(2),
        };
        let line = event_line(&audit_event(0, &record));
        let word = format!("{reason:?}");
        let word = word.split('(').next().unwrap();
        assert!(line.contains(&format!(" reason={word} ")), "{line}");
    }
    for kind in ActionKind::ALL {
        let mut acts = Vec::new();
        act_events(&mut acts, kind, 2, false);
        assert_eq!(
            event_line(&acts[0]),
            format!("event ACT action={kind:?} outcome=2")
        );
        let line = turn_line(World::Mixed, super::super::action(kind, 1, 0).0, 0);
        assert!(line.contains(&format!(" code={kind:?} actor=1 ")), "{line}");
    }
    let (key, attempt) = (6, 2);
    let actions = [
        (
            PutAction::Begin { key, attempt },
            "begin key=6 attempt=2 arg=0",
        ),
        (
            PutAction::Prepare { key, attempt },
            "prepare key=6 attempt=2 arg=0",
        ),
        (
            PutAction::Supply {
                key,
                attempt,
                fragment: 3,
            },
            "supply key=6 attempt=2 fragment=3",
        ),
        (
            PutAction::Defer {
                key,
                attempt,
                ready_us: 9,
            },
            "defer key=6 attempt=2 ready_us=9",
        ),
        (
            PutAction::Cancel { key, attempt },
            "cancel key=6 attempt=2 arg=0",
        ),
        (
            PutAction::Abandon { key, attempt },
            "abandon key=6 attempt=2 arg=0",
        ),
        (
            PutAction::Outcome { key, attempt },
            "outcome key=6 attempt=2 arg=0",
        ),
        (
            PutAction::Retry { key, attempt },
            "retry key=6 attempt=2 arg=0",
        ),
    ];
    // A descriptor this list leaves out fails to compile here.
    let listed = |action: PutAction| match action {
        PutAction::Begin { .. }
        | PutAction::Prepare { .. }
        | PutAction::Supply { .. }
        | PutAction::Defer { .. }
        | PutAction::Cancel { .. }
        | PutAction::Abandon { .. }
        | PutAction::Outcome { .. }
        | PutAction::Retry { .. } => (),
    };
    actions.iter().for_each(|(action, _)| listed(*action));
    assert_eq!(super::PUTS.split(',').count(), actions.len() + 1);
    for (action, named) in actions {
        let line = turn_line(World::Mixed, action.candidate().0, 1);
        assert!(
            line.contains(&format!("domain=Put action={named} outcome=1")),
            "{line}"
        );
    }
    use super::super::{DELIVERED, REKEY_BUSY, REKEY_CUT, REKEY_REFUSED, REKEY_ZERO, REKEYED};
    for (outcome, named) in [
        (DELIVERED, "delivered"),
        (REKEYED, "rekeyed"),
        (REKEY_BUSY, "rekey-busy"),
        (REKEY_REFUSED, "rekey-refused"),
        (REKEY_CUT, "rekey-cut"),
        (REKEY_ZERO, "rekey-zero"),
    ] {
        let mut delivered = super::super::candidate(super::super::DELIVER, 0, 0).0;
        delivered[7] = ActionKind::SessionChange as u8;
        let line = turn_line(World::Mixed, delivered, outcome);
        assert!(line.ends_with(&format!("outcome={named}")), "{line}");
    }
    let delivered = super::super::candidate(super::super::DELIVER, 0, 0).0;
    let line = raw_turn_line(World::Mixed, delivered, REKEY_ZERO + 1);
    assert!(
        line.ends_with(&format!(" outcome=unknown({})", REKEY_ZERO + 1)),
        "{line}"
    );
    assert!(
        raw_turn_line(
            World::Mixed,
            super::super::action(ActionKind::Get, 0, 0).0,
            9
        )
        .ends_with(" outcome=9")
    );
}

/// An identity of a version other than 2 names its version alone and
/// leaves every other byte spare, and a version-1 identity whose byte at
/// the version-2 site offset reads as settled does not move the violation
/// before it into settlement, which notes its site as unrecorded, as does a
/// violation no identity follows. A failure variant or terminal class this
/// decoder does not know names no field it selects.
#[test]
fn unknown_encodings_name_nothing_they_cannot_read() {
    let mut identity =
        Violated::Observed(Failure::Violation(Obligation::Bytes, "x")).identity(Site::Settled);
    for version in [1, 3] {
        identity.payload[0] = version;
        let line = raw_event_line(&identity);
        assert!(
            line.starts_with(&format!("event IDENTITY version={version} spare@5=")),
            "{line}"
        );
        assert!(line.ends_with("(this decoder reads the fields of identity version 2 alone)"));
    }
    identity.payload[0] = 1;
    let violated = Violated::Observed(Failure::Violation(Obligation::Bytes, "x"));
    let violation = violation_record(&violated.code());
    let records = [clock(5), turn(5, 1), violation, event_record(&identity)];
    let bytes = handmade(&records, VIOLATED);
    let text = narrate("identity-v1", &bytes, &[], &here()).text.unwrap();
    assert!(
        text.contains("turn 0: violation variant=violation"),
        "{text}"
    );
    assert!(
        text.contains("(site unrecorded: no version-2 identity event follows)"),
        "{text}"
    );
    for variant in [0, 9, 0x85] {
        let mut payload = [0; PAYLOAD];
        payload[..5].copy_from_slice(&[variant, 1, 1, b'x', 0]);
        let record = violation_record(&payload);
        let line = decode(World::Mixed, &record).line();
        assert_eq!(
            line,
            format!("violation variant=unknown({variant}) spare@5=010178")
        );
    }
    let mut terminal = [0; RECORD];
    terminal[..6].copy_from_slice(&[Tag::Terminal as u8, 0, 0, 0, 3, 1]);
    assert_eq!(
        decode(World::Mixed, &terminal).line(),
        "terminal class=unknown(3) turns=0 decisions=0 progress=0 virtual_us=0 skipped_us=0 \
            spare@5=01"
    );
    let text = narrate("unrecorded", &timeline_bundle(), &[], &here())
        .text
        .unwrap();
    assert!(
        text.contains("rule=\"x\" (site unrecorded: no version-2 identity event follows)"),
        "{text}"
    );
}

/// A table token that names no list and holds no comma fails closed: a
/// misspelled list or special decoder panics instead of naming a value.
#[test]
#[should_panic(expected = "no list is named CLASS")]
fn a_misspelled_list_panics() {
    super::named("CLASS", 0, 1);
}

#[test]
#[should_panic(expected = "no table is named actoin")]
fn a_misspelled_table_panics() {
    super::named("actoin", 0, 1);
}

/// The bounds accept their edges: a bundle of exactly `--max-records`
/// records and one of exactly its manifest's maximum render; a complete
/// unsuccessful or inconclusive run exits 0; and with `--events` a failure
/// or identity event recorded at a turn outside the window renders as
/// context while that turn's other events stay out.
#[test]
fn edges_and_context_events_render() {
    let bytes = timeline_bundle();
    let count = (bytes.len() / RECORD).to_string();
    assert_eq!(
        narrate("max-edge", &bytes, &["--max-records", &count], &here()).code,
        0
    );
    let base = (capped(0).len() / RECORD) as u64;
    let edge = capped(70 - base);
    assert_eq!(edge.len() / RECORD, 70);
    assert_eq!(narrate("cap-edge", &edge, &[], &here()).code, 0);
    let mut acts = Vec::new();
    act_events(&mut acts, ActionKind::Get, 1, false);
    let observed = failure_event(&Failure::Unsuccessful("probe"));
    let mut failed = observed;
    failed.kind = super::super::bundle::FAILURE;
    let records = [
        clock(1),
        turn(1, 1),
        event_record(&acts[0]),
        event_record(&observed),
        event_record(&failed),
        turn(1, 2),
        turn(1, 3),
    ];
    for (outcome, name) in [
        (Outcome::Unsuccessful, "unsuccessful"),
        (Outcome::Inconclusive, "inconclusive"),
    ] {
        let terminal = Terminal::Complete {
            outcome,
            fired: 3,
            required: 3,
        };
        let bytes = handmade(&records, terminal);
        let narrated = narrate(name, &bytes, &["--events", "--from", "2"], &here());
        assert_eq!(narrated.code, 0, "{}", narrated.err);
        let text = narrated.text.unwrap();
        assert!(text.contains(&format!("terminal: complete {name}")));
        let lines: Vec<&str> = body(&text)
            .into_iter()
            .map(|line| line.split_once(' ').unwrap().1)
            .collect();
        assert!(lines[0].starts_with("clock 0 context:"), "{lines:#?}");
        assert!(lines[1].starts_with("turn 0 context: event OBSERVED variant=unsuccessful"));
        assert!(lines[2].starts_with("turn 0 context: event FAILURE variant=unsuccessful"));
        assert!(lines[3].starts_with("turn 2: now_us=1"), "{lines:#?}");
        assert!(!text.contains("event ACT"), "{text}");
    }
}

/// A mixed service turn record holding `observation`.
fn observed_turn(observation: [u8; 12]) -> [u8; RECORD] {
    let mut record = turn(600, 3);
    record[14] = 1;
    record[28..36].copy_from_slice(&2u64.to_le_bytes());
    record[36..].copy_from_slice(&observation);
    record
}

/// Every collection a turn records names its result, its status, client
/// and owner on the turn's line under request field names, and writes back
/// byte for byte: each GET and PUT result with every status. A status no
/// wire code names, 0 and 29 among them, reads unknown. An absent
/// observation names no request field; multiple names neither client nor
/// owner, so a byte past the variant reads as spare, as does a status
/// beside a result that carries none; and an unknown variant reads unknown.
#[test]
fn observations_name_their_collection() {
    use super::super::super::fetch::Outcome as Get;
    use super::super::super::frame::Status;
    use super::super::super::upload::UploadOutcome as Put;
    use super::super::bundle::Collected;
    let line = |observation: [u8; 12]| {
        let record = observed_turn(observation);
        let decoded = decode(World::Mixed, &record);
        assert_eq!(encode(Tag::Turn, 0, &decoded), record);
        let line = decoded.line();
        line.split_once("outcome=2").unwrap().1.trim().to_owned()
    };
    for wire in 1..=28 {
        let status = Status::from_wire(wire).unwrap();
        for (collected, name) in [
            (Collected::Get(1, 2, Get::Pressure(status)), "get-pressure"),
            (Collected::Get(1, 2, Get::Failed(status)), "get-failed"),
            (
                Collected::Get(1, 2, Get::Incomplete(status)),
                "get-incomplete",
            ),
            (Collected::Put(1, 2, Put::Failed(status)), "put-failed"),
        ] {
            assert_eq!(
                line(collected.code()),
                format!("request={name} status={status:?} request_client=1 request_owner=2")
            );
        }
    }
    for wire in [0u16, 29, u16::MAX] {
        let mut bad = Collected::Get(1, 2, Get::Pressure(Status::Missing)).code();
        bad[1..3].copy_from_slice(&wire.to_le_bytes());
        assert_eq!(
            line(bad),
            format!("request=get-pressure status=unknown({wire}) request_client=1 request_owner=2")
        );
    }
    for (collected, name) in [
        (Collected::Get(1, 0, Get::Complete), "get-complete"),
        (Collected::Get(0xfffe, 0x1234, Get::Missing), "get-missing"),
        (Collected::Put(1, 0, Put::Published), "put-published"),
        (Collected::Put(1, 0, Put::NotStarted), "put-not-started"),
        (Collected::Put(1, 0, Put::Unknown), "put-unknown"),
    ] {
        let code = collected.code();
        let (client, owner) = (
            u16::from_le_bytes([code[3], code[4]]),
            u16::from_le_bytes([code[5], code[6]]),
        );
        assert_eq!(
            line(code),
            format!("request={name} request_client={client} request_owner={owner}")
        );
        let mut with_status = code;
        with_status[1] = 7;
        assert!(line(with_status).ends_with("spare@37=07"), "{name}");
    }
    assert_eq!(line(Collected::Absent.code()), "");
    assert_eq!(line(Collected::Multiple.code()), "request=multiple");
    let mut named = Collected::Multiple.code();
    named[3] = 1;
    assert_eq!(line(named), "request=multiple spare@39=01");
    let mut unknown = [0; 12];
    unknown[0] = 11;
    assert_eq!(line(unknown), "request=unknown(11)");
    let mut stray = [0; 12];
    stray[5] = 3;
    assert_eq!(line(stray), "spare@41=03");
}

/// `bytes`, a bundle, recorded again with each of its turns' observations
/// zeroed when `zeroed`, as a writer that records none would.
fn rerecorded(bytes: &[u8], zeroed: bool) -> Vec<u8> {
    let capacity = super::super::replay::recorded(bytes).unwrap().1.capacity();
    crate::sim::trace::reseal(bytes, capacity, |records| {
        let turns = records
            .iter_mut()
            .filter(|record| record[0] == Tag::Turn as u8);
        turns
            .filter(|_| zeroed)
            .for_each(|record| record[36..].fill(0));
    })
}

/// The two byte readers: a bundle whose turns record no observation, as
/// an older writer's do, the committed version-1 fixture's among them,
/// loads, narrates with no request field and no spare byte, and differs
/// only in its semantic digest from the same run
/// with its observations, which loads to the same turns, events and
/// terminal and narrates each request a turn collected. The writing build
/// replays the bundle it records exactly and diverges from the one without
/// observations at its first collecting turn, so exact replay stays with
/// the build a bundle pins.
#[test]
fn old_and_new_bytes_read_as_declared() {
    let bytes = recorded("upload", 3);
    let load = |bytes: &[u8]| crate::sim::trace::load(bytes, u64::MAX).unwrap();
    assert_eq!(load(&rerecorded(&bytes, false)).digest, load(&bytes).digest);
    let old = rerecorded(&bytes, true);
    let (new_loaded, old_loaded) = (load(&bytes), load(&old));
    assert_ne!(new_loaded.digest, old_loaded.digest);
    assert_eq!(
        (&new_loaded.turns, &new_loaded.events, new_loaded.terminal),
        (&old_loaded.turns, &old_loaded.events, old_loaded.terminal)
    );
    let turns = bytes.as_chunks::<RECORD>().0.iter();
    let collecting: Vec<usize> = turns
        .filter(|record| record[0] == Tag::Turn as u8)
        .enumerate()
        .filter(|(_, record)| record[36..] != [0; 12])
        .map(|(at, _)| at)
        .collect();
    assert!(!collecting.is_empty(), "the upload run collects");
    let (new, old_text) = (
        narrate("new", &bytes, &[], &here()),
        narrate("old", &old, &[], &here()),
    );
    assert_eq!((new.code, old_text.code), (0, 0));
    let (new, old_text) = (new.text.unwrap(), old_text.text.unwrap());
    assert_eq!(new.matches(" request=").count(), collecting.len());
    assert!(!old_text.contains("request=") && !old_text.contains("spare@"));
    for (at, line) in body(&new)
        .into_iter()
        .filter(|line| line.contains(" turn "))
        .enumerate()
    {
        assert_eq!(
            line.contains(" request="),
            collecting.contains(&at),
            "{line}"
        );
    }
    let fixture: &[u8] = include_bytes!("../../../sim/fixtures/planted-v1.bundle");
    let turns = fixture.as_chunks::<RECORD>().0.iter();
    let turns: Vec<_> = turns
        .filter(|record| record[0] == Tag::Turn as u8)
        .collect();
    assert!(!turns.is_empty());
    for record in turns {
        let line = decode(World::Mixed, record).line();
        assert!(
            !line.contains("request=") && !line.contains("spare@"),
            "{line}"
        );
    }
    let mut replay = Vec::new();
    assert_eq!(
        super::super::replay::replay_recording(&bytes, &mut replay).unwrap(),
        super::super::replay::Replayed::Reproduced
    );
    let mut replay = Vec::new();
    let diverged = super::super::replay::replay_recording(&old, &mut replay).unwrap();
    let first = old
        .as_chunks::<RECORD>()
        .0
        .iter()
        .filter(|record| crate::sim::trace::is_semantic(record[0]))
        .zip(
            bytes
                .as_chunks::<RECORD>()
                .0
                .iter()
                .filter(|record| crate::sim::trace::is_semantic(record[0])),
        )
        .position(|(old, new)| old != new);
    assert!(
        matches!(diverged, super::super::replay::Replayed::Diverged { at, .. } if at == first),
        "{diverged:?} at {first:?}"
    );
}

/// A scripted turn names its step from the script of the profile the
/// bundle pins only when this decoder is the executable it pins; under
/// another decoder, or past the end of the profile's script, the step's
/// name is unknown.
#[test]
fn script_steps_take_their_names_from_the_pinned_script() {
    let bytes = recorded("i3-put-hole", 2_946_512_557_381_983_801);
    let foreign = (Ok("b".repeat(64)), "x86_64-linux".to_owned());
    let text = narrate("foreign-script", &bytes, &[], &foreign)
        .text
        .unwrap();
    let steps: Vec<&str> = body(&text)
        .into_iter()
        .filter(|line| line.contains(" code=script "))
        .collect();
    assert!(!steps.is_empty());
    assert!(
        steps.iter().all(|line| line.ends_with(" (step unknown)")),
        "{steps:#?}"
    );
    let scripted = handmade(&[clock(1), turn(1, super::super::SCRIPT)], PASS);
    let narrated = narrate("unscripted", &scripted, &[], &here());
    assert_eq!(narrated.code, 0, "{}", narrated.err);
    let text = narrated.text.unwrap();
    assert!(
        text.contains(" code=script actor=0 step=0 outcome=0 (step unknown)\n"),
        "{text}"
    );
}

/// A refusal's reason is cut to 4096 bytes at a character boundary and
/// marked cut, so an oversized manifest value stays far below a stream
/// bound; a short reason prints whole.
#[test]
fn refusal_reasons_are_cut_to_a_bound() {
    for (reason, kept) in [("x".repeat(10_000), 4096), ("€".repeat(2000), 4095)] {
        let mut err = Vec::new();
        assert_eq!(super::complain(&mut err, 2, &reason), 2);
        let text = String::from_utf8(err).unwrap();
        assert_eq!(text, format!("error: {} [cut]\n", &reason[..kept]));
    }
    let mut err = Vec::new();
    super::complain(&mut err, 3, "short");
    assert_eq!(err, b"error: short\n");
}

/// An event and a violation recorded right after the clock boundary after
/// `N` turns belong to boundary `N`: inside a window holding `N`, outside
/// the windows beside it.
#[test]
fn records_after_a_clock_belong_to_its_boundary() {
    let mut acts = Vec::new();
    act_events(&mut acts, ActionKind::Get, 1, false);
    let violated =
        violation_record(&failure_event(&Failure::Violation(Obligation::Bytes, "x")).payload);
    let records = [
        clock(5),
        turn(5, 1),
        clock(9),
        event_record(&acts[0]),
        violated,
        turn(9, 2),
    ];
    let places = super::places(&records);
    assert_eq!(places[3..5], [super::Place::Clock(1); 2]);
    let marks = |from, to| {
        let window = Window {
            from,
            to,
            tier: super::Tier::Events,
        };
        window.select(&records, &places)[3..5].to_vec()
    };
    assert_eq!(marks(1, 2), [Some(""), Some("")]);
    assert_eq!(marks(0, 1), [None, Some(" context")]);
    assert_eq!(marks(2, 2), [None, Some(" context")]);
    let text = narrate(
        "after-clock",
        &handmade(&records, VIOLATED),
        &["--events"],
        &here(),
    )
    .text
    .unwrap();
    assert!(text.contains(" clock 1: event ACT action=Get"), "{text}");
    assert!(
        text.contains(" clock 1: violation variant=violation"),
        "{text}"
    );
}

/// The settlement opens at its first entropy, run-site identity, coverage
/// or stop event, or at a terminal no stop precedes: each renders as
/// settlement context outside a window of the first turn. A clock, turn and
/// event recorded after it reopen the run and render at their own place, as
/// the header counts the turn, until the next settlement record.
#[test]
fn each_settlement_record_opens_the_settlement() {
    let refusal = crate::sim::entropy::DrawRefusal {
        site: ChoiceSite {
            domain: Domain::Entropy,
            actor: 1,
            site: 1,
        },
        incarnation: 1,
        error: ChoiceError::Trailing { bytes: 1 },
    };
    let identity =
        Violated::Observed(Failure::Violation(Obligation::Bytes, "x")).identity(Site::Run);
    let coverage = coverage_event(
        Topology {
            owners: 1,
            keys: 1,
            hot: 0,
        },
        &Reached::default(),
    );
    let settling = [
        (Some(entropy_event(refusal)), "event ENTROPY"),
        (Some(identity), "event IDENTITY"),
        (Some(coverage), "event COVERAGE"),
        (Some(stop_event(End::Done, None)), "event STOP"),
        (None, "terminal class=complete"),
    ];
    for (event, label) in settling {
        let mut records = vec![clock(1), turn(1, 1), turn(1, 2)];
        records.extend(event.as_ref().map(event_record));
        let flags = ["--events", "--from", "0", "--to", "1"];
        let text = narrate("settling", &handmade(&records, PASS), &flags, &here())
            .text
            .unwrap();
        assert!(
            text.contains(&format!(" settle context: {label}")),
            "{text}"
        );
        if let Some(event) = event {
            let mut acts = Vec::new();
            act_events(&mut acts, ActionKind::Get, 1, false);
            records.extend([
                clock(4),
                event_record(&acts[0]),
                turn(4, 3),
                event_record(&acts[0]),
            ]);
            records.push(event_record(&event));
            records.extend([turn(4, 4), event_record(&acts[0]), event_record(&event)]);
            let flags = ["--events", "--from", "2", "--to", "4"];
            let text = narrate("resumed", &handmade(&records, PASS), &flags, &here())
                .text
                .unwrap();
            assert!(text.contains("window: turns 2..4 of 4, "), "{text}");
            for resumed in [
                " clock 2: now_us=4",
                " turn 2: now_us=4 ",
                " clock 2: event ACT ",
                " turn 2: event ACT ",
                " turn 3: event ACT ",
            ] {
                assert!(text.contains(resumed), "{label}: {resumed} {text}");
            }
            assert!(
                text.contains(&format!(" settle context: {label}")),
                "{text}"
            );
        }
    }
}
