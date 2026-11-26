//! Reserved-code admission: the `recovery-cut-v1` record's strict parse and
//! field checks, the chooser and event admission under a parsed record and
//! under a live profile, crash candidates and their drift, the stale
//! incarnation defect, and the loader's admission from the profile name
//! and the Config field.

use super::action::Profile;
use super::choice::{
    Admission, CANDIDATE_LEN, Candidate, ChoiceError, Chooser, Defect, Domain, EventKind, Site,
    TABLE_PREFIX,
};
use super::cut::{Unit, registry, registry_hash};
use super::recovery::{KEYS, Mismatch, Record, RecordError, Recovery, embed, embedded, table_hash};
use super::trace::{Capacity, Field, LoadError, Outcome, Recorder, Terminal, Work, admitted, load};

const ROOT: u64 = 0x5EED_0000_0000_0007;

const TURN: Site = Site {
    domain: Domain::Workload,
    actor: 0,
    site: 1,
};

const CRASH: Site = Site {
    domain: Domain::Persistence,
    actor: 0,
    site: 2,
};

const SITES: [Site; 2] = [TURN, CRASH];

/// A workload candidate below every crash candidate in the total order.
fn action() -> Candidate {
    let mut bytes = [0; CANDIDATE_LEN];
    bytes[0] = Domain::Workload as u8;
    Candidate(bytes)
}

fn crashes(admission: &Admission) -> Vec<Candidate> {
    (0..admission.cuts)
        .map(|index| admission.candidate(index).unwrap())
        .collect()
}

#[test]
fn the_record_round_trips_and_parses_strictly() {
    let record = Recovery::Kib16.record();
    let bytes = record.encode();
    assert_eq!(Record::parse(&bytes), Ok(record.clone()));
    let text = String::from_utf8(bytes).unwrap();
    let edited = |from: &str, to: &str| Record::parse(text.replacen(from, to, 1).as_bytes());
    assert_eq!(
        edited("recovery-cut-v1", "recovery-cut-v2"),
        Err(RecordError::Magic)
    );
    let mut invalid = text.clone().into_bytes();
    invalid[text.find("identify = ").unwrap() + "identify = ".len()] = 0xff;
    assert_eq!(Record::parse(&invalid), Err(RecordError::Magic));
    assert_eq!(
        Record::parse(text.trim_end_matches('\n').as_bytes()),
        Err(RecordError::Magic)
    );
    assert_eq!(
        edited("format = 1\nprofile", "profile = declared-16k\nformat"),
        Err(RecordError::Syntax { line: 3 })
    );
    assert_eq!(
        edited("format = 1", "format = 01"),
        Err(RecordError::Value { key: "format" })
    );
    assert_eq!(
        edited("bound = 70", "bound = x"),
        Err(RecordError::Value { key: "bound" })
    );
    assert_eq!(
        edited("workload = two-key", "workload = "),
        Err(RecordError::Value { key: "workload" })
    );
    assert_eq!(
        edited("descriptor = ", "descriptor = 0"),
        Err(RecordError::Value { key: "descriptor" })
    );
    let cut = text.find("activation").unwrap();
    assert_eq!(
        Record::parse(&text.as_bytes()[..cut]),
        Err(RecordError::Missing { key: "activation" })
    );
    assert_eq!(
        Record::parse(format!("{text}extra = 1\n").as_bytes()),
        Err(RecordError::Trailing)
    );
    assert_eq!(KEYS.len(), 9);
}

/// A change to one field of a record.
type Edit = fn(&mut Record);

/// Every field of the record is checked, each by its own mismatch.
#[test]
fn each_record_field_differs_by_its_own_mismatch() {
    let expected = Recovery::Kib16.record();
    assert_eq!(expected.check(&expected), Ok(()));
    let edits: [(Edit, Mismatch); 9] = [
        (|r| r.protocol.push('x'), Mismatch::Protocol),
        (|r| r.format += 1, Mismatch::Format),
        (|r| r.profile = "declared-512".into(), Mismatch::Profile),
        (|r| r.identify.push('x'), Mismatch::Identify),
        (|r| r.descriptor[0] ^= 1, Mismatch::Descriptor),
        (|r| r.registry[31] ^= 1, Mismatch::Registry),
        (|r| r.workload.push('x'), Mismatch::Workload),
        (|r| r.activation.push('x'), Mismatch::Activation),
        (|r| r.bound += 1, Mismatch::Bound),
    ];
    for (edit, mismatch) in edits {
        let mut recorded = expected.clone();
        edit(&mut recorded);
        assert_eq!(recorded.check(&expected), Err(mismatch));
    }
}

/// The record pins the descriptor's and the registry's hashes, and the two
/// profiles differ by their unit declaration.
#[test]
fn the_record_pins_the_descriptor_and_registry() {
    let (kib16, sector) = (Recovery::Kib16.record(), Recovery::Sector.record());
    assert_eq!(kib16.descriptor, Recovery::Kib16.descriptor().hash());
    assert_eq!(kib16.registry, registry_hash(&registry()));
    assert_eq!(Recovery::Kib16.descriptor().unit, Unit::Kib16);
    assert_eq!(kib16.check(&sector), Err(Mismatch::Profile));
    assert_ne!(kib16.descriptor, sector.descriptor);
    assert_eq!(Recovery::named("recovery-16k"), Some(Recovery::Kib16));
    assert_eq!(Recovery::named("recovery-512"), Some(Recovery::Sector));
    assert_eq!(Recovery::named("upload"), None);
    assert_eq!(Recovery::named("crashing"), None);
}

/// A crash candidate is the persistence domain byte, the crash kind byte,
/// the cut index big-endian and the cut table's hash prefix, so crash
/// candidates sort by index after every other domain's.
#[test]
fn a_crash_candidate_names_its_cut_and_table() {
    let admission = Recovery::Kib16.admission();
    let table = Recovery::Kib16.table();
    assert_eq!(admission.cuts as usize, table.len());
    assert_eq!(admission.table[..], table_hash(&table)[..TABLE_PREFIX]);
    let candidate = admission.candidate(1).unwrap();
    assert_eq!(candidate.0[0], Domain::Persistence as u8);
    assert_eq!(candidate.0[1], EventKind::Crash as u8);
    assert_eq!(candidate.0[2..6], 1u32.to_be_bytes());
    assert_eq!(candidate.0[6..], admission.table);
    assert_eq!(admission.cut(&candidate), Some(1));
    assert_eq!(admission.candidate(admission.cuts), None);
    let candidates = crashes(&admission);
    assert!(candidates.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(action() < candidates[0]);
}

/// A live chooser refuses a decision in the persistence domain, and live
/// event admission refuses the crash kind, each before a decision.
#[test]
fn a_live_chooser_refuses_the_reserved_domain_and_crash_kind() {
    let mut chooser = Chooser::record(ROOT, &SITES);
    chooser.launch(0);
    assert_eq!(
        chooser.bounded(CRASH, 0, 2),
        Err(ChoiceError::HarnessDefect(Defect::ReservedDomain))
    );
    assert_eq!(
        EventKind::Crash.admit(chooser.admission()),
        Err(ChoiceError::HarnessDefect(Defect::ReservedEvent))
    );
    assert_eq!(chooser.decisions(), 0);
}

/// Under an admission the chooser decides in the persistence domain and
/// selects crash candidates, the crash kind is admitted, and the tape
/// replays under the same admission.
#[test]
fn an_admitted_chooser_decides_crashes_and_replays() {
    let admission = Recovery::Kib16.admission();
    let mut candidates = vec![action()];
    candidates.extend(crashes(&admission));
    let mut recorder = Chooser::record(ROOT, &SITES).admitting(admission);
    recorder.launch(0);
    recorder.force(2);
    assert_eq!(recorder.index(TURN, 0, &candidates), Ok(2));
    let mask = recorder.bounded(CRASH, 0, 4).unwrap();
    assert_eq!(
        EventKind::Crash.admit(recorder.admission()),
        Ok(EventKind::Crash)
    );
    let tape = recorder.finish().unwrap();
    let mut replayer = Chooser::replay(&SITES, tape).admitting(admission);
    replayer.launch(0);
    assert_eq!(replayer.index(TURN, 0, &candidates), Ok(2));
    assert_eq!(replayer.bounded(CRASH, 0, 4), Ok(mask));
    replayer.finish().unwrap();
}

/// A recording chooser refuses a crash candidate naming another cut table,
/// here one whose hash differs in its first byte, or an index past its
/// table as a harness defect before any decision; a tape recorded under
/// one table replays under another as `Candidates` at the crash decision.
#[test]
fn crash_candidate_drift_refuses_at_its_decision() {
    let kib16 = Recovery::Kib16.admission();
    let mut drift = kib16;
    drift.table[0] ^= 1;
    let mut chooser = Chooser::record(ROOT, &SITES).admitting(kib16);
    chooser.launch(0);
    let table = Err(ChoiceError::HarnessDefect(Defect::Table));
    assert_eq!(chooser.index(TURN, 0, &crashes(&drift)), table);
    let mut past = kib16.candidate(0).unwrap();
    past.0[2..6].copy_from_slice(&kib16.cuts.to_be_bytes());
    assert_eq!(chooser.index(TURN, 0, &[past]), table);
    assert_eq!(chooser.decisions(), 0);
    let mut recorder = Chooser::record(ROOT, &SITES).admitting(kib16);
    recorder.launch(0);
    recorder.index(TURN, 0, &crashes(&kib16)).unwrap();
    let tape = recorder.finish().unwrap();
    let mut drifted = Chooser::replay(&SITES, tape).admitting(drift);
    drifted.launch(0);
    assert_eq!(
        drifted.index(TURN, 0, &crashes(&drift)),
        Err(ChoiceError::Candidates)
    );
    assert_eq!(drifted.decisions(), 0);
}

/// Only candidates beginning with the persistence domain and crash kind
/// bytes are crash candidates: a live chooser decides among candidates
/// whose first byte is 7, as worlds with other layouts encode them, and an
/// admitted chooser checks only crash-shaped candidates against its table.
#[test]
fn only_crash_shaped_candidates_meet_the_table() {
    let shaped = |second: u8| {
        let mut bytes = [0; CANDIDATE_LEN];
        bytes[0] = Domain::Persistence as u8;
        bytes[1] = second;
        Candidate(bytes)
    };
    let live = [shaped(0), shaped(EventKind::Crash as u8)];
    let mut chooser = Chooser::record(ROOT, &SITES);
    chooser.launch(0);
    assert!(chooser.index(TURN, 0, &live).is_ok());
    let mut admitted = Chooser::record(ROOT, &SITES).admitting(Recovery::Kib16.admission());
    admitted.launch(0);
    assert!(
        admitted
            .index(TURN, 0, &[shaped(EventKind::Delivery as u8)])
            .is_ok()
    );
    assert_eq!(
        admitted.index(TURN, 0, &live),
        Err(ChoiceError::HarnessDefect(Defect::Table))
    );
}

/// Under an admission, a draw for a stale incarnation produces the
/// incarnation defect before any decision.
#[test]
fn a_stale_incarnation_draw_is_a_defect_before_any_effect() {
    let mut chooser = Chooser::record(ROOT, &SITES).admitting(Recovery::Kib16.admission());
    assert_eq!(chooser.launch(0), 0);
    chooser.bounded(CRASH, 0, 2).unwrap();
    assert_eq!(chooser.launch(0), 1);
    let decided = chooser.decisions();
    assert_eq!(
        chooser.bounded(CRASH, 0, 2),
        Err(ChoiceError::HarnessDefect(Defect::Incarnation {
            actor: 0,
            incarnation: 0
        }))
    );
    assert_eq!(chooser.decisions(), decided);
    assert!(chooser.bounded(CRASH, 1, 2).is_ok());
}

/// A live Config keeps its bytes: embedding no record leaves the profile
/// record as it was, and a recovery Config's record parses back.
#[test]
fn a_live_config_keeps_its_bytes_and_a_recovery_config_embeds_its_record() {
    let profile = Profile {
        name: "mixed upload then exact read",
        declared: Vec::new(),
        root: ROOT,
    };
    assert_eq!(embed(profile.record(), None), profile.record());
    let record = Recovery::Sector.record();
    let mut config = embed(profile.record(), Some(&record));
    config.extend([9; 12]);
    assert_eq!(embedded(&config), Ok(record));
    assert_eq!(embedded(&profile.record()), Err(RecordError::Absent));
}

/// A bundle of `profile` whose Config field is `config` and whose tape is
/// one admitted crash decision.
fn bundle(profile: &str, config: &[u8]) -> Vec<u8> {
    let admission = Recovery::Kib16.admission();
    let mut chooser = Chooser::record(ROOT, &SITES).admitting(admission);
    chooser.launch(0);
    chooser.index(TURN, 0, &crashes(&admission)).unwrap();
    chooser.bounded(CRASH, 0, 4).unwrap();
    let tape = chooser.finish().unwrap();
    let mut recorder = Recorder::new(Vec::new(), Capacity::new(8, 4, 10_000, 4).unwrap());
    recorder.field(
        Field::Manifest,
        format!("version = 1\nprofile = {profile}\n").as_bytes(),
    );
    recorder.field(Field::Config, config);
    recorder.choices(&tape);
    let terminal = Terminal::Complete {
        outcome: Outcome::Pass,
        fired: 1,
        required: 1,
    };
    let work = Work {
        decisions: 2,
        ..Work::default()
    };
    recorder.finish(terminal, work).sink
}

fn recovery_config() -> Vec<u8> {
    let profile = Profile {
        name: "mixed upload then exact read",
        declared: Vec::new(),
        root: ROOT,
    };
    embed(profile.record(), Some(&Recovery::Kib16.record()))
}

/// A recovery bundle with a parsed record loads its crash decisions; the
/// same bundle under a live profile refuses by its live record, a live
/// bundle holding a crash decision refuses as reserved, and a recovery
/// profile without a parsed record refuses by the record's error.
#[test]
fn the_loader_admits_reserved_choices_only_under_a_parsed_record() {
    let config = recovery_config();
    let loaded = load(&bundle("recovery-16k", &config), 10_000).unwrap();
    assert_eq!(loaded.decisions, 2);
    assert_eq!(admitted(&loaded.fields), Ok(Some(Recovery::Kib16.record())));
    assert!(matches!(
        load(&bundle("upload", &config), 10_000),
        Err(LoadError::Recovery {
            error: RecordError::Live,
            ..
        })
    ));
    let mut live = Profile {
        name: "mixed upload then exact read",
        declared: Vec::new(),
        root: ROOT,
    }
    .record();
    live.extend([0; 12]);
    assert!(matches!(
        load(&bundle("upload", &live), 10_000),
        Err(LoadError::Reserved { .. })
    ));
    let mut broken = config.clone();
    let at = broken.len() - 3;
    broken[at] = b'x';
    assert!(matches!(
        load(&bundle("recovery-16k", &broken), 10_000),
        Err(LoadError::Recovery {
            error: RecordError::Value { key: "bound" },
            ..
        })
    ));
    let profile = &config[..config.len() - Recovery::Kib16.record().encode().len() - 4];
    assert!(matches!(
        load(&bundle("recovery-16k", profile), 10_000),
        Err(LoadError::Recovery {
            error: RecordError::Absent,
            ..
        })
    ));
}

/// Every recovery profile's descriptor points, reach entries and cut table stay outside the `UNDECIDED` sites, so credit over them returns no `Gap::Undecided`.
#[test]
fn recovery_profiles_enumerate_no_undecided_cut() {
    for profile in [Recovery::Kib16, Recovery::Sector, Recovery::Torn] {
        let descriptor = profile.descriptor();
        let undecided = super::ledger::UNDECIDED.map(|site| site as u16);
        assert!(
            descriptor
                .points
                .iter()
                .all(|point| !undecided.contains(&point.site)),
            "{profile:?}"
        );
        assert!(
            descriptor
                .reach
                .iter()
                .all(|reach| !undecided.contains(&reach.site)),
            "{profile:?}"
        );
        assert!(
            profile
                .table()
                .iter()
                .all(|cut| !undecided.contains(&cut.site)),
            "{profile:?}"
        );
    }
}

/// Every recovery profile records the `reset-roots` protocol, and its descriptor holds exactly three points outside the
/// fills' `Submission` site: slot A's eight-block root write at LBA 0 submitted, then persisted, then slot B's at LBA 8
/// submitted after it, each at operation 0 and occurrence 0; its reach lists the four sites, `Submission` alone
/// required.
#[test]
fn recovery_profiles_record_the_reset_roots_and_their_three_points() {
    use super::cut::{Child, Point, Reach, Site, State};
    let slot_a = Child {
        lba: 0,
        blocks: 8,
        state: State::Outstanding,
    };
    let persisted = Child {
        lba: 0,
        blocks: 8,
        state: State::Qualified,
    };
    let slot_b = Child {
        lba: 8,
        blocks: 8,
        state: State::Outstanding,
    };
    let point = |site: Site, before: Vec<Child>, after: Vec<Child>| Point {
        operation: 0,
        site: site as u16,
        occurrence: 0,
        before,
        after,
    };
    let mut expected = vec![
        point(Site::Publication, vec![], vec![slot_a]),
        point(Site::Persistence, vec![slot_a], vec![persisted]),
        point(
            Site::RecoveryMutation,
            vec![persisted],
            vec![persisted, slot_b],
        ),
    ];
    expected.sort_by_key(Point::identity);
    let reach = |site: Site, required: bool| Reach {
        site: site as u16,
        required,
    };
    for profile in [Recovery::Kib16, Recovery::Sector, Recovery::Torn] {
        assert_eq!(profile.record().protocol, "reset-roots", "{profile:?}");
        let descriptor = profile.descriptor();
        let mut roots: Vec<Point> = (descriptor.points.iter())
            .filter(|point| point.site != Site::Submission as u16)
            .cloned()
            .collect();
        roots.sort_by_key(Point::identity);
        assert_eq!(roots, expected, "{profile:?}");
        let mut sites = descriptor.reach.clone();
        sites.sort_by_key(|reach| reach.site);
        assert_eq!(
            sites,
            [
                reach(Site::Submission, true),
                reach(Site::Persistence, false),
                reach(Site::Publication, false),
                reach(Site::RecoveryMutation, false),
            ],
            "{profile:?}"
        );
    }
}
