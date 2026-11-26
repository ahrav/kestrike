//! Branching recorded bundles at their milestones: where the pending-PUT
//! milestone and the turn and script milestones stand, what an in-process
//! branch keeps, the custody check's controls, how each world's children
//! are judged, and the forked children the worker judges.

use std::path::Path;
use std::time::Duration;

use crate::sim::choice::{Domain, EventKind};
use crate::sim::fork::{Classified, HOST_FAILED, REPORT_FD, Refusal, SETUP_FAILED, Verdict};
use crate::sim::manifest::Manifest;
use crate::sim::trace::{
    Capacity, Infrastructure, Outcome, PAYLOAD, RECORD, Recorder, Terminal, is_semantic, load,
    reseal,
};

use super::super::bundle::{ACT, UPLOAD, UploadState, admit, traced};
use super::super::histories::STAY;
use super::super::{CLIENT_POLL, REFUSED, SCRIPT, scratch};
use super::{
    Branched, ChildPlant, ChildReport, Facts, Judged, Milestone, Reached, Unbranched, branch,
    custody, diverged, milestone_lines, prefix_digest, report_problems, suffix_root, terminal_text,
    witness,
};
use crate::sim::action::ActionKind;
use crate::sim::ledger::counts;
use crate::sim::turn::Turn;

/// The milestone the faulted upload's checks branch at.
const PENDING: &str = "pending-put";

/// A bundle of profile `profile` recorded in memory under the sample
/// manifest.
fn bundle(profile: &str) -> Vec<u8> {
    let platform = format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS);
    let text = crate::sim::manifest_tests::sample(profile, &"a".repeat(64), &platform);
    let manifest = Manifest::parse(&text).expect("the sample manifest");
    traced(admit(&manifest).expect("an admitted manifest"), Vec::new()).sink
}

/// The faulted upload: links that lose, duplicate, reorder and delay
/// traffic leave a granted upload pending with a device holding a source.
fn faulted() -> Vec<u8> {
    bundle("faulted")
}

/// The first stopped boundary, counting from 1, after whose events the
/// upload is granted, undecided and holds a device-held source, read from
/// the bundle's records alone; also the state at the boundary before it.
fn first_pending(bytes: &[u8]) -> Option<(u64, Option<UploadState>)> {
    let pending = |state: Option<UploadState>| {
        state.is_some_and(|s| s.attempt > 0 && s.grant > 0 && s.held > 0 && s.outcome == 0)
    };
    let (mut boundary, mut state, mut before) = (0, None, None);
    // Whether the records since the last clock record are its boundary's
    // events, judged once a record of another tag ends them.
    let mut open = false;
    for record in bytes
        .as_chunks::<RECORD>()
        .0
        .iter()
        .filter(|record| is_semantic(record[0]))
    {
        if open && record[0] != 6 {
            if pending(state) {
                return Some((boundary, before));
            }
            before = state;
            open = false;
        }
        if record[0] == 5 {
            boundary += 1;
            open = true;
        }
        if record[0] == 6 && record[1] == UPLOAD {
            let payload: [u8; PAYLOAD] = record[4..].try_into().expect("a payload");
            state = UploadState::of(&crate::sim::trace::Event {
                kind: UPLOAD,
                payload,
            });
        }
    }
    None
}

/// The suffix roots of run root 100 for suffixes 0 and 1 are fixed
/// values, so a consumer that derives suffix roots outside this crate
/// checks its derivation against the same pair.
#[test]
fn suffix_roots_of_root_100_are_pinned() {
    assert_eq!(
        (suffix_root(100, 0), suffix_root(100, 1)),
        (16_568_251_442_118_978_808, 11_517_070_665_970_554_291)
    );
}

/// A prefix replay reaches the milestone at the first stopped boundary
/// whose own events make the upload pending, read independently from the
/// bundle; the state a boundary earlier is not pending, so a predicate read
/// from the prior boundary would fork one boundary late. Two replays reach
/// one milestone, and the prefix the recorder hashed is the bundle's own.
#[test]
fn a_prefix_replay_reaches_the_milestone_where_its_predicate_first_holds() {
    let original = faulted();
    let (reached, replayed) = diverged(&original, PENDING, None).unwrap();
    let digest = |bytes: &[u8]| load(bytes, u64::MAX).unwrap().digest;
    assert_eq!(
        digest(&replayed),
        digest(&original),
        "a probe replays the bundle"
    );
    let (boundary, before) = first_pending(&original).expect("a pending boundary");
    assert_eq!(reached.facts.boundary, boundary);
    assert!(before.is_none_or(|state| state.held == 0 || state.grant == 0));
    let state = reached.facts.upload.unwrap();
    assert!(state.grant > 0 && state.held > 0 && state.outcome == 0);
    assert_eq!(
        prefix_digest(&original, reached.semantic),
        Some(reached.prefix)
    );
    assert_eq!(diverged(&original, PENDING, None).unwrap().0, reached);
}

/// The witness line holds over the facts where the pending-PUT milestone
/// was reached and names them. The same boundary and prefix with the
/// upload's device-held sources returned, with no upload, or under an
/// unknown milestone holds no longer, so a matching prefix digest alone
/// never witnesses the milestone.
#[test]
fn the_witness_holds_only_over_the_facts_that_reach_the_milestone() {
    let (reached, _) = diverged(&faulted(), PENDING, None).unwrap();
    let state = reached.facts.upload.unwrap();
    assert_eq!(
        witness(PENDING, &reached.facts),
        format!(
            "witness: pending-put holds=true boundary={} upload=attempt:{},grant:{},held:{},outcome:0 armed=false\n",
            reached.facts.boundary, state.attempt, state.grant, state.held
        )
    );
    let returned = Facts {
        upload: Some(UploadState { held: 0, ..state }),
        ..reached.facts
    };
    let without = Facts {
        upload: None,
        ..reached.facts
    };
    for (name, facts) in [
        (PENDING, returned),
        (PENDING, without),
        ("elsewhere", reached.facts),
    ] {
        assert!(
            witness(name, &facts).contains(" holds=false "),
            "{}",
            witness(name, &facts)
        );
    }
}

/// The milestone line names the boundary, the prefix's semantic records,
/// its decisions and the prefix digest in hex, in that order, and the
/// witness line over the same facts follows it.
#[test]
fn the_milestone_lines_name_the_prefix_then_its_witness() {
    let facts = Facts {
        boundary: 3,
        upload: None,
        armed: true,
        ..Facts::default()
    };
    let mut prefix = [0; 32];
    prefix[0] = 0xab;
    prefix[31] = 0x01;
    let reached = Reached {
        facts,
        semantic: 5,
        prefix,
        decisions: 7,
    };
    let hex = format!("ab{}01", "00".repeat(30));
    assert_eq!(
        milestone_lines(PENDING, &reached),
        format!(
            "milestone: pending-put boundary=3 semantic=5 decisions=7 prefix={hex}\n\
             witness: pending-put holds=false boundary=3 upload=none armed=true\n"
        )
    );
}

/// An in-process branch keeps the prefix's semantic records, and its
/// suffix moves the pending upload's custody and result only through
/// recorded evidence; at least one suffix does move them, so the custody
/// check judges real transitions. One suffix branched twice gives one
/// bundle; two suffixes share the prefix yet differ after it.
#[test]
fn an_in_process_branch_keeps_the_prefix_and_its_custody() {
    let original = faulted();
    let (reached, first) = diverged(&original, PENDING, Some(0)).unwrap();
    let (again, same) = diverged(&original, PENDING, Some(0)).unwrap();
    let (other, second) = diverged(&original, PENDING, Some(1)).unwrap();
    assert_eq!((again, other), (reached, reached));
    let digest = |bytes: &[u8]| load(bytes, u64::MAX).unwrap().digest;
    assert_eq!(digest(&first), digest(&same));
    assert_ne!(
        load(&first, u64::MAX).unwrap().digest,
        load(&second, u64::MAX).unwrap().digest
    );
    let pending = reached.facts.upload.unwrap();
    let moved = [&first, &second].iter().any(|bytes| {
        later_states(bytes, reached.semantic)
            .iter()
            .any(|state| state.held < pending.held || state.outcome != 0)
    });
    assert!(moved, "no suffix discharged custody or decided the upload");
    for bytes in [&first, &second] {
        assert_eq!(prefix_digest(bytes, reached.semantic), Some(reached.prefix));
        assert_eq!(
            custody(bytes, reached.semantic, Some(pending), false),
            Vec::<String>::new()
        );
        let loaded = load(bytes, u64::MAX).unwrap();
        assert!(
            loaded.decisions > reached.decisions,
            "the suffix decides more"
        );
    }
}

/// A bundle whose run never makes an upload pending is refused for its
/// predicate, a bundle whose prefix replay diverges before the milestone,
/// by a changed decision or by a record the replay no longer reproduces,
/// is reported as diverged rather than as input that never reaches it, an
/// unknown milestone is refused as input, and a library test branches
/// only by prefix replay: a fork from it is refused for its threads.
#[test]
fn branches_are_refused_without_their_milestone_or_off_the_worker() {
    let upload = bundle("upload");
    assert_eq!(
        diverged(&upload, PENDING, None),
        Err(Unbranched::Milestone(Refusal::Predicate))
    );
    let changed = diverging_before(&faulted(), PENDING);
    assert_eq!(diverged(&changed, PENDING, None), Err(Unbranched::Diverged));
    let differing = differing_before(&faulted(), PENDING);
    assert_eq!(
        diverged(&differing, PENDING, None),
        Err(Unbranched::Diverged),
        "a prefix whose records differ diverged even though its tape reached the milestone"
    );
    assert!(matches!(
        diverged(&upload, "elsewhere", None),
        Err(Unbranched::Input(_))
    ));
    let dir = std::env::temp_dir();
    let forked = branch(
        &faulted(),
        PENDING,
        (1, 1),
        &dir,
        ChildPlant::None,
        Duration::from_secs(1),
    );
    assert!(
        matches!(forked, Err(Unbranched::Milestone(Refusal::Threads(count))) if count > 1),
        "{forked:?}"
    );
    assert!(matches!(
        branch(
            &faulted(),
            PENDING,
            (0, 1),
            &dir,
            ChildPlant::None,
            Duration::from_secs(1)
        ),
        Err(Unbranched::Input(_))
    ));
    assert!(forked_suffixes_keep_the_pending_put_prefix().is_err());
}

/// The upload states `bytes` records past its first `semantic` semantic
/// records.
fn later_states(bytes: &[u8], semantic: u64) -> Vec<UploadState> {
    bytes
        .as_chunks::<RECORD>()
        .0
        .iter()
        .filter(|record| is_semantic(record[0]))
        .skip(semantic as usize)
        .filter(|record| record[0] == 6 && record[1] == UPLOAD)
        .filter_map(|record| {
            UploadState::of(&crate::sim::trace::Event {
                kind: UPLOAD,
                payload: record[4..].try_into().expect("a payload"),
            })
        })
        .collect()
}

/// A record of `tag` and `sub` over `payload`.
fn record(tag: u8, sub: u8, payload: &[u8]) -> [u8; RECORD] {
    let mut out = [0; RECORD];
    out[0] = tag;
    out[1] = sub;
    out[4..4 + payload.len()].copy_from_slice(payload);
    out
}

fn state(attempt: u16, held: u16, outcome: u8) -> [u8; RECORD] {
    let mut payload = [0; PAYLOAD];
    payload[..2].copy_from_slice(&attempt.to_le_bytes());
    payload[14..18].copy_from_slice(&3u32.to_le_bytes());
    payload[18..20].copy_from_slice(&held.to_le_bytes());
    payload[20] = outcome;
    record(6, UPLOAD, &payload)
}

/// A turn record selecting `event`.
fn turn(event: [u8; 3]) -> [u8; RECORD] {
    let mut payload = [0; 32];
    payload[8..11].copy_from_slice(&event);
    record(4, 0, &payload)
}

fn act(kind: ActionKind, outcome: u64) -> [u8; RECORD] {
    record(
        6,
        ACT,
        &[&[kind as u8][..], &outcome.to_le_bytes()].concat(),
    )
}

fn taken(kind: ActionKind) -> [u8; RECORD] {
    act(kind, 1)
}

/// Custody falls only after an event that returns sources, a result is
/// decided only after an outcome collection and stays as decided, and an
/// attempt advances only to the next one, once the device holds no source,
/// through an invocation of the first upload or of one after a publication,
/// or a retry of a decided, unpublished upload, each within the turn that
/// supplied the evidence. The same suffixes with that evidence removed,
/// with the other client's poll, the other link's release or an upload
/// action in its place, with another turn or a clock move between the
/// evidence and the state, with an attempt that skips one, wraps or stays,
/// with sources still held, or with an action the upload's state does not
/// allow, fail; so does a new attempt decided with no collection or with
/// only the old attempt's. On links that release at delivery only the
/// owner's poll returns sources.
#[test]
fn custody_moves_only_with_its_evidence() {
    let pending = UploadState::of(&crate::sim::trace::Event {
        kind: UPLOAD,
        payload: state(1, 2, 0)[4..].try_into().unwrap(),
    })
    .unwrap();
    let owner_poll = turn([Domain::Workload as u8, 1, 0]);
    let uploader_poll = turn([Domain::Workload as u8, CLIENT_POLL, 0]);
    let other_poll = turn([Domain::Workload as u8, CLIENT_POLL, 1]);
    let release = turn([Domain::Link as u8, EventKind::Release as u8, 0]);
    let other_release = turn([Domain::Link as u8, EventKind::Release as u8, 1]);
    let put_action = turn([Domain::Put as u8, 0, 0]);
    let clock = record(5, 0, &7u64.to_le_bytes());
    let stream = |records: &[[u8; RECORD]]| -> Vec<u8> { records.concat() };
    let refused = |kind| act(kind, REFUSED);
    let (collect, retry, invoke) = (
        taken(ActionKind::PutOutcome),
        taken(ActionKind::Retry),
        taken(ActionKind::PutInvoke),
    );
    // Outcome code 2 is a publication and 3 a failure; a decision that
    // returns the device's sources precedes each new attempt.
    let (published, failed) = (state(1, 0, 2), state(1, 0, 3));
    let cases: [(&[[u8; RECORD]], usize); 38] = [
        (&[uploader_poll, state(1, 1, 0)], 0),
        (&[release, state(1, 1, 0)], 0),
        (&[owner_poll, state(1, 1, 0)], 1),
        (&[other_poll, state(1, 1, 0)], 1),
        (&[other_release, state(1, 1, 0)], 1),
        (&[put_action, state(1, 1, 0)], 1),
        (&[collect, state(1, 2, 2)], 0),
        (&[owner_poll, state(1, 2, 2)], 1),
        (&[refused(ActionKind::PutOutcome), state(1, 2, 2)], 1),
        (&[uploader_poll, collect, failed, retry, state(2, 0, 0)], 0),
        (&[uploader_poll, state(2, 2, 0)], 1),
        (
            &[
                uploader_poll,
                collect,
                failed,
                refused(ActionKind::Retry),
                state(2, 0, 0),
            ],
            1,
        ),
        (&[retry, state(2, 2, 0)], 1),
        (
            &[uploader_poll, collect, published, retry, state(2, 0, 0)],
            1,
        ),
        (&[uploader_poll, collect, failed, retry, state(3, 0, 0)], 1),
        (&[uploader_poll, collect, failed, retry, state(1, 0, 3)], 1),
        (&[collect, state(1, 2, 3), retry, state(2, 2, 0)], 1),
        (
            &[uploader_poll, collect, published, invoke, state(2, 0, 0)],
            0,
        ),
        (&[invoke, state(2, 2, 0)], 1),
        (&[uploader_poll, collect, failed, invoke, state(2, 0, 0)], 1),
        (
            &[uploader_poll, collect, published, invoke, state(3, 0, 0)],
            1,
        ),
        (
            &[uploader_poll, collect, published, invoke, state(1, 0, 2)],
            1,
        ),
        (&[collect, state(1, 2, 2), invoke, state(2, 2, 0)], 1),
        (
            &[
                uploader_poll,
                collect,
                published,
                refused(ActionKind::PutInvoke),
                state(2, 0, 0),
            ],
            1,
        ),
        (
            &[
                uploader_poll,
                collect,
                published,
                invoke,
                clock,
                state(2, 0, 0),
            ],
            1,
        ),
        (
            &[
                uploader_poll,
                collect,
                published,
                invoke,
                owner_poll,
                state(2, 0, 0),
            ],
            1,
        ),
        (
            &[uploader_poll, collect, failed, retry, clock, state(2, 0, 0)],
            1,
        ),
        (
            &[
                uploader_poll,
                collect,
                failed,
                retry,
                owner_poll,
                state(2, 0, 0),
            ],
            1,
        ),
        (
            &[
                uploader_poll,
                collect,
                failed,
                state(1, 0, 2),
                invoke,
                state(2, 0, 0),
            ],
            1,
        ),
        (&[uploader_poll, collect, failed, retry, state(2, 0, 3)], 1),
        (
            &[
                uploader_poll,
                collect,
                failed,
                collect,
                retry,
                state(2, 0, 3),
            ],
            1,
        ),
        (
            &[
                uploader_poll,
                collect,
                failed,
                retry,
                collect,
                state(2, 0, 3),
            ],
            0,
        ),
        (
            &[
                uploader_poll,
                collect,
                failed,
                retry,
                state(2, 2, 0),
                uploader_poll,
                state(2, 0, 0),
            ],
            0,
        ),
        (
            &[
                uploader_poll,
                collect,
                failed,
                retry,
                state(2, 2, 0),
                owner_poll,
                state(2, 0, 0),
            ],
            1,
        ),
        (
            &[
                uploader_poll,
                collect,
                failed,
                retry,
                state(2, 2, 0),
                put_action,
                state(2, 0, 0),
            ],
            1,
        ),
        (&[uploader_poll, owner_poll, state(1, 1, 0)], 1),
        (&[uploader_poll, clock, state(1, 1, 0)], 1),
        (&[collect, clock, state(1, 2, 2)], 1),
    ];
    for (records, faults) in cases {
        let found = custody(&stream(records), 0, Some(pending), false);
        assert_eq!(found.len(), faults, "{found:?}");
    }
    let prefixed = stream(&[owner_poll, state(1, 0, 0), uploader_poll, state(1, 1, 0)]);
    assert_eq!(
        custody(&prefixed, 2, Some(pending), false),
        Vec::<String>::new()
    );
    // On links that release at delivery only the owner's poll returns
    // sources: the uploader's poll, the uploader link's release and a turn
    // of another domain with the owner poll's code do not.
    let disk = turn([Domain::Disk as u8, 1, 0]);
    for (records, faults) in [
        ([owner_poll, state(1, 1, 0)], 0),
        ([other_poll, state(1, 1, 0)], 1),
        ([uploader_poll, state(1, 1, 0)], 1),
        ([release, state(1, 1, 0)], 1),
        ([disk, state(1, 1, 0)], 1),
    ] {
        let found = custody(&stream(&records), 0, Some(pending), true);
        assert_eq!(found.len(), faults, "{found:?}");
    }
    // The last attempt number begins no wrapped attempt.
    let last = UploadState {
        attempt: u16::MAX,
        held: 0,
        outcome: 3,
        ..pending
    };
    let wrapped = stream(&[retry, state(0, 0, 0)]);
    assert_eq!(custody(&wrapped, 0, Some(last), false).len(), 1);
    // A boundary before any upload state judges the suffix's first upload
    // from attempt zero: its invocation begins attempt 1, and an attempt
    // that appears with no invocation or a refused one, names attempt 0,
    // skips past 1 or comes from a retry, or a result decided with no
    // collection, fails.
    let unstarted: [(&[[u8; RECORD]], usize); 7] = [
        (&[invoke, state(1, 0, 0)], 0),
        (&[refused(ActionKind::PutInvoke), state(1, 0, 0)], 1),
        (&[owner_poll, state(0, 0, 0)], 1),
        (&[owner_poll, state(1, 0, 0)], 1),
        (&[invoke, state(6, 0, 0)], 1),
        (&[retry, state(1, 0, 0)], 1),
        (&[invoke, state(1, 0, 2)], 1),
    ];
    for (records, faults) in unstarted {
        let found = custody(&stream(records), 0, None, false);
        assert_eq!(found.len(), faults, "{found:?}");
    }
}

/// A credited child's report passes every check when it matches the
/// bundle it wrote. Each other case fails a check: a run that skipped its
/// one teardown audit, a report whose terminal
/// disagrees with the bundle's terminal record, a bundle the record cap
/// closed, whose suffix is incomplete evidence whatever terminal the report
/// claims, a bundle whose run ended in a complete violation, a report
/// naming another child's bundle, and a bundle the parent cannot load, which
/// is incomplete evidence. Incompleteness follows the loaded bundle.
#[test]
fn a_report_is_checked_against_its_bundle() {
    let original = faulted();
    let (reached, bytes) = diverged(&original, PENDING, Some(0)).unwrap();
    let dir = scratch("sim-report").unwrap();
    let report = child_report(&bytes, reached, &dir, 1);
    let judged = |report: &ChildReport, (suffix, sibling): (u32, u32)| {
        let problems = report_problems(report, (suffix, sibling), reached, &dir);
        let branched = Branched {
            reached,
            parent: true,
            children: vec![Judged {
                suffix,
                sibling,
                class: Classified::Success(Vec::new()),
                report: Some(report.clone()),
                problems: problems.clone(),
            }],
        };
        (problems, branched.incomplete())
    };
    assert_eq!(judged(&report, (0, 0)), (Vec::new(), false));
    let untorn = ChildReport {
        teardowns: 0,
        ..report.clone()
    };
    let (problems, incomplete) = judged(&untorn, (0, 0));
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("0 teardown audits"), "{problems:?}");
    assert!(
        !incomplete,
        "a run that skipped its teardown audit is a judged failure"
    );

    let disagreeing = ChildReport {
        terminal: "infrastructure cap".into(),
        ..report.clone()
    };
    assert_ne!(disagreeing.terminal, report.terminal);
    let (problems, incomplete) = judged(&disagreeing, (0, 0));
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        problems[0].contains("its report says infrastructure cap"),
        "{problems:?}"
    );
    assert!(!incomplete, "a claimed terminal alone");

    // The `Begin` record carries the checkpoint interval, so the capped
    // stream keeps the original's for its prefix to digest alike.
    let every = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let records = (bytes.len() / RECORD) as u64 - 16;
    let capped = reseal(&bytes, Capacity::new(8, 4, records, every).unwrap(), |_| {});
    let loaded = load(&capped, u64::MAX).unwrap();
    assert_eq!(
        loaded.terminal,
        Terminal::Infrastructure(Infrastructure::Cap)
    );
    assert_eq!(
        prefix_digest(&capped, reached.semantic),
        Some(reached.prefix)
    );
    std::fs::write(dir.join("suffix-0-1.bundle"), &capped).unwrap();
    let incomplete = ChildReport {
        digest: loaded.digest,
        decisions: loaded.decisions,
        terminal: terminal_text(loaded.terminal),
        bundle: "suffix-0-1.bundle".into(),
        ..report.clone()
    };
    let (problems, unfinished) = judged(&incomplete, (0, 1));
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("infrastructure cap"), "{problems:?}");
    assert!(unfinished, "the loaded bundle stopped at the cap");
    let claiming = ChildReport {
        terminal: report.terminal.clone(),
        ..incomplete.clone()
    };
    let (problems, unfinished) = judged(&claiming, (0, 1));
    assert_eq!(problems.len(), 2, "{problems:?}");
    assert!(unfinished, "the report's claimed terminal changes nothing");

    let (problems, unfinished) = judged(&report, (0, 1));
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("suffix-0-0.bundle for suffix-0-1.bundle")),
        "{problems:?}"
    );
    assert!(
        !unfinished,
        "a report whose digest disagrees with the child's own bundle fails outright"
    );

    let violated = ending_in(&bytes, Outcome::Violation);
    let loaded = load(&violated, u64::MAX).unwrap();
    assert!(!loaded.terminal.counts());
    assert_eq!(
        prefix_digest(&violated, reached.semantic),
        Some(reached.prefix)
    );
    std::fs::write(dir.join("suffix-1-0.bundle"), &violated).unwrap();
    let found = ChildReport {
        digest: loaded.digest,
        decisions: loaded.decisions,
        terminal: terminal_text(loaded.terminal),
        bundle: "suffix-1-0.bundle".into(),
        ..report
    };
    let (problems, unfinished) = judged(&found, (1, 0));
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("complete violation"), "{problems:?}");
    assert!(!unfinished, "a violation is a complete result");

    // A flipped byte breaks a checkpoint, so the bundle fails to load; a
    // cut at a record boundary would load as a truncated bundle instead.
    let mut corrupt = violated.clone();
    let middle = corrupt.len() / 2;
    corrupt[middle] ^= 0xff;
    assert!(load(&corrupt, u64::MAX).is_err());
    std::fs::write(dir.join("suffix-1-1.bundle"), &corrupt).unwrap();
    let torn = ChildReport {
        bundle: "suffix-1-1.bundle".into(),
        ..found
    };
    let (problems, unfinished) = judged(&torn, (1, 1));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("does not load")),
        "{problems:?}"
    );
    assert!(
        unfinished,
        "a bundle the parent cannot load is incomplete evidence"
    );
}

/// Record tags the rerecording below skips: the recorder writes its own.
const BEGIN: u8 = 1;
const TERMINAL: u8 = 8;

/// A copy of bundle `bytes` whose terminal outcome is `outcome`, with the
/// violation record a violation terminal requires. The copy keeps the
/// semantic records and the checkpoint interval, so its prefix digest
/// equals the original's.
fn ending_in(bytes: &[u8], outcome: Outcome) -> Vec<u8> {
    let loaded = load(bytes, u64::MAX).unwrap();
    let Terminal::Complete {
        fired, required, ..
    } = loaded.terminal
    else {
        panic!("a complete original: {:?}", loaded.terminal);
    };
    let every = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let records = (bytes.len() / RECORD) as u64 * 2;
    let mut recorder = Recorder::new(Vec::new(), Capacity::new(8, 4, records, every).unwrap());
    for record in bytes.as_chunks::<RECORD>().0 {
        if is_semantic(record[0]) && record[0] != BEGIN && record[0] != TERMINAL {
            recorder.raw(record);
        }
    }
    if outcome == Outcome::Violation {
        recorder.violation(&[7; PAYLOAD]);
    }
    let terminal = Terminal::Complete {
        outcome,
        fired,
        required,
    };
    recorder.finish(terminal, loaded.work).sink
}

/// A branch is incomplete evidence when a child's suffix left none: the
/// parent lost its pipe or reap, the child could not set up its report, it
/// could not list its descriptors or write its bundle, something outside
/// the branch killed it, or the parent could not read that bundle.
/// Every other uncredited class is a result the child's problems describe,
/// and a credited child's claimed terminal alone decides nothing.
#[test]
fn a_branch_is_incomplete_only_when_a_childs_suffix_left_no_evidence() {
    let original = faulted();
    let (reached, _) = diverged(&original, PENDING, None).unwrap();
    let judged = |class: Classified| Judged {
        suffix: 0,
        sibling: 0,
        report: None,
        problems: vec![format!("{class:?} earns no credit")],
        class,
    };
    let branched = |class| Branched {
        reached,
        parent: true,
        children: vec![judged(class)],
    };
    let reported = |terminal: &str| ChildReport {
        prefix: reached.prefix,
        semantic: reached.semantic,
        digest: [0; 32],
        decisions: 0,
        terminal: terminal.into(),
        bundle: "suffix-0-0.bundle".into(),
        descriptors: vec![0, 1, 2, REPORT_FD],
        inherited: 1,
        baseline: 0,
        teardowns: 1,
    };
    let credited = |report: ChildReport, problems: Vec<String>| Branched {
        reached,
        parent: true,
        children: vec![Judged {
            suffix: 0,
            sibling: 0,
            class: Classified::Success(Vec::new()),
            report: Some(report),
            problems,
        }],
    };
    // A report's claimed terminal is unverified text; incompleteness
    // follows the loaded bundle through the problems the judge records.
    assert!(!credited(reported("infrastructure cap"), Vec::new()).incomplete());
    let passed = reported("complete pass fired=03 required=03");
    assert!(!credited(passed.clone(), Vec::new()).incomplete());
    assert!(
        !credited(
            reported("complete violation fired=03 required=03"),
            Vec::new()
        )
        .incomplete()
    );
    let empty = scratch("sim-unread").unwrap();
    let unread = report_problems(&passed, (0, 0), reached, &empty);
    let _ = std::fs::remove_dir_all(&empty);
    assert!(
        unread
            .iter()
            .any(|problem| problem.starts_with("its bundle cannot be read")),
        "{unread:?}"
    );
    assert!(credited(passed, unread).incomplete());
    let unwritten = Classified::Failed {
        code: HOST_FAILED,
        payload: b"unwritten: Some(Os { code: 28, kind: StorageFull }) None\n".to_vec(),
    };
    let unlisted = Classified::Failed {
        code: HOST_FAILED,
        payload: b"descriptors: /proc/self/fd: Permission denied\n".to_vec(),
    };
    for class in [
        Classified::Lost("poll: EIO".into()),
        Classified::Silent(SETUP_FAILED),
        Classified::Signaled(libc::SIGKILL),
        unwritten,
        unlisted,
    ] {
        assert!(branched(class.clone()).incomplete(), "{class:?}");
    }
    let panicked = Classified::Failed {
        code: 101,
        payload: b"panicked\nteardowns: 1\n".to_vec(),
    };
    for class in [
        panicked,
        Classified::Silent(101),
        Classified::Signaled(libc::SIGSEGV),
        Classified::Malformed(0),
        Classified::Mismatch {
            code: 1,
            verdict: Verdict::Success,
        },
        Classified::Watchdog,
    ] {
        assert!(!branched(class.clone()).incomplete(), "{class:?}");
    }
}

/// A copy of `original` with the last selection among several candidates
/// before milestone `name` moved to the next candidate, so a strict replay
/// diverges before any boundary holds the milestone.
pub(crate) fn diverging_before(original: &[u8], name: &str) -> Vec<u8> {
    let (reached, _) = diverged(original, name, None).expect("the original reaches the milestone");
    let (_, manifest) = super::super::replay::recorded(original).expect("a recorded manifest");
    // `reseal` hands the records after `Begin`, semantic record 0, so a
    // record at index `at` is semantic record `at + 1`.
    reseal(original, manifest.capacity(), |records| {
        let before = (reached.semantic as usize).saturating_sub(1);
        let selection = (0..before.min(records.len()))
            .rev()
            .find(|&at| {
                records[at][0] == 3
                    && records[at][4] == 3
                    && u64::from_le_bytes(records[at][13..21].try_into().unwrap()) > 1
            })
            .expect("a selection among several candidates before the milestone");
        let record = &mut records[selection];
        let bound = u64::from_le_bytes(record[13..21].try_into().unwrap());
        let value = u64::from_le_bytes(record[5..13].try_into().unwrap());
        record[5..13].copy_from_slice(&((value + 1) % bound).to_le_bytes());
    })
}

/// A copy of `original` with the outcome of the last turn before milestone
/// `name` changed: the choice tape still drives a replay to the milestone,
/// and the replay's records differ from the bundle's before it.
fn differing_before(original: &[u8], name: &str) -> Vec<u8> {
    let (reached, _) = diverged(original, name, None).expect("the original reaches the milestone");
    let (_, manifest) = super::super::replay::recorded(original).expect("a recorded manifest");
    reseal(original, manifest.capacity(), |records| {
        let before = (reached.semantic as usize).saturating_sub(1);
        let turn = (0..before.min(records.len()))
            .rev()
            .find(|&at| records[at][0] == 4)
            .expect("a turn before the milestone");
        records[turn][28] ^= 0xff;
    })
}

/// Forks two siblings for each of two suffixes at the pending-PUT
/// milestone. Every child is credited from its frame at exit 0, reports
/// the parent's prefix, closed its inherited descriptors, re-baselined its
/// allocation counters, ran its teardown audit, and wrote a bundle that
/// starts with the prefix and keeps the upload's custody honest. Siblings
/// agree, and one changed sibling report makes them disagree; the two
/// suffixes differ after the shared prefix, each child's bundle equals the
/// in-process branch of its suffix, and the parent's replay still
/// reproduces the original. Children that panic exit
/// nonzero after their teardown audit and children that hang are killed
/// by the watchdog; neither is credited and the parent stays unchanged.
pub(crate) fn forked_suffixes_keep_the_pending_put_prefix() -> Result<(), String> {
    let original = faulted();
    let dir = scratch("sim-branch")?;
    let checked = (|| {
        let wait = Duration::from_secs(300);
        let honest = dir.join("honest");
        std::fs::create_dir(&honest).map_err(|error| error.to_string())?;
        let branched = branch(&original, PENDING, (2, 2), &honest, ChildPlant::None, wait)
            .map_err(|refused| format!("{refused:?}"))?;
        let problems = branched.problems();
        if !problems.is_empty() || branched.children.len() != 4 {
            return Err(format!(
                "{} children: {problems:?}",
                branched.children.len()
            ));
        }
        // Changing one sibling's digest, decisions or terminal alone makes
        // exactly the sibling disagreement problem, and a sibling with no
        // report is compared with none.
        type Change = (&'static str, fn(&mut Option<ChildReport>), bool);
        let changes: [Change; 4] = [
            (
                "digest",
                |report| report.as_mut().unwrap().digest[0] ^= 1,
                true,
            ),
            (
                "decisions",
                |report| report.as_mut().unwrap().decisions += 1,
                true,
            ),
            (
                "terminal",
                |report| report.as_mut().unwrap().terminal.push_str(" different"),
                true,
            ),
            ("no report", |report| *report = None, false),
        ];
        for (label, change, disagrees) in changes {
            let mut different = branched.clone();
            let sibling = different
                .children
                .iter_mut()
                .find(|child| (child.suffix, child.sibling) == (0, 1))
                .ok_or("suffix 0 has a second sibling")?;
            if sibling.report.is_none() {
                return Err("a credited sibling sends its report".into());
            }
            change(&mut sibling.report);
            let expected: Vec<String> = if disagrees {
                vec!["the siblings of suffix 0 disagree".to_owned()]
            } else {
                Vec::new()
            };
            if different.problems() != expected {
                return Err(format!("{label}: {:?}", different.problems()));
            }
        }
        let (probe, _) = diverged(&original, PENDING, None).map_err(|e| format!("{e:?}"))?;
        if probe != branched.reached {
            return Err(format!("{probe:?} against {:?}", branched.reached));
        }
        let mut digests = Vec::new();
        for child in &branched.children {
            let report = child.report.as_ref().ok_or("a credited child's report")?;
            if report.teardowns != 1 {
                return Err(format!("a child ran {} teardown audits", report.teardowns));
            }
            let (_, bytes) = diverged(&original, PENDING, Some(child.suffix))
                .map_err(|refused| format!("{refused:?}"))?;
            let library = load(&bytes, u64::MAX).map_err(|error| format!("{error:?}"))?;
            if library.digest != report.digest {
                return Err(format!(
                    "suffix {} forked and in process differ",
                    child.suffix
                ));
            }
            digests.push(report.digest);
        }
        if digests[0] == digests[2] {
            return Err("the two suffixes recorded one bundle".into());
        }
        planted(&original, PENDING, &dir)
    })();
    let _ = std::fs::remove_dir_all(&dir);
    checked
}

/// Branches `original` at milestone `name` under `dir` with a panicking
/// and with a hanging child: the first exits 101 after its teardown audit,
/// the watchdog ends the second, neither is credited, the branch fails a
/// check, and the parent stays unchanged.
pub(crate) fn planted(original: &[u8], name: &str, dir: &Path) -> Result<(), String> {
    for (label, plant, wait) in [
        ("panic", ChildPlant::Panic, Duration::from_secs(300)),
        ("hang", ChildPlant::Hang, Duration::from_millis(500)),
    ] {
        let out = dir.join(label);
        std::fs::create_dir(&out).map_err(|error| error.to_string())?;
        let branched = branch(original, name, (1, 1), &out, plant, wait)
            .map_err(|refused| format!("{label}: {refused:?}"))?;
        if !branched.parent {
            return Err(format!("{label}: the parent changed"));
        }
        for child in &branched.children {
            let expected = match plant {
                ChildPlant::Panic => Classified::Failed {
                    code: 101,
                    payload: b"panicked\nteardowns: 1\n".to_vec(),
                },
                _ => Classified::Watchdog,
            };
            if child.class != expected || child.class.credited() || child.problems.is_empty() {
                return Err(format!("{label}: {:?}", child.class));
            }
        }
        if branched.problems().is_empty() {
            return Err(format!("{label}: the branch passed"));
        }
    }
    Ok(())
}

/// Whether semantic record `record` is a scripted history's SCRIPT turn,
/// and if so its step and whether the step returned `STAY`.
fn script_turn(record: &[u8]) -> Option<(u32, bool)> {
    let script = record[0] == 4 && record[12..14] == [Domain::Workload as u8, SCRIPT];
    script.then(|| {
        let step = u32::from_be_bytes(record[15..19].try_into().expect("a step"));
        let outcome = u64::from_le_bytes(record[28..36].try_into().expect("an outcome"));
        (step, outcome == STAY)
    })
}

/// Per stopped boundary of `bytes`, in order and read from its records
/// alone: the turns and the completed SCRIPT steps recorded before its
/// clock record. Also the run's turns and completed steps in all.
fn boundaries(bytes: &[u8]) -> (Vec<(u64, u64)>, (u64, u64)) {
    let (mut at, mut turns, mut steps) = (Vec::new(), 0, 0);
    for record in bytes.as_chunks::<RECORD>().0 {
        match record[0] {
            4 => {
                turns += 1;
                steps += u64::from(script_turn(record).is_some_and(|(_, stay)| !stay));
            }
            5 => at.push((turns, steps)),
            _ => {}
        }
    }
    (at, (turns, steps))
}

/// The clock and turn records among the first `semantic` semantic records
/// of `bytes`, and whether the record after them is an event, which would
/// cut a boundary's events.
fn prefix_counts(bytes: &[u8], semantic: u64) -> (u64, u64, bool) {
    let mut records = bytes
        .as_chunks::<RECORD>()
        .0
        .iter()
        .filter(|record| is_semantic(record[0]));
    let prefix: Vec<_> = records.by_ref().take(semantic as usize).collect();
    let count = |tag: u8| prefix.iter().filter(|record| record[0] == tag).count() as u64;
    let next = records.next().is_some_and(|record| record[0] == 6);
    (count(5), count(4), next)
}

/// The first selection, value and bound, among the records of `bytes` past
/// its first `semantic` semantic records.
fn first_selection(bytes: &[u8], semantic: u64) -> Option<(u64, u64)> {
    let word =
        |record: &[u8], at: usize| u64::from_le_bytes(record[at..at + 8].try_into().unwrap());
    bytes
        .as_chunks::<RECORD>()
        .0
        .iter()
        .filter(|record| is_semantic(record[0]))
        .skip(semantic as usize)
        .find(|record| record[0] == 3 && record[4] == 3)
        .map(|record| (word(record, 5), word(record, 13)))
}

/// Replays `original` to milestone `name` and checks the boundary from the
/// bundle's own records: the prefix holds `boundary` clock records and the
/// turns the facts count, ends after that boundary's events, hashes to the
/// reported digest, and the probe reproduces the bundle; the witness holds
/// over records that hold no upload state.
fn reached_at(original: &[u8], name: &str, boundary: u64) -> Reached {
    let (reached, replayed) = diverged(original, name, None).expect(name);
    assert_eq!(reached.facts.boundary, boundary, "{name}");
    assert_eq!(
        prefix_counts(original, reached.semantic),
        (boundary, reached.facts.turns, false),
        "{name}"
    );
    assert_eq!(
        prefix_digest(original, reached.semantic),
        Some(reached.prefix)
    );
    let digest = |bytes: &[u8]| load(bytes, u64::MAX).unwrap().digest;
    assert_eq!(digest(&replayed), digest(original), "{name}");
    assert_eq!(
        witness(name, &reached.facts),
        format!("witness: {name} holds=true boundary={boundary} upload=none armed=false\n")
    );
    reached
}

/// Milestone names parse to their milestones: the fixed names, and each
/// family's instances whose parameter is a canonical unsigned decimal in
/// range, zero and the type's maximum included. A sign, a space, a leading
/// zero, any other character, an empty or out-of-range parameter, another
/// family and the listed patterns themselves name no milestone, and a
/// branch refuses such a name as input.
#[test]
fn milestone_instances_parse_only_canonical_decimals() {
    assert_eq!(
        super::MILESTONES,
        ["pending-put", "recovery-reached", "turn-N", "script-N"]
    );
    for (name, milestone) in [
        ("pending-put", Milestone::PendingPut),
        ("recovery-reached", Milestone::RecoveryReached),
        ("turn-0", Milestone::Turn(0)),
        ("turn-23", Milestone::Turn(23)),
        ("turn-18446744073709551615", Milestone::Turn(u64::MAX)),
        ("script-0", Milestone::Script(0)),
        ("script-4294967295", Milestone::Script(u32::MAX)),
    ] {
        assert_eq!(Milestone::parse(name), Some(milestone), "{name}");
    }
    for name in [
        "turn-N",
        "script-N",
        "turn-",
        "turn-+1",
        "turn--1",
        "turn-01",
        "turn-00",
        "turn- 1",
        "turn-1 ",
        " turn-1",
        "turn-1.0",
        "turn-0x1",
        "turn-18446744073709551616",
        "script-4294967296",
        "script-+0",
        "script-07",
        "Turn-1",
        "turn1",
        "step-1",
        "pending-put-1",
        "",
    ] {
        assert_eq!(Milestone::parse(name), None, "{name}");
    }
    let c4 = bundle("c4");
    for name in ["turn-01", "script-+1", "turn-18446744073709551616"] {
        assert!(
            matches!(diverged(&c4, name, None), Err(Unbranched::Input(reason)) if reason.contains("no milestone")),
            "{name}"
        );
    }
}

/// A turn milestone forks at the first stopped boundary after at least N
/// turns. History c4 records no upload, starts at one clock, applies
/// several turns there, advances once and applies more turns with no
/// boundary after them, all read from its records. `turn-0` holds at the
/// initial boundary before any turn; `turn-1` and the turn count at the
/// advance both fork at the advance, the boundary actually used, so a
/// turn's own completion never forks; one turn more, every turn of the run
/// and the largest count are refused for their predicate, since no later
/// boundary exists, as `turn-1` is in the failing same-time history
/// h1-get-stale. A turn milestone forks under the same fork gate: a library
/// test is refused for its threads.
#[test]
fn a_turn_milestone_forks_at_the_first_boundary_after_its_turns() {
    let original = bundle("c4");
    let (at, (turns, _)) = boundaries(&original);
    assert_eq!(at.len(), 2, "two stopped boundaries");
    let advance = at[1].0;
    assert!(
        at[0].0 == 0 && advance >= 2 && turns > advance,
        "{at:?} {turns}"
    );
    let uploads = original
        .as_chunks::<RECORD>()
        .0
        .iter()
        .filter(|record| record[0] == 6 && record[1] == UPLOAD)
        .count();
    assert_eq!(uploads, 0, "a history without an upload");
    let initial = reached_at(&original, "turn-0", 1);
    assert_eq!(initial.facts.turns, 0);
    assert!(witness("turn-1", &initial.facts).contains(" holds=false "));
    for n in [1, advance] {
        let reached = reached_at(&original, &format!("turn-{n}"), 2);
        assert_eq!(reached.facts.turns, advance);
    }
    for n in [advance + 1, turns, u64::MAX] {
        assert_eq!(
            diverged(&original, &format!("turn-{n}"), None),
            Err(Unbranched::Milestone(Refusal::Predicate)),
            "turn-{n}"
        );
    }
    let stale = bundle("h1-get-stale");
    let (once, (stale_turns, _)) = boundaries(&stale);
    let violated = load(&stale, u64::MAX).unwrap().violation.is_some();
    assert!(
        once.len() == 1 && stale_turns >= 1 && violated,
        "a failing same-time history with a completed turn"
    );
    assert_eq!(
        diverged(&stale, "turn-1", None),
        Err(Unbranched::Milestone(Refusal::Predicate))
    );
    let forked = branch(
        &original,
        "turn-0",
        (1, 1),
        &std::env::temp_dir(),
        ChildPlant::None,
        Duration::from_secs(1),
    );
    assert!(
        matches!(forked, Err(Unbranched::Milestone(Refusal::Threads(count))) if count > 1),
        "{forked:?}"
    );
}

/// A script milestone forks at the first stopped boundary after the
/// history's step N, counted from zero, returned an outcome other than
/// `STAY`. In history h5-put, read from its records, step 3 returns `STAY`
/// at least twice before it completes, every step up to the advance
/// completes at the first clock, and the later steps complete after the
/// last boundary; its completed steps carry indexes 0, 1, 2 and on in
/// order. `script-0`, the step that waited, and the last step completed
/// before the advance each fork at the advance with the steps completed
/// there; the first step completed past the advance, a step beyond the
/// script and the largest index are refused for their predicate, as is any
/// script milestone in a run with no script. History i3-put-late completes
/// steps before its second boundary and again much later: `script-0` forks
/// at the second boundary and the first step completed after it at the
/// first boundary after that step, not at a later qualifying one.
#[test]
fn a_script_milestone_forks_after_its_step_completes() {
    let original = bundle("h5-put");
    let (at, (_, steps)) = boundaries(&original);
    assert_eq!(at.len(), 2, "two stopped boundaries");
    let completed = at[1].1;
    assert!(
        at[0].1 == 0 && completed > 0 && steps > completed,
        "{at:?} {steps}"
    );
    // The SCRIPT turns before the advance's clock record.
    let mut clocks = 0;
    let script: Vec<(u32, bool)> = original
        .as_chunks::<RECORD>()
        .0
        .iter()
        .take_while(|record| {
            clocks += u32::from(record[0] == 5);
            clocks < 2
        })
        .filter_map(|record| script_turn(record))
        .collect();
    let done: Vec<u32> = script
        .iter()
        .filter(|turn| !turn.1)
        .map(|turn| turn.0)
        .collect();
    assert_eq!(
        done,
        (0..completed as u32).collect::<Vec<_>>(),
        "steps complete in index order"
    );
    // Step 3, which the script-3 cases name, returns STAY twice before it
    // completes.
    let waited = 3;
    let stays = script
        .iter()
        .filter(|&&turn| turn == (waited, true))
        .count();
    let done = script.iter().position(|&turn| turn == (waited, false));
    let last_stay = script.iter().rposition(|&turn| turn == (waited, true));
    assert!(
        stays >= 2 && done.is_some() && last_stay < done,
        "{script:?}"
    );
    for step in [0, waited, completed as u32 - 1] {
        let reached = reached_at(&original, &format!("script-{step}"), 2);
        assert_eq!(reached.facts.steps, Some(completed));
    }
    let length = super::super::histories::every()
        .find(|history| history.name == "h5-put")
        .unwrap()
        .script
        .len() as u32;
    for step in [completed as u32, length, u32::MAX] {
        assert_eq!(
            diverged(&original, &format!("script-{step}"), None),
            Err(Unbranched::Milestone(Refusal::Predicate)),
            "script-{step}"
        );
    }
    let unscripted = faulted();
    assert_eq!(boundaries(&unscripted).1.1, 0, "a run with no script");
    assert_eq!(
        diverged(&unscripted, "script-0", None),
        Err(Unbranched::Milestone(Refusal::Predicate))
    );
    let late = bundle("i3-put-late");
    let (at, _) = boundaries(&late);
    let next = at[1].1;
    let after = at
        .iter()
        .position(|&(_, steps)| steps > next)
        .expect("a later step") as u64
        + 1;
    assert!(
        next > 0 && after > 2 && (after as usize) < at.len(),
        "{at:?}"
    );
    reached_at(&late, "script-0", 2);
    reached_at(&late, &format!("script-{next}"), after);
}

/// A step that returns `STAY` has not completed, however often it waits;
/// its completion satisfies its own index and no later one. Every turn
/// counts toward a turn milestone. Outside a mixed run no turn completes a
/// step, though a recovery run's `hold` event shares the SCRIPT code.
#[test]
fn a_waiting_step_is_not_complete_and_only_a_mixed_run_counts_steps() {
    let script = |step: u32, outcome: u64| Turn {
        now: 0,
        event: super::super::candidate(SCRIPT, 0, step),
        outcome,
        observation: [0; crate::sim::trace::TURN_OBSERVATION],
    };
    let mut facts = Facts::starting(true, false);
    for _ in 0..3 {
        facts.turned(&script(0, STAY));
    }
    assert!(!Milestone::Script(0).holds(&facts));
    assert!(Milestone::Turn(3).holds(&facts) && !Milestone::Turn(4).holds(&facts));
    facts.turned(&script(0, 0));
    assert_eq!((facts.turns, facts.steps), (4, Some(1)));
    assert!(Milestone::Script(0).holds(&facts) && !Milestone::Script(1).holds(&facts));
    let mut other = Facts::starting(false, false);
    other.turned(&script(0, 0));
    assert_eq!((other.turns, other.steps), (1, None));
    assert!(!Milestone::Script(0).holds(&other) && Milestone::Turn(1).holds(&other));
}

/// Children at turn and script milestones keep the parent's prefix, and
/// their suffix source applies only after it. At c4's advance every suffix
/// draws the same first value, which is legal, yet the suffixes record
/// different bundles; at c4's initial boundary the first draws differ. At
/// h5-put's script milestone the first draw has one candidate, so every
/// suffix draws it, and at c4's script milestone the suffixes record
/// different bundles. Each child's prefix is the original bundle's, at the
/// boundary the parent's probe reaches.
#[test]
fn turn_and_script_children_keep_the_prefix_and_change_only_after_it() {
    let c4 = bundle("c4");
    let h5 = bundle("h5-put");
    let children = |original: &[u8], name: &str| {
        let probe = diverged(original, name, None).unwrap().0;
        (0..2)
            .map(|suffix| {
                let (reached, bytes) = diverged(original, name, Some(suffix)).unwrap();
                assert_eq!(reached, probe);
                assert_eq!(
                    prefix_digest(&bytes, reached.semantic),
                    prefix_digest(original, reached.semantic)
                );
                let loaded = load(&bytes, u64::MAX).unwrap();
                assert!(counts(&loaded), "{name} suffix {suffix}");
                (
                    first_selection(&bytes, reached.semantic).unwrap(),
                    loaded.digest,
                )
            })
            .collect::<Vec<_>>()
    };
    let advance = children(&c4, "turn-1");
    assert_eq!(advance[0].0, advance[1].0, "equal first draws");
    assert!(advance[0].0.1 > 1, "a draw among several candidates");
    assert_ne!(
        advance[0].1, advance[1].1,
        "the suffixes differ after the prefix"
    );
    let initial = children(&c4, "turn-0");
    assert_ne!(initial[0].0, initial[1].0);
    let script = children(&h5, "script-3");
    assert_eq!((script[0].0, script[1].0), ((0, 1), (0, 1)));
    let stepped = children(&c4, "script-5");
    assert_ne!(stepped[0].1, stepped[1].1, "script suffixes differ");
}

/// The bundle of `bytes` written as suffix 0's into `dir`, and a report
/// that matches it at `reached` from a child that ran `teardowns` audits.
fn child_report(bytes: &[u8], reached: Reached, dir: &Path, teardowns: u64) -> ChildReport {
    std::fs::write(dir.join("suffix-0-0.bundle"), bytes).unwrap();
    let loaded = load(bytes, u64::MAX).unwrap();
    ChildReport {
        prefix: reached.prefix,
        semantic: reached.semantic,
        digest: loaded.digest,
        decisions: loaded.decisions,
        terminal: terminal_text(loaded.terminal),
        bundle: "suffix-0-0.bundle".into(),
        descriptors: vec![0, 1, 2, REPORT_FD],
        inherited: 1,
        baseline: 0,
        teardowns,
    }
}

/// A copy of `bytes` with the attempt of its first upload state past its
/// first `semantic` semantic records raised by five.
pub(crate) fn with_changed_attempt(bytes: &[u8], semantic: u64) -> Vec<u8> {
    let (_, manifest) = super::super::replay::recorded(bytes).unwrap();
    // `reseal` hands the records after `Begin`, semantic record 0.
    reseal(bytes, manifest.capacity(), |records| {
        let state = (semantic as usize - 1..records.len())
            .find(|&at| records[at][0] == 6 && records[at][1] == UPLOAD)
            .expect("an upload state after the prefix");
        records[state][4] = records[state][4].wrapping_add(5);
    })
}

/// The problems the parent finds, in the scratch directory `label`, in the
/// child of `original` forked at `name` with suffix 0, as `edit` leaves its
/// bundle, at the boundary the fork reached.
fn judged_child(
    label: &str,
    original: &[u8],
    name: &str,
    edit: fn(&[u8], u64) -> Vec<u8>,
) -> (Reached, Vec<String>) {
    let (reached, bytes) = diverged(original, name, Some(0)).unwrap();
    let dir = scratch(label).unwrap();
    let report = child_report(&edit(&bytes, reached.semantic), reached, &dir, 1);
    let problems = report_problems(&report, (0, 0), reached, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    (reached, problems)
}

/// Whether `problems` names attempt `from` becoming `to` with no action
/// its prior state allows.
pub(crate) fn attempt_unexplained(problems: &[String], (from, to): (u16, u16)) -> bool {
    let named =
        format!("attempt {from} became {to} with no retry or invocation its prior state allows");
    problems.contains(&named)
}

/// A turn milestone's child is judged for custody as a pending-put child
/// is, from whatever upload state the boundary holds. A turn count that
/// reaches the faulted upload's pending-put boundary forks there with the
/// same pending facts. At an earlier boundary, whose upload is in flight
/// and not yet pending, an honest child passes every check, and the same
/// child with its next upload attempt changed after the prefix, with no
/// retry or invocation, fails custody.
#[test]
fn a_turn_milestone_child_is_judged_for_custody() {
    let original = faulted();
    let (pending, _) = diverged(&original, PENDING, None).unwrap();
    let at_pending = diverged(&original, &format!("turn-{}", pending.facts.turns), None);
    let reached = at_pending.unwrap().0;
    assert_eq!(
        (reached.facts, reached.prefix),
        (pending.facts, pending.prefix)
    );
    let (reached, honest) = judged_child("sim-turn-honest", &original, "turn-3", |bytes, _| {
        bytes.to_vec()
    });
    assert!(reached.facts.upload.is_some() && !reached.facts.pending());
    assert_eq!(honest, Vec::<String>::new());
    let (_, changed) = judged_child(
        "sim-turn-changed",
        &original,
        "turn-3",
        with_changed_attempt,
    );
    assert!(attempt_unexplained(&changed, (1, 6)), "{changed:?}");
}

/// Custody spans every upload a child's suffix runs and starts before the
/// first one, each judged as the parent judges a child. An honest `long`
/// child forked at `turn-3`, whose suffix publishes its first upload and
/// invokes the second, and an honest `upload` child forked at `turn-0`,
/// whose links release at delivery so the owner's poll returns its
/// sources, pass every check, and an `uncertain` child forked at `turn-0`,
/// whose suffix retries its upload, keeps its custody; judged as a delayed link, the `upload`
/// child's custody falls with nothing returning it. A `faulted` child
/// forked at `turn-0`, before any upload state and on delayed links,
/// passes, and fails once its first suffix upload state's attempt skips
/// past attempt 1.
#[test]
fn custody_spans_each_upload_of_a_suffix_and_starts_before_the_first() {
    let long = bundle("long");
    let (reached, bytes) = diverged(&long, "turn-3", Some(0)).unwrap();
    let attempts: Vec<_> = later_states(&bytes, reached.semantic)
        .iter()
        .map(|state| state.attempt)
        .collect();
    assert!(attempts.contains(&2), "the suffix begins a second upload");
    let unedited: fn(&[u8], u64) -> Vec<u8> = |bytes, _| bytes.to_vec();
    assert_eq!(
        judged_child("sim-long-honest", &long, "turn-3", unedited).1,
        Vec::<String>::new()
    );
    let uncertain = bundle("uncertain");
    let (reached, bytes) = diverged(&uncertain, "turn-0", Some(0)).unwrap();
    let retried = later_states(&bytes, reached.semantic)
        .iter()
        .any(|state| state.attempt == 2);
    assert!(retried, "the suffix retries its upload");
    let at_delivery = reached.facts.at_delivery;
    assert_eq!(
        custody(&bytes, reached.semantic, reached.facts.upload, at_delivery),
        Vec::<String>::new()
    );
    let upload = bundle("upload");
    let (reached, problems) = judged_child("sim-upload-honest", &upload, "turn-0", unedited);
    assert!(reached.facts.at_delivery && reached.facts.upload.is_none());
    assert_eq!(problems, Vec::<String>::new());
    let (_, bytes) = diverged(&upload, "turn-0", Some(0)).unwrap();
    let delayed = custody(&bytes, reached.semantic, None, false);
    assert!(
        delayed
            .iter()
            .any(|problem| problem.starts_with("device custody fell")),
        "{delayed:?}"
    );
    let original = faulted();
    let (reached, honest) = judged_child("sim-unstarted-honest", &original, "turn-0", unedited);
    assert!(!reached.facts.at_delivery && reached.facts.upload.is_none());
    assert_eq!(honest, Vec::<String>::new());
    let (_, changed) = judged_child(
        "sim-unstarted-changed",
        &original,
        "turn-0",
        with_changed_attempt,
    );
    assert!(attempt_unexplained(&changed, (0, 6)), "{changed:?}");
}

/// A prefix replay of a bundle edited before a turn or script milestone,
/// by a changed selection or a changed turn outcome, is reported diverged
/// rather than reaching the milestone over records the bundle lacks.
#[test]
fn edited_prefixes_diverge_before_turn_and_script_milestones() {
    let c4 = bundle("c4");
    let h5 = bundle("h5-put");
    for (original, name) in [(&c4, "turn-1"), (&h5, "script-3")] {
        assert!(diverged(original, name, None).is_ok());
        for edited in [
            diverging_before(original, name),
            differing_before(original, name),
        ] {
            assert_eq!(
                diverged(&edited, name, None),
                Err(Unbranched::Diverged),
                "{name}"
            );
        }
    }
}

/// A turn milestone forks each world's run, and its child is judged by the
/// teardown audits its world runs, as the in-process replays here count
/// them on this thread: the mixed run's observer audits its end once, and
/// a cluster run, which checks its cells at its end, and a recovery run,
/// which judges through its ledger, run none. A child that ran its world's
/// count passes every check, and one that ran the other count fails the
/// teardown check. Before a later boundary, cluster and recovery runs
/// record turns that share the SCRIPT code and complete, yet neither
/// counts a scripted step, so a script milestone never holds there.
#[test]
fn each_world_judges_a_turn_milestone_child_by_its_own_audits() {
    let sampled = |profile: &str, edit: fn(Manifest) -> Manifest| {
        let text = crate::sim::manifest_tests::sample(profile, &"a".repeat(64), "x86_64-linux");
        let manifest = edit(Manifest::parse(&text.replace("root = 3", "root = 7")).unwrap());
        traced(admit(&manifest).unwrap(), Vec::new()).sink
    };
    let cluster = sampled("cluster-broad", |manifest| manifest);
    let recovery = sampled("recovery-16k", |manifest| {
        let cuts = crate::sim::recovery::Recovery::named("recovery-16k")
            .unwrap()
            .table();
        manifest.with("restarts", cuts.len() as u64)
    });
    let dir = scratch("sim-world-audits").unwrap();
    for (original, audits) in [(&bundle("c4"), 1), (&cluster, 0), (&recovery, 0)] {
        let (at, _) = boundaries(original);
        assert!(at.len() >= 2 && at[1].0 > 0, "{at:?}");
        // A turn sharing the SCRIPT code and outcome precedes a later
        // boundary, so only the step gate refuses `script-0` there.
        assert!(
            audits == 1 || at[1..].iter().any(|&(_, steps)| steps > 0),
            "{at:?}"
        );
        let before = super::super::super::observe::teardowns();
        let (reached, bytes) = diverged(original, &format!("turn-{}", at[1].0), Some(0)).unwrap();
        assert_eq!(super::super::super::observe::teardowns() - before, audits);
        assert_eq!(reached.facts.boundary, 2);
        let judged = |teardowns| {
            let report = child_report(&bytes, reached, &dir, teardowns);
            report_problems(&report, (0, 0), reached, &dir)
        };
        assert_eq!(judged(audits), Vec::<String>::new(), "{audits}");
        let other = judged(1 - audits);
        assert_eq!(other, [format!("it ran {} teardown audits", 1 - audits)]);
        let script = diverged(original, "script-0", None);
        if audits == 1 {
            assert!(script.is_ok(), "{script:?}");
        } else {
            assert_eq!(script, Err(Unbranched::Milestone(Refusal::Predicate)));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
