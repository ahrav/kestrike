use super::*;
use crate::attempt::targeted;
use crate::record::{
    ChildEvidence, Comparison, Digest, Finding, Finished, ForkForm, Kernel, Summarized, Target,
};

fn frozen_child() -> ChildEvidence {
    let prefix = Digest::of(b"prefix");
    let target = Target {
        asset: Digest::of(b"asset"),
        boundary: 13,
        build: Digest::of(b"build"),
        bundle: Digest::of(b"raw"),
        bytes: 48,
        decisions: 1,
        form: ForkForm::Branch {
            siblings: 1,
            suffixes: 1,
        },
        manifest: Digest::of(b"manifest"),
        milestone: text("pending-put").unwrap(),
        prefix,
        root: 1,
        semantic: 5,
    };
    let output = format!(
        "milestone: pending-put boundary=13 semantic=5 decisions=1 prefix={prefix}\nwitness: pending-put holds=true boundary=13 upload=attempt:1,grant:3,held:2,outcome:0 armed=false\nparent: reproduced\nchild: suffix=0 sibling=0 class=success digest={} terminal=complete violation fired=03 required=03\nbranch: 1 children, 1 credited, 0 problems\n",
        Digest::of(b"semantic child")
    );
    let mut child = targeted::judge(&target, &output)
        .unwrap()
        .children
        .remove(0);
    child.bundle = Some(Digest::of(b"raw child"));
    child
}

fn replay(child: &ChildEvidence) -> (Artifact, Finished) {
    let summary = Summarized {
        cause: None,
        counts: false,
        decisions: Some(10),
        digest: child.digest.unwrap(),
        first_failure: None,
        identity: None,
        ledger: None,
        terminal: child.terminal.clone().unwrap(),
        unsuccessful: None,
    };
    let comparison = Comparison {
        candidate: None,
        divergence: None,
        failure_identity: None,
        failure_kind: None,
        observed: Some(summary.clone()),
        original: Some(summary),
        output: None,
        status: text("reproduced").unwrap(),
    };
    let artifact = Artifact {
        archive: None,
        archive_path: None,
        bundle: child.bundle,
        class: text("complete").unwrap(),
        command: text("replay").unwrap(),
        comparison: Some(comparison),
        manifest: None,
        output: None,
        reason: text("replay").unwrap(),
        run_id: text("child-replay").unwrap(),
        session: None,
        session_original: None,
        summary: None,
        workers: Default::default(),
    };
    let finished = Finished {
        attempt: text("child-replay").unwrap(),
        binding: crate::record::Binding::Matching,
        bound: None,
        class: Class::Violation,
        exit: Some(1),
        interruption: None,
        kernel: Kernel::default(),
        residual_members: false,
        signal: None,
        watchdog: false,
    };
    (artifact, finished)
}

#[test]
fn child_replay_projects_only_frozen_digest_and_terminal_from_the_current_grammar() {
    let child = frozen_child();
    let (mut artifact, mut finished) = replay(&child);
    assert_eq!(
        child_replay(Some(&child), Some(&artifact), &finished, child.bundle),
        ReplayStatus::Reproduced
    );
    let mut inconsistent = artifact.clone();
    inconsistent
        .comparison
        .as_mut()
        .unwrap()
        .original
        .as_mut()
        .unwrap()
        .digest = Digest::of(b"another original");
    assert_eq!(
        child_replay(Some(&child), Some(&inconsistent), &finished, child.bundle),
        ReplayStatus::InsufficientEvidence
    );
    let mut diverged = artifact.clone();
    diverged.comparison.as_mut().unwrap().status = text("diverged").unwrap();
    assert_eq!(
        child_replay(Some(&child), Some(&diverged), &finished, child.bundle),
        ReplayStatus::Diverged
    );
    let mut wrong_bundle = artifact.clone();
    wrong_bundle.bundle = Some(Digest::of(b"wrong input"));
    assert_eq!(
        child_replay(Some(&child), Some(&wrong_bundle), &finished, child.bundle),
        ReplayStatus::InsufficientEvidence
    );
    let mut changed = child.clone();
    changed.digest = Some(Digest::of(b"another trace"));
    assert_eq!(
        child_replay(Some(&changed), Some(&artifact), &finished, child.bundle),
        ReplayStatus::Diverged
    );
    changed = child.clone();
    changed.terminal = Some(text("complete inconclusive fired=03 required=03").unwrap());
    assert_eq!(
        child_replay(Some(&changed), Some(&artifact), &finished, child.bundle),
        ReplayStatus::Diverged
    );
    for missing_digest in [false, true] {
        let mut missing = child.clone();
        if missing_digest {
            missing.digest = None;
        } else {
            missing.terminal = None;
        }
        assert_eq!(
            child_replay(Some(&missing), Some(&artifact), &finished, child.bundle),
            ReplayStatus::InsufficientEvidence
        );
    }
    assert_eq!(
        child_replay(None, Some(&artifact), &finished, child.bundle),
        ReplayStatus::InsufficientEvidence
    );
    assert_eq!(
        child_replay(Some(&child), None, &finished, child.bundle),
        ReplayStatus::InsufficientEvidence
    );
    finished.class = Class::Pass;
    finished.exit = Some(0);
    artifact
        .comparison
        .as_mut()
        .unwrap()
        .observed
        .as_mut()
        .unwrap()
        .terminal = text("complete pass fired=03 required=03").unwrap();
    assert_eq!(
        child_replay(Some(&child), Some(&artifact), &finished, child.bundle),
        ReplayStatus::Unreproduced
    );
    let mut absent = child.clone();
    absent.digest = None;
    assert_eq!(
        child_replay(Some(&absent), Some(&artifact), &finished, child.bundle),
        ReplayStatus::InsufficientEvidence
    );
    finished.class = Class::Inconclusive;
    finished.exit = Some(1);
    artifact.comparison.as_mut().unwrap().status = text("unreproduced").unwrap();
    assert_eq!(
        child_replay(Some(&child), Some(&artifact), &finished, child.bundle),
        ReplayStatus::Unreproduced
    );
    finished.class = Class::Violation;
    finished.exit = Some(4);
    artifact = replay(&child).0;
    assert_eq!(
        child_replay(Some(&child), Some(&artifact), &finished, child.bundle),
        ReplayStatus::InsufficientEvidence
    );
}

#[test]
fn a_child_node_without_a_bundle_waits_for_disposition_and_has_no_next_step() {
    use crate::store::{Store, fixture::Case};
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let listing =
        crate::protocol::Listing::parse(include_str!("../../../testdata/admission-listing.txt"))
            .unwrap();
    let pins = crate::record::Pins {
        build: text(&Digest::of(b"build").to_string()).unwrap(),
        executable: text(&Digest::of(b"exe").to_string()).unwrap(),
        platform: text("linux").unwrap(),
        toolchain: text("rustc").unwrap(),
    };
    let request = crate::campaign::Request {
        profile: text("upload").unwrap(),
        campaign: text("c1").unwrap(),
        run: 0,
        attempts: 1,
        counts: Default::default(),
    };
    let ordinary = crate::campaign::admit(
        &store,
        &listing,
        pins,
        text("/archive").unwrap(),
        &request,
        crate::record::Purpose::Campaign,
    )
    .unwrap()
    .record;
    let child = frozen_child();
    let (_, mut finished) = replay(&child);
    let mut experiment = ordinary.job().experiment().clone();
    experiment.format = 2;
    experiment.target = Some(Target {
        asset: Digest::of(b"asset"),
        boundary: 13,
        build: Digest::of(b"build"),
        bundle: Digest::of(b"raw"),
        bytes: 48,
        decisions: 1,
        form: ForkForm::Branch {
            siblings: 1,
            suffixes: 1,
        },
        manifest: ordinary.job().manifest_sha256(),
        milestone: text("pending-put").unwrap(),
        prefix: Digest::of(b"prefix"),
        root: 1,
        semantic: 5,
    });
    let job = crate::record::Job::targeted(experiment).unwrap();
    finished.attempt = text(&format!("{}-0001", job.id())).unwrap();
    let mut finding = Finding {
        admission: crate::record::Admission::targeted(text("/archive").unwrap(), job.clone(), 1)
            .unwrap(),
        artifact: None,
        attempt: crate::record::Attempt {
            attempt: finished.attempt.clone(),
            file_bytes: 4096,
            job: job.id().digest(),
            manifest: job.manifest_sha256(),
            number: 1,
        },
        calibration_root: None,
        child: Some(child),
        finished,
        kind: FindingKind::Violation,
        parent_attempt: None,
    };
    assert_eq!(history::next(&finding, &[], false), Some(StepKind::Replay));
    let config = crate::record::Configuration::new(
        [
            ("slots", 1),
            ("reserve_slots", 1),
            ("cores", 2),
            ("memory", 512 << 20),
            ("cpu", 60),
            ("tree_memory", 128 << 20),
            ("attempt_output", 16 << 20),
            ("attempt_inodes", 200),
            ("wall", 120),
            ("processes", 64),
            ("artifact_bytes", 256 << 20),
            ("artifact_inodes", 10000),
            ("backlog", 2),
            ("retained_builds", 1),
        ]
        .into_iter()
        .map(|(key, value)| (text(key).unwrap(), value))
        .collect(),
    )
    .unwrap();
    let row = |number| {
        let mut attempt = finding.attempt.clone();
        attempt.number = number;
        let step = crate::record::TriageStep {
            attempt,
            finding: finding.id(),
            kind: StepKind::Replay,
            launcher: text("/campaign").unwrap(),
            limits: config.config().clone(),
        };
        let mut finished = finding.finished.clone();
        finished.class = Class::Incomplete;
        let result = crate::record::TriageResult {
            comparison: None,
            elapsed_ms: None,
            file_limited: false,
            finding: finding.id(),
            finished,
            number,
            output_limited: false,
            state: StepState::Complete,
            status: Some(ReplayStatus::InsufficientEvidence),
        };
        (step, result)
    };
    let records = vec![row(1)];
    assert_eq!(
        history::next(&finding, &records, false),
        Some(StepKind::Replay)
    );
    assert!(!history::stalled_for(
        &finding,
        &records,
        &config,
        StepKind::Replay
    ));
    let mut records = vec![row(1), row(2)];
    assert!(history::stalled_for(
        &finding,
        &records,
        &config,
        StepKind::Replay
    ));
    let mut ordinary_finding = finding.clone();
    ordinary_finding.admission = ordinary.clone();
    assert!(!history::stalled_for(
        &ordinary_finding,
        &records,
        &config,
        StepKind::Replay
    ));
    assert_eq!(
        history::next(&finding, &records, false)
            .filter(|kind| !history::stalled_for(&finding, &records, &config, *kind)),
        None
    );
    records[1].1.finished.class = Class::Infrastructure;
    assert!(history::stalled_for(
        &finding,
        &records,
        &config,
        StepKind::Replay
    ));
    let mut changed = config.config().clone();
    changed.insert(text("wall").unwrap(), 121);
    assert!(!history::stalled_for(
        &finding,
        &[row(1), row(2)],
        &crate::record::Configuration::new(changed).unwrap(),
        StepKind::Replay
    ));
    let mut interrupts = vec![row(1), row(2)];
    for (_, result) in &mut interrupts {
        result.state = StepState::Interrupted;
        result.status = None;
        result.finished.class = Class::Interrupted;
    }
    assert_eq!(
        history::targeted_stall_reason(&finding, &interrupts, &config, StepKind::Replay),
        Some("two consecutive interrupted targeted replays at unchanged limits")
    );
    let mut changed_limits = config.config().clone();
    changed_limits.insert(text("wall").unwrap(), 121);
    let changed_limits = crate::record::Configuration::new(changed_limits).unwrap();
    assert_eq!(
        history::targeted_stall_reason(&finding, &interrupts, &changed_limits, StepKind::Replay),
        None
    );
    assert_eq!(
        history::targeted_stall_reason(&finding, &records, &changed_limits, StepKind::Replay),
        None
    );
    assert_eq!(
        history::targeted_stall_reason(&finding, &records, &config, StepKind::Replay),
        Some("two insufficient targeted replays at unchanged limits")
    );
    let mixed = vec![interrupts[0].clone(), row(2), interrupts[1].clone()];
    assert_eq!(
        history::targeted_stall_reason(&finding, &mixed, &config, StepKind::Replay),
        None
    );
    assert!(!history::stalled_for(
        &finding,
        &mixed,
        &config,
        StepKind::Replay
    ));
    let mut settled = row(3);
    settled.1.status = Some(ReplayStatus::Diverged);
    assert_eq!(
        history::targeted_stall_reason(
            &finding,
            &[row(1), row(2), settled, row(4)],
            &config,
            StepKind::Replay
        ),
        None
    );
    let last = row(1);
    finding.child.as_mut().unwrap().digest = None;
    assert_eq!(
        history::next(&finding, std::slice::from_ref(&last), false),
        None
    );
    let mut interrupted = last.clone();
    interrupted.1.status = None;
    interrupted.1.state = StepState::Interrupted;
    interrupted.1.finished.class = Class::Interrupted;
    assert!(history::facts_settled(
        &finding,
        &[last, interrupted.clone(), interrupted]
    ));
    finding.child.as_mut().unwrap().digest = frozen_child().digest;
    finding.child.as_mut().unwrap().bundle = None;
    assert_eq!(history::next(&finding, &[], true), None);
    assert_eq!(executor::dependencies(&finding).unwrap().bundle, None);
    finding.child = None;
    finding.artifact = None;
    assert_eq!(finding.bundle_wait_reason(), Some("no retained bundle"));
    assert_eq!(history::next(&finding, &[], false), None);
}
