//! The failure view over hand-built bundles: each record boundary a
//! failure surfaces at, rules the catalog knows, does not know or
//! contradicts, audit codes with and without their identity, the first
//! failure kept, and every unsuccessful cause with the evidence it rests
//! on.

use sha2::{Digest, Sha256};

use crate::oracle::Obligation;
use crate::sim::choice::Domain;
use crate::sim::trace::{Event, Field, Outcome, RECORD, Recorder, Tag, Terminal, Work};
use crate::sim::turn::{End, Limit, Limits};

use super::super::super::super::audit::{Class, Reason, Record, Source};
use super::super::super::super::observe::Failure;
use super::super::super::bundle::{Site, Violated, failure_event, named, stop_event};
use super::super::super::cluster::{
    self, GENERATOR, KEPT_RESOURCES, PROBES_FAILED, Reached, Topology, coverage_event,
};
use super::super::tests::{
    PASS, VIOLATING as VIOLATION, body, clock, event_record, handmade, here, manifest, narrate,
    turn, violation_record,
};

const UNSUCCESSFUL: Terminal = Terminal::Complete {
    outcome: Outcome::Unsuccessful,
    fired: 3,
    required: 3,
};

/// The violation record of `violated`.
fn violation(violated: &Violated) -> [u8; RECORD] {
    violation_record(&violated.code())
}

fn rule(obligation: Obligation, rule: &'static str) -> Violated {
    Violated::Observed(Failure::Violation(obligation, rule))
}

/// `name` made distinct from every other scratch name this process
/// takes, so tests narrating at once write apart.
fn unique(name: &str) -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{name}-{next}")
}

/// The failure view of `records` in an upload bundle ending as `terminal`.
fn view(records: &[[u8; RECORD]], terminal: Terminal) -> String {
    let bytes = handmade(records, terminal);
    let failure = narrate(&unique("failure"), &bytes, &["--failure"], &here());
    assert_eq!(failure.code, 0, "{}", failure.err);
    failure.text.unwrap()
}

/// The lines of `text` after its header, from the `failure:` line on.
fn section(text: &str) -> Vec<&str> {
    text.lines()
        .skip_while(|line| !line.starts_with("failure:"))
        .collect()
}

/// A run-site failure following a turn is that turn's action's, the last
/// turn before it and not an earlier or later one; one following a clock
/// move is the stopped-boundary check's and names no turn, though a turn
/// ran before it; a settled-site failure is the settled check's, a turn
/// before it included; and one before the first clock is the setup's. A
/// failure no identity follows, or whose last identity names another site
/// byte or variant, names no raiser, only the record it follows; a
/// run-site failure the settlement holds names none either, and the last
/// identity after the violation decides between two.
/// The header names the failure tier and each view ends at the terminal.
#[test]
fn failures_name_the_record_boundary_that_raised_them() {
    let held = rule(Obligation::Custody, "a source slot tenure was taken twice");
    let run = event_record(&held.identity(Site::Run));
    let settled = event_record(&held.identity(Site::Settled));
    let mut later = turn(700, 2);
    later[16] = 9;
    let cases = [
        (
            vec![clock(600), turn(600, 4), violation(&held), run],
            "raised: by turn 0's action: now_us=600 domain=Workload code=deliver",
        ),
        (
            vec![
                clock(600),
                turn(600, 1),
                turn(650, 4),
                violation(&held),
                later,
                run,
            ],
            "raised: by turn 1's action: now_us=650 domain=Workload code=deliver",
        ),
        (
            vec![clock(600), turn(600, 1), clock(700), violation(&held), run],
            "raised: at the clock boundary after 1 turns, now_us=700: a stopped-boundary check \
                raised it, no turn did",
        ),
        (
            vec![clock(600), turn(600, 1), violation(&held), settled],
            "raised: at settlement, after the last turn: a settled check raised it, no turn did",
        ),
        (
            vec![violation(&held), run, clock(600), turn(600, 1)],
            "raised: before the first clock move: the setup raised it, no turn did",
        ),
    ];
    for (records, raised) in cases {
        let failure = view(&records, VIOLATION);
        let turns = records.iter().filter(|r| r[0] == Tag::Turn as u8).count();
        assert!(
            failure.contains(&format!(
                "window: turns 0..{turns} of {turns}, tier failure"
            )),
            "{failure}"
        );
        let lines = section(&failure);
        assert_eq!(lines[0], "failure: violation");
        assert!(lines[1].starts_with("violation: #"), "{lines:?}");
        assert!(lines[2].starts_with(raised), "{lines:?}");
        assert!(lines[3].starts_with("identity: #"), "{lines:?}");
        assert_eq!(
            lines[4],
            "rule: known \"a source slot tenure was taken twice\""
        );
        assert!(lines[5].starts_with("terminal: #"), "{lines:?}");
        assert_eq!(lines.len(), 6);
    }
    let failure = view(&[clock(600), turn(600, 4), violation(&held)], VIOLATION);
    let lines = section(&failure);
    assert_eq!(
        lines[2],
        "raised: unknown: no version-2 identity records its site; it follows turn 0"
    );
    assert_eq!(lines[3], "identity: none: the site is unrecorded");
    let raised = |records: &[[u8; RECORD]]| {
        let failure = view(records, VIOLATION);
        section(&failure)[2].to_owned()
    };
    let unsited = "raised: unknown: no version-2 identity records its site; it follows turn 0";
    for site in [0, 3] {
        let mut other = run;
        other[8] = site;
        assert_eq!(
            raised(&[clock(600), turn(600, 4), violation(&held), other]),
            unsited
        );
    }
    let mut oracle = run;
    oracle[5] = 2;
    assert_eq!(
        raised(&[clock(600), turn(600, 4), violation(&held), oracle]),
        unsited
    );
    let stop = event_record(&stop_event(End::Done, None));
    let late = [clock(600), turn(600, 4), stop, violation(&held), run];
    let recorded = "raised: unknown: a run site's failure recorded at settlement";
    assert_eq!(raised(&late), recorded);
    let both = [clock(600), turn(600, 4), violation(&held), settled, run];
    assert_eq!(raised(&both), recorded);
    let reversed = [clock(600), turn(600, 4), violation(&held), run, settled];
    assert!(raised(&reversed).starts_with("raised: at settlement, after the last turn"));
}

/// The view names settlement as the recording point of a recovery run's
/// check violation and leaves the turn unspecified. The cause of an
/// unsuccessful recovery run stays unknown.
#[test]
fn recovery_failures_name_no_turn() {
    let recovery = |records: &[[u8; RECORD]], terminal| {
        let manifest = manifest("recovery-512", 3);
        let mut recorder = Recorder::new(Vec::new(), manifest.capacity());
        recorder.field(Field::Manifest, manifest.canonical().as_bytes());
        for record in records {
            recorder.raw(record);
        }
        let bytes = recorder.finish(terminal, Work::default()).sink;
        let narrated = narrate(&unique("recovery"), &bytes, &["--failure"], &here());
        assert_eq!(narrated.code, 0, "{}", narrated.err);
        narrated.text.unwrap()
    };
    let held = rule(Obligation::Restart, "a lookup read bytes no write produced");
    let raised = "raised: at settlement: a recovery check during the run raised it; the bundle names no turn";
    let records = [
        clock(600),
        turn(600, 4),
        violation(&held),
        event_record(&held.identity(Site::Settled)),
    ];
    let text = recovery(&records, VIOLATION);
    assert_eq!(section(&text)[2], raised, "{text}");
    let leaked = rule(Obligation::Restart, crate::net::observe::FREE_RUNS);
    let records = [
        clock(600),
        turn(600, 4),
        violation(&leaked),
        event_record(&leaked.identity(Site::Settled)),
    ];
    let text = recovery(&records, VIOLATION);
    assert_eq!(section(&text)[2], raised, "{text}");
    let text = recovery(&[clock(600), turn(600, 4)], UNSUCCESSFUL);
    let lines = section(&text);
    assert_eq!(
        lines[1],
        "observed: none: the bundle records no OBSERVED event"
    );
    assert!(lines[2].starts_with("cause: unknown: "), "{text}");
}

/// A violation a run retains under an infrastructure terminal keeps its
/// raiser, identity and rule on the failure view, which exits 3; a cut
/// before the terminal record renders no terminal line.
#[test]
fn an_infrastructure_failure_view_keeps_its_violation() {
    let held = rule(Obligation::Custody, "a source slot tenure was taken twice");
    let records = [
        clock(600),
        turn(600, 4),
        violation(&held),
        event_record(&held.identity(Site::Run)),
    ];
    let infrastructure = Terminal::Infrastructure(crate::sim::trace::Infrastructure::Defect);
    let bytes = handmade(&records, infrastructure);
    let narrated = narrate(&unique("infrastructure"), &bytes, &["--failure"], &here());
    assert_eq!(narrated.code, 3, "{}", narrated.err);
    let text = narrated.text.unwrap();
    let lines = section(&text);
    assert_eq!(lines[0], "failure: infrastructure defect");
    assert!(lines[1].starts_with("violation: #"), "{lines:?}");
    assert!(
        lines[2].starts_with("raised: by turn 0's action"),
        "{lines:?}"
    );
    assert!(lines[3].starts_with("identity: #"), "{lines:?}");
    assert_eq!(
        lines[4],
        "rule: known \"a source slot tenure was taken twice\""
    );
    assert!(lines[5].starts_with("terminal: #"), "{lines:?}");
    let cut = &bytes[..bytes.len() - 2 * RECORD];
    let narrated = narrate(&unique("cut"), cut, &["--failure"], &here());
    assert_eq!(narrated.code, 3, "{}", narrated.err);
    let text = narrated.text.unwrap();
    assert!(section(&text)[1].starts_with("violation: #"), "{text}");
    assert!(!text.contains("terminal: #"), "{text}");
}

/// A long cataloged rule resolves whole from its identity, on the failure
/// view and on the default narrative's violation line. A rule no catalog
/// holds stays unknown with its hash, even when its first 41 bytes are a
/// cataloged rule's; an identity whose hash names a cataloged rule whose
/// length, variant or obligation, or whose 41 kept bytes, a shortened
/// prefix or a recorded length past 41 included, the bundle contradicts is
/// inconsistent and names the
/// hash; a truncation bit leaves a rule known; a variant that names no rule
/// renders none; and a violation without an identity names its rule and
/// site unknown.
#[test]
fn rules_render_known_unknown_or_inconsistent() {
    let known = "unrelated work stalled or read bytes outside the visible versions";
    let shared = "unrelated work stalled or read bytes outside the cache";
    let progress = |text| rule(Obligation::Progress, text);
    let identity = |violated: &Violated| event_record(&violated.identity(Site::Run));
    let line = |records: Vec<[u8; RECORD]>| {
        let failure = view(&records, VIOLATION);
        let bytes = handmade(&records, VIOLATION);
        let turns = narrate(&unique("turns"), &bytes, &[], &here())
            .text
            .unwrap();
        let rule = section(&failure)
            .into_iter()
            .find(|line| line.starts_with("rule: "))
            .unwrap()
            .to_owned();
        let violation = body(&turns)
            .into_iter()
            .find(|line| line.contains("violation variant"))
            .unwrap()
            .to_owned();
        (rule, violation, failure)
    };
    let (known_rule, known_line, _) = line(vec![
        violation(&progress(known)),
        identity(&progress(known)),
    ]);
    assert_eq!(known_rule, format!("rule: known \"{known}\""));
    assert!(
        known_line.ends_with(&format!("(rule known \"{known}\")")),
        "{known_line}"
    );
    let (unknown, unknown_line, _) = line(vec![
        violation(&progress(shared)),
        identity(&progress(shared)),
    ]);
    let hash = super::super::super::branch::hex(&Sha256::digest(shared.as_bytes()));
    assert_eq!(
        unknown,
        format!(
            "rule: unknown: no cataloged rule hashes to {hash}; the bundle holds 41 of its {} \
            bytes",
            shared.len()
        )
    );
    assert!(unknown_line.contains("(rule unknown: no cataloged rule hashes to"));
    let (inconsistent, _, _) = line(vec![
        violation(&progress("an unexpected binding")),
        identity(&progress(known)),
    ]);
    let known_hash = super::super::super::branch::hex(&Sha256::digest(known.as_bytes()));
    assert_eq!(
        inconsistent,
        format!(
            "rule: inconsistent: the identity's hash {known_hash} names \"{known}\", which the \
            recorded length 65, prefix, variant or obligation contradicts"
        )
    );
    let mut longer = identity(&progress(known));
    longer[9] += 1;
    let (length, _, _) = line(vec![violation(&progress(known)), longer]);
    assert!(length.contains("recorded length 66, prefix"), "{length}");
    for kept in [5, 0, 42, 255] {
        let mut short = violation(&progress(known));
        short[6] = kept;
        let (shortened, _, _) = line(vec![short, identity(&progress(known))]);
        assert!(
            shortened.starts_with("rule: inconsistent"),
            "{kept}: {shortened}"
        );
    }
    let mut oracle = identity(&progress(known));
    oracle[5] = 2;
    let (variant, _, _) = line(vec![violation(&progress(known)), oracle]);
    assert!(variant.starts_with("rule: inconsistent"), "{variant}");
    let mut cut = violation(&progress(known));
    cut[4] |= 0x80;
    let (truncated, _, _) = line(vec![cut, identity(&progress(known))]);
    assert_eq!(truncated, format!("rule: known \"{known}\""));
    for other in [0, 9] {
        let mut unnamed = violation(&progress(known));
        unnamed[4] = other;
        let failure = view(&[unnamed, identity(&progress(known))], VIOLATION);
        let rule = section(&failure)
            .into_iter()
            .find(|line| line.starts_with("rule: "));
        assert_eq!(
            rule,
            Some("rule: unknown: its variant names no rule"),
            "{other}"
        );
    }
    let other = rule(Obligation::History, known);
    let (obligation, _, _) = line(vec![violation(&other), identity(&progress(known))]);
    assert!(obligation.starts_with("rule: inconsistent"), "{obligation}");
    let (missing, missing_line, failure) = line(vec![violation(&progress(known))]);
    assert_eq!(
        missing,
        "rule: unknown: no version-2 identity event records its hash"
    );
    assert!(failure.contains("identity: none: the site is unrecorded"));
    assert!(missing_line.contains("(site unrecorded"), "{missing_line}");
}

/// An audit failure's violation line names its audit code's class, reason
/// and place, and its view the actor and link end the identity hash fixes,
/// for an actor past one byte and past 4095 alike, which its record cannot
/// hold; a link end past one byte leaves them unknown, as do an identity of
/// another failure and none.
#[test]
fn audit_violations_render_their_audit_code() {
    let audit = |source| {
        Violated::Audit(Record {
            class: Class::Production,
            reason: Reason::Oversize,
            source,
        })
    };
    let render = |violated: &Violated, identity: Option<Event>| {
        let mut records = vec![clock(600), turn(600, 1), violation(violated)];
        records.extend(identity.map(|event| event_record(&event)));
        let failure = view(&records, VIOLATION);
        section(&failure)
            .into_iter()
            .find(|line| line.starts_with("audit: "))
            .unwrap()
            .to_owned()
    };
    for (actor, toward) in [(7, 3), (0x1234, 9), (0xfedc, 255)] {
        let link = audit(Source::Link { actor, toward });
        assert_eq!(
            render(&link, Some(link.identity(Site::Settled))),
            format!("audit: actor={actor} toward={toward} (read from the identity hash)")
        );
    }
    let device = audit(Source::Device(0x0abc));
    assert_eq!(
        render(&device, Some(device.identity(Site::Settled))),
        "audit: actor=2748 toward=0 (read from the identity hash)"
    );
    let far = audit(Source::Link {
        actor: 5,
        toward: 300,
    });
    assert_eq!(
        render(&far, Some(far.identity(Site::Settled))),
        "audit: actor and link end unknown: no actor with a link end below 256 hashes to the \
        identity"
    );
    let near = audit(Source::Link {
        actor: 5,
        toward: 3,
    });
    let other = rule(Obligation::Bytes, "an unexpected binding");
    let unknown = "audit: actor and link end unknown: no audit identity follows";
    assert_eq!(render(&near, Some(other.identity(Site::Run))), unknown);
    assert_eq!(render(&near, None), unknown);
    let failure = view(&[clock(600), violation(&near)], VIOLATION);
    assert!(
        failure.contains("class=Production reason=Oversize reason_arg=0 reason_arg2=0 place=link"),
        "{failure}"
    );
}

/// The violation stays the view's failure when an observation follows it,
/// and when an in-run unsuccessful check's observation precedes a settled
/// audit violation, as a run whose audit fails after a failed check
/// records them, that observation and its cause render before the
/// violation; a poisoned first-failure cell's unsuccessful rule renders
/// whole.
#[test]
fn the_failure_view_keeps_the_first_failure() {
    let first = rule(Obligation::Bytes, "an unexpected binding");
    let later = failure_event(&Failure::Unsuccessful("a required witness never fired"));
    let records = [
        clock(600),
        turn(600, 1),
        violation(&first),
        event_record(&first.identity(Site::Run)),
        event_record(&later),
    ];
    let failure = view(&records, VIOLATION);
    let lines = section(&failure);
    assert!(
        lines[1].contains("rule=\"an unexpected binding\""),
        "{lines:?}"
    );
    assert!(!failure.contains("observed:"), "{failure}");
    let audit = Violated::Audit(Record {
        class: Class::Production,
        reason: Reason::Oversize,
        source: Source::Device(3),
    });
    let records = [
        clock(600),
        turn(600, 1),
        event_record(&later),
        violation(&audit),
        event_record(&audit.identity(Site::Settled)),
    ];
    let failure = view(&records, VIOLATION);
    let lines = section(&failure);
    assert!(lines[1].starts_with("observed: #"), "{lines:?}");
    assert!(
        lines[2].starts_with("cause: \"a required witness never fired\""),
        "{lines:?}"
    );
    assert!(lines[3].starts_with("violation: #"), "{lines:?}");
    assert!(lines[4].starts_with("raised: at settlement"), "{lines:?}");
    assert!(lines[6].starts_with("audit: actor=3"), "{lines:?}");
    let poisoned = failure_event(&Failure::Unsuccessful(
        "the first-failure cell was poisoned",
    ));
    let failure = view(&[clock(600), event_record(&poisoned)], UNSUCCESSFUL);
    assert!(
        failure.contains(
            "cause: \"the first-failure cell was poisoned\" (whole: 35 bytes); owner and key \
            unknown: the bundle names none"
        ),
        "{failure}"
    );
}

/// A cluster bundle's records under `cluster-broad` at root 3: its Config
/// field as a run at `root` over `topology` records it, then `records`.
fn cluster_bundle(root: u64, topology: Topology, records: &[[u8; RECORD]]) -> Vec<u8> {
    let manifest = manifest("cluster-broad", 3);
    let (profile, ..) = named("cluster-broad", root).unwrap();
    let mut config = vec![GENERATOR];
    config.extend(b"cluster-broad\0");
    config.extend([topology.owners, topology.keys, topology.hot, 9, 9]);
    let limits = Limits {
        total: 10,
        same_time: 10,
        no_progress: 10,
    };
    let mut recorder = Recorder::new(Vec::new(), manifest.capacity());
    recorder.field(Field::Manifest, manifest.canonical().as_bytes());
    let config = crate::sim::turn::record(&profile, None, &config, limits);
    recorder.field(Field::Config, &config);
    for record in records {
        recorder.raw(record);
    }
    recorder.finish(UNSUCCESSFUL, Work::default()).sink
}

/// The cause line of `bytes`' failure view.
fn cause(bytes: &[u8]) -> String {
    let narrated = narrate(&unique("cause"), bytes, &["--failure"], &here());
    assert_eq!(narrated.code, 0, "{}", narrated.err);
    let text = narrated.text.unwrap();
    let line = text.lines().find(|line| line.starts_with("cause: "));
    line.unwrap_or_else(|| panic!("{text}")).to_owned()
}

/// A cluster turn of workload `code` at partition `cell` naming `key`.
fn cluster_turn(code: u8, cell: u8, key: u8) -> [u8; RECORD] {
    let mut record = turn(600, 0);
    record[12..15].copy_from_slice(&[Domain::Workload as u8, code, cell]);
    record[20] = key;
    record
}

/// Each unsuccessful cause rests on what the bundle records: a cluster
/// run's post-run shortfall derives from its last recorded coverage and
/// this decoder's minima, in the order the run checks them, noting a
/// saturated count and that a teardown check may have failed first, and
/// only when the run stopped at its goal and the recorded configuration is
/// the profile's at its root and topology; a probe failure names its whole
/// rule and the owner and key of the last probe step before it, kept
/// resources that owner alone, else neither; a variant other than an
/// unsuccessful check's, a recorded prefix shorter
/// than a condition's 41 bytes, any other unsuccessful rule, one in
/// another world, and a rule length past 41 name no condition, and a cut
/// rule says its rest is unknown.
#[test]
fn unsuccessful_causes_name_their_evidence() {
    let topology = Topology {
        owners: 2,
        keys: 5,
        hot: 1,
    };
    let minima = cluster::shape("cluster-broad").unwrap().minima;
    assert!(minima.published > 0 && minima.hits > 0);
    let met = Reached {
        published: minima.published,
        hits: minima.hits,
        cross: minima.cross,
        faults: minima.faults,
        healthy: minima.healthy,
        reused: minima.reused,
        ..Reached::default()
    };
    let coverage = |reached: Reached| event_record(&coverage_event(topology, &reached));
    let done = event_record(&stop_event(End::Done, None));
    let short = coverage(Reached { hits: 0, ..met });
    let required = minima.hits;
    let derived = format!(
        "cause: \"fewer exact reads than the profile requires\" (derived: the run's minimum check \
        over the recorded coverage under this decoder's minima for cluster-broad, short of hits \
        observed=0 required={required}"
    );
    let teardown = "; a teardown check that failed first would leave no record)";
    assert_eq!(
        cause(&cluster_bundle(3, topology, &[short, done])),
        format!("{derived}{teardown}")
    );
    let both = coverage(Reached {
        published: 0,
        hits: 0,
        ..met
    });
    assert!(
        cause(&cluster_bundle(3, topology, &[both, done]))
            .starts_with("cause: \"fewer publications than the profile requires\" (derived:")
    );
    let saturated = coverage(Reached {
        hits: 0,
        misses: u64::MAX,
        ..met
    });
    assert_eq!(
        cause(&cluster_bundle(3, topology, &[saturated, done])),
        format!(
            "{derived}; a count at 4294967295 is saturated and reads as at least that{teardown}"
        )
    );
    assert_eq!(
        cause(&cluster_bundle(3, topology, &[coverage(met), done])),
        "cause: unknown: the recorded coverage meets every minimum this decoder holds for \
        cluster-broad"
    );
    let unstopped = "cause: unknown: no recorded goal stop shows the run made its minimum check";
    let limit = event_record(&stop_event(End::Inconclusive(Limit::Total), None));
    assert_eq!(cause(&cluster_bundle(3, topology, &[short])), unstopped);
    assert_eq!(
        cause(&cluster_bundle(3, topology, &[short, limit])),
        unstopped
    );
    let incompatible = "cause: unknown: the recorded configuration is not cluster-broad's as this \
        decoder runs it";
    assert_eq!(
        cause(&cluster_bundle(4, topology, &[short, done])),
        incompatible
    );
    let other = Topology { hot: 2, ..topology };
    assert_eq!(
        cause(&cluster_bundle(3, other, &[short, done])),
        incompatible
    );
    assert_eq!(
        cause(&cluster_bundle(3, topology, &[done])),
        "cause: unknown: the bundle records no coverage of a cluster profile this decoder holds"
    );
    let narrated = narrate(
        "post-run",
        &cluster_bundle(3, topology, &[coverage(met), short, done]),
        &["--failure"],
        &here(),
    );
    let text = narrated.text.unwrap();
    let lines = section(&text);
    assert_eq!(
        lines[1],
        "observed: none: the bundle records no OBSERVED event"
    );
    assert!(
        lines[2].starts_with("coverage: #") && lines[2].contains(" published=4 hits=0 misses=0 "),
        "the last coverage event, which the cause derives from: {text}"
    );
    assert_eq!(lines[3], format!("{derived}{teardown}"));
    for (rule, condition, key) in [
        (PROBES_FAILED, "probes failed", "key=1"),
        (KEPT_RESOURCES, "kept resources", "key unknown"),
    ] {
        let observed = event_record(&failure_event(&Failure::Unsuccessful(rule)));
        let cut = format!(
            "cause: \"{}\" (its first 41 bytes; the run records no hash, so the rest is unknown); \
            {condition}, whose rule \"{rule}\" the recorded bytes begin; ",
            &rule[..41]
        );
        let probes = [
            clock(600),
            cluster_turn(cluster::PROBE, 0, 0),
            cluster_turn(cluster::PROBE, 1, 1),
            cluster_turn(16, 0, 3),
            observed,
        ];
        assert_eq!(
            cause(&cluster_bundle(3, topology, &probes)),
            format!("{cut}owner=1 {key} (from turn 1, the last probe step before it)")
        );
        let bare = [clock(600), cluster_turn(16, 0, 3), observed];
        assert_eq!(
            cause(&cluster_bundle(3, topology, &bare)),
            format!("{cut}owner and key unknown: no probe step precedes it")
        );
        for length in [0, 10] {
            let mut shortened = observed;
            shortened[6] = length;
            let records = [clock(600), cluster_turn(cluster::PROBE, 1, 1), shortened];
            let cause = cause(&cluster_bundle(3, topology, &records));
            assert!(
                cause.ends_with("; owner and key unknown: the bundle names none"),
                "{length}: {cause}"
            );
        }
        for length in [42, 255] {
            let mut oversized = observed;
            oversized[6] = length;
            assert_eq!(
                cause(&cluster_bundle(3, topology, &[clock(600), oversized])),
                format!("cause: unknown: its rule length {length} passes 41")
            );
        }
    }
    let mut oracle = event_record(&failure_event(&Failure::Unsuccessful(PROBES_FAILED)));
    oracle[4] = 2;
    let records = [clock(600), cluster_turn(cluster::PROBE, 1, 1), oracle];
    assert!(
        cause(&cluster_bundle(3, topology, &records))
            .ends_with("; owner and key unknown: the bundle names none")
    );
    let storage = event_record(&failure_event(&Failure::Unsuccessful(
        "the storage was no longer live",
    )));
    let records = [clock(600), cluster_turn(cluster::PROBE, 1, 1), storage];
    assert_eq!(
        cause(&cluster_bundle(3, topology, &records)),
        "cause: \"the storage was no longer live\" (whole: 30 bytes); owner and key unknown: the \
        bundle names none"
    );
    let witness = event_record(&failure_event(&Failure::Unsuccessful(
        "a required witness was never armed",
    )));
    let failure = view(&[clock(600), witness], UNSUCCESSFUL);
    assert!(failure.contains(
        "cause: \"a required witness was never armed\" (whole: 34 bytes); owner and key unknown: \
        the bundle names none"
    ));
    let long = event_record(&failure_event(&Failure::Unsuccessful(PROBES_FAILED)));
    let failure = view(&[clock(600), long], UNSUCCESSFUL);
    assert!(
        failure.contains("the run records no hash, so the rest is unknown); owner and key unknown"),
        "{failure}"
    );
    let failure = view(&[clock(600), turn(600, 1)], PASS);
    assert_eq!(section(&failure).len(), 2, "{failure}");
}

#[test]
fn a_recorded_shortfall_names_the_minima_its_coverage_misses() {
    let topology = Topology {
        owners: 2,
        keys: 5,
        hot: 1,
    };
    let minima = cluster::shape("cluster-broad").unwrap().minima;
    let met = Reached {
        published: minima.published,
        hits: minima.hits,
        cross: minima.cross,
        faults: minima.faults,
        healthy: minima.healthy,
        reused: minima.reused,
        ..Reached::default()
    };
    let coverage = |reached: Reached| event_record(&coverage_event(topology, &reached));
    let done = event_record(&stop_event(End::Done, None));
    let short = coverage(Reached { hits: 0, ..met });
    let observed = |rule| event_record(&failure_event(&Failure::Unsuccessful(rule)));
    let reads = observed("fewer exact reads than the profile requires");
    let lines = |records: &[[u8; RECORD]]| {
        let narrated = narrate(
            &unique("recorded"),
            &cluster_bundle(3, topology, records),
            &["--failure"],
            &here(),
        );
        assert_eq!(narrated.code, 0, "{}", narrated.err);
        section(&narrated.text.unwrap())
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    let recorded = lines(&[clock(600), turn(600, 0), short, reads, done]);
    assert!(
        recorded[1]
            .split_once(' ')
            .is_some_and(|(_, at)| at.starts_with('#') && at.contains(" settle: event OBSERVED ")),
        "{recorded:?}"
    );
    assert!(
        recorded[2].starts_with("cause: \"fewer exact reads than the profile requir\""),
        "{recorded:?}"
    );
    assert_eq!(
        recorded[3],
        format!(
            "minimum: short of hits observed=0 required={} (derived: the recorded coverage \
            under this decoder's minima for cluster-broad)",
            minima.hits
        )
    );
    for records in [
        [
            clock(600),
            turn(600, 0),
            observed(PROBES_FAILED),
            short,
            done,
        ],
        [clock(600), turn(600, 0), coverage(met), reads, done],
    ] {
        let narrated = lines(&records);
        assert!(
            !narrated.iter().any(|line| line.starts_with("minimum: ")),
            "a derived shortfall that disagrees with the recorded rule is not named: {narrated:?}"
        );
    }
}

#[test]
fn a_recorded_run_short_of_its_minima_places_its_minimum_check_at_settlement() {
    let bytes = super::super::tests::recorded("cluster-broad", 11);
    let narrated = narrate(&unique("settled"), &bytes, &["--failure"], &here());
    assert_eq!(narrated.code, 0, "{}", narrated.err);
    let text = narrated.text.unwrap();
    let lines = section(&text);
    assert_eq!(lines[0], "failure: unsuccessful", "{lines:#?}");
    assert!(
        lines[1]
            .split_once(' ')
            .is_some_and(|(_, at)| at.starts_with('#') && at.contains(" settle: event OBSERVED ")),
        "{lines:#?}"
    );
    assert!(lines[3].starts_with("minimum: short of "), "{lines:#?}");
}

/// A recorded cluster run whose healed owner kept finished work's
/// resources names the owner of its last probe step, owner 0, where its
/// leak plant leaks, and no key, which the bundle does not record.
#[test]
fn a_recorded_leak_names_its_probed_owner() {
    let cause = (1..=6)
        .map(|root| cause(&super::super::tests::recorded("cluster-late-leak", root)))
        .find(|cause| cause.contains("kept resources"))
        .expect("the leak fails a root");
    assert!(
        cause.contains("; owner=0 key unknown (from turn "),
        "{cause}"
    );
}

/// Each bundle the listed profiles record renders its failure view: a
/// failing one names the boundary its rule is raised at, a turn's action
/// for the cluster's stale read and a stopped-boundary check for the mixed
/// world's record and publication checks, and a known rule, the mixed
/// world's own collected-as-published rule among them; the passing upload
/// run names its outcome and terminal alone. Every recorded identity here
/// is a run site; `failures_name_the_record_boundary_that_raised_them` and
/// the recorder's settled-identity test cover settlement.
#[test]
fn recorded_failures_name_their_site_and_rule() {
    let clock = "raised: at the clock boundary after ";
    for (profile, raised) in [
        ("planted", Some(clock)),
        ("corrupted", Some(clock)),
        ("acked", Some(clock)),
        ("settled-planted", Some(clock)),
        ("cluster-stale-read", Some("raised: by turn ")),
        ("upload", None),
    ] {
        let bytes = super::super::tests::recorded(profile, 3);
        let narrated = narrate(&unique(profile), &bytes, &["--failure"], &here());
        let text = narrated.text.unwrap();
        let lines = section(&text);
        let Some(raised) = raised else {
            assert_eq!(lines[0], "failure: pass", "{profile}");
            assert!(
                lines[1].starts_with("terminal: #") && lines.len() == 2,
                "{lines:#?}"
            );
            continue;
        };
        assert_eq!(lines[0], "failure: violation", "{profile}: {lines:#?}");
        assert!(lines[2].starts_with(raised), "{profile}: {lines:#?}");
        assert!(lines[3].contains(" site=run "), "{profile}: {lines:#?}");
        assert!(
            lines[4].starts_with("rule: known \""),
            "{profile}: {lines:#?}"
        );
        if profile == "acked" {
            assert_eq!(
                lines[4],
                "rule: known \"an upload collected as published without its result\""
            );
        }
    }
}

/// A cluster bundle this build records, its Config field as the real
/// writer laid it out, derives its shortfall once its coverage falls short
/// and its run ends unsuccessful, so the compatibility check agrees with
/// the writer's layout and not only with a hand-built one.
#[test]
fn a_recorded_cluster_configuration_admits_the_derived_cause() {
    let bytes = super::super::tests::recorded("cluster-broad", 5);
    let (loaded, manifest) = super::super::super::replay::recorded(&bytes).unwrap();
    let mut recorder = Recorder::new(Vec::new(), manifest.capacity());
    for record in bytes.as_chunks::<RECORD>().0 {
        let mut record = *record;
        match Tag::from_code(record[0]) {
            Some(Tag::Begin | Tag::Checkpoint | Tag::Diagnostic | Tag::Terminal) => continue,
            Some(Tag::Event) if record[1] == cluster::COVERAGE => {
                let (topology, _) = cluster::coverage_of(&Event {
                    kind: record[1],
                    payload: record[4..].try_into().unwrap(),
                });
                let short = coverage_event(topology, &Reached::default());
                record[4..].copy_from_slice(&short.payload);
            }
            _ => {}
        }
        recorder.raw(&record);
    }
    let unsuccessful = recorder.finish(UNSUCCESSFUL, loaded.work).sink;
    let minimum = cluster::shape("cluster-broad").unwrap().minima.published;
    assert!(
        cause(&unsuccessful).starts_with(&format!(
            "cause: \"fewer publications than the profile requires\" (derived: the run's minimum \
            check over the recorded coverage under this decoder's minima for cluster-broad, short \
            of published observed=0 required={minimum}"
        )),
        "{}",
        cause(&unsuccessful)
    );
}

/// A swarm bundle's minima are those of the member its root selects, which
/// require each of the member's phases to heal, so a swarm run that ends
/// unsuccessful with no healed phase derives that shortfall. The family's
/// envelope holds no minimum.
#[test]
fn a_swarm_bundle_derives_its_cause_from_the_member_its_root_selects() {
    let bytes = super::super::tests::recorded("cluster-swarm", 1);
    let (loaded, manifest) = super::super::super::replay::recorded(&bytes).unwrap();
    let mut recorder = Recorder::new(Vec::new(), manifest.capacity());
    for record in bytes.as_chunks::<RECORD>().0 {
        let mut record = *record;
        match Tag::from_code(record[0]) {
            Some(Tag::Begin | Tag::Checkpoint | Tag::Diagnostic | Tag::Terminal) => continue,
            Some(Tag::Event) if record[1] == cluster::COVERAGE => {
                let (topology, _) = cluster::coverage_of(&Event {
                    kind: record[1],
                    payload: record[4..].try_into().unwrap(),
                });
                let short = coverage_event(topology, &Reached::default());
                record[4..].copy_from_slice(&short.payload);
            }
            _ => {}
        }
        recorder.raw(&record);
    }
    let unsuccessful = recorder.finish(UNSUCCESSFUL, loaded.work).sink;
    let cause = cause(&unsuccessful);
    assert!(
        cause.starts_with(
            "cause: \"fewer healed phases than the profile requires\" (derived: the run's minimum \
            check over the recorded coverage under this decoder's minima for cluster-swarm, short \
            of healthy observed=0 required="
        ),
        "{cause}"
    );
}
