//! Bundle summary and run output tests: the parser requires each
//! always-printed line once and each conditional line exactly when the
//! bundle's profile, verdict and ledger call for it, keeps text values as
//! printed, and reads a panicked run's line as a panic with no summary.

use super::fixture::{COUNTING, DIGEST, IDENTITY, LISTING, edited, twice, without};
use crate::record::Text;

use super::{
    COVERAGE, Error, FailureIdentity, Infrastructure, Ledger, Listing, Outcome, Run, Stages,
    Summary, Terminal, Topology,
};

/// The keys every summary prints, each once.
const ALWAYS: [&str; 22] = [
    "digest",
    "decisions",
    "terminal",
    "counts",
    "turns",
    "progress",
    "virtual_us",
    "skipped_us",
    "summary",
    "profile",
    "declared_turns",
    "declared_same_time",
    "declared_no_progress",
    "stop",
    "boundaries_checked",
    "operations",
    "witnesses",
    "faults_delivered",
    "owners",
    "clients",
    "incarnations",
    "retained_depth",
];

const STAGES: &str = "stages: planned=6 reached=5 activated=4 recovered=3 checked=2 skipped=1\n";

/// A cluster summary's coverage line.
const COVERED: &str = "coverage: published=8 hits=1 misses=2 refused=3 invalidated=4 cancelled=5 cross=6 reused=7 healthy=9 faults=25\n";

fn listing() -> Listing {
    Listing::parse(LISTING).expect("the fixture parses")
}

fn parse(text: &str) -> Result<Summary, Error> {
    Summary::parse(text, &listing())
}

/// A planted violation's summary, naming its cause and identity.
fn violation() -> String {
    let text = edited(COUNTING, "complete pass", "complete violation");
    let text = edited(&text, "counts: true", "counts: false");
    let text = edited(&text, "profile: upload", "profile: planted");
    format!("{text}cause: violation, violating Bytes\nidentity: {IDENTITY}\n")
}

/// A credited recovery bundle's summary.
fn recovery() -> String {
    let text = edited(COUNTING, "profile: upload", "profile: recovery-512");
    format!("{text}ledger: credited\n{STAGES}limits: process death; torn writes\n")
}

#[test]
fn the_listing_gates_crash_window_rows_beside_the_rebuilt_stages() {
    let mut listing = listing();
    let old = recovery();
    let current = format!("{old}windows: a=0 b=2 reuse=unplanned\n");
    listing.capabilities = 4;
    assert!(
        Summary::parse(&old, &listing)
            .unwrap()
            .recovery
            .unwrap()
            .windows
            .is_empty()
    );
    assert_eq!(
        Summary::parse(&current, &listing),
        Err(Error::Unknown("windows".into()))
    );
    listing.capabilities = 5;
    assert_eq!(
        Summary::parse(&old, &listing),
        Err(Error::Missing("windows"))
    );
    assert_eq!(
        Summary::parse(&current, &listing)
            .unwrap()
            .recovery
            .unwrap()
            .windows,
        [
            ("a".into(), Some(0)),
            ("b".into(), Some(2)),
            ("reuse".into(), None)
        ]
    );
    for value in [
        "",
        "=1",
        "a=-1",
        "a\u{a0}b=1",
        "a\u{1}b=1",
        "a=what",
        "a=1=2",
        "a=0  b=2",
        "a=18446744073709551616",
    ] {
        assert_eq!(
            Summary::parse(&format!("{old}windows: {value}\n"), &listing),
            Err(Error::Value("windows")),
            "{value:?}"
        );
    }
    assert_eq!(
        Summary::parse(&format!("{old}windows: a=0 a=unplanned\n"), &listing),
        Err(Error::Repeated("window a".into()))
    );
    // A counted cut passed its check and belongs to one row, so the
    // counts sum to at most the checked cuts.
    for value in [
        "a=3",
        "a=1 b=2 reuse=unplanned",
        "a=18446744073709551615 b=1",
    ] {
        assert_eq!(
            Summary::parse(&format!("{old}windows: {value}\n"), &listing),
            Err(Error::Inconsistent(
                "the window counts exceed the checked cuts"
            )),
            "{value:?}"
        );
    }
    let noncounting = edited(&current, "counts: true", "counts: false") + "cause: ledger gap\n";
    for verdict in ["inconclusive gap", "unrecorded", "mismatched Profile"] {
        let text = edited(
            &noncounting,
            "ledger: credited",
            &format!("ledger: {verdict}"),
        );
        assert_eq!(
            Summary::parse(&text, &listing)
                .unwrap()
                .recovery
                .unwrap()
                .windows
                .len(),
            3
        );
        assert_eq!(
            Summary::parse(&without(&text, "windows"), &listing),
            Err(Error::Missing("windows"))
        );
    }
    let refused = without(
        &without(
            &edited(&noncounting, "ledger: credited", "ledger: refused order"),
            "stages",
        ),
        "limits",
    );
    assert_eq!(
        Summary::parse(&refused, &listing),
        Err(Error::Unknown("windows".into()))
    );
}

/// A cluster bundle's summary; its owners line and drawn topology agree.
fn cluster() -> String {
    let text = edited(COUNTING, "profile: upload", "profile: cluster-broad");
    let text = edited(&text, "owners: 1", "owners: 3");
    format!(
        "{text}topology: owners=3 keys=6 hot=2\n{COVERED}unavailable: node-lifecycle,membership\n"
    )
}

/// `text` with every line of each of `keys` printing `unavailable`.
fn unavailable(text: &str, keys: &[&str]) -> String {
    text.lines()
        .map(|line| match line.split_once(": ") {
            Some((key, _)) if keys.contains(&key) => format!("{key}: unavailable\n"),
            _ => format!("{line}\n"),
        })
        .collect()
}

/// The work counts a truncated bundle records no value for.
const WORK: [&str; 5] = ["decisions", "turns", "progress", "virtual_us", "skipped_us"];

/// The observed counts a bundle without a composed stop event records no
/// value for.
const OBSERVED: [&str; 6] = [
    "boundaries_checked",
    "operations",
    "witnesses",
    "faults_delivered",
    "owners",
    "clients",
];

/// A truncated bundle's summary that names no profile.
fn truncated() -> String {
    let text = edited(
        COUNTING,
        "complete pass fired=03 required=03",
        "infrastructure truncated",
    );
    let text = edited(&text, "counts: true", "counts: false");
    let text = edited(&text, "profile: upload", "profile: unavailable");
    let text = unavailable(&text, &WORK);
    format!("{text}cause: infrastructure truncated, stop goal\n")
}

#[test]
fn a_counting_summary_parses_every_value() {
    let summary = parse(COUNTING).expect("the fixture parses");
    assert_eq!(summary.digest.to_string(), DIGEST);
    assert_eq!(
        summary.terminal,
        Terminal::Complete {
            outcome: Outcome::Pass,
            fired: 3,
            required: 3
        }
    );
    assert!(summary.counts && summary.terminal.passes());
    let superset = edited(COUNTING, "fired=03", "fired=07");
    assert!(parse(&superset).is_ok_and(|summary| summary.counts));
    assert_eq!(
        (summary.decisions, summary.turns, summary.progress),
        (Some(61), Some(57), Some(10))
    );
    assert_eq!(
        (summary.virtual_us, summary.skipped_us),
        (Some(600), Some(0))
    );
    assert_eq!(summary.profile.as_deref(), Some("upload"));
    assert_eq!(
        (
            summary.declared_turns,
            summary.declared_same_time,
            summary.declared_no_progress
        ),
        (Some(20000), Some(400), Some(5000))
    );
    assert_eq!(summary.stop.as_deref(), Some("goal"));
    assert_eq!(
        (
            summary.boundaries_checked,
            summary.operations,
            summary.witnesses,
            summary.faults_delivered,
            summary.owners,
            summary.clients
        ),
        (Some(4), Some(18), Some(10), Some(3), Some(1), Some(2))
    );
    assert_eq!(
        (
            summary.cause,
            summary.identity,
            summary.ledger,
            summary.cluster
        ),
        (None, None, None, None)
    );
}

/// Each always-printed line removed is missing and repeated is refused as
/// repeated, so no credit derives from a summary that drifted.
#[test]
fn each_always_printed_line_is_required_exactly_once() {
    for key in ALWAYS {
        assert_eq!(
            parse(&without(COUNTING, key)),
            Err(Error::Missing(key)),
            "{key} removed"
        );
        assert_eq!(
            parse(&twice(COUNTING, key)),
            Err(Error::Repeated(key.to_owned())),
            "{key} repeated"
        );
    }
}

#[test]
fn each_ledger_verdict_renders_its_parsed_word() {
    let summary = parse(&recovery()).expect("credited recovery parses");
    assert_eq!(summary.ledger.expect("ledger").verdict(), "credited");
    for line in [
        "inconclusive Gap { at: 3 }",
        "refused Truncated { at: 3 }",
        "unrecorded",
        "mismatched Profile",
    ] {
        let census = if line.starts_with("inconclusive") {
            format!("{STAGES}limits: torn\n")
        } else {
            String::new()
        };
        let text = format!("{}ledger: {line}\n{census}", truncated());
        let summary = parse(&text).expect("ledger verdict parses");
        assert_eq!(
            summary.ledger.expect("ledger").verdict(),
            line.split_whitespace().next().expect("verdict"),
            "{line}"
        );
    }
}

/// A recovery profile's summary needs its ledger, and its stages and
/// limits beside a ledger that rebuilt; a cluster profile's needs its
/// three cluster lines; a summary that does not count needs its cause.
#[test]
fn each_conditional_line_is_required_where_the_bundle_calls_for_it() {
    let summary = parse(&recovery()).expect("the recovery fixture parses");
    assert_eq!(summary.ledger, Some(Ledger::Credited));
    let recorded = summary
        .recovery
        .expect("stages print beside a rebuilt ledger");
    assert_eq!(
        recorded.stages,
        Stages {
            planned: 6,
            reached: 5,
            activated: 4,
            recovered: 3,
            checked: 2,
            skipped: 1
        }
    );
    assert_eq!(recorded.limits, "process death; torn writes");
    let drawn = parse(&cluster())
        .expect("the cluster fixture parses")
        .cluster
        .and_then(|cluster| cluster.drawn)
        .expect("cluster lines");
    assert_eq!(
        drawn.topology,
        Topology {
            owners: 3,
            keys: 6,
            hot: 2
        }
    );
    assert_eq!(COVERAGE[9], "faults");
    assert_eq!(drawn.coverage, [8, 1, 2, 3, 4, 5, 6, 7, 9, 25]);
    // Without a stop or coverage event both lines print unavailable.
    let unrecorded = unavailable(&cluster(), &["topology", "coverage"]);
    let undrawn = parse(&unrecorded)
        .expect("the unrecorded cluster fixture parses")
        .cluster
        .expect("cluster lines");
    assert_eq!(
        (undrawn.drawn, undrawn.unavailable.as_str()),
        (None, "node-lifecycle,membership")
    );
    for (text, key) in [
        (recovery(), "ledger"),
        (recovery(), "stages"),
        (recovery(), "limits"),
        (cluster(), "topology"),
        (cluster(), "coverage"),
        (cluster(), "unavailable"),
        (violation(), "cause"),
    ] {
        assert_eq!(
            parse(&without(&text, key)),
            Err(Error::Missing(key)),
            "{key} removed"
        );
        assert_eq!(
            parse(&twice(&text, key)),
            Err(Error::Repeated(key.to_owned())),
            "{key} repeated"
        );
    }
    let refused = edited(
        &recovery(),
        "ledger: credited",
        "ledger: refused Truncated { at: 3 }",
    );
    let refused = edited(&refused, "counts: true", "counts: false");
    let refused = format!("{refused}cause: the campaign ledger is Refused\n");
    assert_eq!(parse(&refused), Err(Error::Unknown("stages".to_owned())));
    let rebuilt = without(&without(&refused, "stages"), "limits");
    assert_eq!(
        parse(&rebuilt).map(|summary| summary.ledger),
        Ok(Some(Ledger::Refused("Truncated { at: 3 }".to_owned())))
    );
    // An unrecorded or mismatched verdict returns before the ledger
    // rebuilds, so its census prints only when the ledger rebuilds alone.
    for verdict in ["unrecorded", "mismatched Profile"] {
        let text = edited(
            &rebuilt,
            "ledger: refused Truncated { at: 3 }",
            &format!("ledger: {verdict}"),
        );
        assert!(
            parse(&text).is_ok_and(|summary| summary.recovery.is_none()),
            "{verdict}"
        );
        let census = edited(&text, "cause:", &format!("{STAGES}limits: torn\ncause:"));
        assert!(
            parse(&census).is_ok_and(|summary| summary.recovery.is_some()),
            "{verdict}"
        );
        assert_eq!(
            parse(&without(&census, "limits")),
            Err(Error::Missing("limits"))
        );
        assert_eq!(
            parse(&without(&census, "stages")),
            Err(Error::Missing("stages"))
        );
    }
}

/// A summary whose manifest does not parse names no profile; the worker
/// still judges a recovery ledger by the recorded profile, so the parser
/// takes a ledger line there at most once.
#[test]
fn a_summary_naming_no_profile_takes_its_ledger_when_printed() {
    let text = format!("{}ledger: unrecorded\n", truncated());
    let summary = parse(&text).expect("the unnamed summary parses");
    assert_eq!(
        (summary.profile, summary.ledger),
        (None, Some(Ledger::Unrecorded))
    );
    assert_eq!(
        parse(&twice(&text, "ledger")),
        Err(Error::Repeated("ledger".to_owned()))
    );
    // A family name the catalog admits without a profile line, such as a
    // settled profile, is never recovery, so its ledger line is unknown.
    let family = edited(&text, "profile: unavailable", "profile: settled-batched");
    assert_eq!(parse(&family), Err(Error::Unknown("ledger".to_owned())));
    // A census prints only beside its ledger.
    let census = format!("{}{STAGES}limits: torn\n", truncated());
    assert_eq!(parse(&census), Err(Error::Missing("ledger")));
}

/// A named profile is one the listing admits: a listed profile or a
/// family member naming the family's words, each at most once.
#[test]
fn a_summary_names_only_a_profile_the_listing_admits() {
    for name in ["settled-batched", "settled-scaled-batched"] {
        let text = edited(COUNTING, "profile: upload", &format!("profile: {name}"));
        assert!(parse(&text).is_ok(), "{name}");
    }
    for name in [
        "uploaded",
        "",
        "settled-",
        "settled-cramped",
        "settled-batched-batched",
        "settledbatched",
    ] {
        let text = edited(COUNTING, "profile: upload", &format!("profile: {name}"));
        assert_eq!(parse(&text), Err(Error::Value("profile")), "{name:?}");
    }
}

/// The fields one source records are available together: the work counts
/// exactly when the terminal is not truncated, the declared limits, and
/// the observed counts with their stop event, of which a history leaves
/// its operations and witnesses unavailable. `incarnations` and
/// `retained_depth` are always unavailable.
#[test]
fn each_source_s_fields_are_available_together() {
    let work = Error::Inconsistent(
        "the work counts are available exactly when the terminal is not truncated",
    );
    let declared =
        Error::Inconsistent("the declared limits are available together, and beside a profile");
    let observed =
        Error::Inconsistent("the observed counts are available together with their stop event");
    let stopless = unavailable(&unavailable(COUNTING, &OBSERVED), &["stop"]);
    assert!(parse(&stopless).is_ok());
    // A stop code the worker does not name prints as `unknown`.
    let unnamed = edited(COUNTING, "stop: goal", "stop: unknown");
    assert!(parse(&unnamed).is_ok_and(|summary| summary.stop.as_deref() == Some("unknown")));
    let history = edited(COUNTING, "profile: upload", "profile: h1-get-unheld");
    let scripted = unavailable(&history, &["operations", "witnesses"]);
    assert!(parse(&scripted).is_ok());
    let limits = [
        "declared_turns",
        "declared_same_time",
        "declared_no_progress",
    ];
    let undeclared = unavailable(&unavailable(COUNTING, &limits), &["profile"]);
    assert!(parse(&undeclared).is_ok());
    for (text, error) in [
        (unavailable(COUNTING, &["turns"]), work.clone()),
        (
            truncated().replace("decisions: unavailable", "decisions: 61"),
            work,
        ),
        (
            unavailable(COUNTING, &["declared_same_time"]),
            declared.clone(),
        ),
        (unavailable(COUNTING, &limits), declared),
        (unavailable(&cluster(), &OBSERVED), observed.clone()),
        (unavailable(COUNTING, &["owners"]), observed.clone()),
        (unavailable(COUNTING, &["stop"]), observed.clone()),
        (
            unavailable(&unavailable(COUNTING, &OBSERVED[1..]), &["stop"]),
            observed.clone(),
        ),
        (history, observed),
        (
            edited(COUNTING, "incarnations: unavailable", "incarnations: 2"),
            Error::Value("incarnations"),
        ),
        (
            edited(COUNTING, "retained_depth: unavailable", "retained_depth: 0"),
            Error::Value("retained_depth"),
        ),
    ] {
        assert_eq!(parse(&text), Err(error), "{text}");
    }
}

/// A terminal counts only when it passes with a nonzero required mask that
/// fired in full; a pass with no required obligation, or one that fired
/// short of its mask, does not count, and claiming it does is refused, as
/// is withholding credit from a counting pass.
#[test]
fn a_pass_counts_only_with_its_required_obligations_fired() {
    let counts = Err(Error::Inconsistent(
        "counts disagrees with the terminal and the ledger",
    ));
    for masks in [
        "fired=00 required=00",
        "fired=03 required=00",
        "fired=01 required=03",
    ] {
        let claimed = edited(COUNTING, "fired=03 required=03", masks);
        assert_eq!(parse(&claimed), counts, "{masks}");
        let honest = edited(&claimed, "counts: true", "counts: false");
        let honest = format!("{honest}cause: no required obligation\n");
        assert!(
            parse(&honest).is_ok_and(|summary| !summary.counts),
            "{masks}"
        );
    }
    let withheld = edited(COUNTING, "counts: true", "counts: false");
    let withheld = format!("{withheld}cause: no required obligation\n");
    assert_eq!(parse(&withheld), counts);
}

/// Each outcome and infrastructure word parses as its terminal and no
/// other word does.
#[test]
fn each_terminal_word_names_its_terminal() {
    let outcomes = [
        ("pass", Outcome::Pass),
        ("violation", Outcome::Violation),
        ("inconclusive", Outcome::Inconclusive),
        ("unsuccessful", Outcome::Unsuccessful),
    ];
    let classes = [
        ("sink", Infrastructure::Sink),
        ("cap", Infrastructure::Cap),
        ("truncated", Infrastructure::Truncated),
        ("defect", Infrastructure::Defect),
    ];
    assert_eq!(Outcome::ALL, outcomes.map(|(_, outcome)| outcome));
    assert_eq!(Infrastructure::ALL, classes.map(|(_, class)| class));
    for (word, outcome) in outcomes {
        assert_eq!(outcome.name(), word);
        assert_eq!(
            Terminal::parse(&format!("complete {word} fired=01 required=02"), "terminal"),
            Ok(Terminal::Complete {
                outcome,
                fired: 1,
                required: 2
            }),
            "{word}"
        );
        let rendered = format!("complete {word} fired=0a required=ff");
        let parsed = Terminal::parse(&rendered, "terminal").expect("the terminal parses");
        assert_eq!(
            parsed.to_string(),
            rendered,
            "the terminal prints as parsed"
        );
    }
    for (word, class) in classes {
        assert_eq!(class.name(), word);
        assert_eq!(
            Terminal::parse(&format!("infrastructure {word}"), "terminal"),
            Ok(Terminal::Infrastructure(class)),
            "{word}"
        );
        assert_eq!(
            Terminal::Infrastructure(class).to_string(),
            format!("infrastructure {word}")
        );
    }
    for text in ["infrastructure Cap", "complete Pass fired=01 required=02"] {
        assert_eq!(
            Terminal::parse(text, "terminal"),
            Err(Error::Value("terminal"))
        );
    }
}

/// A line the bundle's profile never prints is refused as unknown.
#[test]
fn a_line_another_profile_prints_is_unknown() {
    assert_eq!(
        parse(&format!("{COUNTING}ledger: credited\n")),
        Err(Error::Unknown("ledger".to_owned()))
    );
    let live = edited(&cluster(), "profile: cluster-broad", "profile: upload");
    assert_eq!(parse(&live), Err(Error::Unknown("topology".to_owned())));
}

#[test]
fn summary_lines_that_disagree_are_refused() {
    let infrastructure = edited(
        COUNTING,
        "complete pass fired=03 required=03",
        "infrastructure cap",
    );
    let withheld = edited(
        &recovery(),
        "ledger: credited",
        "ledger: inconclusive Bound { cut: 1 }",
    );
    let stopless = edited(
        &cluster(),
        "topology: owners=3 keys=6 hot=2",
        "topology: unavailable",
    );
    let counts = Error::Inconsistent("counts disagrees with the terminal and the ledger");
    for (text, error) in [
        (infrastructure, counts.clone()),
        (withheld, counts),
        (
            format!("{COUNTING}cause: no required obligation\n"),
            Error::Inconsistent("a counting bundle names a cause"),
        ),
        (
            format!("{COUNTING}unsuccessful: old read held\n"),
            Error::Inconsistent("a counting bundle names an unsuccessful rule"),
        ),
        (
            format!("{COUNTING}identity: {IDENTITY}\n"),
            Error::Inconsistent("an identity beside no complete violation"),
        ),
        (
            stopless,
            Error::Inconsistent("topology and coverage print from one coverage event"),
        ),
        (
            edited(&cluster(), "owners=3 keys=6", "owners=4 keys=6"),
            Error::Inconsistent("the topology's owners disagree with the owners line"),
        ),
        (
            edited(COUNTING, "skipped_us: 0", "skipped_us: 601"),
            Error::Inconsistent("the skipped time exceeds the clock"),
        ),
        (
            edited(&cluster(), "clients: 2", "clients: 3"),
            Error::Inconsistent("the clients disagree with the cluster declaration"),
        ),
        (
            edited(&cluster(), "owners: 3", "owners: 5").replace("owners=3 keys", "owners=5 keys"),
            Error::Inconsistent("the owners lie outside the cluster declaration's range"),
        ),
        (
            edited(
                &unavailable(&cluster(), &["topology", "coverage"]),
                "owners: 3",
                "owners: 5",
            ),
            Error::Inconsistent("the owners lie outside the cluster declaration's range"),
        ),
        (
            edited(&cluster(), "keys=6 hot=2", "keys=7 hot=2"),
            Error::Inconsistent("the drawn keys lie outside the cluster declaration's range"),
        ),
        (
            edited(&cluster(), "keys=6 hot=2", "keys=2 hot=1"),
            Error::Inconsistent("the drawn keys lie outside the cluster declaration's range"),
        ),
        (
            edited(&cluster(), "owners: 3", "owners: 4")
                .replace("owners=3 keys=6 hot=2", "owners=4 keys=3 hot=1"),
            Error::Inconsistent("the drawn keys lie outside the cluster declaration's range"),
        ),
        (
            edited(COUNTING, "owners: 1", "owners: 2"),
            Error::Inconsistent("the owners and clients disagree with the profile's topology"),
        ),
        (
            edited(COUNTING, "clients: 2", "clients: 1"),
            Error::Inconsistent("the owners and clients disagree with the profile's topology"),
        ),
        (
            edited(&recovery(), "reached=5", "reached=7"),
            Error::Inconsistent("a stage counts more cuts than the stage before it"),
        ),
        (
            edited(&recovery(), "checked=2", "checked=4"),
            Error::Inconsistent("a stage counts more cuts than the stage before it"),
        ),
        (
            edited(&recovery(), "skipped=1", "skipped=3"),
            Error::Inconsistent("the activated and skipped cuts exceed the planned"),
        ),
    ] {
        assert_eq!(parse(&text), Err(error), "{text}");
    }
    // A two-owner history prints the topology its listing line declares,
    // and the fixed topology disagrees with it.
    let paired = edited(COUNTING, "profile: upload", "profile: h6-get");
    let paired = unavailable(&paired, &["operations", "witnesses"]);
    assert!(
        parse(&edited(
            &edited(&paired, "owners: 1", "owners: 2"),
            "clients: 2",
            "clients: 4"
        ))
        .is_ok()
    );
    assert_eq!(
        parse(&paired),
        Err(Error::Inconsistent(
            "the owners and clients disagree with the profile's topology"
        ))
    );
    // A clock that advanced only by skips parses.
    assert!(parse(&edited(COUNTING, "skipped_us: 0", "skipped_us: 600")).is_ok());
}

/// The cause, the unsuccessful rule and the failure identity keep the
/// bytes the worker printed.
#[test]
fn text_values_survive_parsing_exactly() {
    let summary = parse(&violation()).expect("the violation fixture parses");
    assert_eq!(
        summary.identity.as_ref().map(FailureIdentity::as_str),
        Some(IDENTITY)
    );
    assert_eq!(summary.cause.as_deref(), Some("violation, violating Bytes"));
    let history = edited(COUNTING, "complete pass", "complete unsuccessful");
    let history = edited(&history, "counts: true", "counts: false");
    let history = edited(&history, "profile: upload", "profile: h1-get-unheld");
    let history = unavailable(&history, &["operations", "witnesses"]);
    let history = format!("{history}cause: unsuccessful\nunsuccessful: old read: held \"twice\"\n");
    let summary = parse(&history).expect("the history fixture parses");
    assert_eq!(
        summary.unsuccessful.as_ref().map(Text::as_str),
        Some("old read: held \"twice\"")
    );
    assert_eq!(summary.identity, None);
    // A rule is printable ASCII of at most 41 bytes, the payload less its
    // code bytes, and may be empty.
    let longest = "r".repeat(41);
    for rule in [longest.as_str(), ""] {
        let text = history.replace("old read: held \"twice\"", rule);
        assert_eq!(
            parse(&text).map(|summary| summary.unsuccessful.map(|rule| rule.as_str().to_owned())),
            Ok(Some(rule.to_owned())),
            "{rule:?}"
        );
    }
    let longer = "r".repeat(42);
    for rule in [longer.as_str(), "old\tread", "old read\u{e9}"] {
        let text = history.replace("old read: held \"twice\"", rule);
        assert_eq!(parse(&text), Err(Error::Value("unsuccessful")), "{rule:?}");
    }
}

#[test]
fn summary_values_outside_their_form_are_refused() {
    let short = &IDENTITY[..IDENTITY.len() - 1];
    for (text, from, to, error) in [
        (
            COUNTING.to_owned(),
            "summary: 1",
            "summary: 2",
            Error::Value("summary"),
        ),
        (
            COUNTING.to_owned(),
            "digest: f5",
            "digest: F5",
            Error::Value("digest"),
        ),
        (
            COUNTING.to_owned(),
            "decisions: 61",
            "decisions: 061",
            Error::Value("decisions"),
        ),
        (
            COUNTING.to_owned(),
            "decisions: 61",
            "decisions: 18446744073709551616",
            Error::Value("decisions"),
        ),
        (
            COUNTING.to_owned(),
            "turns: 57",
            "turns: -57",
            Error::Value("turns"),
        ),
        (
            COUNTING.to_owned(),
            "fired=03",
            "fired=3",
            Error::Value("terminal"),
        ),
        (
            COUNTING.to_owned(),
            "complete pass",
            "complete passed",
            Error::Value("terminal"),
        ),
        (
            COUNTING.to_owned(),
            "counts: true",
            "counts: yes",
            Error::Value("counts"),
        ),
        (violation(), IDENTITY, short, Error::Value("identity")),
        (
            recovery(),
            "ledger: credited",
            "ledger: credited twice",
            Error::Value("ledger"),
        ),
        (recovery(), "skipped=1", "skipped=x", Error::Value("stages")),
        (cluster(), "hot=2", "hot=two", Error::Value("topology")),
        (cluster(), "hot=2", "hot=6", Error::Value("topology")),
        (
            cluster(),
            "hits=1",
            "hits=4294967296",
            Error::Value("coverage"),
        ),
        (cluster(), "hits=1", "published=1", Error::Value("coverage")),
        (cluster(), " misses=2", "", Error::Value("coverage")),
        (cluster(), "misses=2", "missed=2", Error::Value("coverage")),
        (
            cluster(),
            "hits=1 misses=2",
            "misses=2 hits=1",
            Error::Value("coverage"),
        ),
        (
            cluster(),
            "faults=25",
            "faults=25 extra=1",
            Error::Value("coverage"),
        ),
        (
            COUNTING.to_owned(),
            "stop: goal",
            "stop: ",
            Error::Value("stop"),
        ),
        (
            COUNTING.to_owned(),
            "stop: goal",
            "stop: limit forever",
            Error::Value("stop"),
        ),
        (
            recovery(),
            "ledger: credited",
            "ledger: inconclusive ",
            Error::Value("ledger"),
        ),
        (
            cluster(),
            "unavailable: node-lifecycle,membership",
            "unavailable: membership",
            Error::Inconsistent("the unavailable dimensions differ from the cluster declaration"),
        ),
        (
            violation(),
            "cause: violation, violating Bytes",
            "cause: ",
            Error::Value("cause"),
        ),
    ] {
        assert_eq!(
            parse(&edited(&text, from, to)),
            Err(error),
            "{from} -> {to}"
        );
    }
}

/// A value printed `unavailable`, which the bundle records no value for,
/// reads as absent.
#[test]
fn unavailable_values_read_as_absent() {
    let text = unavailable(&truncated(), &OBSERVED);
    let text = unavailable(&text, &["stop"]);
    let summary = parse(&text).expect("the truncated summary parses");
    assert_eq!(
        summary.terminal,
        Terminal::Infrastructure(Infrastructure::Truncated)
    );
    assert_eq!(
        (summary.decisions, summary.profile, summary.stop),
        (None, None, None)
    );
    assert_eq!((summary.owners, summary.operations), (None, None));
}

/// A run that panicked prints one line naming the panic: it parses as that
/// panic and supplies no summary. The line repeated or cut short, or
/// beside a summary, is refused.
#[test]
fn a_panicked_run_line_is_incomplete_output_without_a_summary() {
    let listing = listing();
    let line = "run: the run panicked at src/a.rs:1:2: a panic: with \"quotes\"\n";
    assert_eq!(
        Run::parse(line, &listing),
        Ok(Run::Panicked(
            "src/a.rs:1:2: a panic: with \"quotes\"".to_owned()
        ))
    );
    assert_eq!(
        Run::parse(&line[..line.len() - 1], &listing),
        Err(Error::Torn)
    );
    assert_eq!(
        Run::parse(&format!("{line}{line}"), &listing),
        Err(Error::Repeated("run".to_owned()))
    );
    assert_eq!(
        Run::parse(&format!("{line}{COUNTING}"), &listing),
        Err(Error::Unknown("digest".to_owned()))
    );
    for empty in ["run: the run panicked at \n", "run: the run ended\n"] {
        assert_eq!(
            Run::parse(empty, &listing),
            Err(Error::Value("run")),
            "{empty}"
        );
    }
    assert_eq!(
        Run::parse(COUNTING, &listing),
        Ok(Run::Summary(Box::new(
            parse(COUNTING).expect("the fixture parses")
        )))
    );
}

#[test]
fn a_summary_cut_short_is_torn() {
    assert_eq!(parse(&COUNTING[..COUNTING.len() - 1]), Err(Error::Torn));
    assert_eq!(parse(""), Err(Error::Torn));
}
