//! `ZoneLoop::step` in `failover/zone_loop/actuate.rs` takes `&StandbyGate` and calls the reclaim step
//! `ZoneLoop::detach` of `failover/zone_loop/reclaim.rs`, a `pub(super)` function that calls `Attacher::detach`.
//! `Attacher::detach` takes a `Witness`.
//!
//! Under `crates/*/src`, the rule skips `tests.rs`, files ending in `_tests.rs`, and directories ending in `_tests`.
//! It counts a `detach` token immediately after `.` or `::` as a call.
//!
//! - Under `failover/zone_loop/`, the detach calls are exactly the two of [`SITES`], each in its file, after its
//!   receiver and inside the function the site names, one call per site.
//! - The gated site's function has a parameter of type `&StandbyGate`, read as the tokens `:`, `&`, `StandbyGate`
//!   and then `,` or `)` in its signature, and the reclaim step's `fn detach` is `pub(super)`, visible to the zone
//!   loop module and its descendants.
//! - Outside `failover/zone_loop/`, the rule flags a source that holds a detach call and the name `Attacher`,
//!   `Witness` or a type that a non-test source implements `Attacher` for, `VolumeActions` among them.
//!
//! A test process reads the workspace's sources once and tokenizes each judged source once: [`workspace`] and
//! [`lexed`] hold the results for both tests, and a planted case tokenizes its one planted text and judges it
//! beside the held tokens of every other source.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use crate::oracle::guard_tests::{sources, tokens};

/// A detach call the rule admits under `failover/zone_loop/`: its file relative to the workspace root, the token
/// before its `.`, the function whose body holds it, and whether that function takes `&StandbyGate`.
struct Site {
    path: &'static str,
    receiver: &'static str,
    within: &'static str,
    gated: bool,
}

/// The reclaim step's `Attacher::detach` call and the gated actuation step's call of the reclaim step.
const SITES: [Site; 2] = [
    Site {
        path: "crates/kestrike/src/failover/zone_loop/reclaim.rs",
        receiver: "effects",
        within: "detach",
        gated: false,
    },
    Site {
        path: "crates/kestrike/src/failover/zone_loop/actuate.rs",
        receiver: "self",
        within: "step",
        gated: true,
    },
];

const ZONE_LOOP: &str = "crates/kestrike/src/failover/zone_loop/";

const RECLAIM: &str = "crates/kestrike/src/failover/zone_loop/reclaim.rs";

/// A judged source: its path relative to the workspace root and its tokens.
type Source<'a> = (&'a str, &'a [&'a str]);

/// Every `.rs` file under each `crates/*/src` directory as its path relative to the workspace root and its text, in
/// path order. The first call of a test process reads the files, and every call returns that one read.
///
/// # Panics
///
/// If a directory scan or file read fails.
fn workspace() -> &'static [(String, String)] {
    static FILES: OnceLock<Vec<(String, String)>> = OnceLock::new();
    FILES.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let mut found = Vec::new();
        for entry in fs::read_dir(root.join("crates")).unwrap() {
            let src = entry.unwrap().path().join("src");
            if src.is_dir() {
                sources(&root, &src, &mut found);
            }
        }
        found.sort();
        found
    })
}

fn test_source(path: &str) -> bool {
    let mut parts = path.rsplit('/');
    let name = parts.next().unwrap_or_default();
    name == "tests.rs" || name.ends_with("_tests.rs") || parts.any(|dir| dir.ends_with("_tests"))
}

/// Whether the rule reads the source at `path` holding `text`: a non-test source that holds `detach` or `Attacher`.
fn judged(path: &str, text: &str) -> bool {
    !test_source(path) && (text.contains("detach") || text.contains("Attacher"))
}

/// The judged sources of [`workspace`]. The first call of a test process tokenizes them, and every call returns
/// those tokens.
fn lexed() -> Vec<Source<'static>> {
    static LEXED: OnceLock<Vec<(&str, Vec<&str>)>> = OnceLock::new();
    let held = LEXED.get_or_init(|| {
        workspace()
            .iter()
            .filter(|(path, text)| judged(path, text))
            .map(|(path, text)| (path.as_str(), tokens(text)))
            .collect()
    });
    held.iter()
        .map(|(path, tokens)| (*path, tokens.as_slice()))
        .collect()
}

fn attachers<'a>(sources: &[Source<'a>]) -> BTreeSet<&'a str> {
    sources
        .iter()
        .flat_map(|(_, tokens)| tokens.windows(3))
        .filter(|window| window[0] == "Attacher" && window[1] == "for")
        .map(|window| window[2])
        .collect()
}

fn findings(sources: &[Source<'_>]) -> Vec<String> {
    let mut names = attachers(sources);
    names.extend(["Attacher", "Witness"]);
    let mut found = Vec::new();
    let mut matched = [0usize; SITES.len()];
    for (path, tokens) in sources {
        let calls = (1..tokens.len())
            .filter(|&at| tokens[at] == "detach" && matches!(tokens[at - 1], "." | "::"));
        if !path.starts_with(ZONE_LOOP) {
            if calls.count() > 0 && tokens.iter().any(|token| names.contains(token)) {
                found.push(format!(
                    "{path} calls detach beside an Attacher name outside the gated actuation"
                ));
            }
            continue;
        }
        for call in calls {
            let within = tokens[..call].iter().rposition(|&token| token == "fn");
            let site = SITES.iter().position(|site| {
                site.path == *path
                    && tokens[call - 1] == "."
                    && call >= 2
                    && tokens[call - 2] == site.receiver
                    && within.is_some_and(|at| tokens.get(at + 1) == Some(&site.within))
            });
            let (Some(site), Some(within)) = (site, within) else {
                found.push(format!(
                    "{path} calls detach outside the gated actuation's sites"
                ));
                continue;
            };
            matched[site] += 1;
            let body = tokens[within..].iter().position(|&token| token == "{");
            let signature = &tokens[within..within + body.unwrap_or(0)];
            let gate = signature.windows(4).any(|window| {
                window[..3] == [":", "&", "StandbyGate"] && matches!(window[3], "," | ")")
            });
            if SITES[site].gated && !gate {
                found.push(format!(
                    "{path} fn {} takes no &StandbyGate parameter",
                    SITES[site].within
                ));
            }
        }
        let declared = tokens
            .windows(6)
            .any(|window| window == ["pub", "(", "super", ")", "fn", "detach"]);
        if *path == RECLAIM && !declared {
            found.push(format!("{path} declares no pub(super) fn detach"));
        }
    }
    for (site, count) in SITES.iter().zip(matched) {
        if count != 1 {
            found.push(format!(
                "{} holds {count} detach calls in fn {}, expected 1",
                site.path, site.within
            ));
        }
    }
    found.sort();
    found
}

/// The findings over the workspace with the source at `path` holding `text`.
fn planted(path: &str, text: &str) -> Vec<String> {
    let plant = tokens(text);
    let mut tree = lexed();
    tree.retain(|(held, _)| *held != path);
    if judged(path, text) {
        tree.push((path, plant.as_slice()));
    }
    findings(&tree)
}

/// The findings over the workspace with the first `from` of the source at `path` replaced by `to`.
fn edited(path: &str, from: &str, to: &str) -> Vec<String> {
    let files = workspace();
    let text = &files.iter().find(|(held, _)| held == path).unwrap().1;
    assert!(text.contains(from), "{path} holds no {from:?}");
    planted(path, &text.replacen(from, to, 1))
}

/// The workspace check verifies both [`SITES`] under `failover/zone_loop/` and requires the derived `Attacher`
/// implementors to include `VolumeActions`.
#[test]
fn only_the_gated_actuation_calls_attacher_detach() {
    let files = workspace();
    let paths: BTreeSet<&str> = files.iter().map(|(path, _)| path.as_str()).collect();
    assert!(paths.contains(RECLAIM));
    assert!(paths.contains("crates/kestrike-aws/src/ec2/actions.rs"));
    let sources = lexed();
    assert!(attachers(&sources).contains("VolumeActions"));
    assert_eq!(findings(&sources), Vec::<String>::new());
}

/// The test requires a distinct finding for each planted violation: a detach call in another crate's source, a
/// second call in the reclaim file, a `pub` reclaim step, a removed reclaim call, and an actuation step whose gate
/// parameter is `&()`, is `Option<StandbyGate>`, or is a generic type bounded by `Into<StandbyGate>`. A planted call
/// in a test source, a comment or a string literal yields no finding.
#[test]
fn each_planted_detach_outside_the_gated_actuation_fails_the_rule() {
    const ROGUE: &str = "crates/kestrike-aws/src/ec2/rogue.rs";
    const ACTUATE: &str = "crates/kestrike/src/failover/zone_loop/actuate.rs";
    let cases = [
        (
            planted(
                ROGUE,
                "use kestrike::failover::zone_loop::sources::{Attacher, Witness};\n\
                 pub fn rogue(a: &mut impl Attacher, w: Witness<'_>) { a.detach(w); }",
            ),
            format!("{ROGUE} calls detach beside an Attacher name outside the gated actuation"),
        ),
        (
            planted(
                ROGUE,
                "use kestrike::failover::zone_loop::sources::*;\n\
                 pub fn rogue<W: Wire>(a: &mut super::VolumeActions<W>, w: Detached) {\n\
                 let _ = VolumeActions::detach(a, w);\n}",
            ),
            format!("{ROGUE} calls detach beside an Attacher name outside the gated actuation"),
        ),
        (
            edited(
                RECLAIM,
                "    pub(super) fn release_attach(",
                "    fn rogue(effects: &mut impl Attacher, w: Witness<'_>) { effects.detach(w); }\n\n    \
                 pub(super) fn release_attach(",
            ),
            format!("{RECLAIM} calls detach outside the gated actuation's sites"),
        ),
        (
            edited(RECLAIM, "pub(super) fn detach(", "pub fn detach("),
            format!("{RECLAIM} declares no pub(super) fn detach"),
        ),
        (
            edited(RECLAIM, "effects.detach(witness)", "DetachReply::Unknown"),
            format!("{RECLAIM} holds 0 detach calls in fn detach, expected 1"),
        ),
        (
            edited(
                ACTUATE,
                "fn step(\n        &mut self,\n        gate: &StandbyGate,",
                "fn step(\n        &mut self,\n        gate: &(),",
            ),
            format!("{ACTUATE} fn step takes no &StandbyGate parameter"),
        ),
        (
            edited(
                ACTUATE,
                "fn step(\n        &mut self,\n        gate: &StandbyGate,",
                "fn step(\n        &mut self,\n        gate: Option<StandbyGate>,",
            ),
            format!("{ACTUATE} fn step takes no &StandbyGate parameter"),
        ),
        (
            edited(
                ACTUATE,
                "fn step(\n        &mut self,\n        gate: &StandbyGate,",
                "fn step<G: Into<StandbyGate>>(\n        &mut self,\n        gate: G,",
            ),
            format!("{ACTUATE} fn step takes no &StandbyGate parameter"),
        ),
    ];
    for (found, finding) in cases {
        assert_eq!(found, std::slice::from_ref(&finding), "{finding}");
    }
    for (path, text) in [
        (
            "crates/kestrike-aws/src/ec2/rogue_tests.rs",
            "use kestrike::failover::zone_loop::sources::Attacher;\n\
             fn rogue(a: &mut impl Attacher) { a.detach(w); }",
        ),
        (
            ROGUE,
            "// Attacher: a.detach(w)\npub const NOTE: &str = \"Witness a.detach(w)\";",
        ),
    ] {
        assert_eq!(planted(path, text), Vec::<String>::new(), "{path}");
    }
}
