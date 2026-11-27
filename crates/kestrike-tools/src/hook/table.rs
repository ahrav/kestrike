//! The hook's ten checks in run order, the paths whose change selects each, and the selection itself.
//! [`checks_for`] names rows of [`ORDER`] and no command's words, so a check that changes its command
//! changes its row and the path lists that name its script.

use std::sync::LazyLock;

use regex::Regex;

use crate::classes::{WORD, compiled};

use super::Members;

/// A check of [`ORDER`]; its order is the run order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Check {
    SelectTests,
    Admit,
    Reconcile,
    Links,
    LinksSelfTest,
    Contract,
    Replay,
    Judges,
    Gameday,
    HostStop,
}

/// One check: its argument vector, run in a worktree of the tip, and the path whose presence at the tip
/// the selection asks for where it asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    pub check: Check,
    pub argv: &'static [&'static str],
    pub held: Option<&'static str>,
}

const LINKS: &str = "verification/models/links.json";
const CONTRACT: &str = "chaos/ledger.json";
const REPLAY: &str = "scripts/chaos-receipt-replay.py";
const JUDGES: &str = "chaos/tests/test_judges.py";
const GAMEDAY: &str = "scripts/test-gameday-judge.py";
const HOST_STOP: &str = "scripts/test-host-stop-controller.py";

/// The checks in run order; the row of `check` stands at index `check as usize`.
pub const ORDER: [Row; 10] = [
    Row {
        check: Check::SelectTests,
        argv: &["python3", "scripts/test-select-tests.py"],
        held: None,
    },
    Row {
        check: Check::Admit,
        argv: &["python3", "scripts/verify-receipts.py", "admit"],
        held: None,
    },
    Row {
        check: Check::Reconcile,
        argv: &["python3", "scripts/judge-verus.py", "reconcile"],
        held: None,
    },
    Row {
        check: Check::Links,
        argv: &["python3", "scripts/model-links.py", "check"],
        held: Some("scripts/model-links.py"),
    },
    Row {
        check: Check::LinksSelfTest,
        argv: &["python3", "scripts/test-model-links.py"],
        held: None,
    },
    Row {
        check: Check::Contract,
        argv: &[
            "python3",
            "-I",
            "chaos/tools/validate_contract.py",
            CONTRACT,
            "--root",
            ".",
            "--project",
            "chaos/project.yaml",
            "--receipts",
            "chaos/receipts",
            "--check-claim",
            "chaos/READINESS.md",
        ],
        held: Some(CONTRACT),
    },
    Row {
        check: Check::Replay,
        argv: &["python3", "-I", REPLAY],
        held: Some(REPLAY),
    },
    Row {
        check: Check::Judges,
        argv: &["python3", "-I", JUDGES],
        held: Some(JUDGES),
    },
    Row {
        check: Check::Gameday,
        argv: &["python3", "-I", GAMEDAY],
        held: Some(GAMEDAY),
    },
    Row {
        check: Check::HostStop,
        argv: &["python3", "-I", HOST_STOP],
        held: Some(HOST_STOP),
    },
];

impl Check {
    /// `row` is the row of this check in [`ORDER`].
    pub fn row(self) -> &'static Row {
        &ORDER[self as usize]
    }
}

/// The links registry, which the links check reads at the tip.
pub(super) const LINKS_REGISTRY: &str = LINKS;

/// The paths whose change selects the test selection and the receipt admission, beside
/// [`SELECTION_PATTERN`] and [`INTAKE_PREFIX`].
const SELECTION_INPUTS: [&str; 16] = [
    "scripts/test-inventory.json",
    "scripts/test-registry.json",
    "scripts/select-tests.py",
    "scripts/test-select-tests.py",
    "verification/obligations.json",
    "verification/control-less.json",
    ".github/workflows/agent-checks.yml",
    "scripts/verify-receipts.py",
    "scripts/test-verify-receipts.py",
    "scripts/run-receipt-selftests.py",
    "scripts/scan-tag-compare.py",
    "scripts/classify-atomics.py",
    "verification/atomics/census.json",
    "tla/check.py",
    "quint/check.py",
    "verification/verus/inventory.json",
];

const INTAKE_PREFIX: &str = "verification/intake/";

/// A judge script or a checker's `expected.json`. A name part is one or more word characters or `-`, and
/// the match may end before one final line feed.
static SELECTION_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    compiled(&format!(
        r"\A(?:scripts/judge-(?:{WORD}|-)+\.py|verification/(?:{WORD}|-)+/expected\.json)\n?\z"
    ))
});

/// The scripts the links check loads, beside the files its registry names.
pub(super) const LINKS_SCRIPTS: [&str; 5] = [
    "scripts/model-links.py",
    "scripts/test-model-links.py",
    "tla/check.py",
    "scripts/judge-verus.py",
    "scripts/judge-rc11.py",
];

/// The directories whose change, at or under them, selects the judges' test.
const JUDGES_DIRS: [&str; 5] = [
    "chaos/harness/",
    "chaos/judges/",
    "chaos/tests/",
    "chaos/tools/",
    "chaos/receipts/",
];

const JUDGES_FILES: [&str; 3] = [CONTRACT, "chaos/project.yaml", "chaos/approval-policy.md"];

/// The Rust sources that the judges' test reads, which select it only at a tip that holds it.
pub(super) const JUDGES_SOURCES: [&str; 4] = [
    "crates/campaign-supervisor/src/campaign/calibration/controls.rs",
    "crates/campaign-supervisor/src/campaign/seeds/required.rs",
    "crates/campaign-supervisor/src/campaign/seeds.rs",
    "crates/campaign-supervisor/src/protocol/summary.rs",
];

/// The game-day judge and its self-test, whose change runs the self-test at any tip.
pub(super) const GAMEDAY_OWN: [&str; 2] = ["scripts/gameday-judge.py", GAMEDAY];

/// The files the game-day judge reads: the scripts `scripts/readiness.py` loads or hashes at import
/// (its `OWNING` tuple), its profiles and records, and the files that declare its fleet bounds.
pub(super) const JUDGE_READS: [&str; 15] = [
    "scripts/gameday-judge.py",
    "scripts/readiness.py",
    "scripts/fis-profiles.json",
    "verification/readiness/gamedays.json",
    "crates/kestrike/src/failover/zone_loop/directory.rs",
    "crates/kestrike/src/failover/standbys.rs",
    "scripts/acceptance.py",
    "scripts/verify-receipts.py",
    "scripts/hit-gate.py",
    "scripts/hardware-lane.py",
    "scripts/recovery-packages.py",
    "scripts/measurement-frame.py",
    "scripts/sizing-worksheet.py",
    "scripts/reproduce-test.py",
    "scripts/select-tests.py",
];

const GAMEDAY_FIXTURES: &str = "scripts/gameday-fixtures/";

/// The host stop controller and its self-test, whose change runs the self-test at any tip.
pub(super) const HOST_STOP_OWN: [&str; 2] = ["scripts/host-stop-controller.py", HOST_STOP];

const HOST_STOP_FIXTURES: [&str; 2] = ["scripts/host-stop-fixtures/", GAMEDAY_FIXTURES];

/// `gameday_input` holds for a path whose change runs the game-day judge's self-test at a tip that holds it.
pub(super) fn gameday_input(path: &str) -> bool {
    path == GAMEDAY
        || JUDGE_READS.contains(&path)
        || path == "verification/readiness/failover.json"
        || path.starts_with(GAMEDAY_FIXTURES)
}

/// `host_stop_input` holds for a path the host stop controller's self-test loads or reads.
pub(super) fn host_stop_input(path: &str) -> bool {
    HOST_STOP_OWN.contains(&path)
        || path == "scripts/fis-controller.py"
        || JUDGE_READS.contains(&path)
        || HOST_STOP_FIXTURES
            .iter()
            .any(|prefix| path.starts_with(prefix))
}

/// `chaos_change` holds when a path is `chaos` or lies under `chaos/`.
pub(super) fn chaos_change<S: AsRef<str>>(paths: &[S]) -> bool {
    paths
        .iter()
        .any(|path| path.as_ref() == "chaos" || path.as_ref().starts_with("chaos/"))
}

/// Whether the tip holds the script of a check that a change to one of its inputs runs only where it is
/// held. [`Held::default`] holds the judges', the game-day and the host stop self-tests, and not the replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Held {
    pub judges: bool,
    pub replay: bool,
    pub gameday: bool,
    pub host_stop: bool,
}

impl Default for Held {
    fn default() -> Self {
        Self {
            judges: true,
            replay: false,
            gameday: true,
            host_stop: true,
        }
    }
}

/// `checks_for` returns the checks that the changed `paths` require, in run order.
///
/// `sources` are the paths the Verus inventory names and `links` the paths whose change needs the links
/// check; `None` stands for a file that could not be read, and then any change runs that check, which
/// reports the defect. `ignore_changed` says an ignore attribute of a Rust test, or the name of the fn it
/// marks, changed. A change to the replay itself runs it at any tip, so a push that removes it fails on the
/// missing file; the game-day judge, the host stop controller and their self-tests run their self-test at
/// any tip for the same reason.
pub fn checks_for<S: AsRef<str>>(
    paths: &[S],
    sources: Option<&Members>,
    links: Option<&Members>,
    ignore_changed: bool,
    held: Held,
) -> Vec<Check> {
    let any = |test: &dyn Fn(&str) -> bool| paths.iter().any(|path| test(path.as_ref()));
    let mut checks = Vec::new();
    if ignore_changed
        || any(&|path| {
            SELECTION_INPUTS.contains(&path)
                || SELECTION_PATTERN.is_match(path)
                || path.starts_with(INTAKE_PREFIX)
        })
    {
        checks.extend([Check::SelectTests, Check::Admit]);
    }
    let named = |members: Option<&Members>, path: &str| members.is_some_and(|set| set.holds(path));
    if (!paths.is_empty() && sources.is_none())
        || any(&|path| path.starts_with("verification/verus/") || named(sources, path))
    {
        checks.push(Check::Reconcile);
    }
    if (!paths.is_empty() && links.is_none()) || any(&|path| named(links, path)) {
        checks.push(Check::Links);
        if any(&|path| LINKS_SCRIPTS.contains(&path)) {
            checks.push(Check::LinksSelfTest);
        }
    }
    let chaos = chaos_change(paths);
    if chaos {
        checks.push(Check::Contract);
    }
    if held.replay && chaos || any(&|path| path == REPLAY) {
        checks.push(Check::Replay);
    }
    if any(&|path| {
        JUDGES_DIRS.iter().any(|dir| path.starts_with(dir))
            || JUDGES_FILES.contains(&path)
            || JUDGES_DIRS
                .iter()
                .any(|dir| dir.strip_suffix('/') == Some(path))
    }) || held.judges && any(&|path| JUDGES_SOURCES.contains(&path))
    {
        checks.push(Check::Judges);
    }
    if any(&|path| GAMEDAY_OWN.contains(&path)) || held.gameday && any(&gameday_input) {
        checks.push(Check::Gameday);
    }
    if any(&|path| HOST_STOP_OWN.contains(&path)) || held.host_stop && any(&host_stop_input) {
        checks.push(Check::HostStop);
    }
    checks
}
