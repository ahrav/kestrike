use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

use crate::args::{Given, Kind, Opt, Parsed, Reader, any};
use crate::git::{GitError, blob_texts, git, git_text, merge_base, strip};
use crate::json::{Integer, MAX_INTEGER_DIGITS};

use super::declarations::{conditions, declarations, plain};
use super::hunks::{Hunk, line_changes, named_bounds, path_hunks};
use super::inventory::{INVENTORY, inventory_changes, inventory_text};
use super::patterns::{ASSERT, rust_budgets, timeouts};

const TOOL: &str = "scan-weakened-tests";
const USAGE: &str = "usage: scan-weakened-tests [-h] --base BASE [--head HEAD]";
const HELP: &str = "usage: scan-weakened-tests [-h] --base BASE [--head HEAD]\n\nReport changes that weaken \
                    a Rust test or its budget.\n\noptional arguments:\n  -h, --help   show this help message \
                    and exit\n  --base BASE\n  --head HEAD\n";
const BLOCKING: [&str; 2] = ["ignore-existing", "budget-lowered"];
const TIMEOUT_FILES: [&str; 2] = [".github/workflows/agent-checks.yml", "scripts/rust-lane.sh"];

const OPTIONS: [Opt; 3] = [
    Opt {
        names: &["-h", "--help"],
        kind: Kind::Help,
    },
    Opt {
        names: &["--base"],
        kind: Kind::Value {
            required: true,
            check: any,
        },
    },
    Opt {
        names: &["--head"],
        kind: Kind::Value {
            required: false,
            check: any,
        },
    },
];

#[derive(Debug)]
pub enum Failure {
    Git(GitError),
    Refused(String),
    Digits(usize),
}

impl From<GitError> for Failure {
    fn from(error: GitError) -> Self {
        Self::Git(error)
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Git(error) => error.fmt(f),
            Self::Refused(text) => f.write_str(text),
            Self::Digits(count) => write!(
                f,
                "a run of {count} digits passes the limit of {MAX_INTEGER_DIGITS} for integer conversion"
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Shown {
    Count(Integer),
    Word(String),
}

impl Shown {
    pub fn absent() -> Self {
        Self::Word("absent".to_owned())
    }
}

impl fmt::Display for Shown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Count(count) => count.fmt(f),
            Self::Word(word) => f.write_str(word),
        }
    }
}

struct Finding {
    kind: &'static str,
    path: String,
    name: String,
    old: Shown,
    new: Shown,
}

impl Finding {
    fn key(&self) -> String {
        format!("{}:{}", self.kind, self.path)
    }

    fn blocking(&self) -> bool {
        BLOCKING.contains(&self.kind)
    }
}

fn finding(kind: &'static str, path: &str, name: String, old: Shown, new: Shown) -> Finding {
    Finding {
        kind,
        path: path.to_owned(),
        name,
        old,
        new,
    }
}

fn findings(base: &str, head: &str) -> Result<Vec<Finding>, Failure> {
    let listed = git(&[
        "diff",
        "--no-relative",
        "--no-renames",
        "--name-only",
        "-z",
        base,
        head,
    ])?;
    let paths: Vec<&str> = listed.split('\0').filter(|path| !path.is_empty()).collect();
    let rust: Vec<&str> = paths
        .iter()
        .copied()
        .filter(|path| path.ends_with(".rs"))
        .collect();
    if rust.iter().any(|path| path.contains('\n')) {
        return Err(Failure::Refused(
            "a changed Rust path holds a newline, which the blob reader cannot name".to_owned(),
        ));
    }
    let specs: Vec<String> = rust
        .iter()
        .flat_map(|path| [format!("{base}:{path}"), format!("{head}:{path}")])
        .collect();
    let texts = if rust.is_empty() {
        Vec::new()
    } else {
        blob_texts(&specs)?
    };
    let diffed: Vec<&str> = paths
        .iter()
        .copied()
        .filter(|path| path.ends_with(".rs") || TIMEOUT_FILES.contains(path))
        .collect();
    let mut diffs = path_hunks(base, head, &diffed)?;
    let mut found = Vec::new();
    for (path, pair) in rust.iter().zip(texts.chunks(2)) {
        let [old, new] = pair else {
            unreachable!("each Rust path reads two blobs");
        };
        ignores(path, old, new, &mut found);
        let changes = diffs.remove(*path).unwrap_or_default();
        let changes = named_bounds(changes, old, new);
        for (name, old, new) in line_changes(&changes, &rust_budgets())? {
            if new < old {
                found.push(finding(
                    "budget-lowered",
                    path,
                    name,
                    Shown::Count(old),
                    Shown::Count(new),
                ));
            }
        }
        assertions(path, &changes, &mut found);
    }
    for path in TIMEOUT_FILES.iter().filter(|path| paths.contains(path)) {
        let changes = diffs.remove(*path).unwrap_or_default();
        for (name, old, new) in line_changes(&changes, &timeouts())? {
            if new > old {
                found.push(finding(
                    "timeout-raised",
                    path,
                    name,
                    Shown::Count(old),
                    Shown::Count(new),
                ));
            }
        }
    }
    if paths.contains(&INVENTORY) {
        let old = inventory_text(base)?;
        let new = inventory_text(head)?;
        for (kind, name, old, new) in inventory_changes(&old, &new)? {
            found.push(finding(kind, INVENTORY, name, old, new));
        }
    }
    Ok(found)
}

fn ignores(path: &str, old: &str, new: &str, found: &mut Vec<Finding>) {
    let after = if new.contains("ignore") {
        declarations(new)
    } else {
        Vec::new()
    };
    let ignored = after
        .iter()
        .any(|(_, heads)| heads.iter().any(|attributes| !attributes.is_empty()));
    let before: HashMap<String, Vec<Vec<String>>> = if ignored {
        declarations(old).into_iter().collect()
    } else {
        HashMap::new()
    };
    for (name, heads) in after {
        let bases = before.get(&name).map_or(&[][..], Vec::as_slice);
        for (index, attributes) in heads.iter().enumerate() {
            let joined = attributes.join("; ");
            match bases.get(index) {
                None if !attributes.is_empty() => {
                    let old = Shown::absent();
                    found.push(finding(
                        "ignore-new",
                        path,
                        name.clone(),
                        old,
                        Shown::Word(joined),
                    ));
                }
                None => {}
                Some(base)
                    if plain(base) == 0 && !conditions(attributes).is_subset(&conditions(base)) =>
                {
                    let old = if base.is_empty() {
                        "not ignored".to_owned()
                    } else {
                        base.join("; ")
                    };
                    let (old, new) = (Shown::Word(old), Shown::Word(joined));
                    found.push(finding("ignore-existing", path, name.clone(), old, new));
                }
                Some(_) => {}
            }
        }
    }
}

fn assertions(path: &str, changes: &[Hunk], found: &mut Vec<Finding>) {
    let holds = |text: &String| ASSERT.is_match(text.as_bytes());
    let removed = changes
        .iter()
        .flat_map(|hunk| &hunk.removed)
        .filter(|text| holds(text))
        .count();
    let added = changes
        .iter()
        .flat_map(|hunk| hunk.added.iter().map(|(_, text)| text))
        .filter(|text| holds(text))
        .count();
    if removed > added {
        let (old, new) = (format!("{removed} removed"), format!("{added} added"));
        let name = "assert lines".to_owned();
        found.push(finding(
            "assertions-removed",
            path,
            name,
            Shown::Word(old),
            Shown::Word(new),
        ));
    }
}

/// `acknowledgements` retains each key's first nonblank reason in `git log base..head` order. A line
/// belongs to the longest `key` whose `Weakens-Test: {key}: ` prefix matches. Empty `keys` make
/// `acknowledgements` return an empty map before invoking Git.
fn acknowledgements(
    base: &str,
    head: &str,
    keys: &[String],
) -> Result<HashMap<String, String>, Failure> {
    let mut reasons = HashMap::new();
    if keys.is_empty() {
        return Ok(reasons);
    }
    let range = format!("{base}..{head}");
    let log = git_text(&["log", "--encoding=UTF-8", "--format=%B", &range])?;
    for line in log.split('\n') {
        if !line.starts_with("Weakens-Test: ") {
            continue;
        }
        let owner = keys
            .iter()
            .filter(|key| line.starts_with(&format!("Weakens-Test: {key}: ")))
            .max_by_key(|key| key.len());
        if let Some(key) = owner {
            let reason = strip(&line["Weakens-Test: ".len() + key.len() + 2..]);
            if !reason.is_empty() {
                reasons.entry(key.clone()).or_insert(reason);
            }
        }
    }
    Ok(reasons)
}

fn resolve(rev: &OsStr) -> Result<String, Failure> {
    let mut named = rev.to_owned();
    named.push("^{commit}");
    let args: [&OsStr; 4] = [
        OsStr::new("rev-parse"),
        OsStr::new("--verify"),
        OsStr::new("--end-of-options"),
        &named,
    ];
    Ok(strip(&git(&args)?))
}

fn short(commit: &str) -> &str {
    &commit[..commit.len().min(12)]
}

struct Scan {
    base: String,
    head: String,
    found: Vec<Finding>,
    reasons: HashMap<String, String>,
}

fn scan(base: &OsStr, head: &OsStr) -> Result<Option<Scan>, Failure> {
    let (base, head) = (resolve(base)?, resolve(head)?);
    let range = format!("{base}..{head}");
    if strip(&git(&["rev-list", "--count", &range])?) == "0" {
        return Ok(None);
    }
    let Some(fork) = merge_base(&base, &head)? else {
        return Err(Failure::Refused(format!(
            "{} and {} share no history",
            short(&base),
            short(&head)
        )));
    };
    let found = findings(&fork, &head)?;
    let mut keys: Vec<String> = Vec::new();
    for key in found
        .iter()
        .filter(|found| found.blocking())
        .map(Finding::key)
    {
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    let reasons = acknowledgements(&fork, &head, &keys)?;
    Ok(Some(Scan {
        base: fork,
        head,
        found,
        reasons,
    }))
}

fn complain(text: &str) -> Result<(), io::Error> {
    io::stderr().write_all(text.as_bytes())
}

pub fn run(_top: &Path, args: &[OsString]) -> u8 {
    let reader = Reader::new(TOOL, USAGE, HELP, true, &OPTIONS);
    let values = match reader.parse(args) {
        Parsed::Run(values) => values,
        Parsed::Help(text) => {
            let mut stdout = io::stdout().lock();
            return match stdout
                .write_all(text.as_bytes())
                .and_then(|()| stdout.flush())
            {
                Ok(()) => 0,
                Err(_) => 120,
            };
        }
        Parsed::Refused { code, text } => return complain(&text).map_or(120, |()| code),
    };
    let rev = |name: &str, absent: &str| match values.get(name) {
        Given::Absent => OsString::from(absent),
        Given::Empty => OsString::from("[]"),
        Given::Value(value) => value.clone(),
    };
    let scanned = match scan(&rev("--base", ""), &rev("--head", "HEAD")) {
        Ok(Some(scanned)) => scanned,
        Ok(None) => return 0,
        Err(error) => return complain(&format!("{TOOL}: {error}\n")).map_or(120, |()| 2),
    };
    report(&scanned).unwrap_or(120)
}

/// `run` maps a `report` error to exit code 120. Only a failed write to standard error produces that error.
fn report(scanned: &Scan) -> Result<u8, io::Error> {
    let mut lines = String::new();
    let mut unacknowledged: Vec<String> = Vec::new();
    for found in &scanned.found {
        let key = found.key();
        let line = format!("{key} {}: {} -> {}", found.name, found.old, found.new);
        if !found.blocking() {
            lines.push_str(&format!("reports {line}\n"));
        } else if let Some(reason) = scanned.reasons.get(&key) {
            lines.push_str(&format!("acknowledged {line} (Weakens-Test: {reason})\n"));
        } else {
            lines.push_str(&format!("blocks {line}\n"));
            if !unacknowledged.contains(&key) {
                unacknowledged.push(key);
            }
        }
    }
    let range = format!("{}..{}", short(&scanned.base), short(&scanned.head));
    if !lines.is_empty() {
        let mut stdout = io::stdout().lock();
        if let Err(error) = stdout
            .write_all(lines.as_bytes())
            .and_then(|()| stdout.flush())
        {
            complain(&format!("{TOOL}: standard output: {error}\n"))?;
            return Ok(1);
        }
        if let Some(summary) =
            std::env::var_os("GITHUB_STEP_SUMMARY").filter(|path| !path.is_empty())
        {
            let text = format!("Weakened-test scan of {range}:\n\n```text\n{lines}```\n");
            let written = OpenOptions::new()
                .append(true)
                .create(true)
                .open(&summary)
                .and_then(|mut file| file.write_all(text.as_bytes()));
            if let Err(error) = written {
                complain(&format!("{TOOL}: step summary: {error}\n"))?;
                return Ok(2);
            }
        }
    }
    for key in &unacknowledged {
        complain(&format!(
            "{TOOL}: {key} blocks; acknowledge it with a commit-message line in {range}: \
             Weakens-Test: {key}: <reason>\n"
        ))?;
    }
    Ok(u8::from(!unacknowledged.is_empty()))
}
