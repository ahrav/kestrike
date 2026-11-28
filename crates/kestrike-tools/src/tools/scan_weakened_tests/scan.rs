use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::path::Path;

use crate::args::{Kind, Opt, Parsed, Prefixes, Reader, any};
use crate::environ::Environ;
use crate::git::{blob_texts, caller_environ, git, git_text, merge_base};
use crate::json::Integer;
use crate::stream::emit;
use crate::text::{escaped, strip_str};

use super::cases::{CASES, removed};
use super::declarations::{conditions, declarations, plain};
use super::finding::short;
use super::hunks::{Hunk, line_changes, named_bounds, path_hunks};
use super::inventory::{INVENTORY, inventory_changes, inventory_text};
use super::patterns::{ASSERT, Pattern, rust_budgets, timeouts};
use super::tree::{directory, files};
use super::{Change, Class, Failure, Finding, Shown};

const TOOL: &str = super::NAME;
const USAGE: &str = "usage: scan-weakened-tests [-h] --base BASE [--head HEAD]";
const HELP: &str = "usage: scan-weakened-tests [-h] --base BASE [--head HEAD]\n\nReport changes that weaken \
                    a Rust test or its budget.\n\noptional arguments:\n  -h, --help   show this help message \
                    and exit\n  --base BASE\n  --head HEAD\n";
const TIMEOUT_FILES: [&str; 2] = [".github/workflows/agent-checks.yml", "scripts/rust-lane.sh"];
const STREAM_FAILED: u8 = 120;

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

fn findings(environ: &Environ, base: &str, head: &str) -> Result<Vec<Finding>, Failure> {
    let listed = git(
        environ,
        &[
            "diff",
            "--no-relative",
            "--no-renames",
            "--ignore-submodules=none",
            "--name-only",
            "-z",
            base,
            head,
        ],
    )?;
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
    let diffed: Vec<&str> = paths
        .iter()
        .copied()
        .filter(|path| path.ends_with(".rs") || TIMEOUT_FILES.contains(path))
        .collect();
    // `files` rejects a checked path at either commit if it names a non-file entry or is missing beneath a link
    // or a submodule.
    let mut checked = diffed.clone();
    for path in std::iter::once(INVENTORY).chain(TIMEOUT_FILES) {
        if !checked.contains(&path) {
            checked.push(path);
        }
    }
    let base_held = files(environ, base, &checked)?;
    let head_held = files(environ, head, &checked)?;
    let specs: Vec<String> = rust
        .iter()
        .flat_map(|path| [format!("{base}:{path}"), format!("{head}:{path}")])
        .collect();
    let texts = if rust.is_empty() {
        Vec::new()
    } else {
        blob_texts(environ, &specs)?
    };
    let diffs = path_hunks(environ, base, head, &diffed)?;
    let hunks_of = |path: &str| {
        diffs
            .get(path)
            .cloned()
            .expect("path_hunks reads every listed path")
    };
    let mut found = Vec::new();
    let mut push = |path: &str, changes: Vec<Change>| {
        found.extend(changes.into_iter().map(|change| Finding {
            path: path.to_owned(),
            change,
        }));
    };
    for (path, pair) in rust.iter().zip(texts.chunks(2)) {
        let [old, new] = pair else {
            unreachable!("each Rust path reads two blobs");
        };
        push(path, ignores(old, new));
        let changes = hunks_of(path);
        let removed = assertions(&changes);
        let valued = named_bounds(changes, old, new);
        push(
            path,
            line_findings(
                &valued,
                &rust_budgets(),
                Class::BudgetLowered,
                |old, new| new < old,
            )?,
        );
        push(path, removed.into_iter().collect());
    }
    for path in TIMEOUT_FILES.iter().filter(|path| paths.contains(path)) {
        let changes = hunks_of(path);
        push(
            path,
            line_findings(&changes, &timeouts(), Class::TimeoutRaised, |old, new| {
                new > old
            })?,
        );
    }
    let within = |root: &'static str| {
        move |path: &&str| {
            path.strip_prefix(root)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        }
    };
    if paths.iter().any(within(INVENTORY)) {
        let old = inventory_text(environ, base, base_held.contains(&INVENTORY))?;
        let new = inventory_text(environ, head, head_held.contains(&INVENTORY))?;
        push(INVENTORY, inventory_changes(&old, &new)?);
    }
    // The test directory is checked at the head and then the base on every range; its cases are listed only
    // when the diff names the directory or a path below it.
    let cases_head = directory(environ, head, CASES)?;
    let cases_base = directory(environ, base, CASES)?;
    if paths.iter().any(within(CASES)) {
        found.extend(removed(&cases_base, &cases_head)?);
    }
    Ok(found)
}

fn line_findings(
    changes: &[Hunk],
    patterns: &[&Pattern],
    class: Class,
    reported: fn(&Integer, &Integer) -> bool,
) -> Result<Vec<Change>, Failure> {
    Ok(line_changes(changes, patterns)?
        .into_iter()
        .filter(|(_, old, new)| reported(old, new))
        .map(|(name, old, new)| Change::new(class, name, Shown::Count(old), Shown::Count(new)))
        .collect())
}

fn ignores(old: &str, new: &str) -> Vec<Change> {
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
    let mut found = Vec::new();
    for (name, heads) in after {
        let bases = before.get(&name).map_or(&[][..], Vec::as_slice);
        for (index, attributes) in heads.iter().enumerate() {
            let new = || Shown::Word(attributes.join("; "));
            match bases.get(index) {
                None if !attributes.is_empty() => {
                    found.push(Change::new(
                        Class::IgnoreNew,
                        name.clone(),
                        Shown::absent(),
                        new(),
                    ));
                }
                Some(base)
                    if plain(base) == 0 && !conditions(attributes).is_subset(&conditions(base)) =>
                {
                    let old = if base.is_empty() {
                        "not ignored".to_owned()
                    } else {
                        base.join("; ")
                    };
                    found.push(Change::new(
                        Class::IgnoreExisting,
                        name.clone(),
                        Shown::Word(old),
                        new(),
                    ));
                }
                _ => {}
            }
        }
    }
    found
}

fn assertions(changes: &[Hunk]) -> Option<Change> {
    let holds = |text: &&String| ASSERT.is_match(text.as_bytes());
    let removed = changes
        .iter()
        .flat_map(|hunk| &hunk.removed)
        .filter(holds)
        .count();
    let added = changes
        .iter()
        .flat_map(|hunk| hunk.added.iter().map(|(_, text)| text))
        .filter(holds)
        .count();
    (removed > added).then(|| {
        let (old, new) = (format!("{removed} removed"), format!("{added} added"));
        Change::new(
            Class::AssertionsRemoved,
            "assert lines".to_owned(),
            Shown::Word(old),
            Shown::Word(new),
        )
    })
}

/// `acknowledgements` retains each key's first nonblank reason in `git log base..head` order. A line
/// belongs to the longest `key` whose `Weakens-Test: {key}: ` prefix matches. Empty `keys` make
/// `acknowledgements` return an empty map before invoking Git.
fn acknowledgements(
    environ: &Environ,
    base: &str,
    head: &str,
    keys: &[String],
) -> Result<HashMap<String, String>, Failure> {
    let mut reasons = HashMap::new();
    if keys.is_empty() {
        return Ok(reasons);
    }
    let prefixes: Vec<(String, &String)> = keys
        .iter()
        .map(|key| (format!("Weakens-Test: {key}: "), key))
        .collect();
    let range = format!("{base}..{head}");
    let log = git_text(environ, &["log", "--encoding=UTF-8", "--format=%B", &range])?;
    for line in log.split('\n') {
        if !line.starts_with("Weakens-Test: ") {
            continue;
        }
        let owner = prefixes
            .iter()
            .filter(|(prefix, _)| line.starts_with(prefix.as_str()))
            .max_by_key(|(prefix, _)| prefix.len());
        if let Some((prefix, key)) = owner {
            let reason = strip_str(&line[prefix.len()..]);
            if !reason.is_empty() {
                reasons
                    .entry((*key).clone())
                    .or_insert_with(|| reason.to_owned());
            }
        }
    }
    Ok(reasons)
}

fn resolve(environ: &Environ, rev: &OsStr) -> Result<String, Failure> {
    let mut named = rev.to_owned();
    named.push("^{commit}");
    let args: [&OsStr; 4] = [
        OsStr::new("rev-parse"),
        OsStr::new("--verify"),
        OsStr::new("--end-of-options"),
        &named,
    ];
    Ok(strip_str(&git(environ, &args)?).to_owned())
}

struct Scan {
    base: String,
    head: String,
    found: Vec<Finding>,
    reasons: HashMap<String, String>,
}

fn scan(environ: &Environ, base: &OsStr, head: &OsStr) -> Result<Option<Scan>, Failure> {
    let (base, head) = (resolve(environ, base)?, resolve(environ, head)?);
    let range = format!("{base}..{head}");
    if strip_str(&git(environ, &["rev-list", "--count", &range])?) == "0" {
        return Ok(None);
    }
    let Some(fork) = merge_base(environ, &base, &head)? else {
        return Err(Failure::Refused(format!(
            "{} and {} share no history",
            short(&base),
            short(&head)
        )));
    };
    let found = findings(environ, &fork, &head)?;
    let mut keys: Vec<String> = Vec::new();
    for key in found
        .iter()
        .filter(|found| found.change.class.blocks())
        .map(Finding::key)
    {
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    let reasons = acknowledgements(environ, &fork, &head, &keys)?;
    Ok(Some(Scan {
        base: fork,
        head,
        found,
        reasons,
    }))
}

fn complain(text: &str) -> Result<(), io::Error> {
    emit(io::stderr().as_fd(), text)
}

fn fail(text: &str, code: u8) -> u8 {
    complain(text).map_or(STREAM_FAILED, |()| code)
}

pub fn run(_top: &Path, args: &[OsString]) -> u8 {
    let reader = Reader::new(TOOL, USAGE, HELP, Prefixes::Select, &OPTIONS);
    let values = match reader.parse(args) {
        Parsed::Run(values) => values,
        Parsed::Help(text) => {
            return match emit(io::stdout().as_fd(), &text) {
                Ok(()) => 0,
                Err(error) => fail(
                    &format!("{TOOL}: standard output: {error}\n"),
                    STREAM_FAILED,
                ),
            };
        }
        Parsed::Refused { code, text } => return fail(&text, code),
    };
    let rev = |name: &str, absent: &str| values.get(name).unwrap_or(OsStr::new(absent)).to_owned();
    scan_range(
        &caller_environ(),
        &rev("--base", ""),
        &rev("--head", "HEAD"),
        io::stdout().as_fd(),
    )
}

/// `scan_range` scans the commits of `head` that `base` lacks, with every Git child started in `environ`,
/// and returns the tool's exit code. It writes the report lines to `lines`, the refusals and the
/// acknowledgement hints to standard error, and with report lines it appends them to the file
/// `GITHUB_STEP_SUMMARY` names in this process's environment. It returns 0 for a range with no commit,
/// writing nothing, and for a scan with no unacknowledged blocking finding; 1 for a scan with one; 2 for a
/// failed scan and for a step summary that cannot be appended after the lines were written; and 120 for a
/// failed write to `lines` or to standard error.
pub fn scan_range(environ: &Environ, base: &OsStr, head: &OsStr, lines: BorrowedFd<'_>) -> u8 {
    let scanned = match scan(environ, base, head) {
        Ok(Some(scanned)) => scanned,
        Ok(None) => return 0,
        Err(error) => return fail(&format!("{TOOL}: {}\n", escaped(&error.to_string())), 2),
    };
    report(&scanned, lines).unwrap_or(STREAM_FAILED)
}

/// `report` writes each field of a line through [`escaped`], and the lines to `stream`. It returns `Err` when
/// standard error cannot be written.
fn report(scanned: &Scan, stream: BorrowedFd<'_>) -> Result<u8, io::Error> {
    let mut lines = String::new();
    let mut unacknowledged: Vec<String> = Vec::new();
    for found in &scanned.found {
        let key = found.key();
        let Change {
            class,
            name,
            old,
            new,
        } = &found.change;
        let line = escaped(&format!("{key} {name}: {old} -> {new}"));
        if !class.blocks() {
            lines.push_str(&format!("reports {line}\n"));
        } else if let Some(reason) = scanned.reasons.get(&key) {
            let reason = escaped(reason);
            lines.push_str(&format!("acknowledged {line} (Weakens-Test: {reason})\n"));
        } else {
            lines.push_str(&format!("blocks {line}\n"));
            if !unacknowledged.contains(&key) {
                unacknowledged.push(key);
            }
        }
    }
    let range = format!("{}..{}", short(&scanned.base), short(&scanned.head));
    let mut code = u8::from(!unacknowledged.is_empty());
    if !lines.is_empty() {
        if let Err(error) = emit(stream, &lines) {
            complain(&format!("{TOOL}: standard output: {error}\n"))?;
            return Ok(STREAM_FAILED);
        }
        if let Some(summary) =
            std::env::var_os("GITHUB_STEP_SUMMARY").filter(|path| !path.is_empty())
        {
            let text = format!("Weakened-test scan of {range}:\n\n```text\n{lines}```\n");
            let written = OpenOptions::new()
                .append(true)
                .create(true)
                .open(
                    Path::new(&summary)
                        .components()
                        .collect::<std::path::PathBuf>(),
                )
                .and_then(|mut file| file.write_all(text.as_bytes()));
            if let Err(error) = written {
                complain(&format!("{TOOL}: step summary: {error}\n"))?;
                unacknowledged.clear();
                code = 2;
            }
        }
    }
    for key in unacknowledged.iter().map(|key| escaped(key)) {
        complain(&format!(
            "{TOOL}: {key} blocks; acknowledge it with a commit-message line in {range}: \
             Weakens-Test: {key}: <reason>\n"
        ))?;
    }
    Ok(code)
}
