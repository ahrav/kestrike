//! The command `run`: the work directory's and the checkout's checks, the copy and its checks, the
//! baseline, each selected row's plant with its restore, and the report.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use super::execute::{Launch, holding, seconds, with_defaults};
use super::files::{fresh_write, regular_digest, save, save_through, sha256};
use super::halt::Halt;
use super::pins::{lane_env, pin};
use super::runner::{Runner, Runs, json_path, os_of, text_of};
use crate::genmc::package_sources;
use crate::json::{self, Integer, Object, Text, Value};
use crate::orderings::check::{CATALOG, check, row_entries};
use crate::orderings::sites::EXTERNAL;
use crate::ownership::status;
use crate::plants::UNANNOUNCED;
use crate::process::{
    INTERRUPT, Interrupt, Interrupted, blocked, capture, install_handlers, refuse_ignored_sigchld,
};
use crate::production_text::blanked;
use crate::python::{hexdigest, repr, returncode, str_of, truthy};
use crate::text::text;

/// The paths whose difference from `HEAD` refuses a run: the tools crate, the build's configuration,
/// the launcher and the workflow whose `STABLE` pin it builds with, and the scripts the GenMC lane
/// judges with.
const JUDGING: [&str; 7] = [
    "crates/kestrike-tools",
    "Cargo.toml",
    ".cargo/config.toml",
    "scripts/tool.sh",
    ".github/workflows/agent-checks.yml",
    "scripts/judge-genmc.py",
    "scripts/judge-rc11.py",
];

fn texts(items: &[Text]) -> String {
    repr(&listed(items))
}

/// `differs` holds where `git status` in `top` names a path of [`JUDGING`]: a change against `HEAD`,
/// staged or not, or an untracked file that no ignore rule covers; a status that exits nonzero counts as
/// a difference, and its standard error is written to `err`.
///
/// # Errors
///
/// A recorded signal, or a status that cannot start or whose output cannot be read.
fn differs(top: &Path, err: &mut impl Write) -> Result<bool, Halt> {
    let mut git = Command::new("git");
    git.args(["--no-optional-locks", "-C"])
        .arg(top)
        .args(["status", "--porcelain", "-z", "--untracked-files=all", "--"])
        .args(JUDGING);
    with_defaults(&mut git);
    let listed = capture(&mut git, &INTERRUPT)??;
    if !listed.status.success() {
        let _ = err.write_all(&listed.stderr);
        let _ = err.flush();
    }
    Ok(!listed.status.success() || !listed.stdout.is_empty())
}

/// `checked_work` refuses a work directory inside the checkout, `top` resolved, which the refusal names;
/// one that cannot be listed; one that is not empty; a checkout whose judging paths differ from `HEAD`,
/// with Git's standard error on `err` where its status fails; and a work directory that cannot hold the
/// copy, in that order, and then makes `work/copy` and `work/evidence`.
///
/// # Errors
///
/// Each refusal above, `top` that cannot be resolved, or a status that cannot run, as [`differs`] says.
fn checked_work(top: &Path, work: &Path, err: &mut impl Write) -> Result<(), Halt> {
    let resolved = crate::paths::resolve(top).map_err(Halt::failed)?;
    if work.starts_with(&resolved) {
        return Err(Halt::stop(
            2,
            text!(
                "the work directory ",
                work,
                " lies inside the checkout ",
                &resolved
            ),
        ));
    }
    let listed = status(work)
        .map_err(|error| error.into_error())
        .and_then(|found| match found {
            None => Ok(false),
            Some(_) => Ok(fs::read_dir(work)?.next().is_some()),
        });
    match listed {
        Err(error) => {
            return Err(Halt::stop(
                2,
                text!(
                    "the work directory ",
                    work,
                    " cannot be listed: ",
                    error.to_string()
                ),
            ));
        }
        Ok(true) => {
            return Err(Halt::stop(
                2,
                text!("the work directory ", work, " is not empty"),
            ));
        }
        Ok(false) => {}
    }
    if differs(top, err)? {
        return Err(Halt::stop(
            2,
            text!(
                texts(&JUDGING.map(Text::from)),
                " differ from HEAD, so the report's revision would not name the code that judged it"
            ),
        ));
    }
    let made = fs::create_dir_all(work)
        .and_then(|()| fs::create_dir(work.join("copy")))
        .and_then(|()| fs::create_dir(work.join("evidence")));
    made.map_err(|error| {
        Halt::stop(
            2,
            text!(
                "the work directory ",
                work,
                " cannot hold the copy: ",
                error.to_string()
            ),
        )
    })
}

/// `run_command` runs `run` with the work directory `work` and the selected rows `selected`, writes
/// `report.json` and prints its path, `mismatched` and `no verdict` as one JSON line on `out`, and
/// returns the run's exit code, or [`UNANNOUNCED`] where that line or its flush fails, with the report
/// written. A halt prints its line on `err` and returns its own code; a signal recorded once the handlers
/// stand makes any halt, and a report written as the signal arrives, end as that signal's interruption.
pub(super) fn run_command(
    top: &Path,
    work: &OsStr,
    selected: &[OsString],
    out: &mut impl Write,
    err: &mut impl Write,
) -> u8 {
    let launch = Launch::new(&INTERRUPT);
    let ran = refuse_ignored_sigchld()
        .map_err(|refusal| Halt::stop(2, refusal))
        .and_then(|()| crate::paths::resolve(Path::new(work)).map_err(Halt::failed))
        .and_then(|work| {
            checked_work(top, &work, err)?;
            install_handlers()?;
            let selected: Vec<Text> = selected.iter().map(|row| Text::from_os(row)).collect();
            let (report, code) = run(top, &work, &selected, &launch, err)?;
            let path = work.join("report.json");
            publish_report(&path, &report, &INTERRUPT)?;
            INTERRUPT.check()?;
            Ok((path, report, code))
        });
    match ran.map_err(|halt| settled(halt, &INTERRUPT)) {
        Ok((path, report, code)) => {
            let member = |key: &str| json_path(&report, &[key]).cloned().unwrap_or(Value::Null);
            let mut line = Object::new();
            line.insert("report", Value::String(text_of(&path)));
            line.insert("mismatched", member("mismatched"));
            line.insert("no verdict", member("no verdict"));
            match writeln!(out, "{}", json::line(&Value::Object(line))).and_then(|()| out.flush()) {
                Ok(()) => code,
                Err(_) => UNANNOUNCED,
            }
        }
        Err(halt) => halt.end(err),
    }
}

/// `settled` is `halt`, or the interruption of the first signal `interrupt` records where `halt` is a
/// refusal or a failed step: a handled signal ends the run whatever step it came during.
fn settled(halt: Halt, interrupt: &Interrupt) -> Halt {
    match interrupt.recorded() {
        Some(signal) if !halt.is_interrupt() => Halt::Interrupted(signal),
        _ => halt,
    }
}

/// `publish_report` writes `report` to `path` as [`save`] does unless `interrupt` records a signal. The
/// last read of the record and the rename run with the handled signals blocked in the calling thread, the
/// run's one thread at this point, so a signal recorded by that read leaves no report and one that
/// arrives during the read or the rename is recorded once the rename is done.
///
/// # Errors
///
/// The interruption of a recorded signal, with `path` as it stood and an attempt to remove the staging
/// file, or a failed write.
fn publish_report(path: &Path, report: &Value, interrupt: &Interrupt) -> Result<(), Halt> {
    interrupt.check()?;
    let gate = |rename: &mut dyn FnMut() -> io::Result<()>| {
        blocked(|| {
            interrupt
                .check()
                .map_err(|Interrupted(signal)| io::Error::other(format!("signal {signal}")))?;
            rename()
        })
        .and_then(|renamed| renamed)
    };
    if let Err(error) = save_through(path, report, &gate) {
        interrupt.check()?;
        return Err(Halt::failed(error));
    }
    Ok(())
}

/// `matched` is `text`'s production text `production` with one space for each code point a test-only
/// element blanks, and for each byte offset of it at a code point's start or at its end, the offset in
/// `text`.
fn matched(text: &str, production: &str) -> (String, Vec<usize>) {
    let (raw, blank) = (text.as_bytes(), production.as_bytes());
    let mut read = String::with_capacity(production.len());
    let mut offsets = vec![0; production.len() + 1];
    for (at, code) in text.char_indices() {
        offsets[read.len()] = at;
        let end = at + code.len_utf8();
        read.push(if raw[at..end] == blank[at..end] {
            code
        } else {
            ' '
        });
    }
    offsets[read.len()] = text.len();
    (read, offsets)
}

/// `plant_of` is `text` with `replace` at the one occurrence of `find` in its production text.
///
/// # Errors
///
/// The count of `find`'s non-overlapping occurrences in the production text, where it is not one.
fn plant_of(text: &str, find: &str, replace: &str) -> Result<String, usize> {
    let production = blanked(text).0;
    let (read, offsets) = matched(text, &production);
    let count = read.matches(find).count();
    let Some(at) = read.find(find).filter(|_| count == 1) else {
        return Err(count);
    };
    let (start, end) = (offsets[at], offsets[at + find.len()]);
    Ok(format!("{}{replace}{}", &text[..start], &text[end..]))
}

fn string(object: &Object, key: &str) -> Text {
    match object.get(key) {
        Some(Value::String(text)) => text.clone(),
        _ => Text::new(),
    }
}

fn object_of(value: &Value) -> Result<&Object, Halt> {
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(Halt::failed("TypeError: a catalog value is no object")),
    }
}

/// The scoped files of the copy, their unweakened texts and digests.
struct Scoped {
    copy: PathBuf,
    files: Vec<Text>,
    originals: BTreeMap<Text, String>,
    digests: BTreeMap<Text, String>,
}

impl Scoped {
    fn path(&self, name: &Text) -> Result<PathBuf, Halt> {
        Ok(self.copy.join(os_of(name)?))
    }

    /// `drifted` is the scoped files that are no regular, readable file holding the unweakened copy's
    /// bytes, in code point order.
    fn drifted(&self) -> Result<Vec<Text>, Halt> {
        let mut drift = Vec::new();
        for name in &self.files {
            if regular_digest(&self.path(name)?).as_ref() != self.digests.get(name) {
                drift.push(name.clone());
            }
        }
        drift.sort();
        Ok(drift)
    }

    /// `planted` holds `row`'s plant in its scoped file while `body` runs, then, with the handled signals
    /// blocked, checks that the plant stayed in place, writes the unweakened file back and compares each
    /// scoped file's digest. Where `body` panics, the same restore runs and the panic then resumes.
    ///
    /// # Errors
    ///
    /// A refusal of exit 2 for a find that does not occur once; of exit 4 for a plant that changed, which a
    /// plant that cannot be written reads as, an unweakened file that cannot be written back or a scoped
    /// file that then differs; a failed read of the scoped file's status before the plant; a failed
    /// change of the signal mask; otherwise `body`'s halt.
    fn planted(&self, row: &Object, body: impl FnOnce() -> Result<(), Halt>) -> Result<(), Halt> {
        let (id, name) = (string(row, "id"), string(row, "path"));
        let text = self.originals.get(&name).cloned().unwrap_or_default();
        let path = self.path(&name)?;
        let plant = plant_of(
            &text,
            &string(row, "find").to_string(),
            &string(row, "replace").to_string(),
        )
        .map_err(|_| {
            Halt::stop(
                2,
                text!(
                    id,
                    ": its find does not occur once in ",
                    name,
                    "'s production text"
                ),
            )
        })?;
        let unweakened = fs::metadata(&path).map_err(Halt::failed)?;
        let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fresh_write(&path, &plant, None)
                .map_err(Halt::failed)
                .and_then(|()| body())
        }));
        let restored = blocked(|| -> Result<(bool, Vec<Text>), Halt> {
            let moved = regular_digest(&path) != Some(hexdigest(plant.as_bytes()));
            fresh_write(&path, &text, moved.then_some(&unweakened)).map_err(|error| {
                Halt::stop(
                    4,
                    text!(
                        "the unweakened ",
                        name,
                        " cannot be written back after ",
                        id,
                        "'s tests: ",
                        error.to_string()
                    ),
                )
            })?;
            Ok((moved, self.drifted()?))
        });
        let ran = ran.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        match restored?? {
            (true, _) => Err(Halt::stop(
                4,
                text!("the plant of ", name, " changed while ", id, "'s tests ran"),
            )),
            (false, drift) if !drift.is_empty() => Err(Halt::stop(
                4,
                text!(
                    "the scoped files ",
                    texts(&drift),
                    " differ from the unweakened copy after a restore"
                ),
            )),
            _ => ran,
        }
    }
}

/// `undecided` holds where some lane and test of `results` has no `killed` or `survived` result.
fn undecided(results: &[Value]) -> bool {
    let mut outcomes: BTreeMap<(String, String), bool> = BTreeMap::new();
    for result in results {
        let Value::Object(result) = result else {
            continue;
        };
        let field = |key: &str| repr(result.get(key).unwrap_or(&Value::Null));
        let decided = matches!(result.get("result"), Some(Value::String(found)) if *found == "killed" || *found == "survived");
        *outcomes.entry((field("lane"), field("test"))).or_default() |= decided;
    }
    outcomes.values().any(|decided| !decided)
}

/// The report so far, its members in the order the files write them.
struct Report {
    revision: Text,
    pins: Object,
    baseline: Vec<Value>,
    rows: Vec<(Text, Object)>,
    seconds: Option<f64>,
    mismatched: Option<Vec<Text>>,
    no_verdict: Option<Vec<Text>>,
}

/// `result_is` holds where `result` is an object whose `result` member is the string `name`.
fn result_is(result: &Value, name: &str) -> bool {
    matches!(result, Value::Object(result) if result.get("result") == Some(&Value::String(Text::from(name))))
}

fn listed(items: &[Text]) -> Value {
    Value::Array(items.iter().cloned().map(Value::String).collect())
}

impl Report {
    fn object(&self) -> Object {
        let mut report = Object::new();
        report.insert("revision", Value::String(self.revision.clone()));
        report.insert("pins", Value::Object(self.pins.clone()));
        report.insert("baseline", Value::Array(self.baseline.clone()));
        let mut rows = Object::new();
        for (id, record) in &self.rows {
            rows.insert(id.clone(), Value::Object(record.clone()));
        }
        report.insert("rows", Value::Object(rows));
        if let Some(seconds) = self.seconds {
            report.insert("seconds", Value::Float(seconds));
        }
        if let Some(mismatched) = &self.mismatched {
            report.insert("mismatched", listed(mismatched));
        }
        if let Some(no_verdict) = &self.no_verdict {
            report.insert("no verdict", listed(no_verdict));
        }
        report
    }

    /// `checkpoint` writes the report so far to `progress.json` under `work`, with `active` and the
    /// seconds since `started`.
    fn checkpoint(&self, work: &Path, active: Value, started: Instant) -> Result<(), Halt> {
        let mut progress = self.object();
        progress.insert("active", active);
        progress.insert("seconds", Value::Float(seconds(started.elapsed())));
        save(&work.join("progress.json"), &Value::Object(progress)).map_err(Halt::failed)
    }

    fn record(&mut self, id: &Text) -> &mut Object {
        let at = self
            .rows
            .iter()
            .position(|(held, _)| held == id)
            .expect("the row's record stands");
        &mut self.rows[at].1
    }
}

/// `captured_text` runs `command`, killing it on a signal recorded in `interrupt`, and returns its exit
/// code and its standard output as UTF-8.
fn captured_text(command: &mut Command, interrupt: &Interrupt) -> Result<(i32, String), Halt> {
    with_defaults(command);
    let output = capture(command, interrupt)??;
    let text = String::from_utf8(output.stdout).map_err(Halt::failed)?;
    Ok((returncode(output.status), text))
}

/// `machine` is the host architecture `uname` names.
fn machine() -> Result<Text, Halt> {
    // SAFETY: all-zero bytes are a valid `utsname`, which `uname` fills; it outlives the call.
    let mut name: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: `name` is a writable `utsname` that outlives the call.
    if unsafe { libc::uname(&mut name) } != 0 {
        return Err(Halt::failed(std::io::Error::last_os_error()));
    }
    let bytes: Vec<u8> = name
        .machine
        .iter()
        .take_while(|&&byte| byte != 0)
        .map(|&byte| u8::from_ne_bytes(byte.to_ne_bytes()))
        .collect();
    Ok(Text::from_os(std::os::unix::ffi::OsStrExt::from_bytes(
        bytes.as_slice(),
    )))
}

/// `cpus` is the count of processors online, JSON null where the system names none.
fn cpus() -> Value {
    // SAFETY: `sysconf` takes a constant name and touches no memory of the caller.
    let online = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    u64::try_from(online)
        .ok()
        .filter(|&count| count >= 1)
        .map_or(Value::Null, |count| Value::Integer(Integer::from(count)))
}

/// The catalog's selected rows with each label, and the tests of the baseline.
struct Selection {
    rows: Vec<Object>,
    labels: BTreeMap<Text, Text>,
    baseline: Vec<(Text, Text)>,
}

/// `selection` reads the copy's catalog: every row, or each row `selected` names, each row's label from
/// its catalog position, and the scoped files with their texts and digests.
///
/// # Errors
///
/// A refusal of exit 2 for a `--row` that names no row or a planted file whose bytes a text restore
/// cannot reproduce; a failure for a catalog or a scoped file that cannot be read.
fn selection(runner: &Runner<'_>, selected: &[Text]) -> Result<(Selection, Scoped), Halt> {
    let source = runner.read(CATALOG).map_err(Halt::failed)?;
    let catalog = json::parse(&source).map_err(Halt::failed)?;
    let catalog = object_of(&catalog)?;
    let all: Vec<Object> = match catalog.get("rows") {
        Some(Value::Array(rows)) => rows
            .iter()
            .map(|row| object_of(row).cloned())
            .collect::<Result<_, _>>()?,
        _ => return Err(Halt::failed("KeyError: 'rows'")),
    };
    let rows: Vec<Object> = all
        .iter()
        .filter(|row| selected.is_empty() || selected.contains(&string(row, "id")))
        .cloned()
        .collect();
    let wanted: BTreeSet<&Text> = selected.iter().collect();
    if !selected.is_empty() && rows.len() != wanted.len() {
        let found: BTreeSet<Text> = rows.iter().map(|row| string(row, "id")).collect();
        let missing: Vec<Text> = wanted
            .into_iter()
            .filter(|id| !found.contains(*id))
            .cloned()
            .collect();
        return Err(Halt::stop(
            2,
            text!("no catalog row named ", texts(&missing)),
        ));
    }
    let labels = all
        .iter()
        .enumerate()
        .map(|(index, row)| {
            (
                string(row, "id"),
                Text::from(format!("row{index:02}").as_str()),
            )
        })
        .collect();
    let files: Vec<Text> = match catalog.get("files") {
        Some(Value::Array(files)) => files.iter().map(str_of).collect(),
        _ => return Err(Halt::failed("KeyError: 'files'")),
    };
    let mut scoped = Scoped {
        copy: runner.copy.clone(),
        files: files.clone(),
        originals: BTreeMap::new(),
        digests: BTreeMap::new(),
    };
    for name in &files {
        let text = runner.read(&name.to_string()).map_err(Halt::failed)?;
        scoped.originals.insert(name.clone(), text);
    }
    for name in &files {
        let digest = sha256(&scoped.path(name)?).map_err(Halt::failed)?;
        scoped.digests.insert(name.clone(), digest);
    }
    let mut planted = BTreeSet::new();
    let mut baseline = BTreeSet::new();
    for row in &rows {
        let (entries, _) =
            row_entries(row).map_err(|reason| Halt::failed(text!("ValueError: ", reason)))?;
        if !entries.is_empty() {
            planted.insert(string(row, "path"));
        }
        for entry in entries {
            if let Some(Value::Array(tests)) = entry.get("tests") {
                for test in tests {
                    baseline.insert((string(entry, "lane"), str_of(test)));
                }
            }
        }
    }
    let mut unfaithful = Vec::new();
    for name in &planted {
        let bytes = fs::read(scoped.path(name)?).map_err(Halt::failed)?;
        if scoped.originals.get(name).map(String::as_bytes) != Some(bytes.as_slice()) {
            unfaithful.push(name.clone());
        }
    }
    if !unfaithful.is_empty() {
        return Err(Halt::stop(
            2,
            text!(
                "the scoped files ",
                texts(&unfaithful),
                " hold line endings a text restore cannot reproduce byte for byte"
            ),
        ));
    }
    let selection = Selection {
        rows,
        labels,
        baseline: baseline.into_iter().collect(),
    };
    Ok((selection, scoped))
}

/// `run` runs the baseline, then each selected row's plant, and returns the report and the exit code:
/// 1 where a row does not agree, else 0.
///
/// # Errors
///
/// A refusal, a red baseline (exit 3), a changed scoped file, plant or restore (exit 4), a recorded
/// signal, or a failed step.
fn run(
    top: &Path,
    work: &Path,
    selected: &[Text],
    launch: &Launch<'_>,
    err: &mut impl Write,
) -> Result<(Value, u8), Halt> {
    let started = Instant::now();
    let environ = crate::environ::first_of_each(std::env::vars_os().collect());
    let mut runner = Runner::new(top, work, environ, launch)?;
    let _ = writeln!(
        err,
        "weaken-orderings: running the committed revision {}; uncommitted changes are not in the copy",
        runner.revision
    );
    let _ = err.flush();
    launch.interrupt.check()?;
    let read = |path: &str| runner.read(path);
    let (checked, code) = check(
        &read,
        &runner.copy,
        &runner.copy,
        EXTERNAL,
        &package_sources,
    );
    if code != 0 {
        let member = |key: &str| json_path(&checked, &[key]).cloned().unwrap_or(Value::Null);
        let refusals = member("refusals");
        let shown = if truthy(&refusals) {
            refusals
        } else {
            member("error")
        };
        return Err(Halt::stop(
            2,
            text!("check refuses the copy's catalog: ", str_of(&shown)),
        ));
    }
    runner.remember_models()?;
    launch.interrupt.check()?;
    runner.prepare()?;
    let (selection, scoped) = selection(&runner, selected)?;
    let lanes: BTreeSet<&str> = selection
        .baseline
        .iter()
        .filter_map(|(lane, _)| match lane.to_str() {
            Some("loom") => Some("loom"),
            Some("genmc") => Some("genmc"),
            _ => None,
        })
        .collect();
    if !lanes.is_empty() {
        runner.check_configs(&lanes)?;
    }
    if lanes.contains("genmc") {
        runner.check_declaration()?;
    }
    let mut pins = Object::new();
    for (name, value) in &runner.pins {
        pins.insert(name.as_str(), Value::String(Text::from(value.as_str())));
    }
    let stable = format!("+{}", pin(&runner.pins, "STABLE"));
    let mut tree = Command::new("cargo");
    tree.arg(&stable)
        .args([
            "tree", "-p", "kestrike", "-i", "loom", "--target", "all", "--depth", "0", "--prefix",
            "none",
        ])
        .current_dir(&runner.copy)
        .env_clear()
        .envs(lane_env(&runner.environ, work, &runner.pins));
    let (code, listed) = captured_text(&mut tree, launch.interrupt)?;
    let words = Text::from(listed.as_str()).split();
    let resolved = match (code, words.get(1)) {
        (0, Some(version)) => version.clone(),
        _ => Text::from("unresolved"),
    };
    let loom = text!("v", pin(&runner.pins, "LOOM"));
    if lanes.contains("loom") && resolved != loom {
        return Err(Halt::stop(
            2,
            text!(
                "the copy resolves loom ",
                resolved,
                ", and the LOOM pin is ",
                loom
            ),
        ));
    }
    pins.insert("loom resolved", Value::String(resolved));
    let lock = regular_digest(&runner.copy.join("Cargo.lock"));
    pins.insert(
        "Cargo.lock sha256",
        lock.map_or(Value::Null, |digest| {
            Value::String(Text::from(digest.as_str()))
        }),
    );
    let mut rustc = Command::new("rustc");
    rustc.args([stable.as_str(), "--version"]);
    let (_, version) = captured_text(&mut rustc, launch.interrupt)?;
    pins.insert("rustc", Value::String(Text::from(version.as_str()).strip()));
    pins.insert("host", Value::String(machine()?));
    pins.insert("cpus", cpus());
    let jobs = std::env::var_os("CARGO_BUILD_JOBS")
        .map_or(Value::Null, |jobs| Value::String(Text::from_os(&jobs)));
    pins.insert("CARGO_BUILD_JOBS", jobs);
    let mut report = Report {
        revision: Text::from(runner.revision.as_str()),
        pins,
        baseline: Vec::new(),
        rows: Vec::new(),
        seconds: None,
        mismatched: None,
        no_verdict: None,
    };
    launch.interrupt.check()?;
    report.checkpoint(work, Value::String(Text::from("baseline")), started)?;
    baseline(&mut runner, &selection, &scoped, &mut report, work, started)?;
    launch.interrupt.check()?;
    report.checkpoint(work, Value::Null, started)?;
    let mismatched = rows(&mut runner, &selection, &scoped, &mut report, work, started)?;
    report.seconds = Some(seconds(started.elapsed()));
    let no_verdict = report
        .rows
        .iter()
        .filter(|(_, record)| match record.get("results") {
            Some(Value::Array(results)) => undecided(results),
            _ => false,
        })
        .map(|(id, _)| id.clone())
        .collect();
    let code = u8::from(!mismatched.is_empty());
    report.mismatched = Some(mismatched);
    report.no_verdict = Some(no_verdict);
    Ok((Value::Object(report.object()), code))
}

/// `baseline` runs each test the selected rows name once on the unweakened copy, recording each result
/// and the progress after it.
///
/// # Errors
///
/// A refusal of exit 4 where a test left a scoped file changed, of exit 3 with the report so far where
/// a result is not `survived`, and the halt of a run or a write.
fn baseline(
    runner: &mut Runner<'_>,
    selection: &Selection,
    scoped: &Scoped,
    report: &mut Report,
    work: &Path,
    started: Instant,
) -> Result<(), Halt> {
    let mut runs: Runs = BTreeMap::new();
    for (lane, test) in &selection.baseline {
        let mut entry = Object::new();
        entry.insert("lane", Value::String(lane.clone()));
        entry.insert("tests", Value::Array(vec![Value::String(test.clone())]));
        let mut judged = |results: Vec<Value>| -> Result<(), Halt> {
            let red = results.iter().any(|result| !result_is(result, "survived"));
            report.baseline.extend(results);
            let drift = scoped.drifted()?;
            if !drift.is_empty() || red {
                report.seconds = Some(seconds(started.elapsed()));
                report.checkpoint(work, Value::Null, started)?;
                if !drift.is_empty() {
                    return Err(Halt::stop(
                        4,
                        text!(
                            "the scoped files ",
                            texts(&drift),
                            " differ from the unweakened copy after the baseline test ",
                            test
                        ),
                    ));
                }
                return Err(Halt::stop(
                    3,
                    json::indented_in_order(&Value::Object(report.object())),
                ));
            }
            report.checkpoint(work, Value::String(Text::from("baseline")), started)
        };
        runner.each(&entry, None, &mut runs, &mut judged)?;
        runner.launch.interrupt.check()?;
    }
    Ok(())
}

/// `rows` runs each selected row under its plant and returns the ids of the rows that do not agree.
///
/// # Errors
///
/// The halt of a plant, a restore, a run or a write.
fn rows(
    runner: &mut Runner<'_>,
    selection: &Selection,
    scoped: &Scoped,
    report: &mut Report,
    work: &Path,
    started: Instant,
) -> Result<Vec<Text>, Halt> {
    let mut mismatched = Vec::new();
    for row in &selection.rows {
        runner.launch.interrupt.check()?;
        let id = string(row, "id");
        let (entries, wanted) =
            row_entries(row).map_err(|reason| Halt::failed(text!("ValueError: ", reason)))?;
        let mut plant = Object::new();
        for key in ["path", "find", "replace"] {
            plant.insert(key, row.get(key).cloned().unwrap_or(Value::Null));
        }
        let mut record = Object::new();
        record.insert("plant", Value::Object(plant));
        record.insert(
            "expected",
            wanted.map_or(Value::Null, |wanted| Value::String(Text::from(wanted))),
        );
        record.insert("results", Value::Array(Vec::new()));
        report.rows.push((id.clone(), record));
        if entries.is_empty() {
            let reason_of = |kind: &str| match row.get(kind) {
                Some(Value::Object(disposition)) => disposition.get("reason").cloned(),
                _ => None,
            };
            let reason = reason_of("unrun")
                .filter(truthy)
                .or_else(|| reason_of("survives"))
                .unwrap_or(Value::Null);
            let record = report.record(&id);
            record.insert("result", Value::String(Text::from("skipped")));
            record.insert("reason", reason);
            record.insert("agrees", Value::Bool(true));
            report.checkpoint(work, Value::Null, started)?;
            continue;
        }
        report.checkpoint(work, Value::String(id.clone()), started)?;
        let row_started = Instant::now();
        let label = selection.labels.get(&id).cloned().unwrap_or_default();
        let mut runs: Runs = BTreeMap::new();
        holding(runner.launch.interrupt, || {
            scoped.planted(row, || {
                for entry in &entries {
                    let mut judged = |results: Vec<Value>| -> Result<(), Halt> {
                        if let Some(Value::Array(held)) = report.record(&id).get_mut("results") {
                            held.extend(results);
                        }
                        report.checkpoint(work, Value::String(id.clone()), started)
                    };
                    runner.each(entry, Some(&label), &mut runs, &mut judged)?;
                }
                Ok(())
            })
        })?;
        let record = report.record(&id);
        record.insert("seconds", Value::Float(seconds(row_started.elapsed())));
        let agrees = wanted.is_none_or(|wanted| match record.get("results") {
            Some(Value::Array(results)) => results.iter().all(|result| result_is(result, wanted)),
            _ => true,
        });
        record.insert("agrees", Value::Bool(agrees));
        if !agrees {
            mismatched.push(id.clone());
        }
        report.checkpoint(work, Value::Null, started)?;
    }
    Ok(mismatched)
}

#[cfg(test)]
#[path = "run_tests.rs"]
mod tests;
