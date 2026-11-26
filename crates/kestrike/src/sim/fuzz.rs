//! The simulation worker's in-process libFuzzer driver.
//!
//! The worker's `main` is the process entry; [`drive`] enters libFuzzer
//! through `LLVMFuzzerRunDriver` once, and a second entry is refused.
//! The entry installs the panic identity hook ([`unwind`]) in front of the
//! process's default hook, so a target's run unwinds through its world's
//! teardown audit under `catch_unwind` like any other run and its failure
//! names the panic's location and payload. The driver runs in process: libFuzzer's modes that start the
//! program again from its name, `-fork`, `-jobs`, `-workers`,
//! `-set_cover_merge`, `-minimize_crash` and `-cleanse_crash`, are refused
//! before it is entered. A corpus merge, `-merge`, is the one such mode
//! the driver enters: libFuzzer starts each inner merge process by
//! joining its own arguments with spaces into a shell command, and
//! [`drive`] passes the worker's own `--fuzz` form as the program name,
//! so that command is the worker's form for the same target and artifact
//! directory. [`command`] builds that name and admits a merge only when
//! the worker's executable path, the artifact directory, and every
//! libFuzzer argument contain only bytes from `A-Za-z0-9/._=,-`. The
//! worker requires `-merge_control_file=FILE` when a libFuzzer argument
//! starts with `-merge=`, [`command`] refuses a FILE that exists, since
//! libFuzzer resumes a merge from an existing control file.
//! For a merge, [`command`] rejects `-ignore_remaining_args=` with any value.
//! A nonzero `-ignore_remaining_args` value stops libFuzzer's flag parser
//! before it reaches a later `-merge_control_file=FILE`.
//!
//! libFuzzer's outer merge process exits 0 when every inner process
//! fails. The outer process prints
//! `MERGE-OUTER: successful in N attempt(s)` when an inner process
//! exits 0.
//!
//! For each input [`judged`] runs the target under `catch_unwind` and
//! classifies the result. A run completes its world's checks, its stopped
//! boundaries, its teardown audit and its bundle's terminal before it
//! returns. A pass, an unsuccessful or
//! inconclusive run and an input the target marks invalid, incomplete or
//! unsupported return to the driver; only a pass earns one, and the three
//! input refusals keep the input out of the corpus. A violation, harness
//! defect or panic causes the callback to print counts, then abort.
//!
//! Beside the class counts, the counts line reports the oracle checkpoint,
//! `nonseed_pass`: executions of generated inputs the oracle judged a pass.
//! A pass reports the run it drove: a fed campaign's tape, or the input
//! bytes a parser target's judgment reads. A pass is generated
//! when that run differs from every seed's. Equal decisions give equal
//! tapes, so a campaign input that changes only feed bytes the run never
//! reads, or bytes whose change leaves every decision the same, repeats the
//! seed and leaves the count unchanged. A parser mode that applies ops reads
//! its input through the last whole op; the record target's claim mode
//! reads its input through the longest header the fixed fields derive, or
//! all of it when it ends sooner. An input repeats a seed's run when those
//! bytes match. [`drive`] runs the seeds once before it enters
//! libFuzzer to learn their runs, so the count is independent of the order
//! libFuzzer runs inputs in.
//!
//! In a merge, the inner processes run the inputs: each judges the seeds,
//! registers the exit report, and prints its own counts line when it
//! exits or before it aborts on a failure it classifies. The merge
//! coordinator ([`coordinates`]) starts the inner processes and prints
//! libFuzzer's `MERGE-OUTER:` lines; each inner process prints its own
//! `MERGE-INNER:` lines. On a timeout or an RSS-limit stop, libFuzzer
//! calls `_Exit`, bypassing the exit report, so a merge's last counts
//! line comes from the last inner process that exited or aborted on a
//! classified failure.
//!
//! A failure whose run reached its terminal replays and reduces through
//! the worker's replay forms. A failure whose feed ended first keeps a
//! bundle whose tape stops with the feed, so a replay refuses it as
//! exhausted; rerun the input to investigate that failure or a panic.

use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

// Links libFuzzer's runtime, which defines `LLVMFuzzerRunDriver`.
use libfuzzer_sys as _;

use crate::net::teardowns;

use super::unwind;

/// Bytes an input may hold; a longer one is invalid.
pub(crate) const MAX_INPUT: usize = 1 << 16;

/// How a target judged one input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    /// The run counted as a pass. `run` identifies it: the tape of a fed
    /// run, or the parser input bytes used to judge the run.
    Pass { run: Vec<u8> },
    /// The run completed without counting: unsuccessful, inconclusive or
    /// cut by a bound.
    Unsuccessful(String),
    /// The input is malformed, or names a run no start admits, by this
    /// rule.
    Invalid(&'static str),
    /// The input ended before a decision the run drew, and the run recorded
    /// no violation.
    Incomplete,
    /// The input names a scenario the target does not run.
    Unsupported(u8),
    /// A violation or a harness defect: the claim and the run's bundle.
    Failure { claim: String, bundle: Vec<u8> },
}

impl Class {
    /// The class's slot in [`CLASSES`] and the counts.
    fn index(&self) -> usize {
        match self {
            Self::Pass { .. } => 0,
            Self::Unsuccessful(_) => 1,
            Self::Invalid(_) => 2,
            Self::Incomplete => 3,
            Self::Unsupported(_) => 4,
            Self::Failure { .. } => 5,
        }
    }

    /// The class's name in the counts.
    pub(crate) fn name(&self) -> &'static str {
        CLASSES[self.index()]
    }

    /// The value the driver receives: 0 keeps the input as a corpus
    /// candidate, -1 rejects an invalid, incomplete or unsupported one.
    fn code(&self) -> i32 {
        match self {
            Self::Invalid(_) | Self::Incomplete | Self::Unsupported(_) => -1,
            _ => 0,
        }
    }
}

/// A fuzz target: its name, the run that judges one input and reports a
/// pass's run, and the seed inputs, each with its file name, a corpus
/// starts from.
#[derive(Debug)]
pub(crate) struct Target {
    pub(crate) name: &'static str,
    pub(crate) run: fn(&[u8]) -> Class,
    pub(crate) seeds: fn() -> Vec<(String, Vec<u8>)>,
}

/// The classes the counts keep, in report order.
const CLASSES: [&str; 6] = [
    "pass",
    "unsuccessful",
    "invalid",
    "incomplete",
    "unsupported",
    "failure",
];

static ENTERED: AtomicBool = AtomicBool::new(false);
static TARGET: OnceLock<&'static Target> = OnceLock::new();
static ARTIFACTS: OnceLock<PathBuf> = OnceLock::new();
static EXECUTED: AtomicU64 = AtomicU64::new(0);
static COUNTS: [AtomicU64; CLASSES.len()] = [const { AtomicU64::new(0) }; CLASSES.len()];
/// The runs the entered target's passing seeds drove, which [`generated`]
/// compares a pass's run against.
static SEED_RUNS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
/// The entered target's generated passes: the oracle checkpoint.
static GENERATED: AtomicU64 = AtomicU64::new(0);

/// The counts line: the target, inputs executed, each class, then the
/// checkpoint count.
pub(crate) fn counts() -> String {
    let name = TARGET.get().map_or("none", |target| target.name);
    let mut out = format!("fuzz: {name} executed={}", EXECUTED.load(Ordering::Relaxed));
    for (class, count) in CLASSES.iter().zip(&COUNTS) {
        out.push_str(&format!(" {class}={}", count.load(Ordering::Relaxed)));
    }
    out.push_str(&format!(
        " nonseed_pass={}",
        GENERATED.load(Ordering::Relaxed)
    ));
    out
}

/// Whether `class` is a generated pass, which the checkpoint counts: a
/// [`Class::Pass`] whose run differs from every one of `seed_runs`.
pub(crate) fn generated(seed_runs: &[Vec<u8>], class: &Class) -> bool {
    matches!(class, Class::Pass { run } if !seed_runs.contains(run))
}

/// The runs `target`'s seeds drive, for the seeds that pass. A seed of
/// another class drives no run a pass can repeat; the driver judges and
/// reports it when libFuzzer runs the corpus.
fn seed_runs(target: &Target) -> Vec<Vec<u8>> {
    (target.seeds)()
        .into_iter()
        .filter_map(
            |(_, seed)| match std::panic::catch_unwind(|| (target.run)(&seed)) {
                Ok(Class::Pass { run }) => Some(run),
                _ => None,
            },
        )
        .collect()
}

/// Judges `input` under `target` to its end: runs it under `catch_unwind`,
/// so a panicking run tears its world down during the unwind, counts its
/// class, and returns it. A panic is a failure with no bundle whose claim
/// names the panic's location and payload ([`unwind`]).
pub(crate) fn judged(target: &Target, input: &[u8]) -> Class {
    let class = unwind::caught(|| (target.run)(input)).unwrap_or_else(|identity| Class::Failure {
        claim: format!("the run panicked at {identity}"),
        bundle: Vec::new(),
    });
    EXECUTED.fetch_add(1, Ordering::Relaxed);
    COUNTS[class.index()].fetch_add(1, Ordering::Relaxed);
    class
}

/// Runs of at most this many bytes are tried at every offset, so a
/// structured input's fields can be removed whole wherever they start.
const FINE_RUN: usize = 8;

/// The budget of removal judgments a minimization makes after it judges
/// its input. At the budget, minimization returns the shortest failing
/// input found.
pub(crate) const MAX_TRIES: usize = 8192;

/// Removes runs of bytes from `input` while `target` still fails it with
/// the claim `input` fails with, a panic's location and payload included, and returns the shortest input found
/// beside that claim, or `None` when `input` does not fail. Run lengths
/// start at a power of two and halve down to one byte. The search tries
/// runs longer than [`FINE_RUN`] at multiples of their length and runs of
/// at most [`FINE_RUN`] bytes at every offset. One-byte passes repeat
/// until a whole pass keeps every byte, since a removal can make an
/// earlier byte removable; so when the search finishes with fewer than
/// [`MAX_TRIES`] removals judged, removing any one byte of the result
/// loses the claim.
pub(crate) fn minimized(target: &Target, input: &[u8]) -> Option<(Vec<u8>, String)> {
    let claim = |bytes: &[u8]| match judged(target, bytes) {
        Class::Failure { claim, .. } => Some(claim),
        _ => None,
    };
    let wanted = claim(input)?;
    let mut smallest = input.to_vec();
    let mut run = smallest.len().max(1).next_power_of_two();
    let mut tries = 0;
    loop {
        let step = if run <= FINE_RUN { 1 } else { run };
        let (mut at, mut removed) = (0, false);
        while at < smallest.len() && tries < MAX_TRIES {
            tries += 1;
            let mut shorter = smallest.clone();
            shorter.drain(at..(at + run).min(smallest.len()));
            if claim(&shorter).as_ref() == Some(&wanted) {
                smallest = shorter;
                removed = true;
            } else {
                at += step;
            }
        }
        if tries == MAX_TRIES || (run == 1 && !removed) {
            return Some((smallest, wanted));
        }
        run = (run / 2).max(1);
    }
}

/// Writes a failure's input, claim and, when it is not empty, bundle into
/// the artifact directory, each created new, so a rerun into the same
/// directory keeps the earliest failure; returns what it wrote.
fn retain(input: &[u8], claim: &str, bundle: &[u8]) -> String {
    let Some(dir) = ARTIFACTS.get() else {
        return "no artifact directory".into();
    };
    let write = |name: &str, bytes: &[u8]| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(name))
            .and_then(|mut file| file.write_all(bytes).and_then(|()| file.flush()))
    };
    let kept = if bundle.is_empty() {
        "first-failure.input"
    } else {
        "first-failure.bundle"
    };
    let written = write("first-failure.input", input)
        .and_then(|()| match bundle.is_empty() {
            true => Ok(()),
            false => write("first-failure.bundle", bundle),
        })
        .and_then(|()| write("first-failure.claim", format!("{claim}\n").as_bytes()));
    match written {
        Ok(()) => dir.join(kept).display().to_string(),
        Err(error) => format!("kept the earlier failure: {error}"),
    }
}

/// The driver's callback: judges the input `data` holds under the entered
/// target, counts it toward the checkpoint when it is a generated pass,
/// and aborts after retaining a failure.
///
/// # Safety
///
/// `data` points to `size` readable bytes, as libFuzzer passes them; a
/// zero `size` may come with any pointer.
unsafe extern "C" fn one_input(data: *const u8, size: usize) -> libc::c_int {
    let Some(target) = TARGET.get() else {
        return -1;
    };
    let bytes = if size == 0 {
        &[][..]
    } else {
        // SAFETY: the caller passes `size` readable bytes at `data`.
        unsafe { std::slice::from_raw_parts(data, size) }
    };
    let class = judged(target, bytes);
    let seed_runs = SEED_RUNS.get().map_or(&[][..], Vec::as_slice);
    if generated(seed_runs, &class) {
        GENERATED.fetch_add(1, Ordering::Relaxed);
    }
    if let Class::Failure { claim, bundle } = &class {
        let kept = retain(bytes, claim, bundle);
        eprintln!(
            "fuzz: audited and tore down {}: {claim}; {} teardowns; retained {kept}",
            target.name,
            teardowns()
        );
        eprintln!("{}", counts());
        std::process::abort();
    }
    class.code()
}

unsafe extern "C" {
    fn LLVMFuzzerRunDriver(
        argc: *mut libc::c_int,
        argv: *mut *mut *mut libc::c_char,
        callback: unsafe extern "C" fn(*const u8, usize) -> libc::c_int,
    ) -> libc::c_int;
}

/// Claims the process's one driver entry.
///
/// # Errors
///
/// When an earlier call claimed it.
pub(crate) fn claim_entry() -> Result<(), String> {
    if ENTERED.swap(true, Ordering::SeqCst) {
        return Err("the fuzz driver was already entered".into());
    }
    Ok(())
}

extern "C" fn report() {
    eprintln!("{}", counts());
}

/// libFuzzer's flags that start the program again from its name and that
/// the driver refuses.
const RESTARTS: [&str; 6] = [
    "-fork",
    "-jobs",
    "-workers",
    "-set_cover_merge",
    "-minimize_crash",
    "-cleanse_crash",
];

/// Whether `word` holds only bytes of `A-Za-z0-9/._=,-`, and at least
/// one: a shell passes such a word as one word, unchanged.
fn plain(word: &str) -> bool {
    let plain = |byte: u8| byte.is_ascii_alphanumeric() || b"/._=,-".contains(&byte);
    !word.is_empty() && word.bytes().all(plain)
}

/// What a directory entry is, read without following a symbolic link.
#[derive(Debug)]
enum Kind {
    Directory,
    Other,
}

/// One entry of a directory listing: its name and its [`Kind`].
struct Listed {
    name: std::ffi::OsString,
    kind: std::io::Result<Kind>,
}

/// The [`Kind`] of `entry`.
fn kind(entry: &std::fs::DirEntry) -> std::io::Result<Kind> {
    let kind = entry.file_type()?;
    Ok(if kind.is_dir() {
        Kind::Directory
    } else {
        Kind::Other
    })
}

/// The entries of the directory `dir`, read from the filesystem one at a
/// time as [`multiline`] walks them.
fn listed(
    dir: &std::path::Path,
) -> std::io::Result<impl Iterator<Item = std::io::Result<Listed>> + use<>> {
    Ok(std::fs::read_dir(dir)?.map(|entry| {
        entry.map(|entry| Listed {
            name: entry.file_name(),
            kind: kind(&entry),
        })
    }))
}

/// The first entry under the corpus directory `dir` whose name holds a
/// line break, where `list` reads each directory's entries. libFuzzer
/// writes one file name per line into a merge's control file, and it
/// recurses into directories whose names start with a byte other than
/// `.`. A path with no entry, `dir` or one removed during the walk, holds
/// none.
///
/// # Errors
///
/// The path and error of a directory that cannot be listed, an entry
/// that cannot be read and an entry whose type cannot be read, so a
/// corpus whose names go unchecked refuses the merge.
fn multiline<I>(
    dir: &std::path::Path,
    list: &impl Fn(&std::path::Path) -> std::io::Result<I>,
) -> Result<Option<PathBuf>, String>
where
    I: IntoIterator<Item = std::io::Result<Listed>>,
{
    use std::io::ErrorKind::NotFound;
    use std::os::unix::ffi::OsStrExt;

    let failed =
        |path: &std::path::Path, error: std::io::Error| format!("{}: {error}", path.display());
    let entries = match list(dir) {
        Err(error) if error.kind() == NotFound => return Ok(None),
        listed => listed.map_err(|error| failed(dir, error))?,
    };
    for entry in entries {
        let Listed { name, kind } = entry.map_err(|error| failed(dir, error))?;
        if name.as_bytes().contains(&b'\n') {
            return Ok(Some(dir.join(&name)));
        }
        let kind = match kind {
            Err(error) if error.kind() == NotFound => continue,
            kind => kind.map_err(|error| failed(&dir.join(&name), error))?,
        };
        if matches!(kind, Kind::Directory)
            && !name.as_bytes().starts_with(b".")
            && let Some(found) = multiline(&dir.join(&name), list)?
        {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

/// libFuzzer takes the worker invocation as its program name, followed
/// by `theirs`. The invocation uses `exe` when supplied and `sim_worker`
/// otherwise.
///
/// # Errors
///
/// `command` returns an error when an argument in `theirs` starts with a
/// flag from [`RESTARTS`] immediately followed by `=`.
/// When `theirs` holds a `-merge=` argument, `command` requires `exe`
/// and a `-merge_control_file=` argument.
/// A merge requires a new control file.
/// A merge requires `exe`, `target`, `artifacts`, and each argument in
/// `theirs` to pass [`plain`].
/// For a merge, `command` refuses an `-ignore_remaining_args=` argument.
/// A merge requires single-line corpus entry names and corpus
/// directories whose entries it can list, as [`multiline`] reads them.
/// A merge requires each `-merge=` value to be `0` or `1`.
fn command(
    exe: Result<&str, &str>,
    target: &str,
    artifacts: &str,
    theirs: &[String],
) -> Result<Vec<String>, String> {
    fn valued<'a>(arg: &'a str, flag: &str) -> Option<&'a str> {
        arg.strip_prefix(flag)?.strip_prefix('=')
    }
    let find = |flags: &[&str]| {
        let named = |arg: &&String| flags.iter().any(|flag| valued(arg, flag).is_some());
        theirs.iter().find(named)
    };
    if let Some(flag) = find(&RESTARTS) {
        return Err(format!("{flag}: the driver runs in process"));
    }
    let name = [
        exe.unwrap_or("sim_worker"),
        "--fuzz",
        target,
        "--artifacts",
        artifacts,
        "--",
    ];
    if find(&["-merge"]).is_some() {
        let other =
            |arg: &&String| valued(arg, "-merge").is_some_and(|value| !matches!(value, "0" | "1"));
        if let Some(merge) = theirs.iter().find(other) {
            return Err(format!("{merge}: a merge takes -merge=0 or -merge=1"));
        }
        exe.map_err(|cause| format!("a merge takes the worker's executable path: {cause}"))?;
        // libFuzzer stops reading arguments after a nonzero
        // `-ignore_remaining_args`, so it ignores a later
        // `-merge_control_file=FILE`.
        // libFuzzer inserts the inner process's `-merge_inner=1` before the
        // literal `-ignore_remaining_args=1` when present and at the end of
        // the argument list otherwise.
        if let Some(cut) = find(&["-ignore_remaining_args"]) {
            return Err(format!(
                "{cut}: a merge takes every flag where libFuzzer reads it"
            ));
        }
        let control = theirs
            .iter()
            .rev()
            .find_map(|arg| valued(arg, "-merge_control_file"))
            .filter(|file| !file.is_empty())
            .ok_or("a merge takes -merge_control_file=FILE")?;
        let mut line = name.into_iter().chain(theirs.iter().map(String::as_str));
        if let Some(word) = line.find(|word| !plain(word)) {
            let set = "A-Za-z0-9/._=,-";
            return Err(format!("{word:?}: a merge takes only bytes of {set}"));
        }
        // libFuzzer resumes a merge from an existing control file.
        match std::fs::symlink_metadata(control) {
            Ok(_) => return Err(format!("{control}: a merge takes a new control file")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("{control}: {error}")),
        }
        for dir in theirs.iter().filter(|arg| !arg.starts_with('-')) {
            let found = multiline(dir.as_ref(), &listed)
                .map_err(|cause| format!("{cause}: a merge checks every corpus entry name"))?;
            if let Some(entry) = found {
                return Err(format!(
                    "{entry:?}: a merge takes corpus entry names of one line"
                ));
            }
        }
    }
    Ok(std::iter::once(name.join(" "))
        .chain(theirs.iter().cloned())
        .collect())
}

/// Whether `theirs` makes this process libFuzzer's merge coordinator: the
/// last `-merge=` value is `1`. The coordinator starts the inner process,
/// which runs the inputs.
fn coordinates(theirs: &[String]) -> bool {
    let merge = theirs
        .iter()
        .rev()
        .find_map(|arg| arg.strip_prefix("-merge="));
    merge == Some("1")
}

/// Enters libFuzzer's driver once in this process for `target`, with
/// the arguments [`command`] builds from `theirs`, and returns the
/// driver's result. `one_input` runs each input the driver passes and
/// retains failures in the directory `artifacts`. Every process but the
/// merge coordinator ([`coordinates`]) judges the seeds for the
/// checkpoint and registers the exit report. During a merge, each inner
/// process prints one counts line when it exits or before it aborts on
/// a classified failure. On a timeout or an RSS-limit stop, libFuzzer
/// calls `_Exit`, bypassing the exit report.
///
/// # Errors
///
/// A flag of [`RESTARTS`], a second entry in one process, an argument
/// holding a NUL byte, or a failed exit-report registration.
///
/// If `current_exe` fails or the executable path is not valid UTF-8,
/// `drive` passes that cause to [`command`] as `Err`.
/// If [`command`] returns `Err`, `drive` propagates the error before
/// claiming the entry.
pub(crate) fn drive(
    target: &'static Target,
    artifacts: &str,
    theirs: &[String],
) -> Result<i32, String> {
    let exe = std::env::current_exe().map_err(|error| error.to_string());
    let exe = match &exe {
        Ok(path) => path.to_str().ok_or("the path is not UTF-8"),
        Err(error) => Err(error.as_str()),
    };
    let args = command(exe, target.name, artifacts, theirs)?;
    claim_entry()?;
    unwind::install();
    let owned: Vec<std::ffi::CString> = args
        .iter()
        .map(|arg| std::ffi::CString::new(arg.as_str()).map_err(|error| error.to_string()))
        .collect::<Result<_, _>>()?;
    let _ = TARGET.set(target);
    let _ = ARTIFACTS.set(artifacts.into());
    let coordinator = coordinates(theirs);
    if !coordinator {
        let _ = SEED_RUNS.set(seed_runs(target));
    }
    let mut pointers: Vec<*mut libc::c_char> = owned
        .iter()
        .map(|arg| arg.as_ptr().cast_mut())
        .chain(std::iter::once(std::ptr::null_mut()))
        .collect();
    let mut argc = owned.len() as libc::c_int;
    let mut argv = pointers.as_mut_ptr();
    // SAFETY: `report` is a plain `extern "C"` function with no captures.
    if !coordinator && unsafe { libc::atexit(report) } != 0 {
        return Err("the exit report could not be registered".into());
    }
    // SAFETY: `argc` counts the NUL-terminated strings `argv` points to,
    // followed by a null pointer; `owned` and `pointers` outlive the call,
    // and libFuzzer calls `one_input` with each input's bytes and length.
    Ok(unsafe { LLVMFuzzerRunDriver(&raw mut argc, &raw mut argv, one_input) })
}

#[cfg(test)]
mod tests {
    //! The plain-word check, the argument checks [`command`] makes, the
    //! merge coordinator, the corpus walk, and the minimizer's search and
    //! judgment bound.

    use std::sync::atomic::AtomicUsize;

    use super::*;

    /// A word is plain exactly when every byte of it is of the merge's
    /// byte set: each other ASCII byte, among them every byte a shell
    /// splits, expands, quotes or redirects on, a byte past ASCII and an
    /// empty word are refused.
    #[test]
    fn only_words_a_shell_passes_unchanged_are_plain() {
        const SET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/._=,-";
        assert!(plain("/data/fuzz-1/root_2.a=b,c") && plain("-merge=1"));
        assert!(!plain("") && !plain("/data/fuzz\u{e9}"));
        for refused in [
            "a b", "a;b", "$a", "`a`", "a|b", "a&b", "a>b", "a*", "~", "a:b", "a+b", "'a'", "a\nb",
        ] {
            assert!(!plain(refused), "{refused:?}");
        }
        for byte in 0..128u8 {
            let word = format!("/data/fuzz{}root", byte as char);
            assert_eq!(plain(&word), SET.contains(byte as char), "{byte:#04x}");
        }
    }

    const EXE: Result<&str, &str> = Ok("/bin/sim_worker");
    const CONTROL: &str = "-merge_control_file=/nonexistent/merge.txt";
    const STALE: &str = "-merge_control_file=/";
    const BYTES: &str = "a merge takes only bytes of";

    fn words(list: &[&str]) -> Vec<String> {
        list.iter().map(|word| (*word).to_owned()).collect()
    }

    fn refused(exe: Result<&str, &str>, target: &str, artifacts: &str, list: &[&str]) -> String {
        command(exe, target, artifacts, &words(list)).expect_err("an admitted run")
    }

    #[test]
    fn a_merge_runs_under_the_workers_form_built_of_plain_words() {
        let merge = ["-merge=1", CONTROL, "new", "old"];
        let built = command(EXE, "campaign", "/art", &words(&merge)).expect("a plain merge");
        assert_eq!(
            built[0],
            "/bin/sim_worker --fuzz campaign --artifacts /art --"
        );
        assert_eq!(built[1..], words(&merge));

        let spaced = Ok("/bin dir/sim_worker");
        assert!(refused(spaced, "campaign", "/art", &merge).contains(BYTES));
        assert!(refused(EXE, "cam paign", "/art", &merge).contains(BYTES));
        assert!(refused(EXE, "campaign", "/art dir", &merge).contains(BYTES));
        let argument = ["-merge=0", CONTROL, "new dir"];
        assert!(refused(EXE, "campaign", "/art", &argument).contains(BYTES));

        for cause in ["the lookup failed", "the path is not UTF-8"] {
            let reason = refused(Err(cause), "campaign", "/art", &merge);
            assert_eq!(
                reason,
                format!("a merge takes the worker's executable path: {cause}")
            );
        }
    }

    #[test]
    fn a_merge_takes_a_new_control_file_where_libfuzzer_reads_it() {
        let merge = |list: &[&str]| refused(EXE, "campaign", "/art", list);
        let file = "-merge_control_file=FILE";
        let empty = "-merge_control_file=";
        assert!(merge(&["-merge=1", "new", "old"]).contains(file));
        assert!(merge(&["-merge=1", empty, "new"]).contains(file));
        assert!(merge(&["-merge=1", CONTROL, empty]).contains(file));

        let stale = "a merge takes a new control file";
        assert!(merge(&["-merge=1", STALE, "new", "old"]).contains(stale));
        assert!(merge(&["-merge=1", CONTROL, STALE, "new"]).contains(stale));
        let last = ["-merge=1", STALE, CONTROL, "new", "old"];
        assert!(command(EXE, "campaign", "/art", &words(&last)).is_ok());
        assert!(merge(&["-merge=1", STALE, "new dir"]).contains(BYTES));
        let under = "-merge_control_file=/proc/self/exe/merge.txt";
        let reason = merge(&["-merge=1", under, "new", "old"]);
        assert!(reason.starts_with("/proc/self/exe/merge.txt: ") && !reason.contains(stale));

        for cut in ["-ignore_remaining_args=1", "-ignore_remaining_args=0"] {
            assert!(merge(&["-merge=1", cut, CONTROL, "new", "old"]).starts_with(cut));
        }
        let cut = "-ignore_remaining_args=2";
        assert!(merge(&["-merge=1", CONTROL, "new", "old", cut]).starts_with(cut));
    }

    /// The coordinator requires the last `-merge=` value to be `1`.
    #[test]
    fn only_the_outer_merge_process_coordinates() {
        let coordinates = |list: &[&str]| coordinates(&words(list));
        assert!(coordinates(&["-merge=1", CONTROL, "new", "old"]));
        assert!(coordinates(&["-merge=0", "-merge=1", "-merge_inner=0"]));
        assert!(coordinates(&["-merge=1", "-merge_inner=1"]));
        for list in [
            &["-merge=1", "-merge=0"][..],
            &["-merge=", "new"],
            &["-runs=1", "old"],
            &["-merge_inner=1"],
        ] {
            assert!(!coordinates(list), "{list:?}");
        }
    }

    /// `command` refuses a merge that holds a `-merge=` value other than
    /// `0` or `1`, in any position.
    #[test]
    fn a_merge_takes_the_values_zero_and_one() {
        let value = "a merge takes -merge=0 or -merge=1";
        for merge in ["1x", "2", "-1", "01", "4294967296", ""] {
            let merge = format!("-merge={merge}");
            let reason = refused(EXE, "campaign", "/art", &[&merge, CONTROL, "new", "old"]);
            assert_eq!(reason, format!("{merge}: {value}"));
        }
        let first = ["-merge=1x", "-merge=1", CONTROL, "new", "old"];
        assert!(refused(EXE, "campaign", "/art", &first).ends_with(value));
        let both = ["-merge=0", "-merge=1", CONTROL, "new", "old"];
        assert!(command(EXE, "campaign", "/art", &words(&both)).is_ok());
    }

    /// A merge over a corpus whose names it cannot list is refused before
    /// libFuzzer starts: here a corpus path that names a file. A corpus
    /// path with no entry holds no name.
    #[test]
    fn a_merge_refuses_a_corpus_it_cannot_list() {
        let dir = std::env::temp_dir().join(format!("sim-fuzz-corpus-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("file");
        std::fs::write(&file, b"input").unwrap();
        let path = file.to_str().unwrap();
        let reason = refused(EXE, "campaign", "/art", &["-merge=1", CONTROL, "new", path]);
        assert!(
            reason.starts_with(&format!("{path}: "))
                && reason.ends_with("a merge checks every corpus entry name"),
            "{reason}"
        );
        let missing = dir.join("missing");
        let merge = ["-merge=1", CONTROL, "new", missing.to_str().unwrap()];
        assert!(command(EXE, "campaign", "/art", &words(&merge)).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An I/O error of `kind`.
    fn failed(kind: std::io::ErrorKind) -> std::io::Error {
        std::io::Error::from(kind)
    }

    /// The error the faulted listings of [`tree`] fail with.
    fn denied() -> std::io::Error {
        failed(std::io::ErrorKind::PermissionDenied)
    }

    /// An entry named `name` of kind `kind`.
    fn entry(name: &str, kind: Kind) -> std::io::Result<Listed> {
        Ok(Listed {
            name: name.into(),
            kind: Ok(kind),
        })
    }

    /// An entry named `name` whose type read finds no entry.
    fn removed(name: &str) -> std::io::Result<Listed> {
        Ok(Listed {
            name: name.into(),
            kind: Err(failed(std::io::ErrorKind::NotFound)),
        })
    }

    /// A listing in the form [`listed`] returns, for the fakes.
    type Listing = std::io::Result<Vec<std::io::Result<Listed>>>;

    /// A directory and the listing that replaces its own.
    type Fault = (&'static str, fn() -> Listing);

    /// A listing of the tree `/c`: its entries `a` and `.hidden`, both
    /// directories, and `/c/a`'s entry `b`, a file; `/c/.hidden` holds a
    /// name with a line break, which the walk does not reach. `fault`
    /// replaces the listing of the directory it names.
    fn tree(fault: Option<Fault>) -> impl Fn(&std::path::Path) -> Listing {
        move |dir: &std::path::Path| {
            if let Some((faulted, listing)) = fault
                && dir == std::path::Path::new(faulted)
            {
                return listing();
            }
            match dir.to_str() {
                Some("/c") => Ok(vec![
                    entry("a", Kind::Directory),
                    entry(".hidden", Kind::Directory),
                ]),
                Some("/c/a") => Ok(vec![entry("b", Kind::Other)]),
                Some("/c/.hidden") => Ok(vec![entry("x\ny", Kind::Other)]),
                Some("/c/a/b") => Err(failed(std::io::ErrorKind::NotADirectory)),
                _ => Err(failed(std::io::ErrorKind::NotFound)),
            }
        }
    }

    /// The walk finds no line break in the tree, whose one such name lies
    /// under a directory named with a leading `.`, and finds the name in a
    /// nested directory it does descend into. A corpus directory that does
    /// not exist and an entry whose type read finds no entry hold no name,
    /// and the walk reads on past that entry to a later name.
    #[test]
    fn a_walk_reads_a_missing_directory_and_a_removed_entry_as_holding_no_name() {
        let root = std::path::Path::new("/c");
        assert_eq!(multiline(root, &tree(None)), Ok(None));
        assert_eq!(
            multiline(std::path::Path::new("/missing"), &tree(None)),
            Ok(None)
        );
        let untyped = tree(Some(("/c", || Ok(vec![removed("a")]))));
        assert_eq!(multiline(root, &untyped), Ok(None));
        let later = tree(Some(("/c", || {
            Ok(vec![removed("a"), entry("x\ny", Kind::Other)])
        })));
        assert_eq!(multiline(root, &later), Ok(Some("/c/x\ny".into())));
        let lined = tree(Some(("/c/a", || Ok(vec![entry("x\ny", Kind::Other)]))));
        assert_eq!(multiline(root, &lined), Ok(Some("/c/a/x\ny".into())));
    }

    /// A nested directory the walk cannot list refuses the walk with its
    /// path and error, so no name under it passes the line-break check
    /// unread.
    #[test]
    fn a_walk_refuses_a_nested_directory_it_cannot_list() {
        let unlistable = tree(Some(("/c/a", || Err(denied()))));
        assert_eq!(
            multiline(std::path::Path::new("/c"), &unlistable),
            Err(format!("/c/a: {}", denied()))
        );
    }

    /// An entry the walk cannot read refuses the walk with its directory's
    /// path and the error.
    #[test]
    fn a_walk_refuses_an_entry_it_cannot_read() {
        let unread = tree(Some(("/c/a", || Ok(vec![Err(denied())]))));
        assert_eq!(
            multiline(std::path::Path::new("/c"), &unread),
            Err(format!("/c/a: {}", denied()))
        );
    }

    /// An entry whose type the walk cannot read refuses the walk with the
    /// entry's path and the error: the entry may be a directory whose
    /// names the walk would otherwise skip.
    #[test]
    fn a_walk_refuses_an_entry_whose_type_it_cannot_read() {
        let untyped = tree(Some(("/c", || {
            Ok(vec![Ok(Listed {
                name: "a".into(),
                kind: Err(denied()),
            })])
        })));
        assert_eq!(
            multiline(std::path::Path::new("/c"), &untyped),
            Err(format!("/c/a: {}", denied()))
        );
    }

    #[test]
    fn a_run_that_is_no_merge_takes_any_word_but_a_restart_flag() {
        let spaced = ["-runs=1", "-ignore_remaining_args=1", "a b"];
        let unknown = Err("the lookup failed");
        let built = command(unknown, "campaign", "/art dir", &words(&spaced)).expect("a run");
        assert_eq!(
            built[0],
            "sim_worker --fuzz campaign --artifacts /art dir --"
        );
        assert_eq!(built[1..], words(&spaced));
        for flag in [
            "-fork",
            "-jobs",
            "-workers",
            "-set_cover_merge",
            "-minimize_crash",
            "-cleanse_crash",
        ] {
            let restart = format!("{flag}=2");
            let reason = refused(EXE, "campaign", "/art", &["-runs=1", &restart, "old"]);
            assert_eq!(reason, format!("{restart}: the driver runs in process"));
        }
    }

    /// Judgments the whole-input target made.
    static JUDGED: AtomicUsize = AtomicUsize::new(0);

    static WHOLE: Target = Target {
        name: "whole",
        run: |input| {
            JUDGED.fetch_add(1, Ordering::Relaxed);
            if input.len() == MAX_INPUT {
                Class::Failure {
                    claim: "the input is whole".into(),
                    bundle: Vec::new(),
                }
            } else {
                Class::Pass { run: Vec::new() }
            }
        },
        seeds: Vec::new,
    };

    /// A minimization no removal advances stops after its bounded
    /// judgments with the input and claim unchanged.
    #[test]
    fn a_minimization_stops_at_its_judgment_bound() {
        let input = vec![7; MAX_INPUT];
        let (smallest, claim) = minimized(&WHOLE, &input).unwrap();
        assert_eq!((smallest, claim.as_str()), (input, "the input is whole"));
        assert_eq!(JUDGED.load(Ordering::Relaxed), 1 + MAX_TRIES);
    }

    /// A claim whose removals interact: `a` becomes removable only after
    /// `c` is removed.
    static UNCOVERED: Target = Target {
        name: "uncovered",
        run: |input| match input {
            b"abcd" | b"abd" | b"bd" => Class::Failure {
                claim: "the same claim".into(),
                bundle: Vec::new(),
            },
            _ => Class::Pass { run: Vec::new() },
        },
        seeds: Vec::new,
    };

    /// Panics at one site for inputs longer than four bytes and at another
    /// for shorter ones.
    static TWO_PANICS: Target = Target {
        name: "two-panics",
        run: |input| {
            if input.len() > 4 {
                panic!("a long input");
            }
            panic!("a short input")
        },
        seeds: Vec::new,
    };

    /// Two panics at different sites are different failures: the
    /// minimizer keeps the long input's panic, so it stops at the shortest
    /// input that still panics there, and the short input's panic is a
    /// candidate it refuses.
    #[test]
    fn a_minimization_keeps_its_panic_identity() {
        let input = [9; 12];
        let (smallest, claim) = minimized(&TWO_PANICS, &input).unwrap();
        assert_eq!(smallest.len(), 5, "{claim}");
        assert!(claim.starts_with("the run panicked at "), "{claim}");
        assert!(claim.ends_with(": a long input"), "{claim}");
        assert!(claim.contains(file!()), "{claim}");
        let Class::Failure { claim: short, .. } = judged(&TWO_PANICS, &[9; 4]) else {
            panic!("a short input fails");
        };
        assert!(
            short.ends_with(": a short input") && short != claim,
            "{short}"
        );
    }

    /// Removing `c` makes `a` removable while preserving the claim.
    #[test]
    fn a_minimization_ends_with_no_byte_removable() {
        let (smallest, claim) = minimized(&UNCOVERED, b"abcd").unwrap();
        assert_eq!(
            (smallest.as_slice(), claim.as_str()),
            (&b"bd"[..], "the same claim")
        );
    }
}
