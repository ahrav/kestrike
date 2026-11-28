use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::super::execute::{Launch, execute};
use super::super::halt::Halt;
use super::super::runner::Runner;
use super::{Report, rows, selection};
use crate::json::{self, Text, Value};
use crate::paths::tests::Scratch;
use crate::process::Interrupt;

const RUN_FENCE: &str = "fill-run-fence";
const FIRST: &str = "storage::fill_model::two_owners_on_one_key_and_a_servicer_observing_the_run";

fn top() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the checkout resolves")
}

fn words(argv: &[&str]) -> Vec<OsString> {
    argv.iter().map(OsString::from).collect()
}

fn test_of(argv: &[OsString]) -> String {
    argv[7].to_string_lossy().into_owned()
}

fn passing(log: &Path, test: &str) -> String {
    format!(
        "echo '{test}' >> '{}'; echo '   Compiling kestrike v0.1.0 (copy)'; echo 'running 1 test'; \
         echo 'test {test} ... ok'; echo; \
         echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out'",
        log.display()
    )
}

static BETWEEN: Interrupt = Interrupt::new();
static BETWEEN_LOG: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Each loom test logs its name and passes; the first one's end records SIGTERM.
fn between(
    launch: &Launch<'_>,
    argv: &[OsString],
    cwd: &Path,
    _: Option<&[(OsString, OsString)]>,
    deadline: Duration,
    output: &Path,
) -> Result<(Option<i32>, f64), Halt> {
    let log = BETWEEN_LOG
        .lock()
        .expect("unpoisoned")
        .clone()
        .expect("a log");
    let script = passing(&log, &test_of(argv));
    let ran = execute(
        launch,
        &words(&["sh", "-c", &script]),
        cwd,
        None,
        deadline,
        output,
    )?;
    launch.interrupt.record(libc::SIGTERM);
    Ok(ran)
}

static RESTORE: Interrupt = Interrupt::new();
static RESTORE_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);

/// The first loom test passes. The second waits until SIGTERM is recorded while it runs, and its stop
/// ends by SIGHUP recorded as the run turns to the restore.
fn restore(
    launch: &Launch<'_>,
    argv: &[OsString],
    cwd: &Path,
    _: Option<&[(OsString, OsString)]>,
    deadline: Duration,
    output: &Path,
) -> Result<(Option<i32>, f64), Halt> {
    let at = RESTORE_DIR
        .lock()
        .expect("unpoisoned")
        .clone()
        .expect("a directory");
    let (log, test) = (at.join("log"), test_of(argv));
    if test == FIRST {
        let script = passing(&log, &test);
        return execute(
            launch,
            &words(&["sh", "-c", &script]),
            cwd,
            None,
            deadline,
            output,
        );
    }
    let sleeping = at.join("sleeping");
    let waiter = std::thread::spawn(move || {
        let start = Instant::now();
        while !sleeping.exists() && start.elapsed() < Duration::from_secs(30) {
            std::thread::sleep(Duration::from_millis(10));
        }
        RESTORE.record(libc::SIGTERM);
    });
    let script = format!(
        "echo '{test}' >> '{}'; trap 'touch {}; exit 143' TERM; touch {}; sleep 60 & wait",
        log.display(),
        at.join("stopped").display(),
        at.join("sleeping").display()
    );
    let ran = execute(
        launch,
        &words(&["sh", "-c", &script]),
        cwd,
        None,
        deadline,
        output,
    );
    waiter.join().expect("the waiter ends");
    RESTORE.record(libc::SIGHUP);
    ran
}

/// `planted_run` runs the plant of `fill-run-fence` in a copy of this checkout's `HEAD` under `work`,
/// each loom test run by `fake`, and returns the end of the rows' run and the scoped file's bytes.
fn planted_run(
    work: &Path,
    interrupt: &Interrupt,
    fake: super::super::runner::Execute,
) -> (Result<Vec<Text>, Halt>, PathBuf, Vec<u8>) {
    fs::create_dir(work.join("copy")).expect("made");
    fs::create_dir(work.join("evidence")).expect("made");
    let launch = Launch::new(interrupt);
    let mut runner = Runner::new(&top(), work, Vec::new(), &launch).expect("the copy is made");
    runner.execute = fake;
    runner.prepare().expect("the declaration reads");
    let (selection, scoped) =
        selection(&runner, &[Text::from(RUN_FENCE)]).expect("the row is selected");
    let Some(Value::String(path)) = selection.rows[0].get("path") else {
        panic!("the row names its file");
    };
    let planted = work.join("copy").join(path.to_string());
    let unweakened = fs::read(&planted).expect("reads");
    let mut report = Report {
        revision: Text::from(runner.revision.as_str()),
        pins: json::Object::new(),
        baseline: Vec::new(),
        rows: Vec::new(),
        seconds: None,
        mismatched: None,
        no_verdict: None,
    };
    let ran = rows(
        &mut runner,
        &selection,
        &scoped,
        &mut report,
        work,
        Instant::now(),
    );
    (ran, planted, unweakened)
}

fn staged(directory: &Path) -> Vec<PathBuf> {
    fs::read_dir(directory)
        .expect("lists")
        .map(|entry| entry.expect("lists").path())
        .filter(|path| path.to_string_lossy().ends_with(".weaken"))
        .collect()
}

fn logged(log: &Path) -> Vec<String> {
    fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// A signal recorded after a row's first test ends and before its second starts ends the row: the second
/// test never starts, the first result stands in the progress, and the plant is written back.
#[test]
fn a_signal_between_a_rows_tests_starts_no_further_test_and_restores_the_plant() {
    let scratch = Scratch::new("weaken-between");
    let log = scratch.0.join("log");
    *BETWEEN_LOG.lock().expect("unpoisoned") = Some(log.clone());
    let (ran, planted, unweakened) = planted_run(&scratch.0, &BETWEEN, between);
    assert!(
        matches!(ran, Err(Halt::Interrupted(libc::SIGTERM))),
        "{ran:?}"
    );
    assert_eq!(logged(&log), [FIRST]);
    let progress =
        json::parse(&fs::read_to_string(scratch.0.join("progress.json")).expect("reads"))
            .expect("parses");
    let Value::Object(progress) = progress else {
        panic!("the progress is an object");
    };
    assert_eq!(
        progress.get("active"),
        Some(&Value::String(Text::from(RUN_FENCE)))
    );
    let Some(Value::Object(rows)) = progress.get("rows") else {
        panic!("the progress holds rows");
    };
    let Some(Value::Object(record)) = rows.get(RUN_FENCE) else {
        panic!("the row's record stands");
    };
    let Some(Value::Array(results)) = record.get("results") else {
        panic!("the record holds results");
    };
    assert_eq!(results.len(), 1);
    assert_eq!(fs::read(&planted).expect("reads"), unweakened);
    assert_eq!(
        staged(planted.parent().expect("a parent")),
        Vec::<PathBuf>::new()
    );
}

/// A second signal recorded as the run turns from a stopped test to the restore leaves the restore whole:
/// the test's group got SIGTERM, and the scoped file holds its unweakened bytes with no staging file left.
#[test]
fn a_second_signal_as_the_restore_begins_still_restores_the_plant() {
    let scratch = Scratch::new("weaken-restore");
    *RESTORE_DIR.lock().expect("unpoisoned") = Some(scratch.0.clone());
    let work = scratch.0.join("work");
    fs::create_dir(&work).expect("made");
    let (ran, planted, unweakened) = planted_run(&work, &RESTORE, restore);
    assert!(
        matches!(ran, Err(Halt::Interrupted(libc::SIGTERM))),
        "{ran:?}"
    );
    assert_eq!(RESTORE.deliveries(), 2);
    assert!(
        scratch.0.join("stopped").exists(),
        "the sleeping test got SIGTERM"
    );
    assert_eq!(logged(&scratch.0.join("log")).len(), 2);
    assert_eq!(fs::read(&planted).expect("reads"), unweakened);
    assert_eq!(
        staged(planted.parent().expect("a parent")),
        Vec::<PathBuf>::new()
    );
}
