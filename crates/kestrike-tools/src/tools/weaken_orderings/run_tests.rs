use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::super::execute::{Launch, execute, seconds};
use super::super::halt::Halt;
use super::super::runner::Runner;
use super::{Report, Scoped, plant_of, publish_report, rows, selection, settled};
use crate::json::{self, Text, Value};
use crate::paths::tests::Scratch;
use crate::process::Interrupt;

const RUN_FENCE: &str = "fill-run-fence";
const FIRST: &str = "storage::fill_model::two_owners_on_one_key_and_a_servicer_observing_the_run";
const SECOND: &str = "storage::fill_model::three_participants_over_two_keys_observing_the_run";

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
    assert_eq!(
        deadline,
        Duration::from_secs(3600),
        "a loom test runs under the loom deadline"
    );
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

/// `seed` gives `fill-run-fence` of the catalog in `copy` one disposition, an `unrun` entry that names
/// [`FIRST`] and then [`SECOND`], whatever the committed row holds, through a new file renamed over the
/// catalog.
fn seed(copy: &Path) {
    let path = copy.join(crate::orderings::check::CATALOG);
    let mut catalog = json::parse(&fs::read_to_string(&path).expect("reads")).expect("parses");
    let Value::Object(object) = &mut catalog else {
        panic!("the catalog is an object");
    };
    let Some(Value::Array(rows)) = object.get_mut("rows") else {
        panic!("the catalog lists rows");
    };
    let row = rows
        .iter_mut()
        .find_map(|row| match row {
            Value::Object(row) if row.get("id") == Some(&Value::String(Text::from(RUN_FENCE))) => {
                Some(row)
            }
            _ => None,
        })
        .expect("the row stands");
    for kind in ["kill", "survives", "unrun", "revision"] {
        row.remove(kind);
    }
    row.insert(
        "unrun",
        json::parse(&format!(
            r#"{{"needs": [{{"lane": "loom", "tests": ["{FIRST}", "{SECOND}"], "failure": "a departed record whose owner had not ended"}}]}}"#
        ))
        .expect("parses"),
    );
    let staged = copy.join(".catalog.seeded");
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .and_then(|mut file| {
            std::io::Write::write_all(&mut file, json::indented_in_order(&catalog).as_bytes())
        })
        .expect("the seeded catalog writes");
    fs::rename(&staged, &path).expect("the seeded catalog takes the catalog's place");
}

/// `planted_run` runs the plant of `fill-run-fence`, seeded as [`seed`] says, in a copy of this checkout's
/// `HEAD` under `work`,
/// each loom test run by `fake`, and returns the end of the rows' run and the scoped file's bytes.
fn planted_run(
    work: &Path,
    interrupt: &Interrupt,
    fake: super::super::runner::Execute,
) -> (Result<Vec<Text>, Halt>, PathBuf, Vec<u8>, usize) {
    fs::create_dir(work.join("copy")).expect("made");
    fs::create_dir(work.join("evidence")).expect("made");
    let starts = std::cell::Cell::new(0);
    let counted = |_: &std::process::Child| starts.set(starts.get() + 1);
    let launch = Launch {
        started: &counted,
        ..Launch::new(interrupt)
    };
    let mut runner = Runner::new(&top(), work, Vec::new(), &launch).expect("the copy is made");
    runner.execute = fake;
    seed(&runner.copy);
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
    (ran, planted, unweakened, starts.get())
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
    let (ran, planted, unweakened, starts) = planted_run(&scratch.0, &BETWEEN, between);
    assert_eq!(starts, 1, "one test of the row started");
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
    let (ran, planted, unweakened, starts) = planted_run(&work, &RESTORE, restore);
    assert_eq!(starts, 2);
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

/// A plant replaces the one production occurrence of its find, whatever a test-only element before it
/// holds: the blanked element's multibyte code points keep the offsets of the raw text, and the copy of
/// the find inside the element stays; a find with no or two production occurrences is refused with its
/// count.
#[test]
fn a_plant_maps_its_find_back_to_the_raw_text() {
    let text = "#[cfg(test)]\nmod tests {\n    // é ü\n    fn t() { x.load(Acquire); }\n}\nfn a() { x.load(Acquire); }\n";
    let planted = plant_of(text, "x.load(Acquire)", "x.load(Relaxed)").expect("one occurrence");
    assert_eq!(
        planted,
        "#[cfg(test)]\nmod tests {\n    // é ü\n    fn t() { x.load(Acquire); }\n}\nfn a() { x.load(Relaxed); }\n"
    );
    assert_eq!(plant_of(text, "x.store(", "y"), Err(0));
    let twice = format!("{text}fn b() {{ x.load(Acquire); }}\n");
    assert_eq!(plant_of(&twice, "x.load(Acquire)", "y"), Err(2));
}

/// A run's seconds are its elapsed time rounded to a tenth as Python's `round` rounds a float: to the
/// nearest tenth, with a tie that the float cannot hold exactly going the way its stored value lies.
#[test]
fn seconds_round_to_a_tenth_as_python_rounds() {
    assert_eq!(seconds(Duration::from_millis(1240)), 1.2);
    assert_eq!(seconds(Duration::from_millis(1260)), 1.3);
    assert_eq!(seconds(Duration::from_millis(250)), 0.2);
    assert_eq!(seconds(Duration::from_millis(350)), 0.3);
}

/// `scoped_copy` is a copy under `scratch` that holds `f.rs` with `text`, the one scoped file, and a row
/// whose plant replaces `find` with `replace` there.
fn scoped_copy(scratch: &Scratch, text: &str, find: &str, replace: &str) -> (Scoped, json::Object) {
    let copy = scratch.0.join("copy");
    fs::create_dir(&copy).expect("made");
    fs::write(copy.join("f.rs"), text).expect("written");
    let name = Text::from("f.rs");
    let scoped = Scoped {
        copy,
        files: vec![name.clone()],
        originals: [(name.clone(), text.to_owned())].into(),
        digests: [(name, crate::python::hexdigest(text.as_bytes()))].into(),
    };
    let row = json::parse(&format!(
        r#"{{"id": "r", "path": "f.rs", "find": "{find}", "replace": "{replace}"}}"#
    ))
    .expect("parses");
    let Value::Object(row) = row else {
        panic!("an object");
    };
    (scoped, row)
}

const SCOPED: &str = "fn a() { x.load(Acquire); }\n";

/// A body that panics under the plant leaves the scoped file with its unweakened bytes and no staging
/// file, and the body's own panic reaches the caller.
#[test]
fn a_panic_under_the_plant_restores_the_file_and_resumes() {
    let scratch = Scratch::new("weaken-panic");
    let (scoped, row) = scoped_copy(&scratch, SCOPED, "x.load(Acquire)", "x.load(Relaxed)");
    let path = scratch.0.join("copy/f.rs");
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        scoped.planted(&row, || {
            assert_eq!(
                fs::read_to_string(&path).expect("reads"),
                "fn a() { x.load(Relaxed); }\n"
            );
            panic!("the body's own panic")
        })
    }));
    let payload = caught.expect_err("the panic resumes");
    assert_eq!(
        payload.downcast_ref::<&str>(),
        Some(&"the body's own panic")
    );
    assert_eq!(fs::read_to_string(&path).expect("reads"), SCOPED);
    assert_eq!(staged(&scratch.0.join("copy")), Vec::<PathBuf>::new());
}

const FSIZE_ROLE: &str = "KESTRIKE_WEAKEN_PLANT_FSIZE_ROLE";

/// A plant whose staged write fails, here past the soft file size limit with SIGXFSZ ignored, reads as a
/// plant that changed: exit 4 with that sentence, the body never runs, and the file holds its unweakened
/// bytes, which fit the limit. The case runs in this test executable started again in that role, so the
/// limit binds no other case.
#[test]
fn a_plant_that_cannot_be_written_reads_as_a_changed_plant() {
    if let Some(at) = std::env::var_os(FSIZE_ROLE) {
        let scratch = Scratch(PathBuf::from(at));
        let (scoped, row) = scoped_copy(
            &scratch,
            SCOPED,
            "x.load(Acquire)",
            "x.load(AcquireAndMore)",
        );
        let limit = libc::rlim_t::try_from(SCOPED.len()).expect("a length fits");
        // SAFETY: `signal` takes a signal number and a disposition constant and touches no memory of
        // the caller; `setrlimit` reads the limit record, which outlives the call.
        let set = unsafe {
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            let mut limits: libc::rlimit = std::mem::zeroed();
            libc::getrlimit(libc::RLIMIT_FSIZE, &mut limits);
            limits.rlim_cur = limit.min(limits.rlim_max);
            libc::setrlimit(libc::RLIMIT_FSIZE, &limits)
        };
        assert_eq!(set, 0, "the limit is set");
        let ran = std::cell::Cell::new(false);
        let ended = scoped.planted(&row, || {
            ran.set(true);
            Ok(())
        });
        std::mem::forget(scratch);
        let held = fs::read_to_string(scoped.copy.join("f.rs")).expect("reads");
        let ok = matches!(&ended, Err(Halt::Stop { code: 4, reason })
            if *reason == "the plant of f.rs changed while r's tests ran")
            && !ran.get()
            && held == SCOPED;
        eprintln!("{ended:?}, ran {}, held {held:?}", ran.get());
        std::process::exit(if ok { 0 } else { 3 });
    }
    let scratch = Scratch::new("weaken-fsize");
    let name = module_path!()
        .split_once("::")
        .map_or("", |(_, rest)| rest)
        .to_owned()
        + "::a_plant_that_cannot_be_written_reads_as_a_changed_plant";
    let status = std::process::Command::new(std::env::current_exe().expect("the test executable"))
        .args([name.as_str(), "--exact", "--nocapture", "--test-threads=1"])
        .env(FSIZE_ROLE, &scratch.0)
        .status()
        .expect("the role runs");
    assert_eq!(status.code(), Some(0));
}

/// A signal recorded before the report's last check leaves no `report.json` and no staging file and
/// ends as that signal's interruption; with none recorded the report is written whole.
#[test]
fn a_signal_recorded_before_the_report_s_rename_leaves_no_report() {
    let scratch = Scratch::new("weaken-report-gate");
    let path = scratch.0.join("report.json");
    let report = json::parse(r#"{"mismatched": [], "no verdict": []}"#).expect("parses");
    let interrupt = Interrupt::new();
    interrupt.record(libc::SIGHUP);
    let ended = publish_report(&path, &report, &interrupt);
    assert!(
        matches!(ended, Err(Halt::Interrupted(libc::SIGHUP))),
        "{ended:?}"
    );
    assert!(!path.exists());
    assert_eq!(staged(&scratch.0), Vec::<PathBuf>::new());
    let quiet = Interrupt::new();
    publish_report(&path, &report, &quiet).expect("the report is written");
    assert_eq!(
        fs::read_to_string(&path).expect("reads"),
        format!("{}\n", json::indented_in_order(&report))
    );
    assert_eq!(staged(&scratch.0), Vec::<PathBuf>::new());
}

/// A signal recorded once the handlers stand turns a refusal or a failed step into that signal's
/// interruption, an interruption keeps its own signal, and with no signal a halt stays as it is.
#[test]
fn a_recorded_signal_settles_any_halt_as_its_interruption() {
    let interrupt = Interrupt::new();
    interrupt.record(libc::SIGHUP);
    interrupt.record(libc::SIGTERM);
    assert!(matches!(
        settled(Halt::stop(2, "refused"), &interrupt),
        Halt::Interrupted(libc::SIGHUP)
    ));
    assert!(matches!(
        settled(Halt::failed("failed"), &interrupt),
        Halt::Interrupted(libc::SIGHUP)
    ));
    assert!(matches!(
        settled(Halt::Interrupted(libc::SIGINT), &interrupt),
        Halt::Interrupted(libc::SIGINT)
    ));
    let quiet = Interrupt::new();
    assert!(matches!(
        settled(Halt::stop(3, "red"), &quiet),
        Halt::Stop { code: 3, .. }
    ));
}
