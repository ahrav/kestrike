//! The cases of the signal record that no run of the fixture can place: the stop a recorded signal
//! reads, a signal while a child is being started, and a signal once the score is written. A case that
//! installs the handlers starts this test executable again for its own test with a role in [`WINDOW`],
//! so the handlers stand in a process of the case's own.

use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::Command;

use kestrike_tools::plants::{
    Halt, Logged, Outcome, Run, Stopped, conclude, logged, prepare, publish, score,
};
use kestrike_tools::process::{INTERRUPT, Interrupt, install_handlers};

use super::fixture::Fixture;
use super::repository::Repository;

const WINDOW: &str = "PLANT_RUNNER_WINDOW";
const ARGS: &str = "PLANT_RUNNER_ARGS";

fn raise(signal: i32) {
    // SAFETY: `raise` takes an integer; the handlers record the signal and return.
    assert_eq!(unsafe { libc::raise(signal) }, 0);
}

/// `start_window` starts this test executable again for the test `name` with its role set, in `cwd`
/// with `env`, and fails the case unless that run passes; it returns the run's standard output.
fn start_window(name: &str, cwd: &Path, env: &[(OsString, OsString)]) -> String {
    let output = Command::new(std::env::current_exe().expect("the test executable is known"))
        .args(["--exact", name, "--nocapture", "--test-threads", "1"])
        .current_dir(cwd)
        .env_clear()
        .envs(env.iter().cloned())
        .env(WINDOW, "1")
        .output()
        .expect("the test executable starts");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let shown = format!(
        "{}\n{stdout}{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{shown}");
    assert!(stdout.contains("1 passed"), "{shown}");
    stdout
}

/// The defaults: 28 workers, a floor of 300 runs, 60 s a sweep and 10 sweeps a plant.
#[test]
fn a_run_without_options_takes_the_working_values() {
    let repository = Repository::new();
    let Outcome::Run(inputs) = repository.prepare(&repository.call(&[])) else {
        panic!("a run without options is accepted");
    };
    let options = inputs.options();
    let values = [
        options.workers(),
        options.runs(),
        options.seconds(),
        options.rounds(),
    ]
    .map(ToString::to_string);
    assert_eq!(values, ["28", "300", "60", "10"]);
    assert_eq!(kestrike_tools::plants::FLOOR, 300);
}

/// A recorded SIGHUP reads as the stop 129, and the record keeps the signal.
#[test]
fn the_handler_exits_128_plus_the_signal_outside_a_deferred_region() {
    let interrupt = Interrupt::new();
    interrupt.record(libc::SIGHUP);
    let stop = interrupt
        .check()
        .expect_err("a recorded signal stops the run");
    assert_eq!(Halt::from(stop).code(), 129);
    assert_eq!(interrupt.recorded(), Some(libc::SIGHUP));
}

/// `spawn_window` installs the handlers and starts a child that sends this process SIGTERM as it
/// starts: the start returns the interruption once the child, sent SIGTERM in turn, has ended.
fn spawn_window() {
    let place = std::env::current_dir().expect("the case's directory is known");
    install_handlers().expect("the handlers install");
    let script = "trap 'sleep 0.5; echo 15 > terminated; exit 4' TERM; kill -TERM $PPID; \
                  i=0; while [ $i -lt 600 ]; do sleep 0.05; i=$((i + 1)); done";
    let argv = ["sh", "-c", script].map(OsString::from);
    let env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    let log = place.join("sweep");
    let started = Logged {
        log: &log,
        argv: &argv,
        what: "campaign sweep",
        cwd: None,
        env: &env,
        session: false,
        work: &place,
    };
    match logged(&started, &INTERRUPT) {
        Err(Stopped::Halt(halt)) => assert_eq!(halt, Halt::Interrupted(libc::SIGTERM)),
        other => panic!("the start ends the run, not {other:?}"),
    }
    let terminated = std::fs::read_to_string(place.join("terminated")).expect("the child ended");
    assert_eq!(terminated.trim(), "15");
}

/// A signal that the child sends as it starts, before or during the run's first wait for it, stops the
/// child with SIGTERM, waits for it, and ends the run.
#[test]
fn a_signal_in_the_spawn_window_terminates_and_reaps_the_child() {
    if std::env::var_os(WINDOW).is_some() {
        spawn_window();
        return;
    }
    let fx = Fixture::new();
    start_window(
        "plant_runner::signals::a_signal_in_the_spawn_window_terminates_and_reaps_the_child",
        &fx.scratch,
        &fx.env,
    );
}

/// `score_window` runs the store of the arguments in [`ARGS`] and takes the run's last two steps with a
/// writer that writes the score and then records SIGTERM: the exit stays the run's own.
fn score_window() {
    let args: Vec<OsString> = std::env::var(ARGS)
        .expect("the arguments are given")
        .split('\n')
        .map(OsString::from)
        .collect();
    let env: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(name, _)| name != OsStr::new(WINDOW) && name != OsStr::new(ARGS))
        .collect();
    let Outcome::Run(inputs) = prepare(&args, env, std::env::current_dir()) else {
        panic!("the arguments pass the checks");
    };
    let mut run = Run::new(&inputs, &INTERRUPT).expect("the run starts");
    install_handlers().expect("the handlers install");
    let entries = run
        .run_store(&mut std::io::stderr())
        .expect("the store runs");
    assert!(run.remove_trees().expect("the worktrees go").is_empty());
    let written = score::bytes(&score::score(inputs.head(), &entries, run.settings()));
    let write = |target: &Path, bytes: &str| {
        publish(target, bytes)?;
        raise(libc::SIGTERM);
        Ok::<(), kestrike_tools::ownership::PathError>(())
    };
    let code = conclude(
        inputs.head(),
        &inputs.score(),
        &entries,
        &written,
        write,
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    );
    assert_eq!(INTERRUPT.recorded(), Some(libc::SIGTERM));
    assert_eq!(code, 0);
}

/// A signal that lands once the score is written ends nothing: the run prints its score's lines and
/// keeps its own exit.
#[test]
fn a_signal_that_lands_once_the_score_is_written_leaves_the_run_its_own_exit() {
    if std::env::var_os(WINDOW).is_some() {
        score_window();
        return;
    }
    let mut fx = Fixture::new();
    let args = fx.args(&["p-miss"], &[], None);
    let joined: Vec<String> = args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let mut env = fx.environment(&[]);
    env.push((ARGS.into(), joined.join("\n").into()));
    let repo = fx.repo.clone();
    let stdout = start_window(
        "plant_runner::signals::a_signal_that_lands_once_the_score_is_written_leaves_the_run_its_own_exit",
        &repo,
        &env,
    );
    fx.no_stand_in_failed();
    let (written, _) = fx.results();
    let sentence = super::fixture::text_of(written.get("sentence").expect("a sentence"));
    assert!(stdout.contains(&sentence), "{stdout}");
    fx.verdict("p-miss", "missed", "each expected profile reached 300 runs");
}
