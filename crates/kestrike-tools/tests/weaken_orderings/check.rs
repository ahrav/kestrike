use std::fs;
use std::path::Path;
use std::process::Command;

use kestrike_tools::genmc::{package_sources, read_source};
use kestrike_tools::json::{self, Value};
use kestrike_tools::orderings::check::check;
use kestrike_tools::orderings::sites::EXTERNAL;

use super::{Scratch, tool, top};

fn status(top: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(["--no-optional-locks", "-C"])
        .arg(top)
        .args(["status", "--porcelain", "--untracked-files=all"])
        .args(args)
        .output()
        .expect("git starts");
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).expect("UTF-8")
}

fn snapshot(top: &Path) -> (String, String) {
    (
        status(top, &[]),
        status(
            top,
            &["--ignored", "--", "scripts", "verification", "evidence"],
        ),
    )
}

/// `check` on the checkout exits 0 and prints the report the library's check gives, and leaves the
/// working directory it starts in empty and the checkout's status, ignored files included, as it was.
#[test]
fn the_command_prints_the_report_and_writes_nothing() {
    let top = top();
    let before = snapshot(&top);
    let scratch = Scratch::new("check");
    let run = tool(&top, &["check"], &scratch.0);
    assert_eq!(
        run.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let read = |path: &str| read_source(&top, path);
    let (expected, code) = check(&read, &top, &top, EXTERNAL, &package_sources);
    assert_eq!(code, 0);
    let printed = String::from_utf8(run.stdout).expect("UTF-8");
    assert_eq!(json::parse(&printed).expect("one JSON report"), expected);
    assert_eq!(printed, format!("{}\n", json::indented_in_order(&expected)));
    assert_eq!(fs::read_dir(&scratch.0).expect("lists").count(), 0);
    assert_eq!(snapshot(&top), before);
}

/// A tree that holds none of the check's inputs exits 2 with the report of one member, `error`, naming
/// the unreadable catalog; a word that names no command exits 2 with the usage on standard error and
/// nothing on standard output; and `--help` prints the help, which lists the refusals, and exits 0.
#[test]
fn a_helper_that_cannot_load_or_a_usage_error_exits_2() {
    let scratch = Scratch::new("unreadable");
    let run = tool(&scratch.0, &["check"], &scratch.0);
    assert_eq!(
        run.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let report =
        json::parse(&String::from_utf8(run.stdout).expect("UTF-8")).expect("one JSON report");
    let Value::Object(report) = report else {
        panic!("the report is an object");
    };
    assert_eq!(report.len(), 1);
    let Some(Value::String(error)) = report.get("error") else {
        panic!("the report names its error");
    };
    assert!(
        error.to_string().starts_with(
            "unreadable catalog or declaration: verification/orderings/expected.json: "
        ),
        "{error}"
    );
    let top = top();
    let run = tool(&top, &["bogus"], &scratch.0);
    assert_eq!(
        (run.status.code(), run.stdout.as_slice()),
        (Some(2), &b""[..])
    );
    let stderr = String::from_utf8(run.stderr).expect("UTF-8");
    assert!(stderr.contains("usage:"), "{stderr}");
    assert!(
        stderr.contains(
            "error: argument command: invalid choice: 'bogus' (choose from 'check', 'run')"
        ),
        "{stderr}"
    );
    let run = tool(&top, &["--help"], &scratch.0);
    assert_eq!(
        run.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        String::from_utf8(run.stdout)
            .expect("UTF-8")
            .contains("`check` refuses, each by name:")
    );
}

/// `copy_tracked` copies each file Git tracks under `directory` of the checkout `top` into `to`, each a
/// regular file at its own path.
fn copy_tracked(top: &Path, directory: &str, to: &Path) {
    let listed = Command::new("git")
        .arg("-C")
        .arg(top)
        .args(["ls-files", "-z", "--", directory])
        .output()
        .expect("git starts");
    assert!(listed.status.success(), "{listed:?}");
    for name in String::from_utf8(listed.stdout).expect("UTF-8").split('\0') {
        if name.is_empty() {
            continue;
        }
        let source = top.join(name);
        let status = fs::symlink_metadata(&source).expect("stats");
        if !status.is_file() {
            continue;
        }
        let copy = to.join(name);
        fs::create_dir_all(copy.parent().expect("a parent")).expect("made");
        fs::copy(&source, &copy).expect("copied");
    }
}

/// A tree that holds the declarations but no crate source exits 1 with a report that
/// credits nothing and refuses each listed file as one the kernel package does not include.
#[test]
fn the_command_exits_1_and_prints_the_refusing_report() {
    let top = top();
    let scratch = Scratch::new("refusing");
    copy_tracked(&top, "verification", &scratch.0);
    let run = tool(&scratch.0, &["check"], &scratch.0);
    assert_eq!(
        run.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let report =
        json::parse(&String::from_utf8(run.stdout).expect("UTF-8")).expect("one JSON report");
    let Value::Object(report) = report else {
        panic!("the report is an object");
    };
    assert_eq!(report.get("credited"), Some(&Value::Bool(false)));
    let expected = json::parse(
        r#"{"refusal": "scope file", "message": "crates/kestrike/src/storage/fill.rs is listed and the kernel package includes no production file there"}"#,
    )
    .expect("parses");
    let Some(Value::Array(refusals)) = report.get("refusals") else {
        panic!("the report lists its refusals");
    };
    assert!(refusals.contains(&expected), "{refusals:?}");
}

/// A report written past the soft file size limit fails with `EFBIG` and exits 120: the tool ignores
/// SIGXFSZ, so the limit ends no process. The tool starts with SIGXFSZ at its default action and unblocked,
/// and the limit lowers the soft bound alone.
#[test]
fn a_report_past_the_file_size_limit_exits_120() {
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    let top = top();
    let scratch = Scratch::new("check-fsize");
    let sink = fs::File::create(scratch.0.join("out")).expect("made");
    let mut command = Command::new(super::BINARY);
    command
        .arg(&top)
        .args(["weaken-orderings", "check"])
        .current_dir(&scratch.0)
        .stdout(sink);
    // SAFETY: the hook runs in the forked child before `exec` and calls only `signal`, `sigemptyset`,
    // `sigaddset`, `sigprocmask`, `getrlimit` and `setrlimit`, which are async-signal-safe, on local
    // values that outlive the calls.
    unsafe {
        command.pre_exec(|| {
            libc::signal(libc::SIGXFSZ, libc::SIG_DFL);
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGXFSZ);
            libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            let mut limit: libc::rlimit = std::mem::zeroed();
            if libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            limit.rlim_cur = limit.rlim_max.min(100);
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let status = command.status().expect("the binary starts");
    assert_eq!(status.signal(), None, "{status:?}");
    assert_eq!(status.code(), Some(120));
    assert!(fs::metadata(scratch.0.join("out")).expect("stats").len() <= 100);
}

/// The help written to a standard output that refuses every write exits 120.
#[test]
fn a_help_that_standard_output_refuses_exits_120() {
    let top = top();
    let scratch = Scratch::new("help-full");
    let full = fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("opens");
    let status = Command::new(super::BINARY)
        .arg(&top)
        .args(["weaken-orderings", "--help"])
        .current_dir(&scratch.0)
        .stdout(full)
        .status()
        .expect("the binary starts");
    assert_eq!(status.code(), Some(120));
}
