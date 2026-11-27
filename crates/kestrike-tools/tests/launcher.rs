//! The tests run `scripts/tool.sh` against stand-ins for rustup, Cargo and the built binary. Each case
//! copies the launcher into a scratch tree whose top level holds `.github/workflows/agent-checks.yml`,
//! and starts the copy with `bash`. The first directory on `PATH` holds a stand-in `rustup`, and a `git`
//! and a `cargo` that each log a decoy line. The `rustup` stand-in prints its `show`, `toolchain list` and
//! `which` answers from files under `answers/` and logs each call with its working directory, its rustup
//! and Cargo homes and its rustup variables. The `cargo` that `which` names stands beside an executable
//! `rustc`; it logs its arguments and directory, records its environment, and writes a binary that logs
//! and prints its build's number, then prints its arguments. A case compares the whole log of each call,
//! so a decoy's line, a missing resolution, a skipped build or an earlier build's binary fails it.

use std::collections::BTreeMap;
use std::fs::{self, DirBuilder, File};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

const HOST: &str = "stand-in-host";
const PIN: &str = "1.99.0";
const PATH_TAIL: &str = "/usr/bin:/bin";
/// Bash may set these variables in the environment it passes to the binary.
const SHELL_SET: [&str; 4] = ["PWD", "OLDPWD", "SHLVL", "_"];

const RUSTUP: &str = r#"#!/bin/sh
root='@ROOT@'
printf 'rustup %s|%s|RUSTUP_HOME=%s|CARGO_HOME=%s|RUSTUP_TOOLCHAIN=%s|RUSTUP_AUTO_INSTALL=%s\n' "$*" \
  "$(pwd -P)" "${RUSTUP_HOME-unset}" "${CARGO_HOME-unset}" "${RUSTUP_TOOLCHAIN-unset}" \
  "${RUSTUP_AUTO_INSTALL-unset}" >> "$root/log"
case $* in
show) cat "$root/answers/show" ;;
'toolchain list') [ ! -e "$root/answers/list-fails" ] && cat "$root/answers/list" ;;
'which --toolchain '*) [ ! -e "$root/answers/which-fails" ] && cat "$root/answers/cargo" ;;
*) exit 3 ;;
esac
"#;

const CARGO: &str = r#"#!/bin/sh
root='@ROOT@'
build=$(( $(cat "$root/builds") + 1 ))
echo "$build" > "$root/builds"
printf 'cargo %s|%s\n' "$*" "$(pwd -P)" >> "$root/log"
env > "$root/cargo.env"
if [ -e "$root/answers/build-fails" ]; then
  echo 'stand-in cargo: compiling'
  echo 'error: the stand-in build fails' >&2
  exit 101
fi
binary="$root/top/target/tools/@HOST@/debug/kestrike-tools"
mkdir -p "${binary%/*}"
cat > "$binary.new" <<EOF
#!/bin/sh
echo "binary $build" >> '$root/log'
pwd -P > '$root/binary.dir'
env > '$root/binary.env'
echo "marker $build"
printf '%s\n' "\$@"
echo 'the binary on standard error' >&2
exit 7
EOF
chmod 755 "$binary.new" && mv -f "$binary.new" "$binary"
"#;

const DECOY: &str = r#"#!/bin/sh
echo "decoy $0 $*" >> '@ROOT@/log'
exit 3
"#;

/// Writes the executable script at `path` from a child process. `execve` refuses a file that any process
/// holds open for writing with `ETXTBSY`, and another test thread's child inherits this process's
/// descriptors until its own `execve`.
fn script(path: &Path, text: &str) {
    let mut writer = Command::new("sh")
        .args(["-c", r#"cat > "$1" && chmod 755 "$1""#, "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .expect("the script's writer starts");
    writer
        .stdin
        .take()
        .expect("the writer's standard input is a pipe")
        .write_all(text.as_bytes())
        .expect("the script's text reaches the writer");
    let status = writer.wait().expect("the script's writer is reaped");
    assert!(status.success(), "the script is written: {status}");
}

fn workflow_text(end: &str) -> String {
    [
        "name: checks",
        "env:",
        &format!("  STABLE: \"{PIN}\""),
        "jobs:",
        "  run: rustup toolchain install \"$STABLE\"",
        "",
    ]
    .join(end)
}

/// A scratch tree with the launcher's copy under `top/`, the stand-ins, their answers under `answers/`,
/// the call log and a caller's directory. It is removed on drop.
struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(workflow: &[u8]) -> Self {
        let scratch = Path::new(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(scratch).expect("the scratch directory is made");
        let scratch = scratch
            .canonicalize()
            .expect("the scratch directory resolves");
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = loop {
            let at = NEXT.fetch_add(1, Ordering::Relaxed);
            let root = scratch.join(format!("launcher-{}-{at}", std::process::id()));
            match DirBuilder::new().mode(0o700).create(&root) {
                Ok(()) => break root,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("{}: {error}", root.display()),
            }
        };
        let text = root
            .to_str()
            .expect("the scratch path reads as UTF-8")
            .to_owned();
        let text = text.as_str();
        assert!(!text.contains('\''), "the scratch path holds no quote");
        let tree = Self { root };
        for directory in [
            "top/scripts",
            "top/.github/workflows",
            "top/crates/kestrike-tools/src",
            "bin",
            "decoy",
            "toolchain/bin",
            "answers",
            "caller",
        ] {
            fs::create_dir_all(tree.at(directory)).expect("the directory is made");
        }
        let launcher = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/tool.sh");
        fs::copy(launcher, tree.at("top/scripts/tool.sh")).expect("the launcher is copied");
        fs::write(tree.workflow(), workflow).expect("the workflow is written");
        fs::write(tree.at("top/Cargo.lock"), "# the lock file\n")
            .expect("the lock file is written");
        fs::write(
            tree.at("top/crates/kestrike-tools/src/main.rs"),
            "fn main() {}\n",
        )
        .expect("the source is written");
        fs::write(tree.at("builds"), "0\n").expect("the build count is written");
        fs::write(tree.at("log"), "").expect("the log is written");
        tree.answer(
            "show",
            Some(&format!("Default host: {HOST}\nrustup home:  {text}\n")),
        );
        tree.answer(
            "list",
            Some(&format!("nightly-{HOST}\n{PIN}-{HOST} (default)\n")),
        );
        tree.answer("cargo", Some(&format!("{text}/toolchain/bin/cargo\n")));
        let fill = |template: &str| template.replace("@ROOT@", text).replace("@HOST@", HOST);
        script(&tree.at("bin/rustup"), &fill(RUSTUP));
        for decoy in ["bin/git", "bin/cargo", "decoy/rustup"] {
            script(&tree.at(decoy), &fill(DECOY));
        }
        script(&tree.at("toolchain/bin/cargo"), &fill(CARGO));
        script(&tree.at("toolchain/bin/rustc"), "#!/bin/sh\nexit 0\n");
        tree
    }

    fn at(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    fn top(&self) -> String {
        self.at("top").display().to_string()
    }

    fn workflow(&self) -> PathBuf {
        self.at("top/.github/workflows/agent-checks.yml")
    }

    fn binary(&self) -> PathBuf {
        self.at(&format!("top/target/tools/{HOST}/debug/kestrike-tools"))
    }

    /// Writes the answer file `name`, or removes it for `None`.
    fn answer(&self, name: &str, text: Option<&str>) {
        let path = self.at(&format!("answers/{name}"));
        match text {
            Some(text) => fs::write(&path, text).expect("the answer is written"),
            None => fs::remove_file(&path).expect("the answer is removed"),
        }
    }

    fn default_path(&self) -> String {
        format!("{}:{PATH_TAIL}", self.at("bin").display())
    }

    /// Starts the launcher copy with `bash` in `caller`, with an environment of `PATH` and `env` alone.
    fn start(&self, caller: &Path, path: &str, env: &[(&str, &str)], args: &[&str]) -> Output {
        Command::new("bash")
            .arg(self.at("top/scripts/tool.sh"))
            .args(args)
            .current_dir(caller)
            .env_clear()
            .env("PATH", path)
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .output()
            .expect("bash starts")
    }

    fn call(&self, args: &[&str]) -> Output {
        self.start(&self.at("caller"), &self.default_path(), &[], args)
    }

    /// Returns the lines logged since the last read and empties the log.
    fn take_log(&self) -> Vec<String> {
        let text = fs::read_to_string(self.at("log")).expect("the log reads");
        fs::write(self.at("log"), "").expect("the log is emptied");
        text.lines().map(str::to_owned).collect()
    }

    fn environment(&self, name: &str) -> BTreeMap<String, String> {
        let text = fs::read_to_string(self.at(name)).expect("the environment record reads");
        text.lines()
            .map(|line| {
                let (name, value) = line.split_once('=').expect("each line is NAME=VALUE");
                (name.to_owned(), value.to_owned())
            })
            .collect()
    }

    /// The log of a call that resolves `pin`, builds once and starts build `build`'s binary.
    fn resolved(&self, pin: &str, homes: (&str, &str), build: u32) -> Vec<String> {
        let top = self.top();
        let (rustup_home, cargo_home) = homes;
        let rustup = |call: &str| {
            format!(
                "rustup {call}|{top}|RUSTUP_HOME={rustup_home}|CARGO_HOME={cargo_home}|\
                 RUSTUP_TOOLCHAIN=unset|RUSTUP_AUTO_INSTALL=0"
            )
        };
        vec![
            rustup("show"),
            rustup("toolchain list"),
            rustup(&format!("which --toolchain {pin} cargo")),
            format!(
                "cargo build --quiet --package kestrike-tools --bin kestrike-tools --target {HOST} \
                 --target-dir {top}/target/tools|{top}"
            ),
            format!("binary {build}"),
        ]
    }

    /// Builds the binary of build 1 through a successful call, so a later refusal has an old binary to
    /// leave unstarted.
    fn with_old_binary(self) -> Self {
        let output = self.call(&["first"]);
        assert_eq!(output.status.code(), Some(7), "{output:?}");
        assert_eq!(self.take_log().last().map(String::as_str), Some("binary 1"));
        self
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).expect("the stream reads as UTF-8")
}

/// Asserts that a call exited 127 with the one launcher line `line` and started neither rustup, Cargo
/// nor a binary.
fn refused_early(tree: &Tree, output: &Output, line: &str) {
    assert_eq!(output.status.code(), Some(127), "{output:?}");
    assert_eq!(text(&output.stderr), format!("tool.sh: {line}\n"));
    assert!(output.stdout.is_empty(), "{output:?}");
    assert_eq!(tree.take_log(), Vec::<String>::new());
}

/// Each row is a workflow text and the pin it gives, if any. A line ends at `\n`, `\r\n` or a lone `\r`;
/// a pin is `STABLE: "VALUE"` after spaces or tabs alone, with text after the closing quote allowed. An
/// empty value, a value with a space, no pin line and two pin lines each give no single pin.
#[test]
fn the_pin_is_read_by_the_line_rule() {
    let lf = workflow_text("\n");
    let rows: Vec<(&str, String, Option<&str>)> = vec![
        ("line feed", lf.clone(), Some(PIN)),
        (
            "carriage return and line feed",
            workflow_text("\r\n"),
            Some(PIN),
        ),
        ("lone carriage return", workflow_text("\r"), Some(PIN)),
        ("tab indent", lf.replace("  STABLE", "\tSTABLE"), Some(PIN)),
        ("no indent", lf.replace("  STABLE", "STABLE"), Some(PIN)),
        (
            "trailing space",
            lf.replace(&format!("{PIN}\""), &format!("{PIN}\" ")),
            Some(PIN),
        ),
        (
            "trailing comment",
            lf.replace(&format!("{PIN}\""), &format!("{PIN}\" # pinned")),
            Some(PIN),
        ),
        (
            "text before the key",
            lf.replace("  STABLE", "  x STABLE"),
            None,
        ),
        (
            "empty value",
            lf.replace(&format!("\"{PIN}\""), "\"\""),
            None,
        ),
        (
            "value with a space",
            lf.replace(&format!("\"{PIN}\""), "\"1.99 .0\""),
            None,
        ),
        (
            "value across lines",
            lf.replace(&format!("\"{PIN}\""), "\"1.99\n.0\""),
            None,
        ),
        ("no pin", lf.replace("STABLE", "UNSTABLE"), None),
        (
            "two pins",
            lf.replace("env:\n", &format!("env:\n  STABLE: \"{PIN}\"\n")),
            None,
        ),
    ];
    for (row, workflow, pin) in rows {
        let tree = Tree::new(workflow_text("\n").as_bytes()).with_old_binary();
        fs::write(tree.workflow(), &workflow).expect("the row's workflow is written");
        let output = tree.call(&["scan-weakened-tests"]);
        match pin {
            Some(pin) => {
                assert_eq!(output.status.code(), Some(7), "{row}: {output:?}");
                assert_eq!(
                    tree.take_log(),
                    tree.resolved(pin, ("unset", "unset"), 2),
                    "{row}"
                );
            }
            None => {
                let line = format!(
                    "{} pins no single STABLE toolchain",
                    tree.workflow().display()
                );
                refused_early(&tree, &output, &line);
            }
        }
    }
}

/// A workflow path that is no regular file once links are followed is refused before it is opened; a link
/// to a regular file is read.
#[test]
fn a_workflow_that_is_no_regular_file_is_refused() {
    type Make = fn(&Tree);
    let rows: [(&str, Make); 3] = [
        ("absent", |tree| {
            fs::remove_file(tree.workflow()).expect("removed")
        }),
        ("a directory", |tree| {
            fs::remove_file(tree.workflow()).expect("removed");
            fs::create_dir(tree.workflow()).expect("the directory is made");
        }),
        ("a link to a device", |tree| {
            fs::remove_file(tree.workflow()).expect("removed");
            symlink("/dev/null", tree.workflow()).expect("the link is made");
        }),
    ];
    for (row, make) in rows {
        let tree = Tree::new(workflow_text("\n").as_bytes()).with_old_binary();
        make(&tree);
        let output = tree.call(&["scan-weakened-tests"]);
        let line = format!("{} is not a regular file", tree.workflow().display());
        assert_eq!(text(&output.stderr), format!("tool.sh: {line}\n"), "{row}");
        refused_early(&tree, &output, &line);
    }

    let tree = Tree::new(b"");
    fs::write(tree.at("pins.yml"), workflow_text("\n")).expect("the target is written");
    fs::remove_file(tree.workflow()).expect("removed");
    symlink(tree.at("pins.yml"), tree.workflow()).expect("the link is made");
    let output = tree.call(&["scan-weakened-tests"]);
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert_eq!(tree.take_log(), tree.resolved(PIN, ("unset", "unset"), 1));
}

/// A relative `RUSTUP_HOME` and `CARGO_HOME`, and a relative `PATH` entry that holds `rustup`, resolve
/// against the caller's directory for rustup and Cargo, which run in the top level. The binary gets the
/// caller's own values and runs in the caller's directory. The decoy `rustup` later on `PATH` is what a
/// lookup from the top level finds.
#[test]
fn relative_homes_and_path_resolve_against_the_callers_directory() {
    let tree = Tree::new(workflow_text("\n").as_bytes());
    let caller = tree.at("caller");
    fs::create_dir(caller.join("tools")).expect("the directory is made");
    fs::copy(tree.at("bin/rustup"), caller.join("tools/rustup")).expect("the stand-in is copied");
    let path = format!(
        "tools:{}:{}:{PATH_TAIL}",
        tree.at("decoy").display(),
        tree.at("bin").display()
    );
    let env = [
        ("RUSTUP_HOME", "rustup-home"),
        ("CARGO_HOME", "../cargo-home"),
    ];
    let output = tree.start(&caller, &path, &env, &["scan-weakened-tests"]);
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    let rustup_home = format!("{}/rustup-home", caller.display());
    let cargo_home = format!("{}/../cargo-home", caller.display());
    assert_eq!(
        tree.take_log(),
        tree.resolved(PIN, (&rustup_home, &cargo_home), 1)
    );
    let cargo = tree.environment("cargo.env");
    assert_eq!(cargo.get("RUSTUP_HOME"), Some(&rustup_home));
    assert_eq!(cargo.get("CARGO_HOME"), Some(&cargo_home));
    let binary = tree.environment("binary.env");
    assert_eq!(
        binary.get("RUSTUP_HOME").map(String::as_str),
        Some("rustup-home")
    );
    assert_eq!(
        binary.get("CARGO_HOME").map(String::as_str),
        Some("../cargo-home")
    );
    assert_eq!(binary.get("PATH"), Some(&path));
    let directory =
        fs::read_to_string(tree.at("binary.dir")).expect("the binary's directory reads");
    assert_eq!(directory, format!("{}\n", caller.display()));
}

/// Each call resolves the toolchain, runs one build and starts the binary that build left: cold, warm
/// twice, with the binary dated a day ahead, with a source dated in the year 2000, and with the lock
/// file changed and then absent. Each call's output carries its own build's marker.
#[test]
fn cargo_is_asked_on_every_call() {
    let tree = Tree::new(workflow_text("\n").as_bytes());
    let dated = |path: &Path, time: SystemTime| {
        File::open(path)
            .expect("the file opens")
            .set_modified(time)
            .expect("the time is set");
    };
    type Change = Box<dyn Fn(&Tree)>;
    let changes: Vec<(&str, Change)> = vec![
        ("cold", Box::new(|_| {})),
        ("warm", Box::new(|_| {})),
        ("warm again", Box::new(|_| {})),
        (
            "binary in the future",
            Box::new(move |tree| {
                dated(
                    &tree.binary(),
                    SystemTime::now() + Duration::from_secs(86_400),
                );
            }),
        ),
        (
            "source in the past",
            Box::new(move |tree| {
                let past = SystemTime::UNIX_EPOCH + Duration::from_secs(946_684_800);
                dated(&tree.at("top/crates/kestrike-tools/src/main.rs"), past);
            }),
        ),
        (
            "lock changed",
            Box::new(|tree| fs::write(tree.at("top/Cargo.lock"), "# changed\n").expect("written")),
        ),
        (
            "lock absent",
            Box::new(|tree| fs::remove_file(tree.at("top/Cargo.lock")).expect("removed")),
        ),
    ];
    let rustc = tree.at("toolchain/bin/rustc").display().to_string();
    for (build, (row, change)) in (1..).zip(changes) {
        change(&tree);
        let output = tree.call(&["scan-weakened-tests", "--help"]);
        assert_eq!(output.status.code(), Some(7), "{row}: {output:?}");
        assert_eq!(
            tree.take_log(),
            tree.resolved(PIN, ("unset", "unset"), build),
            "{row}"
        );
        built_with(&tree, &[], &rustc, wrapper());
        let marker = format!("marker {build}\n");
        assert!(
            text(&output.stdout).starts_with(&marker),
            "{row}: {output:?}"
        );
    }
}

/// Variables the launcher clears or sets for the build, with at least one of each class it clears.
const CLEARED: [&str; 13] = [
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "RUSTDOCFLAGS",
    "CARGO_ENCODED_RUSTDOCFLAGS",
    "RUSTDOC",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_PROFILE_DEV_OPT_LEVEL",
    "CARGO_BUILD_TARGET",
    "CARGO_BUILD_RUSTC",
    "CARGO_TARGET_DIR",
    "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS",
];

/// The wrapper the launcher names where `/usr/bin/env` is an executable file and the rustc path holds
/// no `=`.
fn wrapper() -> &'static str {
    use std::os::unix::fs::PermissionsExt;
    match fs::metadata("/usr/bin/env") {
        Ok(env) if env.is_file() && env.permissions().mode() & 0o111 != 0 => "/usr/bin/env",
        _ => "",
    }
}

/// Asserts that the last build saw the caller's environment `caller` with the cleared variables
/// removed, the pinned toolchain set, and each of the launcher's own settings, apart from the variables
/// a shell sets.
fn built_with(tree: &Tree, caller: &[(&str, &str)], rustc: &str, wrapper: &str) {
    let pinned = format!("{PIN}-{HOST}");
    let mut expected: BTreeMap<String, String> = caller
        .iter()
        .filter(|(name, _)| !CLEARED.contains(name))
        .map(|&(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
    expected.insert("PATH".to_owned(), tree.default_path());
    for (name, value) in [
        ("RUSTUP_TOOLCHAIN", pinned.as_str()),
        ("RUSTUP_AUTO_INSTALL", "0"),
        ("RUSTC", rustc),
        ("RUSTC_WRAPPER", wrapper),
        ("RUSTC_WORKSPACE_WRAPPER", wrapper),
        ("CARGO_BUILD_BUILD_DIR", "target/tools"),
    ] {
        expected.insert(name.to_owned(), value.to_owned());
    }
    let mut seen = tree.environment("cargo.env");
    seen.retain(|name, _| !SHELL_SET.contains(&name.as_str()));
    assert_eq!(seen, expected);
}

/// A successful call prints nothing of its own: the binary's standard output, standard error and exit
/// code come back, it runs in the caller's directory with the caller's arguments after the top level's
/// canonical path, and it sees the caller's environment unchanged apart from the variables bash sets.
/// The build alone sees the cleared variables removed and the launcher's own settings.
#[test]
fn a_successful_call_passes_the_caller_through() {
    let tree = Tree::new(workflow_text("\n").as_bytes());
    let mut caller: Vec<(&str, &str)> = CLEARED
        .iter()
        .map(|&name| (name, "caller's value"))
        .collect();
    caller.extend([
        ("CARGO_BUILD_JOBS", "3"),
        ("RUSTUP_TOOLCHAIN", "nightly"),
        ("RUSTUP_AUTO_INSTALL", "1"),
        ("KESTRIKE_CASE", "a value with spaces"),
    ]);
    let args = ["mutants-diff", "--base", "", "two words", "-x"];
    let output = tree.start(&tree.at("caller"), &tree.default_path(), &caller, &args);
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert_eq!(text(&output.stderr), "the binary on standard error\n");
    let mut printed = vec!["marker 1".to_owned(), tree.top()];
    printed.extend(args.iter().map(|arg| (*arg).to_owned()));
    assert_eq!(text(&output.stdout), format!("{}\n", printed.join("\n")));
    let log = tree.take_log();
    assert_eq!(
        log.iter()
            .filter(|line| line.starts_with("rustup "))
            .count(),
        3,
        "{log:?}"
    );
    assert_eq!(log.len(), 5, "{log:?}");
    assert!(log[3].starts_with("cargo build "), "{log:?}");
    assert_eq!(log[4], "binary 1");
    let rustc = tree.at("toolchain/bin/rustc").display().to_string();
    built_with(&tree, &caller, &rustc, wrapper());
    let mut binary = tree.environment("binary.env");
    binary.retain(|name, _| !SHELL_SET.contains(&name.as_str()));
    let mut expected: BTreeMap<String, String> = caller
        .iter()
        .map(|&(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
    expected.insert("PATH".to_owned(), tree.default_path());
    assert_eq!(binary, expected);
    let directory =
        fs::read_to_string(tree.at("binary.dir")).expect("the binary's directory reads");
    assert_eq!(directory, format!("{}\n", tree.at("caller").display()));
}

/// Where the pinned rustc's path holds a `=`, which `/usr/bin/env` would read as an assignment, both
/// wrappers are the empty value.
#[test]
fn a_rustc_path_with_an_equals_sign_gets_the_empty_wrappers() {
    let tree = Tree::new(workflow_text("\n").as_bytes());
    fs::create_dir_all(tree.at("tool=chain/bin")).expect("the directory is made");
    fs::rename(
        tree.at("toolchain/bin/cargo"),
        tree.at("tool=chain/bin/cargo"),
    )
    .expect("moved");
    fs::rename(
        tree.at("toolchain/bin/rustc"),
        tree.at("tool=chain/bin/rustc"),
    )
    .expect("moved");
    let cargo = tree.at("tool=chain/bin/cargo").display().to_string();
    tree.answer("cargo", Some(&format!("{cargo}\n")));
    let output = tree.call(&["scan-weakened-tests"]);
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    let rustc = tree.at("tool=chain/bin/rustc").display().to_string();
    built_with(&tree, &[], &rustc, "");
}

/// With a working binary of an earlier call in place, each state the launcher refuses exits 127 with its
/// line and starts no binary: rustup absent from `PATH`, a `show` that names no host or two, a failing
/// `toolchain list`, a list without the pin, a failing `which`, and a `rustc` missing beside `cargo`. The
/// rustup calls each refusal needs come first in the log, and nothing after them.
#[test]
fn each_refused_state_exits_127_and_starts_no_binary() {
    let pinned = format!("{PIN}-{HOST}");
    type Make = fn(&Tree);
    let rows: [(&str, Make, usize, String); 7] = [
        (
            "no rustup",
            |_| {},
            0,
            "rustup names no single host".to_owned(),
        ),
        (
            "no host",
            |tree| tree.answer("show", Some("rustup home: x\n")),
            1,
            "rustup names no single host".to_owned(),
        ),
        (
            "two hosts",
            |tree| {
                tree.answer(
                    "show",
                    Some(&format!("Default host: {HOST}\nDefault host: other\n")),
                )
            },
            1,
            "rustup names no single host".to_owned(),
        ),
        (
            "no toolchain list",
            |tree| tree.answer("list-fails", Some("")),
            2,
            "rustup lists no toolchains".to_owned(),
        ),
        (
            "pin not installed",
            |tree| tree.answer("list", Some(&format!("nightly-{HOST}\n{PIN}-other\n"))),
            2,
            format!(
                "the pinned toolchain {pinned} is not installed; install it with: rustup toolchain \
                 install {PIN}"
            ),
        ),
        (
            "no cargo",
            |tree| tree.answer("which-fails", Some("")),
            3,
            format!("the pinned toolchain {pinned} has no cargo"),
        ),
        (
            "no rustc",
            |tree| fs::remove_file(tree.at("toolchain/bin/rustc")).expect("removed"),
            3,
            format!("the pinned toolchain {pinned} has no rustc"),
        ),
    ];
    for (row, make, calls, line) in rows {
        let tree = Tree::new(workflow_text("\n").as_bytes()).with_old_binary();
        make(&tree);
        let path = if row == "no rustup" {
            format!("{}:{PATH_TAIL}", tree.at("toolchain/bin").display())
        } else {
            tree.default_path()
        };
        let output = tree.start(&tree.at("caller"), &path, &[], &["scan-weakened-tests"]);
        assert_eq!(output.status.code(), Some(127), "{row}: {output:?}");
        assert_eq!(text(&output.stderr), format!("tool.sh: {line}\n"), "{row}");
        assert!(output.stdout.is_empty(), "{row}: {output:?}");
        let mut expected = tree.resolved(PIN, ("unset", "unset"), 2);
        expected.truncate(calls);
        assert_eq!(tree.take_log(), expected, "{row}");
    }
}

/// A failed build exits 127 with Cargo's output and the launcher's line, starts neither the old binary
/// nor any other, and the next call builds again and starts that build's binary.
#[test]
fn a_failed_build_starts_no_binary_and_the_next_call_builds_again() {
    let tree = Tree::new(workflow_text("\n").as_bytes()).with_old_binary();
    tree.answer("build-fails", Some(""));
    let output = tree.call(&["scan-weakened-tests"]);
    assert_eq!(output.status.code(), Some(127), "{output:?}");
    assert_eq!(
        text(&output.stderr),
        "stand-in cargo: compiling\nerror: the stand-in build fails\n\
         tool.sh: the build of kestrike-tools failed\n"
    );
    assert!(output.stdout.is_empty(), "{output:?}");
    let mut expected = tree.resolved(PIN, ("unset", "unset"), 2);
    expected.truncate(4);
    assert_eq!(tree.take_log(), expected);

    tree.answer("build-fails", None);
    let output = tree.call(&["scan-weakened-tests"]);
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert_eq!(tree.take_log(), tree.resolved(PIN, ("unset", "unset"), 3));
}

/// A launcher whose directory is gone when it starts cannot find the top level. The launcher is read
/// through a descriptor of the deleted file, so its own path names no directory.
#[test]
fn a_launcher_whose_directory_is_gone_cannot_find_the_top_level() {
    let tree = Tree::new(workflow_text("\n").as_bytes()).with_old_binary();
    let output = Command::new("sh")
        .args([
            "-c",
            r#"exec 3<"$1" && rm -rf "$2" && exec bash /dev/fd/3 scan-weakened-tests"#,
            "sh",
        ])
        .arg(tree.at("top/scripts/tool.sh"))
        .arg(tree.at("top"))
        .current_dir(tree.at("caller"))
        .env_clear()
        .env("PATH", tree.default_path())
        .stdin(Stdio::null())
        .output()
        .expect("sh starts");
    assert_eq!(output.status.code(), Some(127), "{output:?}");
    assert!(
        text(&output.stderr).ends_with("tool.sh: cannot find the top level\n"),
        "{output:?}"
    );
    assert!(output.stdout.is_empty(), "{output:?}");
    assert_eq!(tree.take_log(), Vec::<String>::new());
}
