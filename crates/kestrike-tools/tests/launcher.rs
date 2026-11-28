//! The tests run `scripts/tool.sh` against stand-ins for rustup, Cargo and the built binary. Each case
//! copies the launcher into a scratch tree whose top level holds `.github/workflows/agent-checks.yml`,
//! and starts the copy with `bash` by its absolute path. The first directory on `PATH` holds a stand-in
//! `rustup`, and a `git` and a `cargo` that each log a decoy line. The `rustup` stand-in prints its
//! `show`, `toolchain list` and `which` answers from files under `answers/`, writes a line to standard
//! error, and logs each call with its working directory, its rustup and Cargo homes and its rustup
//! variables. The `cargo` that `which` names stands beside a `rustc`, and each of the two writes a line
//! to each stream, logs its arguments and directory and records its environment; `rustc` fails where
//! its answer file says so, and `cargo` writes a binary that logs and prints its build's number, then
//! prints its arguments. The stand-ins log each argument in brackets,
//! so a merged, split or extra argument changes the logged line, and the scratch tree's path holds a space.
//! Each case checks the complete call log. A decoy's line, a missing resolution, a skipped build or an
//! earlier build's binary causes a log mismatch. A successful call's standard error must equal the
//! binary's line, and its standard output must start with the binary's marker. The pass-through, link and
//! `CDPATH` rows compare standard output in full.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, DirBuilder, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

const HOST: &str = "stand-in-host";
const PIN: &str = "1.99.0";
const PATH_TAIL: &str = "/usr/bin:/bin";
const WRAPPER: &str = "/usr/bin/env";
/// A launcher call on stand-ins takes well under a second; a call that reaches this bound has hung.
const LIMIT: Duration = Duration::from_secs(60);
/// Bash may set these variables in the environment it passes to the binary.
const SHELL_SET: [&str; 4] = ["PWD", "OLDPWD", "SHLVL", "_"];
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

const RUSTUP: &str = r#"#!/bin/sh
root='@ROOT@'
args=
for arg; do args="$args[$arg]"; done
printf 'rustup %s|%s|RUSTUP_HOME=%s|CARGO_HOME=%s|RUSTUP_TOOLCHAIN=%s|RUSTUP_AUTO_INSTALL=%s\n' "$args" \
  "$(pwd -P)" "${RUSTUP_HOME-unset}" "${CARGO_HOME-unset}" "${RUSTUP_TOOLCHAIN-unset}" \
  "${RUSTUP_AUTO_INSTALL-unset}" >> "$root/log"
echo 'info: the stand-in rustup on standard error' >&2
case $#$args in
'1[show]') [ ! -e "$root/answers/read-stdin" ] || cat > "$root/rustup.stdin"; cat "$root/answers/show" ;;
'2[toolchain][list]') [ ! -e "$root/answers/list-fails" ] && cat "$root/answers/list" ;;
'4[which][--toolchain]'*'][cargo]') [ ! -e "$root/answers/which-fails" ] && cat "$root/answers/cargo" ;;
*) exit 3 ;;
esac
"#;

const CARGO: &str = r#"#!/bin/sh
root='@ROOT@'
build=$(( $(cat "$root/builds") + 1 ))
echo "$build" > "$root/builds"
args=
for arg; do args="$args[$arg]"; done
printf 'cargo %s|%s\n' "$args" "$(pwd -P)" >> "$root/log"
env > "$root/cargo.env"
echo 'stand-in cargo: compiling'
echo 'warning: the stand-in cargo on standard error' >&2
if [ -e "$root/answers/build-fails" ]; then
  echo 'error: the stand-in build fails' >&2
  exit 101
fi
[ ! -e "$root/answers/build-noop" ] || exit 0
binary="$root/top/target/tools/@HOST@/debug/kestrike-tools"
mkdir -p "${binary%/*}"
cat > "$binary.new" <<EOF
#!/bin/sh
echo "binary $build" >> '$root/log'
pwd -P > '$root/binary.dir'
env > '$root/binary.env'
cat > '$root/binary.stdin'
echo "marker $build"
printf '%s\n' "\$@"
echo 'the binary on standard error' >&2
exit 7
EOF
chmod 755 "$binary.new" && mv -f "$binary.new" "$binary"
"#;

const RUSTC: &str = r#"#!/bin/sh
root='@ROOT@'
args=
for arg; do args="$args[$arg]"; done
printf 'rustc %s|%s\n' "$args" "$(pwd -P)" >> "$root/log"
env > "$root/rustc.env"
echo 'rustc 1.99.0 (stand-in)'
echo 'warning: the stand-in rustc on standard error' >&2
if [ -e "$root/answers/rustc-fails" ]; then
  echo 'error: the stand-in rustc fails' >&2
  exit 1
fi
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

/// The absolute path of `bash` on the test process's own `PATH`, resolved against the test process's
/// directory. Cases start it from any working directory with any `PATH` for the launcher.
fn bash() -> &'static Path {
    static BASH: OnceLock<PathBuf> = OnceLock::new();
    BASH.get_or_init(|| {
        let path = std::env::var_os("PATH").unwrap_or_else(|| OsString::from(PATH_TAIL));
        let found = std::env::split_paths(&path)
            .map(|directory| directory.join("bash"))
            .find(|candidate| {
                fs::metadata(candidate)
                    .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
            })
            .expect("bash is on PATH");
        std::path::absolute(found).expect("bash's path is made absolute")
    })
}

fn kill_group(group: u32) {
    let _ = Command::new("kill")
        .args(["-KILL", "--", &format!("-{group}")])
        .stderr(Stdio::null())
        .status();
}

/// Runs `command` in a process group of its own with `stdin` on its standard input and both streams
/// captured. If the call is still running or a stream remains open at [`LIMIT`], `finish` kills the
/// whole group and panics.
fn finish(mut command: Command, stdin: &[u8]) -> Output {
    let mut child = command
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the call starts");
    let mut input = child.stdin.take().expect("standard input is a pipe");
    let bytes = stdin.to_vec();
    let writer = thread::spawn(move || {
        let _ = input.write_all(&bytes);
    });
    let drain = |mut stream: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).expect("the stream reads");
            bytes
        })
    };
    let stdout = drain(Box::new(child.stdout.take().expect("a pipe")));
    let stderr = drain(Box::new(child.stderr.take().expect("a pipe")));
    let deadline = Instant::now() + LIMIT;
    loop {
        let exited = child.try_wait().expect("the call is polled").is_some();
        if exited && writer.is_finished() && stdout.is_finished() && stderr.is_finished() {
            break;
        }
        if Instant::now() >= deadline {
            kill_group(child.id());
            let _ = child.wait();
            panic!("the call ran past {LIMIT:?}");
        }
        thread::sleep(Duration::from_millis(5));
    }
    let status = child.wait().expect("the call is reaped");
    writer.join().expect("the writer ends");
    Output {
        status,
        stdout: stdout.join().expect("standard output is drained"),
        stderr: stderr.join().expect("standard error is drained"),
    }
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
        let env = fs::metadata(WRAPPER).expect("the cases need /usr/bin/env");
        assert!(
            env.is_file() && env.permissions().mode() & 0o111 != 0,
            "/usr/bin/env is executable"
        );
        let scratch = Path::new(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(scratch).expect("the scratch directory is made");
        let scratch = scratch
            .canonicalize()
            .expect("the scratch directory resolves");
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = loop {
            let at = NEXT.fetch_add(1, Ordering::Relaxed);
            let root = scratch.join(format!("launcher {} {at}", std::process::id()));
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
        assert!(!text.contains('\''), "the scratch path holds no quote");
        assert!(
            !text.contains('='),
            "the scratch path holds no `=`, which gives the rustc path the empty wrappers"
        );
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
        fs::copy(launcher, tree.launcher()).expect("the launcher is copied");
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
        script(&tree.at("bin/rustup"), &tree.fill(RUSTUP));
        for decoy in ["bin/git", "bin/cargo", "decoy/rustup"] {
            script(&tree.at(decoy), &tree.fill(DECOY));
        }
        script(&tree.at("toolchain/bin/cargo"), &tree.fill(CARGO));
        script(&tree.at("toolchain/bin/rustc"), &tree.fill(RUSTC));
        tree
    }

    fn fill(&self, template: &str) -> String {
        let root = self.root.to_str().expect("the scratch path reads as UTF-8");
        template.replace("@ROOT@", root).replace("@HOST@", HOST)
    }

    fn at(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    fn top(&self) -> String {
        self.at("top").display().to_string()
    }

    fn launcher(&self) -> PathBuf {
        self.at("top/scripts/tool.sh")
    }

    fn workflow(&self) -> PathBuf {
        self.at("top/.github/workflows/agent-checks.yml")
    }

    /// Cargo's cache of rustc's answers under the build directory.
    fn cache(&self) -> PathBuf {
        self.at("top/target/tools/.rustc_info.json")
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

    /// A `PATH` of the stand-ins' directory alone.
    fn isolated_path(&self) -> String {
        self.at("bin").display().to_string()
    }

    /// Starts `bash <launcher> <args>` in `caller` with an environment of `PATH` and `env` alone.
    fn start(
        &self,
        launcher: &Path,
        caller: &Path,
        path: &str,
        env: &[(&str, &str)],
        args: &[&str],
    ) -> Output {
        self.start_with_input(launcher, caller, path, env, args, b"")
    }

    fn start_with_input(
        &self,
        launcher: &Path,
        caller: &Path,
        path: &str,
        env: &[(&str, &str)],
        args: &[&str],
        stdin: &[u8],
    ) -> Output {
        let mut command = Command::new(bash());
        command
            .arg(launcher)
            .args(args)
            .current_dir(caller)
            .env_clear()
            .env("PATH", path)
            .envs(env.iter().copied());
        finish(command, stdin)
    }

    fn call(&self, args: &[&str]) -> Output {
        self.start(
            &self.launcher(),
            &self.at("caller"),
            &self.default_path(),
            &[],
            args,
        )
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
            .filter(|(name, _)| !SHELL_SET.contains(&name.as_str()))
            .collect()
    }

    /// The log of a call that resolves `pin`, builds once and starts build `build`'s binary, with the
    /// rustup homes `homes` as rustup sees them.
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
            rustup("[show]"),
            rustup("[toolchain][list]"),
            rustup(&format!("[which][--toolchain][{pin}][cargo]")),
            format!("rustc [-vV]|{top}"),
            format!(
                "cargo [build][--quiet][--package][kestrike-tools][--bin][kestrike-tools][--target]\
                 [{HOST}][--target-dir][{top}/target/tools]|{top}"
            ),
            format!("binary {build}"),
        ]
    }

    /// The log of a call refused after its first `calls` entries of [`Tree::resolved`].
    fn resolved_until(&self, calls: usize) -> Vec<String> {
        let mut log = self.resolved(PIN, ("unset", "unset"), 0);
        log.truncate(calls);
        log
    }

    /// Builds the binary of build 1 through a successful call, so a later refusal has an old binary to
    /// leave unstarted.
    fn with_old_binary(self) -> Self {
        let output = self.call(&["first"]);
        ran("the old binary's build", &output, 1);
        assert_eq!(self.take_log(), self.resolved(PIN, ("unset", "unset"), 1));
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

/// Asserts that build `build`'s binary ran, and that standard error holds its line alone: the
/// preparation and the stand-ins it starts add nothing to either stream.
fn ran(row: &str, output: &Output, build: u32) {
    assert_eq!(output.status.code(), Some(7), "{row}: {output:?}");
    assert_eq!(
        text(&output.stderr),
        "the binary on standard error\n",
        "{row}"
    );
    let marker = format!("marker {build}\n");
    assert!(
        text(&output.stdout).starts_with(&marker),
        "{row}: {output:?}"
    );
}

/// Asserts that a call exited 127 with `stderr` as its whole standard error and an empty standard
/// output.
fn refused(row: &str, output: &Output, stderr: &str) {
    assert_eq!(output.status.code(), Some(127), "{row}: {output:?}");
    assert_eq!(text(&output.stderr), stderr, "{row}");
    assert!(output.stdout.is_empty(), "{row}: {output:?}");
}

/// Asserts that a call exited 127 with the one launcher line `line` and started neither rustup, Cargo
/// nor a binary.
fn refused_early(tree: &Tree, row: &str, output: &Output, line: &str) {
    refused(row, output, &format!("tool.sh: {line}\n"));
    assert_eq!(tree.take_log(), Vec::<String>::new(), "{row}");
}

/// Asserts that the last build saw the caller's environment `caller` with the cleared variables
/// removed, and each of the launcher's own settings, apart from the variables a shell sets.
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
    assert_eq!(tree.environment("cargo.env"), expected);
    assert_eq!(tree.environment("rustc.env"), expected);
}

enum Pin {
    Read,
    NoneSingle,
    /// The pin read, with a NUL byte read as 0x02, that the list then does not name.
    NotInstalled(&'static str),
}

/// Each row is a workflow text and what the launcher makes of it. A line ends at `\n`, `\r\n` or a lone
/// `\r`; a pin is `STABLE: "VALUE"` after spaces or tabs alone, with text after the closing quote allowed.
/// An empty value, a value with a space, a value without its closing quote on the line, no pin line and
/// two pin lines each give no single pin.
#[test]
fn the_pin_is_read_by_the_line_rule() {
    let lf = workflow_text("\n");
    let quoted = format!("\"{PIN}\"");
    let rows: Vec<(&str, String, Pin)> = vec![
        ("line feed", lf.clone(), Pin::Read),
        (
            "carriage return and line feed",
            workflow_text("\r\n"),
            Pin::Read,
        ),
        ("lone carriage return", workflow_text("\r"), Pin::Read),
        ("tab indent", lf.replace("  STABLE", "\tSTABLE"), Pin::Read),
        ("no indent", lf.replace("  STABLE", "STABLE"), Pin::Read),
        (
            "first line",
            format!("  STABLE: {quoted}\nname: checks\n"),
            Pin::Read,
        ),
        (
            "trailing space",
            lf.replace(&quoted, &format!("{quoted} ")),
            Pin::Read,
        ),
        (
            "trailing comment",
            lf.replace(&quoted, &format!("{quoted} # pinned \"x\"")),
            Pin::Read,
        ),
        (
            "an unclosed value on the line before",
            lf.replace("env:\n", "env:\n  STABLE: \"x\n"),
            Pin::Read,
        ),
        (
            "text before the key",
            lf.replace("  STABLE", "  x STABLE"),
            Pin::NoneSingle,
        ),
        (
            "a quote before the key",
            lf.replace("  STABLE", "  a: \"b\" STABLE"),
            Pin::NoneSingle,
        ),
        ("empty value", lf.replace(&quoted, "\"\""), Pin::NoneSingle),
        (
            "value with a space",
            lf.replace(&quoted, "\"1.99 .0\""),
            Pin::NoneSingle,
        ),
        (
            "value across lines",
            lf.replace(&quoted, "\"1.99\n.0\""),
            Pin::NoneSingle,
        ),
        (
            "no closing quote at the end",
            format!("name: x\n  STABLE: \"{PIN}"),
            Pin::NoneSingle,
        ),
        (
            "NUL in the key",
            lf.replace("STABLE", "STA\0BLE"),
            Pin::NoneSingle,
        ),
        ("no pin", lf.replace("STABLE", "UNSTABLE"), Pin::NoneSingle),
        (
            "two pins",
            lf.replace("env:\n", &format!("env:\n  STABLE: {quoted}\n")),
            Pin::NoneSingle,
        ),
        (
            "NUL in the value",
            lf.replace(&quoted, "\"1.99\0.0\""),
            Pin::NotInstalled("1.99\u{2}.0"),
        ),
        (
            "value with a tab",
            lf.replace(&quoted, "\"1.99\t.0\""),
            Pin::NoneSingle,
        ),
        (
            "an empty value on the line before",
            lf.replace("env:\n", "env:\n  STABLE: \"\"\n"),
            Pin::Read,
        ),
        (
            "an unclosed value before a lone carriage return",
            lf.replace("env:\n", "env:\n  STABLE: \"x\r"),
            Pin::Read,
        ),
        (
            "a glob value",
            lf.replace(&quoted, "\"*\""),
            Pin::NotInstalled("*"),
        ),
        (
            "the closing quote at the end",
            format!("name: x\n  STABLE: {quoted}"),
            Pin::Read,
        ),
        ("an empty file", String::new(), Pin::NoneSingle),
    ];
    for (row, workflow, pin) in rows {
        let tree = Tree::new(workflow_text("\n").as_bytes()).with_old_binary();
        fs::write(tree.workflow(), &workflow).expect("the row's workflow is written");
        let output = tree.call(&["scan-weakened-tests"]);
        match pin {
            Pin::Read => {
                ran(row, &output, 2);
                assert_eq!(
                    tree.take_log(),
                    tree.resolved(PIN, ("unset", "unset"), 2),
                    "{row}"
                );
            }
            Pin::NoneSingle => {
                let line = format!(
                    "{} pins no single STABLE toolchain",
                    tree.workflow().display()
                );
                refused_early(&tree, row, &output, &line);
            }
            Pin::NotInstalled(read) => {
                let line = format!(
                    "tool.sh: the pinned toolchain {read}-{HOST} is not installed; install it with: \
                     rustup toolchain install {read}\n"
                );
                refused(row, &output, &line);
                assert_eq!(tree.take_log(), tree.resolved_until(2), "{row}");
            }
        }
    }

    let tree = Tree::new(lf.as_bytes()).with_old_binary();
    fs::write(tree.workflow(), lf.replace("STABLE", "UNSTABLE")).expect("the workflow is written");
    fs::remove_file(tree.at("bin/rustup")).expect("the stand-in is removed");
    let output = tree.start(
        &tree.launcher(),
        &tree.at("caller"),
        &tree.isolated_path(),
        &[],
        &["scan-weakened-tests"],
    );
    let line = format!(
        "{} pins no single STABLE toolchain",
        tree.workflow().display()
    );
    refused_early(&tree, "no pin and no rustup", &output, &line);
}

/// The launcher follows workflow symlinks and checks the target type before opening the file, so it
/// rejects a FIFO before an open can block. The launcher reports `cannot read` if opening or reading a
/// regular file fails.
#[test]
fn the_workflow_file_must_be_a_regular_file() {
    type Make = fn(&Tree);
    let rows: [(&str, Make); 4] = [
        ("absent", |_| {}),
        ("a directory", |tree| {
            fs::create_dir(tree.workflow()).expect("the directory is made")
        }),
        ("a link to a device", |tree| {
            symlink("/dev/null", tree.workflow()).expect("the link is made");
        }),
        ("a FIFO", |tree| {
            let made = Command::new("mkfifo")
                .arg(tree.workflow())
                .status()
                .expect("mkfifo starts");
            assert!(made.success(), "the FIFO is made");
        }),
    ];
    for (row, make) in rows {
        let tree = Tree::new(workflow_text("\n").as_bytes()).with_old_binary();
        fs::remove_file(tree.workflow()).expect("the workflow is removed");
        make(&tree);
        let output = tree.call(&["scan-weakened-tests"]);
        let line = format!("{} is not a regular file", tree.workflow().display());
        refused_early(&tree, row, &output, &line);
    }

    let tree = Tree::new(workflow_text("\n").as_bytes()).with_old_binary();
    fs::set_permissions(tree.workflow(), fs::Permissions::from_mode(0o000))
        .expect("the mode is set");
    match File::open(tree.workflow()) {
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            let output = tree.call(&["scan-weakened-tests"]);
            let line = format!("cannot read {}", tree.workflow().display());
            refused_early(&tree, "unreadable", &output, &line);
        }
        Err(error) => panic!("the mode 000 file: {error}"),
        Ok(_) => {
            eprintln!("the mode 000 row needs an account without CAP_DAC_OVERRIDE; it ran no call")
        }
    }

    let tree = Tree::new(workflow_text("\n").as_bytes()).with_old_binary();
    fs::remove_file(tree.workflow()).expect("the workflow is removed");
    symlink("/proc/self/mem", tree.workflow()).expect("the link is made");
    let output = tree.call(&["scan-weakened-tests"]);
    let line = format!("cannot read {}", tree.workflow().display());
    refused_early(&tree, "a read error after the open", &output, &line);

    let tree = Tree::new(b"");
    fs::write(tree.at("pins.yml"), workflow_text("\n")).expect("the target is written");
    fs::remove_file(tree.workflow()).expect("the workflow is removed");
    symlink(tree.at("pins.yml"), tree.workflow()).expect("the link is made");
    let output = tree.call(&["scan-weakened-tests"]);
    ran("a link to a file", &output, 1);
    assert_eq!(tree.take_log(), tree.resolved(PIN, ("unset", "unset"), 1));
}

/// A relative `RUSTUP_HOME` and `CARGO_HOME`, and a relative `PATH` entry that holds `rustup`, resolve
/// against the caller's directory for rustup and Cargo, which run in the top level; the binary gets the
/// caller's own values and runs in the caller's directory. The decoy `rustup` later on `PATH` is what a
/// lookup from the top level finds. An absolute `RUSTUP_HOME` and `CARGO_HOME` reach rustup unchanged.
/// When `RUSTUP_HOME` is unset, the launcher resolves a relative `CARGO_HOME` against the caller's
/// directory. An empty `CARGO_HOME` stays empty.
#[test]
fn relative_homes_and_path_resolve_against_the_callers_directory() {
    let tree = Tree::new(workflow_text("\n").as_bytes());
    let homes = |file: &str, rustup: Option<&str>, cargo: Option<&str>| {
        let record = tree.environment(file);
        assert_eq!(
            record.get("RUSTUP_HOME").map(String::as_str),
            rustup,
            "{file}"
        );
        assert_eq!(
            record.get("CARGO_HOME").map(String::as_str),
            cargo,
            "{file}"
        );
    };
    let caller = tree.at("caller");
    fs::create_dir(caller.join("tools")).expect("the directory is made");
    script(&caller.join("tools/rustup"), &tree.fill(RUSTUP));
    let path = format!(
        "tools:{}:{}:{PATH_TAIL}",
        tree.at("decoy").display(),
        tree.at("bin").display()
    );
    let env = [
        ("RUSTUP_HOME", "rustup-home"),
        ("CARGO_HOME", "../cargo-home"),
    ];
    let output = tree.start(
        &tree.launcher(),
        &caller,
        &path,
        &env,
        &["scan-weakened-tests"],
    );
    ran("relative", &output, 1);
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

    let env = [
        ("RUSTUP_HOME", "/x/rustup-home"),
        ("CARGO_HOME", "/x/cargo-home"),
    ];
    let output = tree.start(
        &tree.launcher(),
        &caller,
        &tree.default_path(),
        &env,
        &["x"],
    );
    ran("absolute", &output, 2);
    assert_eq!(
        tree.take_log(),
        tree.resolved(PIN, ("/x/rustup-home", "/x/cargo-home"), 2)
    );
    for file in ["cargo.env", "binary.env"] {
        homes(file, Some("/x/rustup-home"), Some("/x/cargo-home"));
    }

    let env = [("CARGO_HOME", "cargo-home")];
    let output = tree.start(
        &tree.launcher(),
        &caller,
        &tree.default_path(),
        &env,
        &["x"],
    );
    ran("cargo home alone", &output, 3);
    let cargo_home = format!("{}/cargo-home", caller.display());
    assert_eq!(
        tree.take_log(),
        tree.resolved(PIN, ("unset", &cargo_home), 3)
    );
    homes("cargo.env", None, Some(&cargo_home));
    homes("binary.env", None, Some("cargo-home"));

    let env = [("RUSTUP_HOME", ""), ("CARGO_HOME", "")];
    let output = tree.start(
        &tree.launcher(),
        &caller,
        &tree.default_path(),
        &env,
        &["x"],
    );
    ran("empty", &output, 4);
    assert_eq!(tree.take_log(), tree.resolved(PIN, ("unset", ""), 4));
    homes("cargo.env", None, Some(""));
    homes("binary.env", Some(""), Some(""));

    let env = [
        ("RUSTUP_HOME", "rustup-home"),
        ("CARGO_HOME", "../cargo-home"),
    ];
    let output = tree.start(
        &tree.launcher(),
        &caller,
        &tree.default_path(),
        &env,
        &["x"],
    );
    ran("relative homes on an absolute PATH", &output, 5);
    assert_eq!(
        tree.take_log(),
        tree.resolved(
            PIN,
            (&rustup_home, &format!("{}/../cargo-home", caller.display())),
            5
        )
    );

    let env = [
        ("PWD", "/proc/self/cwd"),
        ("RUSTUP_HOME", "rustup-home"),
        ("CARGO_HOME", "cargo-home"),
    ];
    let output = tree.start(&tree.launcher(), &caller, &path, &env, &["x"]);
    ran("PWD through /proc/self/cwd", &output, 6);
    let cargo_home = format!("{}/cargo-home", caller.display());
    assert_eq!(
        tree.take_log(),
        tree.resolved(PIN, (&rustup_home, &cargo_home), 6)
    );
    homes("cargo.env", Some(&rustup_home), Some(&cargo_home));
    homes("binary.env", Some("rustup-home"), Some("cargo-home"));
}

/// Each call resolves the toolchain, starts the pinned `rustc -vV` once, runs one build and starts the
/// binary that build left: cold, warm twice, with the binary dated a day ahead, with a source dated in the
/// year 2000, and with the lock file changed and then absent. Each build and its `rustc -vV` get the
/// pinned toolchain's full name, the rustc beside its cargo, the `/usr/bin/env` wrappers and the cleared
/// variables. A successful call leaves Cargo's cache file as it stands.
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
    let mut caller: Vec<(&str, &str)> = CLEARED
        .iter()
        .map(|&name| (name, "caller's value"))
        .collect();
    caller.push(("CARGO_BUILD_JOBS", "3"));
    let start = || {
        tree.start(
            &tree.launcher(),
            &tree.at("caller"),
            &tree.default_path(),
            &caller,
            &["scan-weakened-tests", "--help"],
        )
    };
    for (build, (row, change)) in (1..).zip(changes) {
        change(&tree);
        let output = start();
        ran(row, &output, build);
        assert_eq!(
            tree.take_log(),
            tree.resolved(PIN, ("unset", "unset"), build),
            "{row}"
        );
        built_with(&tree, &caller, &rustc, WRAPPER);
    }

    fs::write(tree.cache(), "{}").expect("the cache is written");
    tree.answer("build-noop", Some(""));
    let output = start();
    ran("a build that compiles nothing", &output, 7);
    assert_eq!(tree.take_log(), tree.resolved(PIN, ("unset", "unset"), 7));
    built_with(&tree, &caller, &rustc, WRAPPER);
    let cache = fs::read_to_string(tree.cache()).expect("a successful call keeps the cache");
    assert_eq!(cache, "{}");
}

/// Where the pinned rustc's path holds a `=`, which `/usr/bin/env` would read as an assignment, both
/// wrappers are the empty value; elsewhere they are `/usr/bin/env`, as `cargo_is_asked_on_every_call`
/// shows.
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
    ran("equals sign", &output, 1);
    let rustc = tree.at("tool=chain/bin/rustc").display().to_string();
    built_with(&tree, &[], &rustc, "");
}

/// With a working binary of an earlier call in place, each state the launcher refuses exits 127 with its
/// line and starts no binary: rustup absent from `PATH`, a `show` that names no host, two, or an empty
/// one before the host, a host with a `/`, a failing `toolchain list`, a list without the pin, a failing
/// `which` or one whose reply is no absolute path, a `rustc` missing or not executable beside `cargo`, a
/// `rustc -vV` that fails or cannot start, a cache path that is a link, a dangling link or a directory,
/// a variable the launcher clears or sets made readonly through `BASH_ENV`, and a failed build, which
/// also prints Cargo's output. The calls a refusal needs come first in the log, and nothing after them. A
/// failed probe or build removes the cache file, and the call after it builds again; a refused link
/// leaves its target unchanged. A launcher whose directory is gone, read through a descriptor of its
/// deleted file, cannot find the top level.
#[test]
fn each_refused_state_exits_127_and_starts_no_binary() {
    let pinned = format!("{PIN}-{HOST}");
    let no_host = "rustup names no single host".to_owned();
    type Make = fn(&Tree);
    let rows: [(&str, Make, usize, String); 10] = [
        (
            "no host",
            |tree| tree.answer("show", Some("rustup home: x\n")),
            1,
            no_host.clone(),
        ),
        (
            "two hosts",
            |tree| {
                let two = format!("Default host: {HOST}\nDefault host: other\n");
                tree.answer("show", Some(&two))
            },
            1,
            no_host.clone(),
        ),
        (
            "a host with a slash",
            |tree| tree.answer("show", Some("Default host: a/b\n")),
            1,
            no_host.clone(),
        ),
        (
            "an empty host before the host",
            |tree| {
                tree.answer(
                    "show",
                    Some(&format!("Default host: \nDefault host: {HOST}\n")),
                )
            },
            1,
            no_host,
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
            "a which reply that is no absolute path",
            |tree| tree.answer("cargo", Some("true\n")),
            3,
            format!("the pinned toolchain {pinned} has no cargo"),
        ),
        (
            "no rustc",
            |tree| fs::remove_file(tree.at("toolchain/bin/rustc")).expect("removed"),
            3,
            format!("the pinned toolchain {pinned} has no rustc"),
        ),
        (
            "rustc not executable",
            |tree| {
                let rustc = tree.at("toolchain/bin/rustc");
                fs::set_permissions(rustc, fs::Permissions::from_mode(0o644)).expect("set")
            },
            3,
            format!("the pinned toolchain {pinned} has no rustc"),
        ),
    ];
    for (row, make, calls, line) in rows {
        let tree = Tree::new(workflow_text("\n").as_bytes()).with_old_binary();
        make(&tree);
        let output = tree.call(&["scan-weakened-tests"]);
        refused(row, &output, &format!("tool.sh: {line}\n"));
        assert_eq!(tree.take_log(), tree.resolved_until(calls), "{row}");
    }

    let tree = Tree::new(workflow_text("\n").as_bytes()).with_old_binary();
    fs::remove_file(tree.at("bin/rustup")).expect("removed");
    let output = tree.start(
        &tree.launcher(),
        &tree.at("caller"),
        &tree.isolated_path(),
        &[],
        &["scan-weakened-tests"],
    );
    refused_early(&tree, "no rustup", &output, "no rustup on PATH");

    let tree = Tree::new(workflow_text("\n").as_bytes()).with_old_binary();
    let home = tree.root.display().to_string();
    let env = [("HOME", home.as_str())];
    let output = tree.start(
        &tree.launcher(),
        &tree.at("caller"),
        "~/bin",
        &env,
        &["scan-weakened-tests"],
    );
    refused_early(&tree, "a literal ~ entry", &output, "no rustup on PATH");

    let tree = Tree::new(workflow_text("\n").as_bytes()).with_old_binary();
    fs::write(tree.cache(), "{}").expect("the cache is written");
    tree.answer("build-fails", Some(""));
    let output = tree.call(&["scan-weakened-tests"]);
    refused(
        "failed build",
        &output,
        "stand-in cargo: compiling\nwarning: the stand-in cargo on standard error\n\
         error: the stand-in build fails\ntool.sh: the build of kestrike-tools failed\n",
    );
    assert_eq!(tree.take_log(), tree.resolved_until(5));
    assert!(!tree.cache().exists(), "a failed build removes the cache");
    tree.answer("build-fails", None);
    let output = tree.call(&["scan-weakened-tests"]);
    ran("the build after a failed one", &output, 3);
    assert_eq!(tree.take_log(), tree.resolved(PIN, ("unset", "unset"), 3));

    let tree = Tree::new(workflow_text("\n").as_bytes()).with_old_binary();
    fs::write(tree.cache(), "{}").expect("the cache is written");
    tree.answer("rustc-fails", Some(""));
    let output = tree.call(&["scan-weakened-tests"]);
    refused(
        "a rustc that fails its probe",
        &output,
        "rustc 1.99.0 (stand-in)\nwarning: the stand-in rustc on standard error\n\
         error: the stand-in rustc fails\ntool.sh: the build of kestrike-tools failed\n",
    );
    assert_eq!(tree.take_log(), tree.resolved_until(4));
    assert!(!tree.cache().exists(), "a failed probe removes the cache");
    tree.answer("rustc-fails", None);
    let output = tree.call(&["scan-weakened-tests"]);
    ran("the call after a failed probe", &output, 2);
    assert_eq!(tree.take_log(), tree.resolved(PIN, ("unset", "unset"), 2));

    let tree = Tree::new(workflow_text("\n").as_bytes()).with_old_binary();
    script(
        &tree.at("toolchain/bin/rustc"),
        "#!/nonexistent/interpreter\n",
    );
    let output = tree.call(&["scan-weakened-tests"]);
    assert_eq!(output.status.code(), Some(127), "{output:?}");
    let rustc = tree.at("toolchain/bin/rustc").display().to_string();
    let lines: Vec<&str> = text(&output.stderr).lines().collect();
    assert!(
        lines.len() == 2
            && lines[0].contains(&format!("{rustc}: "))
            && lines[1] == "tool.sh: the build of kestrike-tools failed",
        "bash's line for the rustc that cannot start, then the launcher's: {output:?}"
    );
    assert!(output.stdout.is_empty(), "{output:?}");
    assert_eq!(
        tree.take_log(),
        tree.resolved_until(3),
        "a rustc that cannot start"
    );

    type Place = fn(&Tree);
    let places: [(&str, Place); 3] = [
        ("a link to a file", |tree| {
            symlink(tree.at("outside.json"), tree.cache()).expect("the link is made")
        }),
        ("a dangling link", |tree| {
            symlink(tree.at("absent.json"), tree.cache()).expect("the link is made")
        }),
        ("a directory", |tree| {
            fs::create_dir(tree.cache()).expect("the directory is made")
        }),
    ];
    for (row, place) in places {
        let tree = Tree::new(workflow_text("\n").as_bytes()).with_old_binary();
        fs::write(tree.at("outside.json"), "the link's target\n").expect("the target is written");
        place(&tree);
        let output = tree.call(&["scan-weakened-tests"]);
        let line = format!(
            "tool.sh: {} is not a regular file\n",
            tree.cache().display()
        );
        refused(row, &output, &line);
        assert_eq!(tree.take_log(), tree.resolved_until(4), "{row}");
        let target = fs::read_to_string(tree.at("outside.json")).expect("the target reads");
        assert_eq!(target, "the link's target\n", "{row}");
        assert!(!tree.at("absent.json").exists(), "{row}");
        assert!(
            fs::symlink_metadata(tree.cache()).is_ok(),
            "{row}: the path stays"
        );
    }

    let readonly = [
        ("an exported RUSTFLAGS", "readonly RUSTFLAGS\n", "RUSTFLAGS"),
        ("an unset RUSTC", "declare -r RUSTC\n", "RUSTC"),
        (
            "a CARGO_PROFILE_ name",
            "readonly CARGO_PROFILE_DEV_OPT_LEVEL\n",
            "CARGO_PROFILE_DEV_OPT_LEVEL",
        ),
    ];
    for (row, startup, name) in readonly {
        let tree = Tree::new(workflow_text("\n").as_bytes()).with_old_binary();
        fs::write(tree.at("readonly.sh"), startup).expect("the startup file is written");
        let file = tree.at("readonly.sh").display().to_string();
        let env = [
            ("BASH_ENV", file.as_str()),
            ("RUSTFLAGS", "caller's value"),
            ("CARGO_PROFILE_DEV_OPT_LEVEL", "3"),
        ];
        let output = tree.start(
            &tree.launcher(),
            &tree.at("caller"),
            &tree.default_path(),
            &env,
            &["scan-weakened-tests"],
        );
        let line = format!("the variable {name} is readonly");
        refused_early(&tree, row, &output, &line);
    }

    let tree = Tree::new(workflow_text("\n").as_bytes());
    let mut command = Command::new("sh");
    command
        .args([
            "-c",
            r#"exec 3<"$1" && rm -rf "$2" && exec "$3" /dev/fd/3 scan-weakened-tests"#,
            "sh",
        ])
        .arg(tree.launcher())
        .arg(tree.at("top"))
        .arg(bash())
        .current_dir(tree.at("caller"))
        .env_clear()
        .env("PATH", tree.default_path());
    let output = finish(command, b"");
    assert_eq!(output.status.code(), Some(127), "{output:?}");
    assert!(
        text(&output.stderr).ends_with("tool.sh: cannot find the top level\n"),
        "{output:?}"
    );
    assert!(output.stdout.is_empty(), "{output:?}");
    assert_eq!(tree.take_log(), Vec::<String>::new());
}

/// A successful call prints nothing of its own: the binary's standard output, standard error and exit
/// code come back, the binary reads the caller's standard input, runs in the caller's directory with the
/// top level's canonical path and the caller's arguments, and sees the caller's environment unchanged
/// apart from the variables bash sets. The rustup calls see neither the caller's `RUSTUP_TOOLCHAIN` nor
/// its `RUSTUP_AUTO_INSTALL`, and the build sees the cleared variables removed. A launcher started
/// through a link to its file, a chain of links with a relative target, a link to the top level, or a
/// relative path with `CDPATH` set passes the same canonical path. A shell function named `rustup` in the
/// caller's environment is passed over for the `rustup` on `PATH`.
#[test]
fn the_preparation_reads_no_byte_of_the_binary_s_standard_input() {
    let tree = Tree::new(workflow_text("\n").as_bytes());
    tree.answer("read-stdin", Some(""));
    let input = b"refs/heads/a 1 refs/heads/a 2\nrefs/heads/b 3 refs/heads/b 4\n";
    let output = tree.start_with_input(
        &tree.launcher(),
        &tree.at("caller"),
        &tree.default_path(),
        &[],
        &["pre-push-checks"],
        input,
    );
    ran("input", &output, 1);
    let read = fs::read(tree.at("rustup.stdin")).expect("the preparation's read is recorded");
    assert_eq!(read, b"");
    let stdin = fs::read(tree.at("binary.stdin")).expect("the binary's standard input reads");
    assert_eq!(stdin, input);
}

#[test]
fn a_successful_call_passes_the_caller_through() {
    let tree = Tree::new(workflow_text("\n").as_bytes());
    let caller_dir = tree.at("caller");
    let mut caller: Vec<(&str, &str)> = CLEARED
        .iter()
        .map(|&name| (name, "caller's value"))
        .collect();
    caller.extend([
        ("CARGO_BUILD_JOBS", "3"),
        ("RUSTUP_TOOLCHAIN", "nightly"),
        ("RUSTUP_AUTO_INSTALL", "1"),
        ("KESTRIKE_CASE", "a value with spaces"),
        ("host", "the caller's host"),
        ("value", "the caller's value"),
    ]);
    let args = ["mutants-diff", "--base", "", "two words", "-x"];
    let output = tree.start_with_input(
        &tree.launcher(),
        &caller_dir,
        &tree.default_path(),
        &caller,
        &args,
        b"probe\n",
    );
    ran("pass-through", &output, 1);
    let mut printed = vec!["marker 1".to_owned(), tree.top()];
    printed.extend(args.iter().map(|arg| (*arg).to_owned()));
    assert_eq!(text(&output.stdout), format!("{}\n", printed.join("\n")));
    assert_eq!(tree.take_log(), tree.resolved(PIN, ("unset", "unset"), 1));
    let rustc = tree.at("toolchain/bin/rustc").display().to_string();
    built_with(&tree, &caller, &rustc, WRAPPER);
    let mut expected: BTreeMap<String, String> = caller
        .iter()
        .map(|&(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
    expected.insert("PATH".to_owned(), tree.default_path());
    assert_eq!(tree.environment("binary.env"), expected);
    let directory =
        fs::read_to_string(tree.at("binary.dir")).expect("the binary's directory reads");
    assert_eq!(directory, format!("{}\n", caller_dir.display()));
    let stdin = fs::read(tree.at("binary.stdin")).expect("the binary's standard input reads");
    assert_eq!(stdin, b"probe\n");

    symlink(tree.at("top"), tree.at("top-link")).expect("the link is made");
    symlink(tree.launcher(), tree.at("tool-link.sh")).expect("the link is made");
    symlink("top/scripts/tool.sh", tree.at("relative-link.sh")).expect("the link is made");
    symlink("relative-link.sh", tree.at("chain-link.sh")).expect("the link is made");
    let links = [
        tree.at("top-link/scripts/tool.sh"),
        tree.at("tool-link.sh"),
        tree.at("chain-link.sh"),
    ];
    for (build, launcher) in (2..).zip(links) {
        let output = tree.start(&launcher, &caller_dir, &tree.default_path(), &[], &["x"]);
        ran("a link", &output, build);
        assert_eq!(
            text(&output.stdout),
            format!("marker {build}\n{}\nx\n", tree.top())
        );
        assert_eq!(
            tree.take_log(),
            tree.resolved(PIN, ("unset", "unset"), build)
        );
    }

    let function = [("BASH_FUNC_rustup%%", "() { echo the function runs >&2; }")];
    let output = tree.start(
        &tree.launcher(),
        &caller_dir,
        &tree.default_path(),
        &function,
        &["x"],
    );
    ran("a rustup function", &output, 5);
    assert_eq!(tree.take_log(), tree.resolved(PIN, ("unset", "unset"), 5));

    let decoy = tree.at("decoy/rustup").display().to_string();
    let cmds = [("BASH_CMDS", decoy.as_str())];
    let output = tree.start(
        &tree.launcher(),
        &caller_dir,
        &tree.default_path(),
        &cmds,
        &["x"],
    );
    ran("an exported BASH_CMDS", &output, 6);
    assert_eq!(tree.take_log(), tree.resolved(PIN, ("unset", "unset"), 6));

    fs::write(tree.at("no-hash.sh"), "set +h\n").expect("the file is written");
    let startup = tree.at("no-hash.sh").display().to_string();
    let env = [("BASH_ENV", startup.as_str())];
    let output = tree.start(
        &tree.launcher(),
        &caller_dir,
        &tree.default_path(),
        &env,
        &["x"],
    );
    ran("command hashing off", &output, 7);
    assert_eq!(tree.take_log(), tree.resolved(PIN, ("unset", "unset"), 7));

    fs::create_dir_all(tree.at("elsewhere/scripts")).expect("the directory is made");
    let cdpath = tree.at("elsewhere").display().to_string();
    let env = [("CDPATH", cdpath.as_str())];
    let relative = Path::new("scripts/tool.sh");
    let output = tree.start(
        relative,
        &tree.at("top"),
        &tree.default_path(),
        &env,
        &["x"],
    );
    ran("a relative path with CDPATH set", &output, 8);
    assert_eq!(
        text(&output.stdout),
        format!("marker 8\n{}\nx\n", tree.top())
    );
    assert_eq!(tree.take_log(), tree.resolved(PIN, ("unset", "unset"), 8));
}
