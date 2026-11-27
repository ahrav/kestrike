//! Step 1 and the input checks before it: the variables the run refuses, the invoking checkout's top
//! level, the two revisions, the pins, the artifacts directory, the tool's environment and the tool's
//! version and host.
//!
//! A set Git repository or index variable is refused before the first Git call, which would read it.
//! Every Git call runs with `GIT_NO_REPLACE_OBJECTS=1` and without `GIT_DIFF_OPTS`. The text the tool and
//! Cargo print is read as UTF-8 with each invalid sequence replaced by U+FFFD; the configuration and the
//! workflow file must be UTF-8. Both outputs and both files are read with `\r\n` and `\r` as `\n`.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::config::{self, pins, stables};
use super::options::{Options, Revision};
use super::pieces::text;
use super::process::{INTERRUPT, capture, exit_code};
use super::stop::{Fault, Stop};
use crate::ownership::{foreign_toolchain_paths, status};
use crate::paths;
use crate::text::Text;

pub(super) const CONFIG: &str = ".cargo/mutants.toml";
const WORKFLOW: &str = ".github/workflows/agent-checks.yml";
const OVERRIDES: [&str; 5] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
];
const DEFAULT_PATH: &str = "/bin:/usr/bin";
pub(super) const DEFAULT_TESTS: [&str; 8] = [
    "--lib", "--", "--skip", "bind::", "--skip", "native::", "--skip", "soak",
];

pub(super) type Environ = Vec<(OsString, OsString)>;

/// What step 1 fixed: the top level, the report's first fields, the artifacts directory, the
/// environments of Git and of the tool, and the program that stands for `cargo`.
#[derive(Clone, Debug)]
pub struct Prepared {
    pub(super) options: Options,
    pub(super) top: PathBuf,
    pub(super) base: String,
    pub(super) head: String,
    pub(super) version: Text,
    pub(super) machine: Text,
    pub(super) tests: Vec<OsString>,
    pub(super) artifacts: PathBuf,
    pub(super) git_env: Environ,
    pub(super) env: Environ,
    pub(super) cargo: OsString,
}

/// `lossy` decodes command output as UTF-8 with replacement and reads `\r\n` and `\r` as `\n`.
pub(super) fn lossy(bytes: &[u8]) -> Text {
    let decoded = String::from_utf8_lossy(bytes);
    Text::from(decoded.replace("\r\n", "\n").replace('\r', "\n"))
}

/// `join` joins `entry` to `directory` as a path: an absolute entry stands alone, and an empty one leaves
/// the directory with a final `/`.
fn join(directory: &OsStr, entry: &OsStr) -> OsString {
    let (directory, entry) = (directory.as_bytes(), entry.as_bytes());
    if entry.starts_with(b"/") {
        return OsString::from_vec(entry.to_vec());
    }
    let mut joined = directory.to_vec();
    if !joined.is_empty() && !joined.ends_with(b"/") {
        joined.push(b'/');
    }
    joined.extend_from_slice(entry);
    OsString::from_vec(joined)
}

fn get<'a>(environ: &'a Environ, name: &str) -> Option<&'a OsString> {
    environ
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
}

fn set(environ: &mut Environ, name: &str, value: OsString) {
    environ.retain(|(key, _)| key != name);
    environ.push((OsString::from(name), value));
}

/// `is_file` holds for a path whose target is a regular file; [`status`] decides which errors read as no
/// file.
pub(super) fn is_file(path: &Path) -> Result<bool, Fault> {
    status(path)
        .map(|status| status.is_some_and(|status| status.is_file()))
        .map_err(|error| Fault::os(error.error(), Some(error.path().as_os_str())))
}

/// A failed Git call: an exit other than 0 with the call and Git's standard error, a start or wait that
/// failed, or a recorded signal.
pub(super) enum GitError {
    Failed(Text),
    Start(Fault),
    Interrupted(Stop),
}

impl GitError {
    /// `incomplete` is the stop of a failure inside the run's steps: a failed call makes the run
    /// incomplete with its reason, and an unexpected error is the runner's failure.
    pub(super) fn incomplete(self) -> Stop {
        match self {
            Self::Failed(reason) => Stop::incomplete(reason),
            Self::Start(fault) => Stop::failed(&fault),
            Self::Interrupted(stop) => stop,
        }
    }

    /// `rejected` is the stop of a failure in the input checks, where an unexpected error is rejected
    /// input too.
    fn rejected(self) -> Stop {
        match self {
            Self::Failed(reason) => Stop::rejected(reason),
            Self::Start(fault) => Stop::rejected(fault.to_text()),
            Self::Interrupted(stop) => stop,
        }
    }
}

/// `git` runs `git -C top ARGS` in `git_env` and returns its standard output.
pub(super) fn git(git_env: &Environ, top: &OsStr, args: &[&OsStr]) -> Result<Vec<u8>, GitError> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(top)
        .args(args)
        .env_clear()
        .envs(git_env.iter().cloned());
    let output = match capture(&mut command, &INTERRUPT) {
        Err(stop) => return Err(GitError::Interrupted(stop)),
        Ok(Err(error)) => return Err(GitError::Start(Fault::os(&error, Some(OsStr::new("git"))))),
        Ok(Ok(output)) => output,
    };
    if output.status.success() {
        return Ok(output.stdout);
    }
    let mut call = Text::from("git");
    for arg in args {
        call = text!(call, " ", arg);
    }
    let detail = Text::from(String::from_utf8_lossy(&output.stderr).into_owned()).strip();
    Err(GitError::Failed(text!(call, ": ", detail)))
}

fn hex(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

fn commit(git_env: &Environ, top: &Path, revision: &Revision) -> Result<String, Stop> {
    let mut spec = revision.argument();
    spec.push("^{commit}");
    let args = ["rev-parse", "--verify", "--quiet", "--end-of-options"].map(OsStr::new);
    let args: Vec<&OsStr> = args.into_iter().chain([spec.as_os_str()]).collect();
    match git(git_env, top.as_os_str(), &args) {
        Ok(output) => Ok(hex(&output)),
        Err(GitError::Failed(_)) => Err(Stop::rejected(text!(format!(
            "unknown revision {}",
            revision.repr()
        )))),
        Err(error) => Err(error.rejected()),
    }
}

/// `rejected_fault` is the refusal `<Kind>: <text>` of an unexpected error in the input checks.
fn rejected_fault(fault: &Fault) -> Stop {
    Stop::rejected(fault.to_text())
}

/// `read_pins` returns the text of `path` when it is a file, with `\r\n` and `\r` read as `\n`, or an
/// empty text when it is none.
pub(super) fn read_pins(path: &Path) -> Result<String, Stop> {
    if !is_file(path).map_err(|fault| rejected_fault(&fault))? {
        return Ok(String::new());
    }
    let bytes = fs::read(path)
        .map_err(|error| rejected_fault(&Fault::os(&error, Some(path.as_os_str()))))?;
    let text = String::from_utf8(bytes)
        .map_err(|error| rejected_fault(&Fault::library("Utf8Error", &error.utf8_error())))?;
    Ok(text.replace("\r\n", "\n").replace('\r', "\n"))
}

fn text_command(program: &OsStr, args: &[&str], env: &Environ) -> Command {
    let mut command = Command::new(program);
    command.args(args).env_clear().envs(env.iter().cloned());
    command
}

/// `tool_version` requires `cargo mutants --version` to print `cargo-mutants PIN` and returns the version.
fn tool_version(cargo: &OsStr, env: &Environ, pin: &str) -> Result<Text, Stop> {
    let install = format!("cargo install --locked --version {pin} cargo-mutants");
    let mut command = text_command(cargo, &["mutants", "--version"], env);
    let output = match capture(&mut command, &INTERRUPT)? {
        Ok(output) => output,
        Err(error) => {
            let fault = Fault::os(&error, Some(cargo));
            return Err(Stop::rejected(text!(
                cargo,
                " cannot run (",
                fault.text(),
                "); install the pinned tool: ",
                install
            )));
        }
    };
    let stdout = lossy(&output.stdout);
    let words = stdout.split();
    let code = exit_code(output.status);
    if code != 0 {
        let lines = lossy(&output.stderr).strip().splitlines();
        let detail = lines.last().cloned().unwrap_or_default();
        return Err(Stop::rejected(text!(
            format!("cargo mutants --version exited {code} ("),
            detail,
            "); install the pinned tool: ",
            install
        )));
    }
    if words.len() != 2 || words[0] != "cargo-mutants" {
        return Err(Stop::rejected(text!(
            "cargo mutants --version printed ",
            stdout.strip().repr(),
            "; install the pinned tool: ",
            install
        )));
    }
    if words[1] != pin {
        return Err(Stop::rejected(text!(
            "cargo mutants is ",
            words[1],
            format!(", the configuration pins {pin}; install it: {install}")
        )));
    }
    Ok(words[1].clone())
}

/// `host_machine` returns the part before the first `-` of the one `host:` line `cargo -vV` prints.
fn host_machine(cargo: &OsStr, env: &Environ) -> Result<Text, Stop> {
    let mut command = text_command(cargo, &["-vV"], env);
    let output = capture(&mut command, &INTERRUPT)?
        .map_err(|error| rejected_fault(&Fault::os(&error, Some(cargo))))?;
    let hosts: Vec<String> = lossy(&output.stdout)
        .splitlines()
        .iter()
        .filter_map(|line| {
            let host = line.to_str()?.strip_prefix("host: ")?;
            Text::from(host).strip().to_str().map(str::to_owned)
        })
        .collect();
    let machine = match hosts.as_slice() {
        [host] => host.split('-').next().unwrap_or_default(),
        _ => "",
    };
    if exit_code(output.status) != 0 || machine.is_empty() {
        return Err(Stop::rejected(text!(cargo, " -vV names no host")));
    }
    Ok(Text::from(machine))
}

fn listed(names: &[Text]) -> Text {
    let mut joined = Text::new();
    for (at, name) in names.iter().enumerate() {
        if at > 0 {
            joined.push_str(", ");
        }
        joined.push_text(name);
    }
    joined
}

/// `preflight` runs step 1 and the checks before it in the process's working directory and environment.
///
/// # Errors
///
/// A rejected input, or a fatal stop when `--cargo=--` leaves no program to run.
pub fn preflight(options: Options) -> Result<Prepared, Stop> {
    let environ: Environ = std::env::vars_os().collect();
    let set_names: Vec<Text> = OVERRIDES
        .iter()
        .filter(|name| get(&environ, name).is_some())
        .map(|&name| Text::from(name))
        .collect();
    if !set_names.is_empty() {
        return Err(Stop::rejected(text!(
            "unset ",
            listed(&set_names),
            "; the runner uses the invoking checkout's repository"
        )));
    }
    let inherited = config::build_overrides(&environ);
    if !inherited.is_empty() {
        return Err(Stop::rejected(text!(
            "unset ",
            listed(&inherited),
            "; the runner sets the tool's options and the build profile"
        )));
    }
    let mut git_env = environ.clone();
    set(&mut git_env, "GIT_NO_REPLACE_OBJECTS", OsString::from("1"));
    git_env.retain(|(name, _)| name != "GIT_DIFF_OPTS");
    let here = std::env::current_dir()
        .map_err(|error| rejected_fault(&Fault::os(&error, None)))?
        .into_os_string();
    let cargo = options.cargo.as_ref().map(|cargo| {
        if cargo.as_bytes().contains(&b'/') {
            join(&here, cargo)
        } else {
            cargo.clone()
        }
    });
    let output = git(
        &git_env,
        &here,
        &["rev-parse", "--show-toplevel"].map(OsStr::new),
    )
    .map_err(GitError::rejected)?;
    let top = output.strip_suffix(b"\n").unwrap_or(&output);
    let top = PathBuf::from(OsStr::from_bytes(top));
    let head = commit(&git_env, &top, &options.head)?;
    let base = match &options.base {
        Some(base) => commit(&git_env, &top, &Revision::Given(base.clone()))?,
        None => {
            let args = [
                OsStr::new("merge-base"),
                OsStr::new(&head),
                OsStr::new("origin/main"),
            ];
            hex(&git(&git_env, top.as_os_str(), &args).map_err(GitError::rejected)?)
        }
    };
    let config_text = read_pins(&top.join(CONFIG))?;
    let workflow_text = read_pins(&top.join(WORKFLOW))?;
    let (pins, stables) = (pins(&config_text), stables(&workflow_text));
    let ([pin], [stable]) = (pins.as_slice(), stables.as_slice()) else {
        return Err(Stop::rejected(Text::from(format!(
            "{CONFIG} must hold one tool pin line and {WORKFLOW} one STABLE pin"
        ))));
    };
    let artifacts = options
        .artifacts
        .as_ref()
        .map_or_else(|| top.join("target/mutants"), PathBuf::from);
    let artifacts =
        paths::resolve(&artifacts).map_err(|error| rejected_fault(&Fault::os(&error, None)))?;
    let foreign = foreign_toolchain_paths(&artifacts).map_err(|error| {
        rejected_fault(&Fault::os(error.error(), Some(error.path().as_os_str())))
    })?;
    if !foreign.is_empty() {
        let shown: Vec<Text> = foreign
            .iter()
            .map(|path| Text::from_os(path.as_os_str()))
            .collect();
        return Err(Stop::rejected(text!(
            "another user owns or can write ",
            listed(&shown),
            ", where Cargo would read configuration; pass --artifacts under a directory only you control"
        )));
    }
    let env = tool_env(&git_env, &here, &artifacts, stable);
    let Some(cargo) = cargo else {
        return Err(Stop::fatal(Text::from(
            "--cargo=-- names no program to run",
        )));
    };
    let version = tool_version(&cargo, &env, pin)?;
    let machine = host_machine(&cargo, &env)?;
    let tests = options
        .tests
        .clone()
        .unwrap_or_else(|| DEFAULT_TESTS.map(OsString::from).to_vec());
    Ok(Prepared {
        options,
        top,
        base,
        head,
        version,
        machine,
        tests,
        artifacts,
        git_env,
        env,
        cargo,
    })
}

/// `tool_env` is the Git environment with each `PATH` entry and a set `CARGO_HOME` and `RUSTUP_HOME`
/// joined to the invoking directory `here`, a `..` after a link kept, and the build variables the run sets.
fn tool_env(git_env: &Environ, here: &OsStr, artifacts: &Path, stable: &str) -> Environ {
    let mut env = git_env.clone();
    let path = get(git_env, "PATH").map_or(OsStr::new(DEFAULT_PATH), OsString::as_os_str);
    let entries: Vec<Vec<u8>> = path
        .as_bytes()
        .split(|&byte| byte == b':')
        .map(|entry| join(here, OsStr::from_bytes(entry)).into_vec())
        .collect();
    let path = OsString::from_vec(entries.join(&b':'));
    for name in ["CARGO_HOME", "RUSTUP_HOME"] {
        if let Some(home) = get(git_env, name).filter(|home| !home.is_empty()) {
            let joined = join(here, home);
            set(&mut env, name, joined);
        }
    }
    let build = artifacts.join("build").into_os_string();
    set(&mut env, "CARGO_PROFILE_DEV_OPT_LEVEL", OsString::from("1"));
    set(
        &mut env,
        "CARGO_PROFILE_DEV_DEBUG",
        OsString::from("line-tables-only"),
    );
    set(&mut env, "RUSTUP_TOOLCHAIN", OsString::from(stable));
    set(&mut env, "CARGO_TARGET_DIR", build.clone());
    set(&mut env, "CARGO_BUILD_BUILD_DIR", build);
    set(&mut env, "PATH", path);
    env
}
