//! Building the simulation worker once, from the checkout of the working
//! directory, with its provenance.
//!
//! The build reads the toolchain's versions, the workspace lockfile and
//! the checkout's revision and status before it runs. A workspace without
//! a lockfile has one resolved first; the build then runs `--locked`, so a
//! lockfile that needs an update fails it, and the lockfile's exact bytes
//! from before the build are the ones the archive keeps. The build runs
//! the compiler whose version is recorded. Lockfile bytes, a revision or a
//! checkout status that differ after the build make the result
//! incomplete. Cargo's messages are read up to a byte bound, and a
//! message that fails to parse fails the build. The listed
//! build-affecting environment variables are recorded. A build that
//! compiles this crate, as the worker's protocol contract configuration
//! does, is a build failure, so an archived worker holds no supervisor
//! code.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use super::command::Context;
use super::run::Stderr;
use super::{Built, Error};
use crate::record::{Digest, Native, Provenance, Text};
use crate::store::{open_host, read_host};

/// The build command's arguments after the Cargo program.
const BUILD: [&str; 9] = [
    "test",
    "-p",
    "kestrike",
    "--test",
    "sim_worker",
    "--no-run",
    "--locked",
    "--message-format=json-render-diagnostics",
    "--quiet",
];

/// The environment variables the build record keeps: each one named here,
/// and each whose name starts with a prefix below.
const ENVIRONMENT: [&str; 6] = [
    "CARGO_ENCODED_RUSTFLAGS",
    "RUSTC",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTC_WRAPPER",
    "RUSTFLAGS",
    "RUSTUP_TOOLCHAIN",
];
const ENVIRONMENT_PREFIXES: [&str; 7] = [
    "CARGO_BUILD_",
    "CARGO_PROFILE_",
    "CARGO_RESOLVER_",
    "CARGO_TARGET_",
    "CARGO_UNSTABLE_",
    "KESTRIKE_",
    "SPDK_",
];

/// The most bytes a lockfile may hold.
const LOCK_BOUND: u64 = 16 << 20;

/// Builds the worker with `cargo` and returns it with its provenance. The
/// caller gives this function ownership of the process's SIGCHLD
/// disposition, as the [module doc](super#sigchld) states.
///
/// # Errors
///
/// [`Error::Build`] when the checkout names no revision, a probe before the build or the
/// build fails, the lockfile before the build is unreadable, Cargo prints a message that fails to
/// parse, or the build reports no single worker executable or native
/// build identity, or compiles the supervisor;
/// [`Error::Incomplete`] when the lockfile, the revision or the checkout's
/// status changes during the build, a closing checkout probe fails, or the lockfile, the executable,
/// the native install record or the link plan is unreadable after it.
pub fn build(cargo: &Path) -> Result<Built, Error> {
    build_with(cargo, std::env::vars_os().collect())
}

pub(super) fn build_with(cargo: &Path, vars: Vec<(OsString, OsString)>) -> Result<Built, Error> {
    let context = Context::open()?;
    context.finish(build_archiving(cargo, vars, &context))
}

pub(super) fn build_archiving(
    cargo: &Path,
    vars: Vec<(OsString, OsString)>,
    context: &Context,
) -> Result<Built, Error> {
    context.check()?;
    let variable = |name: &str| {
        vars.iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    let rustc = variable("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let toolchain = probe(context, &rustc, &["-V"]).map_err(Error::Build)?;
    let host = probe(context, &rustc, &["-vV"]).map_err(Error::Build)?;
    let host = host.lines().find_map(|line| line.strip_prefix("host: "));
    let host = host.ok_or_else(|| Error::Build("rustc names no host target".to_owned()))?;
    let target = variable("CARGO_BUILD_TARGET").map(|value| value.to_string_lossy().into_owned());
    let target = target
        .filter(|target| target != "host-tuple")
        .unwrap_or_else(|| host.to_owned());
    let version = probe(context, cargo, &["-V"]).map_err(Error::Build)?;
    let manifest = probe(
        context,
        cargo,
        &["locate-project", "--workspace", "--message-format", "plain"],
    )
    .map_err(Error::Build)?;
    let lockfile = Path::new(&manifest).with_file_name("Cargo.lock");
    let cargo_command = || {
        let mut command = Command::new(cargo);
        command
            .env_clear()
            .envs(vars.iter().cloned())
            .env("RUSTC", &rustc)
            .env("CARGO_BUILD_TARGET", &target)
            .env("CARGO_RESOLVER_LOCKFILE_PATH", &lockfile);
        command
    };
    let before = match lock(&lockfile)? {
        Some(bytes) => bytes,
        None => {
            probed(context, cargo_command().arg("generate-lockfile")).map_err(Error::Build)?;
            lock(&lockfile)?.ok_or_else(|| Error::Build("no lockfile was resolved".to_owned()))?
        }
    };
    let checkout = Checkout::read(context).map_err(Error::Build)?;
    let mut command = cargo_command();
    command.args(BUILD);
    let built = context
        .run(&mut command, Stderr::Inherit, None)
        .map_err(|failure| Error::Build(format!("cargo: {failure}")))?;
    if !built.status.success() {
        return Err(Error::Build(format!("the build exited {}", built.status)));
    }
    let messages = messages(&built.stdout)?;
    if messages.iter().any(|message| {
        matches!(message,
        Message::Artifact { target, .. } if target.name == "campaign_supervisor")
    }) {
        return Err(Error::Build(
            "the build compiles the supervisor into the worker".to_owned(),
        ));
    }
    let executable = executable(&messages)?;
    let identity = open_host(&executable)
        .map_err(|why| Error::Incomplete(format!("{} is unreadable: {why}", executable.display())))?
        .identity();
    let native = native(&messages)?;
    let after = read_host(&lockfile, LOCK_BOUND).map_err(|why| {
        Error::Incomplete(format!("the lockfile is unreadable after the build: {why}"))
    })?;
    if after.as_ref() != Some(&before) {
        return Err(Error::Incomplete(
            "the lockfile changed during the build".to_owned(),
        ));
    }
    let unchanged = Checkout::read(context).map_err(Error::Incomplete)?;
    if unchanged != checkout {
        return Err(Error::Incomplete(
            "the checkout's revision or status changed during the build".to_owned(),
        ));
    }
    Ok(Built {
        executable,
        identity,
        lock: before,
        provenance: Provenance {
            cargo: text(&version)?,
            command: text(&BUILD.join(" "))?,
            dirty: checkout.dirty(),
            environment: environment(
                command
                    .get_envs()
                    .filter_map(|(name, value)| Some((name.to_owned(), value?.to_owned()))),
            )?,
            native,
            revision: text(&checkout.revision)?,
            target: text(&target)?,
            toolchain: text(&toolchain)?,
            untracked: checkout.untracked(),
        },
    })
}

/// The checkout's revision and its full porcelain status, which two
/// readings compare whole. Changed status rows are detected; a further
/// edit of an already listed dirty file can keep its row unchanged.
#[derive(Debug, PartialEq, Eq)]
struct Checkout {
    revision: String,
    status: String,
}

impl Checkout {
    fn read(context: &Context) -> Result<Self, String> {
        let unrevised = |why: &str| format!("git names no revision for the checkout: {why}");
        let revision =
            probe(context, "git", &["rev-parse", "HEAD"]).map_err(|why| unrevised(&why))?;
        if !revised(&revision) {
            return Err(unrevised(&revision));
        }
        let status = probe(
            context,
            "git",
            &["status", "--porcelain", "--untracked-files=all"],
        )?;
        Ok(Self { revision, status })
    }

    /// How many untracked files the checkout holds.
    fn untracked(&self) -> u64 {
        let untracked = self.status.lines().filter(|line| line.starts_with("??"));
        untracked.count() as u64
    }

    /// Whether a tracked file differs from the revision.
    fn dirty(&self) -> bool {
        self.status.lines().count() as u64 > self.untracked()
    }
}

/// Whether `revision` has the shape of a git object name: 40 or 64
/// lowercase hexadecimal digits.
pub(super) fn revised(revision: &str) -> bool {
    let hex = revision
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    matches!(revision.len(), 40 | 64) && hex
}

/// The trimmed standard output of `program` run with `args`; its standard
/// error goes to this process's.
fn probe(
    context: &Context,
    program: impl AsRef<std::ffi::OsStr>,
    args: &[&str],
) -> Result<String, String> {
    probed(context, Command::new(program).args(args))
}

fn probed(context: &Context, command: &mut Command) -> Result<String, String> {
    let label = format!("{:?}", command.get_program());
    let ran = context
        .run(command, Stderr::Inherit, None)
        .map_err(|failure| format!("{label}: {failure}"))?;
    if !ran.status.success() {
        return Err(format!("{label} exited {}", ran.status));
    }
    Ok(String::from_utf8_lossy(&ran.stdout).trim().to_owned())
}

/// Cargo's JSON messages in `stdout`. A line that starts no JSON object,
/// such as a wrapper's text, is skipped.
///
/// # Errors
///
/// [`Error::Build`] for output that is not UTF-8 or a line that starts a
/// JSON object and fails to parse.
fn messages(stdout: &[u8]) -> Result<Vec<Message>, Error> {
    let stdout = std::str::from_utf8(stdout)
        .map_err(|_| Error::Build("cargo printed output that is not UTF-8".to_owned()))?;
    let mut messages = Vec::new();
    for line in stdout.lines() {
        if line.trim_start().starts_with('{') {
            let message = serde_json::from_str(line).map_err(|error| {
                Error::Build(format!("cargo printed a malformed message: {error}"))
            })?;
            messages.push(message);
        }
    }
    Ok(messages)
}

fn lock(path: &Path) -> Result<Option<Vec<u8>>, Error> {
    read_host(path, LOCK_BOUND).map_err(|why| {
        Error::Build(format!(
            "the lockfile {} is unreadable: {why}",
            path.display()
        ))
    })
}

/// The build-affecting variables among `vars`.
pub(super) fn environment(
    vars: impl Iterator<Item = (OsString, OsString)>,
) -> Result<BTreeMap<Text, Text>, Error> {
    let mut kept = BTreeMap::new();
    for (name, value) in vars {
        let name = name.to_string_lossy();
        let prefixed = ENVIRONMENT_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix));
        if ENVIRONMENT.contains(&&*name) || prefixed {
            let value = value.to_string_lossy().escape_default().to_string();
            kept.insert(text(&name)?, text(&value)?);
        }
    }
    Ok(kept)
}

fn text(value: &str) -> Result<Text, Error> {
    Text::new(value).ok_or_else(|| Error::Build(format!("{value:?} is no printable ASCII")))
}

#[derive(Deserialize)]
#[serde(tag = "reason")]
enum Message {
    #[serde(rename = "compiler-artifact")]
    Artifact {
        target: Target,
        profile: Profile,
        executable: Option<String>,
    },
    #[serde(rename = "build-script-executed")]
    Script {
        package_id: String,
        env: Vec<(String, String)>,
        out_dir: String,
    },
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
struct Target {
    name: String,
    kind: Vec<String>,
}
#[derive(Deserialize)]
struct Profile {
    test: bool,
}

fn executable(messages: &[Message]) -> Result<PathBuf, Error> {
    let mut found = messages.iter().filter_map(|message| match message {
        Message::Artifact {
            target,
            profile,
            executable,
        } if target.name == "sim_worker"
            && profile.test
            && target.kind.iter().any(|kind| kind == "test") =>
        {
            Some(executable)
        }
        _ => None,
    });
    match (found.next(), found.next()) {
        (Some(Some(path)), None) => Ok(PathBuf::from(path)),
        _ => Err(Error::Build(
            "the build names no single worker executable".to_owned(),
        )),
    }
}

fn native(messages: &[Message]) -> Result<Native, Error> {
    let unidentified = || Error::Build("the build's native SPDK build is unidentified".to_owned());
    let mut exported = messages.iter().flat_map(|message| {
        let Message::Script {
            package_id,
            env,
            out_dir,
        } = message
        else {
            return Vec::new();
        };
        env.iter()
            .filter(|(name, _)| name == "SPDK_SYS_INSTALL")
            .map(|(_, install)| (package_id, out_dir, install))
            .collect::<Vec<_>>()
    });
    let (package, out, install) = exported.next().ok_or_else(unidentified)?;
    if exported.next().is_some() {
        return Err(Error::Build(
            "more than one native SPDK build identity".to_owned(),
        ));
    }
    let install = Path::new(install);
    let record = install.file_name().ok_or_else(unidentified)?;
    Ok(Native {
        install_record: text(&record.to_string_lossy())?,
        install_record_sha256: digest(install)?,
        link_plan_sha256: digest(&Path::new(out).join("link-plan.txt"))?,
        package: text(package)?,
    })
}

fn digest(path: &Path) -> Result<Digest, Error> {
    let unreadable =
        |why: String| Error::Incomplete(format!("{} is unreadable: {why}", path.display()));
    let opened = open_host(path).map_err(|why| unreadable(why.to_string()))?;
    Digest::read(opened).map_err(|error| unreadable(error.to_string()))
}
