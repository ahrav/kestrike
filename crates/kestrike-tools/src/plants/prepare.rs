//! The entry of the plant run's checks: from a command line, an environment and an invoking directory,
//! the checked inputs of a run, or the first refusal in the order below with its reason.
//!
//! The order: the command line; a set Git repository or index variable ([`REPOSITORY_VARIABLES`]); the
//! invoking directory, which must lie in a Git checkout; the head commit; the plant store; the
//! checkout's `Cargo.lock`; the `campaign` binary; and last the work directory, which is made, so a
//! refusal leaves no work directory; only the missing ancestors of `--work`, made just before it, can
//! stay. Every Git call runs in the given environment with `GIT_NO_REPLACE_OBJECTS=1`.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};

use super::campaign::campaign;
use super::git;
use super::lock::lock;
use super::options::{Options, parse};
use super::record::Plant;
use super::stop::Stop;
use super::store::{SCORE, STORE, load_plants};
use super::work::work_directory;
use crate::args::Parsed;
use crate::environ::{Environ, first_of_each, get, set};
use crate::git::REPOSITORY_VARIABLES;
use crate::paths;
use crate::text::{Text, strip_str};

/// The checked inputs of a run, each read once.
#[derive(Debug)]
pub struct Inputs {
    options: Options,
    env: Environ,
    top: PathBuf,
    head: String,
    plants: Vec<Plant>,
    lock: Vec<u8>,
    campaign: PathBuf,
    campaign_sha256: String,
    work: PathBuf,
}

impl Inputs {
    pub fn options(&self) -> &Options {
        &self.options
    }

    /// The environment every Git call of the run is given: the caller's, the first variable of each name
    /// kept, with `GIT_NO_REPLACE_OBJECTS=1`.
    pub fn env(&self) -> &Environ {
        &self.env
    }

    /// The checkout's top level, its links resolved.
    pub fn top(&self) -> &Path {
        &self.top
    }

    /// The head commit's object name.
    pub fn head(&self) -> &str {
        &self.head
    }

    /// The plants the run selected, in store order.
    pub fn plants(&self) -> &[Plant] {
        &self.plants
    }

    /// The bytes of the checkout's `Cargo.lock`.
    pub fn lock(&self) -> &[u8] {
        &self.lock
    }

    /// The `campaign` binary, its links resolved.
    pub fn campaign(&self) -> &Path {
        &self.campaign
    }

    /// The SHA-256 of the `campaign` binary as 64 lowercase hexadecimal digits.
    pub fn campaign_sha256(&self) -> &str {
        &self.campaign_sha256
    }

    /// The score's path, `score.json` in the store.
    pub fn score(&self) -> PathBuf {
        self.top.join(STORE).join(SCORE)
    }

    /// The work directory the checks made.
    pub fn work(&self) -> &Path {
        &self.work
    }
}

/// What [`prepare`] returns.
#[derive(Debug)]
pub enum Outcome {
    /// The checked inputs; the work directory exists.
    Run(Box<Inputs>),
    /// The help text, which the caller writes to standard output before exiting 0.
    Help(String),
    /// The argument reader's refusal, which the caller writes to standard error before exiting with
    /// `code`.
    Usage { code: u8, text: String },
    /// Input the run refuses before any worktree, exit 2 in the tool; the reason follows
    /// `plant-runner rejected: `.
    Rejected(Text),
    /// A failure outside a plant, exit 4 in the tool.
    Failed(Text),
}

/// `prepare` checks a run's inputs: `args` after the tool's name, the environment `env` and the invoking
/// directory `here`, an absolute path or the error of reading it. A relative `--work`, `TMPDIR` or
/// `--campaign` is joined to `here` as given before its `..` is read lexically, so a caller passes the
/// physical path `std::env::current_dir` returns. Of a variable `env` names twice, the first is read and
/// passed on.
pub fn prepare(args: &[OsString], env: Environ, here: io::Result<PathBuf>) -> Outcome {
    let options = match parse(args) {
        Parsed::Run(options) => options,
        Parsed::Help(text) => return Outcome::Help(text),
        Parsed::Refused { code, text } => return Outcome::Usage { code, text },
    };
    match checked(options, env, here) {
        Ok(inputs) => Outcome::Run(Box::new(inputs)),
        Err(Stop::Rejected(reason)) => Outcome::Rejected(reason),
        Err(Stop::Failed(reason)) => Outcome::Failed(reason),
    }
}

/// `rev_parse` runs `git rev-parse ARGS` in `dir` and returns its output stripped, or `refusal` when it
/// exits nonzero.
fn rev_parse(env: &Environ, dir: &Path, args: &[&str], refusal: &str) -> Result<String, Stop> {
    let mut call = vec![OsStr::new("rev-parse")];
    call.extend(args.iter().map(OsStr::new));
    let done = git::text(env, dir, &call).map_err(Stop::git)?;
    if done.code != 0 {
        return Err(Stop::rejected(refusal));
    }
    Ok(strip_str(&done.stdout).to_owned())
}

fn checked(options: Options, env: Environ, here: io::Result<PathBuf>) -> Result<Inputs, Stop> {
    let mut env = first_of_each(env);
    set(&mut env, "GIT_NO_REPLACE_OBJECTS", OsString::from("1"));
    let overrides: Vec<&str> = REPOSITORY_VARIABLES
        .into_iter()
        .filter(|name| get(&env, name).is_some())
        .collect();
    if !overrides.is_empty() {
        return Err(Stop::rejected(format!(
            "{} would point the run's Git commands at another repository or index; unset them",
            overrides.join(", ")
        )));
    }
    let here = here
        .map_err(|error| Stop::failed(format!("the invoking directory cannot be read: {error}")))?;
    let found = rev_parse(
        &env,
        &here,
        &["--show-toplevel"],
        "the invoking directory is outside a Git checkout",
    )?;
    let top = paths::resolve(&here.join(found))
        .map_err(|error| Stop::failed(format!("the checkout's top: {error}")))?;
    let head = rev_parse(
        &env,
        &top,
        &["--verify", "HEAD^{commit}"],
        "the checkout names no HEAD commit",
    )?;
    let plants = load_plants(&env, &top, &head, options.plants())?;
    let lock = lock(&top)?;
    let path = get(&env, "PATH").map(OsString::as_os_str);
    let (campaign, campaign_sha256) = campaign(options.campaign(), path, &here)?;
    let tmpdir = get(&env, "TMPDIR").map(OsString::as_os_str);
    let work = work_directory(options.work(), tmpdir, &here, &top)?;
    Ok(Inputs {
        options,
        env,
        top,
        head,
        plants,
        lock,
        campaign,
        campaign_sha256,
        work,
    })
}
