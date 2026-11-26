use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::Duration;

use super::{Error, Request, text};
use crate::exit::Supervisor;
use crate::record::{Configuration, Purpose};
use crate::store::Store;

struct Args {
    values: BTreeMap<String, OsString>,
    settings: Vec<String>,
}

enum Action {
    CorpusAdd {
        archive: PathBuf,
        bundle: PathBuf,
        milestone: String,
        root: PathBuf,
    },
    CorpusRemove(crate::record::Digest),
    Admit {
        target: Option<(crate::record::Digest, Option<(u64, u64)>)>,
        request: Request,
        archive: PathBuf,
        root: PathBuf,
        watchdog: Duration,
    },
    Calibrate {
        request: Request,
        archive: PathBuf,
        root: PathBuf,
        watchdog: Duration,
    },
    Configure(Configuration),
    Triage {
        id: String,
        kind: crate::record::StepKind,
        alternate: Option<PathBuf>,
        root: PathBuf,
    },
    Dispatch {
        archive: PathBuf,
        root: PathBuf,
        seconds: Option<Duration>,
        max_attempts: Option<u64>,
        poll: Duration,
        kill_wait: Duration,
    },
}

impl Args {
    fn parse(command: &str, args: &[OsString]) -> Result<Self, Error> {
        let keys: &[&str] = match command {
            "corpus-add" => &[
                "--state",
                "--archive",
                "--bundle",
                "--milestone",
                "--cgroup-root",
            ],
            "corpus-remove" => &["--state", "--asset"],
            "calibrate" => &[
                "--state",
                "--archive",
                "--profile",
                "--run",
                "--watchdog",
                "--cgroup-root",
            ],
            "admit" => &[
                "--target",
                "--suffixes",
                "--siblings",
                "--explore",
                "--state",
                "--archive",
                "--profile",
                "--campaign",
                "--run",
                "--attempts",
                "--watchdog",
                "--cgroup-root",
            ],
            "dispatch" => &[
                "--state",
                "--archive",
                "--cgroup-root",
                "--for",
                "--max-attempts",
                "--poll",
                "--kill-wait",
            ],
            "triage" => &[
                "--state",
                "--from-run",
                "--step",
                "--archive",
                "--cgroup-root",
            ],
            "sweep" => &[
                "--root",
                "--archive",
                "--campaign",
                "--profiles",
                "--workers",
                "--batch",
                "--wall",
                "--for",
                "--memory",
                "--processes",
                "--cgroup-root",
                "--scope",
                "--verdict",
            ],
            "sweep-status" => &["--root"],
            "fuzz" => &[
                "--root",
                "--archive",
                "--for",
                "--workers",
                "--memory",
                "--processes",
                "--cgroup-root",
                "--scope",
                "--verdict",
            ],
            "fuzz-status" => &["--root"],
            "confirm" => &["--root", "--archive", "--slots", "--cgroup-root", "--scope"],
            "configure" | "show" | "findings" | "status" | "report" | "collect" => &["--state"],
            "dispose" => &["--state", "--finding", "--disposition", "--evidence"],
            _ => return Err(Error::Rejected("unknown campaign command".into())),
        };
        let flag = match command {
            "admit" => Some("--explore"),
            "collect" => Some("--dry-run"),
            _ => None,
        };
        let mut parsed = Self {
            values: BTreeMap::new(),
            settings: Vec::new(),
        };
        let mut rest = args;
        while let Some((key, next)) = rest.split_first() {
            if let Some(flag) = flag.filter(|flag| key == *flag) {
                if parsed
                    .values
                    .insert(flag.to_owned(), "true".into())
                    .is_some()
                {
                    return Err(Error::Rejected(format!("repeated {flag}")));
                }
                rest = next;
                continue;
            }
            let (value, next) = next
                .split_first()
                .ok_or_else(|| Error::Rejected("each option requires a value".into()))?;
            let pair = [key, value];
            rest = next;
            if pair[1].is_empty() {
                return Err(Error::Rejected(
                    "each option requires a nonempty value".into(),
                ));
            }
            let key = pair[0]
                .to_str()
                .ok_or_else(|| Error::Rejected("option must be ASCII".into()))?;
            if key == "--set" && matches!(command, "admit" | "calibrate" | "configure" | "sweep") {
                parsed.settings.push(
                    pair[1]
                        .to_str()
                        .ok_or_else(|| Error::Rejected("setting must be ASCII".into()))?
                        .to_owned(),
                );
            } else if !keys.contains(&key)
                || parsed
                    .values
                    .insert(key.to_owned(), pair[1].to_owned())
                    .is_some()
            {
                return Err(Error::Rejected(format!("unknown or repeated option {key}")));
            }
        }
        Ok(parsed)
    }
    fn required(&self, key: &str) -> Result<&OsString, Error> {
        self.values
            .get(key)
            .ok_or_else(|| Error::Rejected(format!("missing {key}")))
    }
    fn string(&self, key: &str) -> Result<&str, Error> {
        self.required(key)?
            .to_str()
            .ok_or_else(|| Error::Rejected(format!("{key} must be ASCII")))
    }
    fn number(&self, key: &str, default: u64) -> Result<u64, Error> {
        self.values
            .get(key)
            .map(|v| decimal(v.to_str().unwrap_or(""), true))
            .unwrap_or(Ok(default))
    }
    fn settings(&self, canonical: bool) -> Result<BTreeMap<crate::record::Text, u64>, Error> {
        self.settings
            .iter()
            .map(|setting| {
                let (key, value) = setting
                    .split_once('=')
                    .ok_or_else(|| Error::Rejected("setting requires KEY=COUNT".into()))?;
                Ok((text(key)?, decimal(value, canonical)?))
            })
            .collect()
    }
}

fn decimal(value: &str, canonical: bool) -> Result<u64, Error> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Rejected("count must be unsigned decimal".into()));
    }
    let count = value
        .parse::<u64>()
        .map_err(|e| Error::Rejected(e.to_string()))?;
    if canonical && value != count.to_string() {
        return Err(Error::Rejected("count must be canonical decimal".into()));
    }
    Ok(count)
}

fn window(value: &str) -> Result<Duration, Error> {
    if value.parse::<f64>() == Ok(0.0) && !value.starts_with('-') {
        return Ok(Duration::ZERO);
    }
    crate::sim::seconds(value).map_err(Error::Rejected)
}

/// What a command prints: a JSON value, the status snapshot, which
/// serializes straight to standard output, or a JSON value that reports a
/// verdict other than success, after which the command exits 1.
enum Output {
    Value(serde_json::Value),
    Status(Box<super::status::Snapshot>),
    Verdict(serde_json::Value),
}

impl Output {
    /// The class a command exits with once it has printed this output.
    fn exit(&self) -> Supervisor {
        match self {
            Self::Verdict(_) => Supervisor::Verdict,
            Self::Value(_) | Self::Status(_) => Supervisor::Success,
        }
    }
}

fn execute(command: &str, args: &[OsString]) -> Result<Output, Error> {
    if command == "status" {
        let args = Args::parse(command, args)?;
        let path = PathBuf::from(args.required("--state")?);
        return super::status(&path).map(|snapshot| Output::Status(Box::new(snapshot)));
    }
    let ran = match command {
        "sweep" | "sweep-status" | "confirm" => {
            sweep_campaign(command, &Args::parse(command, args)?)?
        }
        "fuzz" | "fuzz-status" => fuzz_campaign(command, &Args::parse(command, args)?)?,
        _ => return value(command, args).map(Output::Value),
    };
    Ok(output(command, ran))
}

/// What `command` prints for its result `ran`: a verdict when
/// [`is_verdict`] finds one.
fn output(command: &str, ran: serde_json::Value) -> Output {
    if is_verdict(command, &ran) {
        Output::Verdict(ran)
    } else {
        Output::Value(ran)
    }
}

/// `value` as a command's output, or `failure` after `value` is printed,
/// so the report of a window that a refusal or a rejection stopped
/// reaches standard output beside the failing exit.
fn reported(value: serde_json::Value, failure: Option<Error>) -> Result<serde_json::Value, Error> {
    match failure {
        None => Ok(value),
        Some(failure) => {
            let _ = writeln!(std::io::stdout().lock(), "{value}");
            Err(failure)
        }
    }
}

fn rooted(path: &OsString) -> Result<PathBuf, Error> {
    crate::store::absolute_host(std::path::Path::new(path))
        .map_err(|error| Error::Rejected(error.to_string()))
}

/// The cgroup root a `sweep`, `confirm` or `fuzz` divides: `--cgroup-root`, else
/// `CAMPAIGN_CGROUP_ROOT`, else the command's own cgroup when `--scope`
/// says it runs inside a scope [`in_scope`] made; `None` when the command
/// names none.
///
/// # Errors
///
/// [`Error::Rejected`] for a `--scope` value other than `own`, and
/// [`Error::Held`] when the command's own cgroup cannot be read.
fn cgroup(args: &Args) -> Result<Option<PathBuf>, Error> {
    let scoped = match args.values.get("--scope") {
        None => false,
        Some(value) if value == "own" => true,
        Some(_) => return Err(Error::Rejected("--scope takes the value own".into())),
    };
    if let Some(root) = args
        .values
        .get("--cgroup-root")
        .cloned()
        .or_else(|| std::env::var_os("CAMPAIGN_CGROUP_ROOT"))
    {
        return Ok(Some(PathBuf::from(root)));
    }
    if scoped {
        return crate::store::cgroup::own()
            .map(Some)
            .map_err(|error| Error::Held(error.to_string()));
    }
    Ok(None)
}

/// Runs `command` again with `args` inside a delegated systemd scope,
/// whose output is the inner command's, and returns what [`scoped`] makes
/// of that run's end.
fn in_scope(command: &str, args: &Args, root: &Path) -> Result<serde_json::Value, Error> {
    let mut argv: Vec<OsString> = vec![command.into()];
    for (key, value) in &args.values {
        argv.extend([key.into(), value.clone()]);
    }
    for setting in &args.settings {
        argv.extend(["--set".into(), setting.into()]);
    }
    let token = super::scope::token();
    argv.extend(["--scope".into(), "own".into()]);
    if matches!(command, "sweep" | "fuzz") {
        argv.extend(["--verdict".into(), token.clone()]);
    }
    scoped(command, super::scope::run(argv)?, root, &token)
}

/// A sweep exits 1 for `alarm`, `no_pass`, `unreached` or `no_window` in
/// its totals, a fuzz run for a missed control, and each for the recorded
/// exit 1 of a scoped invocation. For every other command `is_verdict`
/// returns `false` on success.
fn is_verdict(command: &str, value: &serde_json::Value) -> bool {
    let verdict = match command {
        "sweep" => super::seeds::carries_verdict(value),
        "fuzz" => super::seeds::fuzz::missed(value),
        _ => return false,
    };
    verdict || value["exit"] == 1
}

/// Records under `root` the verdict of a scoped `command`, a sweep or a
/// fuzz run, whose result is `ran`, for the command that gave it `token`.
/// That command reads its exit 1 as this verdict only beside this record.
fn record(
    command: &str,
    root: &Path,
    token: Option<&OsString>,
    ran: &serde_json::Value,
) -> Result<(), Error> {
    match token {
        Some(token) if is_verdict(command, ran) => super::scope::record_verdict(root, token),
        _ => Ok(()),
    }
}

/// The result of a scoped `command` that this command named `token` and
/// whose run ended with `status`: `{"exit": 1}` for the exit 1 of a
/// `sweep` or a `fuzz` when that run recorded its verdict under `root`,
/// else `{"exit": 0}` after a success or the failure
/// [`ended`](super::scope::ended) maps that end to.
fn scoped(
    command: &str,
    status: ExitStatus,
    root: &Path,
    token: &OsString,
) -> Result<serde_json::Value, Error> {
    if matches!(command, "sweep" | "fuzz")
        && status.code() == Some(1)
        && super::scope::recorded_verdict(root, token)?
    {
        return Ok(serde_json::json!({"exit": 1}));
    }
    super::scope::ended(command, status)?;
    Ok(serde_json::json!({"exit": status.code()}))
}

/// The token a scoped sweep or fuzz run records its verdict under, which
/// the command that made its scope named it with.
///
/// # Errors
///
/// [`Error::Rejected`] for a token given without `--scope` or one that
/// [`scope::names`](super::scope::names) refuses.
fn verdict_token(args: &Args) -> Result<Option<&OsString>, Error> {
    match args.values.get("--verdict") {
        Some(token) if !(args.values.contains_key("--scope") && super::scope::names(token)) => Err(
            Error::Rejected("--verdict takes the token of a scoped run".into()),
        ),
        token => Ok(token),
    }
}

/// Runs `campaign sweep`, prints the totals of a sweep root for
/// `sweep-status`, or admits and dispatches a sweep root's suspects for
/// `confirm`. A `sweep` or `confirm` with no cgroup root runs itself
/// again through [`in_scope`].
fn sweep_campaign(command: &str, args: &Args) -> Result<serde_json::Value, Error> {
    let root = rooted(args.required("--root")?)?;
    let seconds = |key: &str| {
        args.values
            .get(key)
            .map(|v| window(v.to_str().unwrap_or("")))
            .transpose()
    };
    match command {
        "sweep-status" => super::seeds::status(&root)?
            .ok_or_else(|| Error::Rejected("the root holds no sweep".into())),
        "confirm" => {
            let archive = rooted(args.required("--archive")?)?;
            let slots = args.number("--slots", 8)?;
            match cgroup(args)? {
                Some(cgroup) => {
                    let confirmed = super::confirm::confirm(&root, &archive, cgroup, slots)?;
                    reported(confirmed.value, confirmed.stopped)
                }
                None => in_scope(command, args, &root),
            }
        }
        _ => {
            let archive = rooted(args.required("--archive")?)?;
            let campaign = text(args.string("--campaign")?)?;
            let profiles = args
                .string("--profiles")?
                .split(',')
                .map(text)
                .collect::<Result<Vec<_>, _>>()?;
            let counts = args.settings(true)?;
            let workers = args.number("--workers", 1)?;
            let batch = seconds("--batch")?.unwrap_or(Duration::from_secs(30));
            let wall = seconds("--wall")?.unwrap_or(Duration::from_secs(600));
            let length = seconds("--for")?;
            let memory = args.number("--memory", 2 << 30)?;
            let processes = args.number("--processes", 64)?;
            if profiles.iter().any(|profile| profile.as_str().is_empty())
                || !(1..=super::seeds::WORKERS).contains(&workers)
                || batch.is_zero()
                || wall.is_zero()
                || memory == 0
                || !(1..=crate::custody::MAX_PIDS).contains(&processes)
            {
                return Err(Error::Rejected(format!(
                    "sweep needs profiles, 1 to 1024 workers, a batch, a wall limit, a memory limit and 1 to {} processes",
                    crate::custody::MAX_PIDS
                )));
            }
            let verdict = verdict_token(args)?;
            // The range checks above, and for a sweep that names no cgroup
            // root the checks of its campaign, profile names and counts,
            // come before a scope is made, so each of those refusals is a
            // rejection on a host that can start no scope too. The checks
            // that read the root, the archive or the listing run inside the
            // scope.
            let Some(cgroup) = cgroup(args)? else {
                super::seeds::accepted(&campaign, &profiles, &counts)?;
                return in_scope(command, args, &root);
            };
            let plan = super::seeds::Plan {
                root,
                archive,
                campaign,
                profiles,
                counts,
                workers,
                batch,
                wall,
                seconds: length,
                cgroup,
                memory,
                processes,
            };
            let swept = super::seeds::sweep(&plan)?;
            record(command, &plan.root, verdict, &swept)?;
            Ok(swept)
        }
    }
}

/// Runs `campaign fuzz`, or prints the `fuzz.json` of a fuzz root for
/// `fuzz-status`. The range checks and the root and archive paths' byte
/// check come before a scope is made, so each refusal is a rejection on a
/// host that can start no scope too. A `fuzz` with no cgroup root runs
/// itself again through [`in_scope`].
fn fuzz_campaign(command: &str, args: &Args) -> Result<serde_json::Value, Error> {
    use super::seeds::fuzz;
    let root = rooted(args.required("--root")?)?;
    if command == "fuzz-status" {
        return fuzz::status(&root)?
            .ok_or_else(|| Error::Rejected("the root holds no fuzz run".into()));
    }
    let archive = rooted(args.required("--archive")?)?;
    let seconds = decimal(args.string("--for")?, true)?;
    let workers = args.number("--workers", 1)?;
    let memory = args.number("--memory", fuzz::MEMORY)?;
    let processes = args.number("--processes", 64)?;
    if !(1..=fuzz::SECONDS).contains(&seconds)
        || !(1..=super::seeds::WORKERS).contains(&workers)
        || memory == 0
        || !(1..=crate::custody::MAX_PIDS).contains(&processes)
    {
        return Err(Error::Rejected(format!(
            "fuzz needs 1 to {} seconds, 1 to 1024 workers, a memory limit and 1 to {} processes",
            fuzz::SECONDS,
            crate::custody::MAX_PIDS
        )));
    }
    fuzz::accepted(&root, &archive)?;
    let verdict = verdict_token(args)?;
    let Some(cgroup) = cgroup(args)? else {
        return in_scope(command, args, &root);
    };
    let plan = fuzz::Plan {
        root,
        archive,
        seconds,
        workers,
        cgroup,
        memory,
        processes,
    };
    let ran = fuzz::fuzz(&plan)?;
    record(command, &plan.root, verdict, &ran)?;
    Ok(ran)
}

fn value(command: &str, args: &[OsString]) -> Result<serde_json::Value, Error> {
    let (command, args) = if command == "corpus" {
        let (operation, args) = args
            .split_first()
            .ok_or_else(|| Error::Rejected("corpus requires add or remove".into()))?;
        (
            match operation.to_str() {
                Some("add") => "corpus-add",
                Some("remove") => "corpus-remove",
                _ => return Err(Error::Rejected("corpus requires add or remove".into())),
            },
            args,
        )
    } else {
        (command, args)
    };
    let args = Args::parse(command, args)?;
    let path = PathBuf::from(args.required("--state")?);
    let action = match command {
        "corpus-add" => {
            let root = args
                .values
                .get("--cgroup-root")
                .cloned()
                .or_else(|| std::env::var_os("CAMPAIGN_CGROUP_ROOT"))
                .ok_or_else(|| {
                    Error::Rejected("corpus add requires a delegated cgroup root".into())
                })?;
            crate::custody::Custody::check_root(std::path::Path::new(&root))?;
            Action::CorpusAdd {
                archive: PathBuf::from(args.required("--archive")?),
                bundle: PathBuf::from(args.required("--bundle")?),
                milestone: args.string("--milestone")?.to_owned(),
                root: root.into(),
            }
        }
        "corpus-remove" => Action::CorpusRemove(
            crate::record::Digest::parse(args.string("--asset")?)
                .ok_or_else(|| Error::Rejected("invalid corpus asset digest".into()))?,
        ),
        "show" => return super::show(&path),
        "report" => return super::report(&path),
        "collect" => return super::collect::collect(&path, args.values.contains_key("--dry-run")),
        "findings" => return super::findings(&path),
        "dispose" => {
            let label = args.string("--disposition")?;
            let decision = crate::record::Decision::ALL
                .iter()
                .copied()
                .find(|decision| decision.name() == label)
                .ok_or_else(|| Error::Rejected("unknown disposition".into()))?;
            return super::dispose(
                &path,
                text(args.string("--finding")?)?,
                decision,
                text(args.string("--evidence")?)?,
            );
        }
        "triage" => {
            super::triage::controller_limit()?;
            let label = args.string("--step")?;
            let kind = crate::record::StepKind::ALL
                .iter()
                .copied()
                .find(|kind| kind.name() == label)
                .ok_or_else(|| Error::Rejected("unknown triage step".into()))?;
            let id = args.string("--from-run")?.to_owned();
            if crate::store::Name::new(&id).is_none() {
                return Err(Error::Rejected("invalid retained run id".into()));
            }
            let root = args
                .values
                .get("--cgroup-root")
                .cloned()
                .or_else(|| std::env::var_os("CAMPAIGN_CGROUP_ROOT"))
                .ok_or_else(|| Error::Rejected("triage requires a delegated cgroup root".into()))?;
            crate::custody::Custody::check_root(std::path::Path::new(&root))?;
            Action::Triage {
                id,
                kind,
                alternate: args.values.get("--archive").map(PathBuf::from),
                root: root.into(),
            }
        }
        "admit" | "calibrate" => {
            let calibration = command == "calibrate";
            let purpose = if calibration {
                Purpose::Calibration
            } else {
                Purpose::Campaign
            };
            let target = args
                .values
                .get("--target")
                .map(|value| {
                    let id = value
                        .to_str()
                        .and_then(crate::record::Digest::parse)
                        .ok_or_else(|| Error::Rejected("invalid target asset".into()))?;
                    let branch = if args.values.contains_key("--explore") {
                        if args.values.contains_key("--suffixes")
                            || args.values.contains_key("--siblings")
                        {
                            return Err(Error::Rejected(
                                "explore takes tree bounds from its asset".into(),
                            ));
                        }
                        None
                    } else {
                        if !args.values.contains_key("--suffixes") {
                            return Err(Error::Rejected(
                                "targeted branch requires --suffixes or --explore".into(),
                            ));
                        }
                        Some((args.number("--suffixes", 0)?, args.number("--siblings", 1)?))
                    };
                    Ok((id, branch))
                })
                .transpose()?;
            if target.is_none()
                && ["--suffixes", "--siblings", "--explore"]
                    .iter()
                    .any(|key| args.values.contains_key(*key))
            {
                return Err(Error::Rejected("fork bounds require --target".into()));
            }
            if target.is_some() && args.values.contains_key("--profile") {
                return Err(Error::Rejected(
                    "target profile comes from the asset".into(),
                ));
            }
            let request = Request {
                profile: text(if target.is_some() {
                    "target"
                } else {
                    args.string("--profile")?
                })?,
                campaign: if calibration {
                    text("calibration")?
                } else {
                    text(args.string("--campaign")?)?
                },
                run: args.number("--run", 0)?,
                attempts: args.number("--attempts", super::freeze::ATTEMPTS)?,
                counts: args.settings(true)?,
            };
            request.validate(purpose)?;
            let archive = PathBuf::from(args.required("--archive")?);
            let root = args
                .values
                .get("--cgroup-root")
                .cloned()
                .or_else(|| std::env::var_os("CAMPAIGN_CGROUP_ROOT"))
                .ok_or_else(|| {
                    Error::Rejected("admission needs --cgroup-root or CAMPAIGN_CGROUP_ROOT".into())
                })?;
            let root = PathBuf::from(root);
            crate::custody::Custody::check_root(&root)
                .map_err(|error| Error::Rejected(error.to_string()))?;
            let watchdog = args
                .values
                .get("--watchdog")
                .map(|v| crate::sim::seconds(v.to_str().unwrap_or("")))
                .transpose()
                .map_err(Error::Rejected)?
                .unwrap_or(Duration::from_secs(300));
            if watchdog > Duration::from_secs(86_400) {
                return Err(Error::Rejected("watchdog exceeds 86400 seconds".into()));
            }
            if crate::sys::file_limit().map_err(|error| Error::Held(error.to_string()))?
                < crate::record::BOUND
            {
                return Err(Error::Rejected(
                    "output limit exceeds the inherited hard limit".into(),
                ));
            }
            if calibration {
                Action::Calibrate {
                    request,
                    archive,
                    root,
                    watchdog,
                }
            } else {
                Action::Admit {
                    target,
                    request,
                    archive,
                    root,
                    watchdog,
                }
            }
        }
        "dispatch" => {
            let root = args
                .values
                .get("--cgroup-root")
                .cloned()
                .or_else(|| std::env::var_os("CAMPAIGN_CGROUP_ROOT"))
                .ok_or_else(|| {
                    Error::Rejected("dispatch requires a delegated cgroup root".into())
                })?;
            let duration = |key: &str| {
                args.values
                    .get(key)
                    .map(|v| crate::sim::seconds(v.to_str().unwrap_or("")))
                    .transpose()
                    .map_err(Error::Rejected)
            };
            crate::custody::Custody::check_root(std::path::Path::new(&root))?;
            Action::Dispatch {
                archive: PathBuf::from(args.required("--archive")?),
                root: PathBuf::from(root),
                seconds: args
                    .values
                    .get("--for")
                    .map(|v| window(v.to_str().unwrap_or("")))
                    .transpose()?,
                max_attempts: args
                    .values
                    .get("--max-attempts")
                    .map(|v| decimal(v.to_str().unwrap_or(""), true))
                    .transpose()?,
                poll: duration("--poll")?.unwrap_or(Duration::from_millis(50)),
                kill_wait: duration("--kill-wait")?.unwrap_or(Duration::from_secs(5)),
            }
        }
        "configure" => Action::Configure(super::configuration::prepare(args.settings(false)?)?),
        _ => return Err(Error::Rejected("unknown campaign command".into())),
    };
    crate::store::given_ancestors(&path).map_err(Error::input_path)?;
    crate::store::create_dirs(&path).map_err(|e| Error::Held(e.to_string()))?;
    let store = Store::open(&path)?;
    store.check_path()?;
    match action {
        Action::CorpusAdd {
            archive,
            bundle,
            milestone,
            root,
        } => {
            let (asset, version) =
                super::corpus::add(&store, &archive, &bundle, &milestone, &root)?;
            Ok(
                serde_json::json!({"asset": asset.id(), "semantic_key": asset.semantic_key(), "version": version, "state": "registered"}),
            )
        }
        Action::CorpusRemove(asset) => Ok(
            serde_json::json!({"asset": asset, "version": super::corpus::remove(&store, asset)?, "state": "retired"}),
        ),
        Action::Admit {
            target,
            request,
            archive,
            root,
            watchdog,
        } => {
            let outcome = match target {
                Some((asset, branch)) => super::targeted::admit(
                    &store, &archive, &root, watchdog, &request, asset, branch,
                )?,
                None => super::admit_campaign(&store, &archive, &root, watchdog, &request)?,
            };
            Ok(
                serde_json::json!({"id": outcome.record.job().id().to_string(), "seed": outcome.record.job().seed(), "state": if outcome.existing {"existing"} else {"admitted"}}),
            )
        }
        Action::Calibrate {
            request,
            archive,
            root,
            watchdog,
        } => {
            let record = super::calibration::execute(&store, &archive, &root, &request, watchdog)?;
            Ok(serde_json::to_value(record).expect("calibration result encodes"))
        }
        Action::Triage {
            id,
            kind,
            alternate,
            root,
        } => {
            let config = store
                .read_record::<Configuration>(store.root(), &super::name("config.json"))?
                .ok_or_else(|| Error::Held("triage configuration missing".into()))?;
            store.barrier(config.read())?;
            let config = config.record();
            let mut custody = crate::custody::Custody::open(
                &root,
                crate::custody::Timing {
                    poll: Duration::from_millis(50),
                    kill_wait: Duration::from_secs(5),
                    watchdog: Duration::from_secs(config.value("wall")),
                },
            )?;
            let executable = crate::store::canonical_host(std::path::Path::new("/proc/self/exe"))
                .map_err(|error| Error::Held(error.to_string()))?;
            let result = super::triage::execute(
                &store,
                &mut custody,
                &id,
                kind,
                alternate.as_deref(),
                config,
                crate::attempt::Launch {
                    gate: executable.clone(),
                    launcher: executable,
                    environment: BTreeMap::new(),
                    limits: super::configuration::limits(config),
                },
            )?;
            Ok(result.value())
        }
        Action::Dispatch {
            archive,
            root,
            seconds,
            max_attempts,
            poll,
            kill_wait,
        } => {
            let deadline = seconds
                .map(|seconds| {
                    std::time::Instant::now()
                        .checked_add(seconds)
                        .ok_or_else(|| Error::Rejected("dispatch deadline overflows".into()))
                })
                .transpose()?;
            let mut custody = crate::custody::Custody::open(
                &root,
                crate::custody::Timing {
                    poll,
                    kill_wait,
                    watchdog: Duration::from_secs(300),
                },
            )?;
            let executable = crate::store::canonical_host(std::path::Path::new("/proc/self/exe"))
                .map_err(|e| Error::Held(e.to_string()))?;
            let report = super::dispatch::dispatch(
                &store,
                &mut custody,
                &super::dispatch::Options {
                    archive,
                    gate: executable.clone(),
                    launcher: executable,
                    environment: BTreeMap::new(),
                    deadline,
                    max_attempts,
                },
            )?;
            let value = serde_json::to_value(&report).expect("dispatch report encodes");
            reported(value, report.failure())
        }
        Action::Configure(config) => {
            Ok(serde_json::json!({"config": super::configure(&store, config)?}))
        }
    }
}

pub fn run(command: &str, args: &[OsString]) -> Supervisor {
    if command == "corpus"
        && ((args.len() == 1 && args[0] == "--help")
            || (args.len() == 2
                && (args[0] == "add" || args[0] == "remove")
                && args[1] == "--help"))
    {
        let _ = writeln!(
            std::io::stdout().lock(),
            "usage: campaign corpus add --state DIR --archive DIR --bundle FILE --milestone NAME [--cgroup-root DIR]\n       campaign corpus remove --state DIR --asset DIGEST\nConfigure corpus_count and corpus_bytes before registration. Registration requires a verified one-suffix probe under custody. A probe's attempt_output holds two bundle copies, four 1 MiB stream bounds and controller-record bytes; its attempt_inodes hold two bundle files, the fixed branch files and controller inodes. Every probe directory stays in probes/ and the census charges it the running-attempt charge against artifact_bytes and artifact_inodes. Retirement keeps probe bytes counted toward corpus_bytes and frees one corpus_count slot. The cgroup root defaults to CAMPAIGN_CGROUP_ROOT."
        );
        return Supervisor::Success;
    }
    if command == "admit" && args.len() == 1 && args[0] == "--help" {
        let _ = writeln!(
            std::io::stdout().lock(),
            "usage: campaign admit --state DIR --archive DIR --campaign NAME --profile NAME [--run N] [--attempts N] [--set KEY=COUNT] [--watchdog SECONDS] [--cgroup-root DIR]\n       campaign admit --state DIR --archive DIR --campaign NAME --target ASSET (--suffixes N [--siblings M] | --explore) [--run N] [--attempts N] [--watchdog SECONDS] [--cgroup-root DIR]\nTargeted admission freezes an active corpus asset and the corpus version current at admission. Branch suffixes range from 1 to 16 and siblings from 1 to 4. Exploration uses the asset's manifest bounds. Retired assets exit 2 before a probe or job write. Admitted jobs keep their own replay inputs through retirement. The cgroup root defaults to CAMPAIGN_CGROUP_ROOT; --cgroup-root supplies an explicit root."
        );
        return Supervisor::Success;
    }
    if command == "triage" && args.len() == 1 && args[0] == "--help" {
        let _ = writeln!(
            std::io::stdout().lock(),
            "usage: campaign triage --state DIR --from-run FINDING_ID --step replay|rerun|reduce [--archive DIR] [--cgroup-root DIR]\nTargeted findings support explicit replay. Child finding IDs append a child label to the parent attempt. Explicit commands may repeat a bounded step under the triage reserve. Each repeat creates a new step and preserves earlier records. A reduced or unreducible result ends automatic reduction for the finding; explicit reduce may repeat. Triage preserves the finding's disposition. A drain exits 0 and prints its drained or interrupted state. The cgroup root defaults to CAMPAIGN_CGROUP_ROOT. The archive option validates the recorded build; execution uses the recorded archive."
        );
        return Supervisor::Success;
    }
    match execute(command, args) {
        Ok(output) => {
            let mut stdout = std::io::BufWriter::with_capacity(64 << 10, std::io::stdout().lock());
            let written = match &output {
                Output::Value(value) | Output::Verdict(value) => {
                    serde_json::to_writer(&mut stdout, value).map_err(std::io::Error::from)
                }
                Output::Status(snapshot) => snapshot.write(&mut stdout),
            };
            let _ = written
                .and_then(|()| writeln!(stdout))
                .and_then(|()| stdout.flush());
            output.exit()
        }
        Err(error) => {
            let _ = writeln!(std::io::stderr().lock(), "campaign {command}: {error}");
            error.exit()
        }
    }
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;
