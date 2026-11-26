//! The `sim-host` command line: one subcommand and its flags, parsed into
//! a [`Command`] whose values are already range-checked. A refused command
//! line exits [`EXIT_USAGE`].

use std::collections::BTreeMap;
use std::path::PathBuf;

pub const USAGE: &str = "\
usage: sim-host run --state DIR --bucket NAME [HOST OPTIONS] [--disk-reserve BYTES]
           [--system-memory BYTES]
       sim-host check --bucket NAME [HOST OPTIONS] [--system-memory BYTES]
       sim-host status --state DIR
       sim-host publish --checkout DIR --state DIR --bucket NAME [--interval SECONDS]
       sim-host report --bucket NAME [--build ID]
       sim-host watch --bucket NAME --state DIR [--interval SECONDS]

HOST OPTIONS:
  --cgroup DIR            the unit's delegated cgroup, an absolute path
                          without `..` (default: this process's cgroup-v2
                          group)
  --confirm-slots N       attempts `campaign confirm` runs at once, at
                          least 1 (default 8)
  --system-cores N        cores left to the system (default 4)

  --disk-reserve BYTES    free bytes below which a stint is skipped
                          (default 68719476736, 64 GiB)
  --system-memory BYTES   memory check and run leave to the system, the
                          runner and the controllers (default 4294967296,
                          4 GiB)
  --interval SECONDS      seconds publish waits after each fetch of main,
                          and watch after each cycle, 1 to 4294967295
                          (default 60 for publish, 300 for watch)

run keeps the host sweeping until SIGTERM or SIGINT, then exits 0 after
its children stop. Until a stop is requested it starts an upload of its
health record to hosts/<instance-id>/health.json at least every half
stint length and every 300 seconds while its poll runs, and at a stop it
stores a record in phase stopped last; the host's role needs write
access to its own hosts/<instance-id>/. It exits
2 when it cannot start: another runner holds the state directory, the
instance id, the state, the cgroup layout or the signal handlers fail. It
exits 1 when a stint ends with an error, such as a failed write of its
state; a new root that cannot be recorded pauses the runner in phase
blocked instead. check reads assignment.json from the bucket, prints the
partition and exits 0, or 2 when it refuses it. status prints the health
record and exits 0, 1 for a warning, or 2 for a critical condition.
publish stores each new head of main once, until SIGTERM or SIGINT.
report prints the host set's totals, one row per host under hosts and one
count per host state under host_counts, and exits 0, 1 for a flag, 2 for
a silent or unhealthy host or a root flagged alarm, no_pass, unreached or
no_window, or 3 when the bucket cannot be read. A host is missing (1) when its record cannot be
read or parsed or contradicts its key, or when it uploads snapshots with
no record; silent (2) when its record has a stint length of 1 to
4294967295 seconds and is older than two of them; stopped, with no flag,
when such a fresh record has phase stopped; unhealthy (2) when its record
has no such stint length; and else unhealthy (2), degraded (1) or active
by its status verdict. A planned restart raises no flag while the stored
record stays within two stint lengths of its written. Deleting a host's
record retires the host once its newest snapshot is older than two stint
lengths. --build ID, a build's SHA-256 in lowercase hex, limits the
totals and the per-root flags to that build's roots; host flags and
unreadable envelopes of every build still set the exit code. watch runs
one cycle, waits --interval seconds and repeats, until SIGTERM or SIGINT,
then exits 0. Each cycle that reaches its report step replaces
reports/latest.json once with the report document, the cycle's seconds
up to that put, the whole seconds of the cycle before it and the second
written. The watch creates one events/failure-<id>.json per new failure
identity, holding its profile, key, build, count, roots and rerun line;
one events/hosts-<unix seconds>.json per cycle in which a host turned
unhealthy, silent or missing, listing each opened alert with its host
and reasons; and one events/digest-<yyyy-mm-dd>.json per UTC day, with
the host counts, build totals, known identities and flag counts. It exits 2 when it cannot
start: another watch holds the state directory, the state directory or
the signal handlers fail, or events/failure- lists more than 1048576
objects. Its role lists and reads the bucket and writes only under
reports/ and events/, with no delete. The bucket keeps every
events/failure-* object: a deleted record makes the watch announce its
identity again once the watch restarts and a report still lists it. One
state directory, with its cache and its open alerts, serves one bucket.
The watch runs on its own host with its own role, shared with no runner or
publisher. A usage error exits 64.

SIM_HOST_METADATA=HOST:PORT names the instance metadata service; unset, it
is 169.254.169.254:80. A simulation host leaves it unset.
";

pub const EXIT_USAGE: u8 = 64;
pub const DEFAULT_CONFIRM_SLOTS: u64 = 8;
pub const DEFAULT_SYSTEM_CORES: u64 = 4;
pub const DEFAULT_DISK_RESERVE: u64 = 64 << 30;
pub const DEFAULT_SYSTEM_MEMORY: u64 = 4 << 30;
pub const DEFAULT_INTERVAL: u64 = 60;
pub const DEFAULT_WATCH_INTERVAL: u64 = 300;

#[derive(Clone, Debug, PartialEq)]
pub struct Host {
    pub bucket: String,
    pub cgroup: Option<PathBuf>,
    pub confirm_slots: u64,
    pub system_cores: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Run {
    pub state: PathBuf,
    pub disk_reserve: u64,
    pub system_memory: u64,
    pub host: Host,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Check {
    pub host: Host,
    pub system_memory: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Publish {
    pub checkout: PathBuf,
    pub state: PathBuf,
    pub bucket: String,
    pub interval: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Watch {
    pub bucket: String,
    pub state: PathBuf,
    pub interval: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    Run(Run),
    Check(Check),
    Status {
        state: PathBuf,
    },
    Publish(Publish),
    Report {
        bucket: String,
        build: Option<String>,
    },
    Watch(Watch),
}

#[derive(Clone, Copy)]
enum Kind {
    Run,
    Check,
    Status,
    Publish,
    Report,
    Watch,
}

pub fn parse(args: &[String]) -> Result<Command, String> {
    let (command, rest) = args.split_first().ok_or("no command")?;
    let (kind, allowed): (Kind, &[&str]) = match command.as_str() {
        "run" => (
            Kind::Run,
            &[
                "--state",
                "--bucket",
                "--cgroup",
                "--confirm-slots",
                "--system-cores",
                "--disk-reserve",
                "--system-memory",
            ],
        ),
        "check" => (
            Kind::Check,
            &[
                "--bucket",
                "--cgroup",
                "--confirm-slots",
                "--system-cores",
                "--system-memory",
            ],
        ),
        "status" => (Kind::Status, &["--state"]),
        "publish" => (
            Kind::Publish,
            &["--checkout", "--state", "--bucket", "--interval"],
        ),
        "report" => (Kind::Report, &["--bucket", "--build"]),
        "watch" => (Kind::Watch, &["--bucket", "--state", "--interval"]),
        other => return Err(format!("unknown command {other:?}")),
    };
    let mut values = BTreeMap::new();
    let mut rest = rest.iter();
    while let Some(flag) = rest.next() {
        if !allowed.contains(&flag.as_str()) {
            return Err(format!("{command} takes no {flag:?}"));
        }
        let value = rest.next().ok_or_else(|| format!("{flag} needs a value"))?;
        if values.insert(flag.as_str(), value.as_str()).is_some() {
            return Err(format!("{flag} is given twice"));
        }
    }
    let text = |flag: &str| {
        values
            .get(flag)
            .map(|value| (*value).to_owned())
            .ok_or_else(|| format!("{command} needs {flag}"))
    };
    let path = |flag: &str| text(flag).map(PathBuf::from);
    let number = |flag: &str, default: u64| {
        values.get(flag).map_or(Ok(default), |value| {
            value
                .parse::<u64>()
                .map_err(|_| format!("{flag} {value:?} is no whole number"))
        })
    };
    let bucket = || {
        let bucket = text("--bucket")?;
        if bucket.is_empty()
            || !bucket.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte)
            })
        {
            return Err(format!("--bucket {bucket:?} is no bucket name"));
        }
        Ok(bucket)
    };
    let host = || -> Result<Host, String> {
        let host = Host {
            bucket: bucket()?,
            cgroup: values.get("--cgroup").map(PathBuf::from),
            confirm_slots: number("--confirm-slots", DEFAULT_CONFIRM_SLOTS)?,
            system_cores: number("--system-cores", DEFAULT_SYSTEM_CORES)?,
        };
        if host.confirm_slots == 0 {
            return Err("--confirm-slots must be at least 1".into());
        }
        if let Some(dir) = &host.cgroup
            && !crate::cgroup::is_plain_absolute(dir)
        {
            return Err(format!(
                "--cgroup {} must be an absolute path without `..`",
                dir.display()
            ));
        }
        Ok(host)
    };
    let interval = |default: u64| {
        let interval = number("--interval", default)?;
        if (1..=crate::assignment::SECONDS_MAX).contains(&interval) {
            Ok(interval)
        } else {
            Err(format!(
                "--interval {interval} is not 1 to {}",
                crate::assignment::SECONDS_MAX
            ))
        }
    };
    match kind {
        Kind::Run => Ok(Command::Run(Run {
            state: path("--state")?,
            disk_reserve: number("--disk-reserve", DEFAULT_DISK_RESERVE)?,
            system_memory: number("--system-memory", DEFAULT_SYSTEM_MEMORY)?,
            host: host()?,
        })),
        Kind::Check => Ok(Command::Check(Check {
            host: host()?,
            system_memory: number("--system-memory", DEFAULT_SYSTEM_MEMORY)?,
        })),
        Kind::Status => Ok(Command::Status {
            state: path("--state")?,
        }),
        Kind::Publish => Ok(Command::Publish(Publish {
            checkout: path("--checkout")?,
            state: path("--state")?,
            bucket: bucket()?,
            interval: interval(DEFAULT_INTERVAL)?,
        })),
        Kind::Watch => Ok(Command::Watch(Watch {
            bucket: bucket()?,
            state: path("--state")?,
            interval: interval(DEFAULT_WATCH_INTERVAL)?,
        })),
        Kind::Report => {
            let build = values.get("--build").map(|build| (*build).to_owned());
            if build
                .as_deref()
                .is_some_and(|build| !crate::file::is_sha256(build))
            {
                return Err("--build takes a build's SHA-256".into());
            }
            Ok(Command::Report {
                bucket: bucket()?,
                build,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    /// The arguments after the program of a unit file's `ExecStart` line,
    /// with the bucket placeholder replaced by a bucket name.
    fn exec_start(unit: &str) -> Vec<String> {
        let line = unit
            .lines()
            .find_map(|line| line.strip_prefix("ExecStart="))
            .expect("the unit has an ExecStart line");
        let mut words = args(&line.replace("SIM_BUCKET", "sims"));
        assert_eq!(words.remove(0), "/usr/local/bin/sim-host");
        words
    }

    #[test]
    fn the_shipped_units_pass_arguments_the_command_line_accepts() {
        let Ok(Command::Run(run)) = parse(&exec_start(include_str!("../sim-host.service"))) else {
            panic!("the runner unit runs `run`");
        };
        assert_eq!(run.host.confirm_slots, 1);
        assert_eq!(run.host.system_cores, 0);
        assert_eq!(run.disk_reserve, 16 << 30);
        let publish = exec_start(include_str!("../sim-host-publish.service"));
        assert_eq!(publish[0], "publish");
        assert!(matches!(parse(&publish), Ok(Command::Publish(_))));
    }

    #[test]
    fn each_command_takes_its_flags_and_refuses_others() {
        let Ok(Command::Run(run)) = parse(&args(
            "run --state /s --bucket sims --confirm-slots 2 --disk-reserve 10",
        )) else {
            panic!("run parses");
        };
        assert_eq!(run.host.confirm_slots, 2);
        assert_eq!(run.host.system_cores, DEFAULT_SYSTEM_CORES);
        assert_eq!(run.disk_reserve, 10);
        assert!(parse(&args("status --state /s")).is_ok());
        let Ok(Command::Check(check)) =
            parse(&args("check --bucket sims --cgroup /g --system-memory 5"))
        else {
            panic!("check parses");
        };
        assert_eq!(check.system_memory, 5);
        assert_eq!(check.host.confirm_slots, DEFAULT_CONFIRM_SLOTS);
        assert!(parse(&args("publish --checkout /c --state /s --bucket sims")).is_ok());
        assert!(parse(&args("report --bucket sims")).is_ok());
        assert_eq!(
            parse(&args("watch --bucket sims --state /w")),
            Ok(Command::Watch(Watch {
                bucket: "sims".into(),
                state: "/w".into(),
                interval: 300,
            })),
            "the watch waits 300 seconds by default"
        );
        let Ok(Command::Publish(publish)) =
            parse(&args("publish --checkout /c --state /s --bucket sims"))
        else {
            panic!("publish parses");
        };
        assert_eq!(publish.interval, 60, "the publisher keeps its default");
        for interval in [1, 4_294_967_295] {
            assert!(
                matches!(
                    parse(&args(&format!("watch --bucket sims --state /w --interval {interval}"))),
                    Ok(Command::Watch(Watch { interval: parsed, .. })) if parsed == interval
                ),
                "--interval {interval}"
            );
        }
        let build = "a".repeat(64);
        assert!(matches!(
            parse(&args(&format!("report --bucket sims --build {build}"))),
            Ok(Command::Report { build: Some(parsed), .. }) if parsed == build
        ));
        assert!(
            parse(&args(
                "publish --checkout /c --state /s --bucket sims --interval 4294967295"
            ))
            .is_ok()
        );
        for refused in [
            "",
            "sweep --state /s",
            "status --state /s --state /t",
            "status --bucket sims",
            "status",
            "run --state /s",
            "run --state /s --bucket Sims",
            "run --state /s --bucket sims --confirm-slots 0",
            "check --bucket sims --confirm-slots 0",
            "check --bucket sims --system-cores many",
            "check --bucket sims --cgroup sim-host.service",
            "run --state /s --bucket sims --cgroup /sys/fs/cgroup/../g",
            "publish --checkout /c --state /s --bucket sims --interval 0",
            "report --bucket sims --build latest",
            "publish --checkout /c --state /s --bucket sims --interval 4294967296",
            "watch --bucket sims --state /w --interval 0",
            "watch --bucket sims --state /w --interval 4294967296",
            "watch --bucket sims --state /w --checkout /c",
            "watch --bucket sims",
            "watch --state /w",
        ] {
            assert!(parse(&args(refused)).is_err(), "{refused:?} is refused");
        }
    }
}
