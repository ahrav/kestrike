//! The command line of `campaign-monitor`: option parsing, the usage text
//! and the exit codes. Numeric options are bounded so that deadline,
//! byte-limit and staleness arithmetic on them cannot overflow, an option
//! the chosen mode or source would ignore is a usage error, and the history
//! file never lies inside the monitored state.

use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use crate::source::{Limits, Source};
use crate::tui::theme::ColorDepth;

pub const USAGE: &str = "\
usage: campaign-monitor [watch|check] SOURCE [OPTIONS]

SOURCE, one of:
  --state DIR [--ssh HOST] [--campaign BIN]
        run `BIN status --state DIR`, on HOST over ssh when given
        (BIN defaults to `campaign` on PATH)
  --file PATH
        read one saved `campaign status` snapshot

OPTIONS:
  --interval SECONDS       watch: least seconds between snapshots
                           (default 15); a snapshot that takes T seconds
                           to fetch waits at least 4T before the next
  --timeout SECONDS        --state: kill the local snapshot command, or
                           the ssh client for --ssh, after this long
                           (default 300)
  --max-snapshot-mib MIB   refuse a snapshot larger than this (default 256)
  --history PATH           JSON-lines history file, outside the state
                           directory (default for --state sources:
                           ~/.local/state/campaign-monitor/HASH.jsonl, HASH
                           naming the source command; history stays in
                           memory for --file sources and when HOME is unset)
  --no-history             keep history in memory only
  --json                   check prints one JSON object instead of text
  --color WHEN             watch: auto (default; NO_COLOR, COLORTERM and
                           TERM decide), never, 16, 256 or truecolor
  --ascii                  watch: draw ASCII stand-ins for the Unicode
                           glyphs, for consoles without them

Seconds go up to 604800 and MiB up to 1048576.

watch (the default) opens the terminal monitor. check prints the signals
once. Exit codes: 0 no signal above info, 1 a warning, 2 a critical
signal, 3 the snapshot failed, 4 the history file is unusable (check
prints its full report first when only recording the sample failed),
5 watch stopped because its terminal or its snapshot poller failed,
64 a usage error.
";

pub const EXIT_WARNING: u8 = 1;
pub const EXIT_CRITICAL: u8 = 2;
pub const EXIT_SNAPSHOT: u8 = 3;
pub const EXIT_HISTORY: u8 = 4;
pub const EXIT_TERMINAL: u8 = 5;
pub const EXIT_USAGE: u8 = 64;

const MAX_SECONDS: u64 = 7 * 24 * 3600;
const MAX_MIB: u64 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Watch,
    Check { json: bool },
}

/// The parsed command line.
#[derive(Debug)]
pub struct Options {
    pub mode: Mode,
    pub source: Source,
    pub interval: Duration,
    pub limits: Limits,
    /// The history file, or `None` to keep history in memory: for
    /// `--no-history`, for a `--file` source without `--history`, and for a
    /// `--state` source when HOME is unset.
    pub history: Option<PathBuf>,
    /// The `--color` depth, or `None` to detect it.
    pub color: Option<ColorDepth>,
    pub ascii: bool,
}

/// The ways [`parse`] ends without options: `Help` asks `main` to print
/// [`USAGE`] and exit 0, and `Error` carries a message for exit
/// [`EXIT_USAGE`].
#[derive(Debug, PartialEq, Eq)]
pub enum Usage {
    Help,
    Error(String),
}

/// Parses the arguments after the program name. `home` locates the default
/// history file of a `--state` source. A local `--state` is resolved to its
/// canonical path, so every spelling of one state directory, from any
/// working directory, runs the same command and keys the same default
/// history file.
///
/// # Errors
///
/// [`Usage::Help`] for `-h` or `--help`; [`Usage::Error`] for an unknown or
/// conflicting option, an option the mode or source ignores, a value out of
/// range, a local path that does not resolve, or a history path inside the
/// monitored state.
pub fn parse(args: &[String], home: Option<PathBuf>) -> Result<Options, Usage> {
    let mut args = args.iter().peekable();
    let check = match args.peek().map(|arg| arg.as_str()) {
        Some("check") => {
            args.next();
            true
        }
        Some("watch") => {
            args.next();
            false
        }
        _ => false,
    };
    let (mut state, mut ssh, mut campaign, mut file) = (None, None, None, None);
    let (mut interval, mut timeout) = (None, None);
    let mut limits = Limits::default();
    let mut history = None;
    let (mut keep, mut json) = (true, false);
    let (mut color, mut ascii) = (None, false);
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .cloned()
                .ok_or_else(|| Usage::Error(format!("{arg} requires a value")))
        };
        let seconds = |text: String| {
            text.parse::<u64>()
                .ok()
                .filter(|n| *n <= MAX_SECONDS)
                .map(|n| Duration::from_secs(n.max(1)))
                .ok_or_else(|| {
                    Usage::Error(format!("{arg} takes whole seconds up to {MAX_SECONDS}"))
                })
        };
        match arg.as_str() {
            "--state" => state = Some(value()?),
            "--ssh" => ssh = Some(value()?),
            "--campaign" => campaign = Some(value()?),
            "--file" => file = Some(PathBuf::from(value()?)),
            "--interval" => interval = Some(seconds(value()?)?),
            "--timeout" => timeout = Some(seconds(value()?)?),
            "--max-snapshot-mib" => {
                let mib = value()?
                    .parse::<u64>()
                    .ok()
                    .filter(|n| *n <= MAX_MIB)
                    .ok_or_else(|| {
                        Usage::Error(format!(
                            "--max-snapshot-mib takes whole MiB up to {MAX_MIB}"
                        ))
                    })?;
                limits.max_bytes = mib.max(1) << 20;
            }
            "--history" => history = Some(PathBuf::from(value()?)),
            "--no-history" => keep = false,
            "--json" => json = true,
            "--color" => {
                color = Some(match value()?.as_str() {
                    "auto" => None,
                    "never" => Some(ColorDepth::None),
                    "16" => Some(ColorDepth::Ansi16),
                    "256" => Some(ColorDepth::Indexed256),
                    "truecolor" => Some(ColorDepth::TrueColor),
                    _ => {
                        return Err(Usage::Error(
                            "--color takes auto, never, 16, 256 or truecolor".into(),
                        ));
                    }
                });
            }
            "--ascii" => ascii = true,
            "-h" | "--help" => return Err(Usage::Help),
            other => return Err(Usage::Error(format!("unknown option {other}"))),
        }
    }
    if json && !check {
        return Err(Usage::Error("--json applies to check".into()));
    }
    if check && interval.is_some() {
        return Err(Usage::Error("--interval applies to watch".into()));
    }
    if check && (color.is_some() || ascii) {
        return Err(Usage::Error("--color and --ascii apply to watch".into()));
    }
    if file.is_some() && timeout.is_some() {
        return Err(Usage::Error("--timeout applies to --state".into()));
    }
    if let Some(timeout) = timeout {
        limits.timeout = timeout;
    }
    let program = campaign.as_deref().unwrap_or("campaign");
    let mut local = None;
    let source = match (state, file) {
        (Some(state), None) => match ssh {
            Some(host) => Source::ssh(&host, program, &state),
            None => {
                let path = resolved(Path::new(&state))?;
                let text = path.to_str().ok_or_else(|| {
                    Usage::Error(format!("--state {} is not UTF-8", path.display()))
                })?;
                let source = Source::local(program, text);
                local = Some(path);
                source
            }
        },
        (None, Some(_)) if ssh.is_some() || campaign.is_some() => {
            return Err(Usage::Error("--ssh and --campaign apply to --state".into()));
        }
        (None, Some(file)) => Source::File(file),
        _ => return Err(Usage::Error("give exactly one of --state or --file".into())),
    };
    let history = match (keep, history, &source) {
        (false, Some(_), _) => {
            return Err(Usage::Error("give one of --history or --no-history".into()));
        }
        (false, None, _) | (true, None, Source::File(_)) => None,
        (true, Some(path), _) => Some(path),
        (true, None, source) => home.map(|home| default_history(&home, &source.describe())),
    };
    if let Some(path) = &history {
        let target = resolved(path)?;
        let monitored = match (&source, &local) {
            (Source::File(file), _) => target == resolved(file)?,
            (_, Some(state)) => target.starts_with(state),
            _ => false,
        };
        if monitored {
            return Err(Usage::Error(format!(
                "history file {} lies inside the monitored state; give another --history",
                path.display()
            )));
        }
    }
    Ok(Options {
        mode: if check {
            Mode::Check { json }
        } else {
            Mode::Watch
        },
        source,
        interval: interval.unwrap_or(Duration::from_secs(15)),
        limits,
        history,
        color: color.flatten(),
        ascii,
    })
}

/// `path` made absolute, with its longest existing prefix canonicalized so
/// that symlinks resolve before a comparison or containment check. The part
/// below that prefix names entries that do not exist yet, so the kernel
/// later resolves it the same way only when it holds no `..` and no
/// dangling symlink; either one is an error.
fn resolved(path: &Path) -> Result<PathBuf, Usage> {
    let shown = path.display();
    let path =
        std::path::absolute(path).map_err(|error| Usage::Error(format!("{shown}: {error}")))?;
    for ancestor in path.ancestors() {
        if let Ok(real) = ancestor.canonicalize() {
            let rest = path
                .strip_prefix(ancestor)
                .expect("an ancestor of a path is a prefix of it");
            if rest.components().any(|part| part == Component::ParentDir) {
                return Err(Usage::Error(format!(
                    "{shown} climbs out of a directory that does not exist"
                )));
            }
            return Ok(if rest.as_os_str().is_empty() {
                real
            } else {
                real.join(rest)
            });
        }
        if ancestor.symlink_metadata().is_ok() {
            return Err(Usage::Error(format!(
                "{shown}: {} exists but does not resolve",
                ancestor.display()
            )));
        }
    }
    Ok(path)
}

/// The file is named by the 64-bit FNV-1a hash of the source command, so
/// each source keeps its own history.
fn default_history(home: &Path, source: &str) -> PathBuf {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in source.bytes() {
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
    }
    home.join(".local/state/campaign-monitor")
        .join(format!("{hash:016x}.jsonl"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn check_with_json_over_ssh_builds_a_bounded_remote_command() {
        let options = parse(
            &args("check --json --state /s --ssh xxl --campaign ~/bin/campaign --timeout 9 --max-snapshot-mib 2"),
            Some("/home/u".into()),
        )
        .unwrap();
        assert_eq!(options.mode, Mode::Check { json: true });
        assert_eq!(
            options.source.describe(),
            "ssh -o 'BatchMode=yes' -- xxl '~/bin/campaign status --state /s'"
        );
        assert_eq!(options.limits.timeout, Duration::from_secs(9));
        assert_eq!(options.limits.max_bytes, 2 << 20);
        assert!(
            options
                .history
                .unwrap()
                .starts_with("/home/u/.local/state/campaign-monitor")
        );
    }

    #[test]
    fn a_file_source_keeps_history_in_memory_unless_a_path_is_given() {
        let options = parse(&args("--file s.json"), Some("/h".into())).unwrap();
        assert!(options.history.is_none());
        let options = parse(&args("--file s.json --history h.jsonl"), None).unwrap();
        assert_eq!(options.history, Some(PathBuf::from("h.jsonl")));
    }

    #[test]
    fn usage_errors_name_the_problem() {
        for (line, expected) in [
            ("--state", "--state requires a value"),
            ("--state a --file b", "exactly one of"),
            ("--file a --json", "--json applies to check"),
            ("--file a --interval x", "--interval takes whole seconds"),
            ("check --file a --interval 5", "--interval applies to watch"),
            (
                "check --file a --ascii",
                "--color and --ascii apply to watch",
            ),
            (
                "check --file a --color 16",
                "--color and --ascii apply to watch",
            ),
            ("--file a --color blue", "--color takes auto, never"),
            ("--file a --timeout 5", "--timeout applies to --state"),
            ("--bogus", "unknown option --bogus"),
        ] {
            match parse(&args(line), None) {
                Err(Usage::Error(error)) => assert!(error.contains(expected), "{line}: {error}"),
                other => panic!("{line}: {other:?}"),
            }
        }
        assert_eq!(parse(&args("--help"), None).unwrap_err(), Usage::Help);
    }

    #[test]
    fn numeric_options_above_their_ceiling_are_usage_errors() {
        for line in [
            "--state /s --timeout 604801",
            "--file a --interval 18446744073709551615",
            "--file a --max-snapshot-mib 1048577",
        ] {
            assert!(
                matches!(parse(&args(line), None), Err(Usage::Error(_))),
                "{line}"
            );
        }
        let options = parse(
            &args("--state /s --timeout 604800 --max-snapshot-mib 1048576"),
            None,
        )
        .unwrap();
        assert_eq!(options.limits.timeout, Duration::from_secs(604_800));
        assert_eq!(options.limits.max_bytes, 1 << 40);
    }

    #[test]
    fn an_explicit_watch_with_no_history_clamps_the_interval_to_one_second() {
        let options = parse(
            &args("watch --file a --no-history --interval 0"),
            Some("/h".into()),
        )
        .unwrap();
        assert_eq!(options.mode, Mode::Watch);
        assert_eq!(options.interval, Duration::from_secs(1));
        assert!(options.history.is_none());
        let options = parse(&args("--state /s --no-history"), Some("/h".into())).unwrap();
        assert!(options.history.is_none());
    }

    #[test]
    fn color_and_ascii_override_detection_for_watch() {
        let options = parse(&args("--file a --color never --ascii"), None).unwrap();
        assert_eq!(options.color, Some(ColorDepth::None));
        assert!(options.ascii);
        let options = parse(&args("--file a --color 256 --color auto"), None).unwrap();
        assert_eq!(options.color, None, "the last --color wins");
        let options = parse(&args("--file a --color truecolor"), None).unwrap();
        assert_eq!(options.color, Some(ColorDepth::TrueColor));
    }

    #[test]
    fn options_that_a_file_source_would_ignore_are_usage_errors() {
        for (line, expected) in [
            ("--file a --ssh xxl", "apply to --state"),
            ("--file a --campaign bin", "apply to --state"),
            ("--file a --history h --no-history", "one of --history"),
        ] {
            match parse(&args(line), None) {
                Err(Usage::Error(error)) => assert!(error.contains(expected), "{line}: {error}"),
                other => panic!("{line}: {other:?}"),
            }
        }
    }

    #[test]
    fn every_spelling_of_a_local_state_keys_one_default_history() {
        let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
        let relative = parse(&args("--state s"), Some("/h".into())).unwrap();
        assert_eq!(
            relative.source.describe(),
            format!("campaign status --state {}", cwd.join("s").display())
        );
        let name = cwd.file_name().unwrap().to_str().unwrap();
        for spelling in [
            cwd.join("s").display().to_string(),
            "./s/".to_owned(),
            format!("../{name}/s"),
        ] {
            let named = parse(&args(&format!("--state {spelling}")), Some("/h".into())).unwrap();
            assert_eq!(relative.history, named.history, "{spelling}");
        }
        let other = parse(&args("--state t"), Some("/h".into())).unwrap();
        assert_ne!(relative.history, other.history);
    }

    #[test]
    fn a_history_file_inside_the_monitored_state_is_refused() {
        let dir = std::env::temp_dir().join(format!("cm-cli-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("state")).unwrap();
        let state = dir.join("state");
        for line in [
            format!(
                "--state {} --history {}/config.json",
                state.display(),
                state.display()
            ),
            format!(
                "--state {} --history {}/../state/h.jsonl",
                state.display(),
                state.display()
            ),
            format!(
                "--file {}/s.json --history {}/s.json",
                dir.display(),
                dir.display()
            ),
        ] {
            match parse(&args(&line), None) {
                Err(Usage::Error(error)) => assert!(
                    error.contains("inside the monitored state"),
                    "{line}: {error}"
                ),
                other => panic!("{line}: {other:?}"),
            }
        }
        std::os::unix::fs::symlink(state.join("absent"), dir.join("link")).unwrap();
        for (line, expected) in [
            (
                format!(
                    "--state {} --history {}/missing/../state/config.json",
                    state.display(),
                    dir.display()
                ),
                "climbs out of a directory that does not exist",
            ),
            (
                format!(
                    "--file {}/s.json --history {}/missing/../s.json",
                    dir.display(),
                    dir.display()
                ),
                "climbs out of a directory that does not exist",
            ),
            (
                format!(
                    "--state {} --history {}/link",
                    state.display(),
                    dir.display()
                ),
                "exists but does not resolve",
            ),
        ] {
            match parse(&args(&line), None) {
                Err(Usage::Error(error)) => assert!(error.contains(expected), "{line}: {error}"),
                other => panic!("{line}: {other:?}"),
            }
        }
        let outside = parse(
            &args(&format!(
                "--state {} --history {}/h.jsonl",
                state.display(),
                dir.display()
            )),
            None,
        );
        assert!(outside.is_ok(), "{outside:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
