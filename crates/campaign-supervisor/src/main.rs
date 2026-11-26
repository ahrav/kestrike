//! The `campaign` binary. Every command lives in the library; an
//! invocation that names no command the library provides exits with the
//! supervisor's rejected code before it reads or writes any state.
//!
//! `campaign sim archive --output DIR [--cargo PATH]` builds the
//! simulation worker and publishes it as the new archive DIR, then prints
//! one JSON line naming the archive's canonical path and the `build`, `executable`,
//! `platform` and `toolchain` values a run manifest pins.
//!
//! `campaign sim run --archive DIR --manifest PATH` and `campaign sim
//! inspect BUNDLE --archive DIR`, each with optional `--artifacts DIR`,
//! `--run-id ID` and `--watchdog SECONDS`, run the archived worker as
//! [`campaign_supervisor::sim`] describes. Once a command opens its
//! artifact directory as a store, it prints one JSON line naming the directory's
//! absolute path, the class and the reason; its exit code is the class.
//! `sim capabilities --archive DIR` prints the worker listing with its artifact.
//! `sim replay BUNDLE --archive DIR` and `sim replay --from-run DIR` compare
//! fresh replay evidence. `sim reduce BUNDLE --archive DIR --output DIR`
//! writes reduction evidence into a new output directory. These commands take
//! the same artifact, run-id and watchdog options as run and inspect.
//! `sim branch BUNDLE --archive DIR --milestone NAME --suffixes N [--siblings M]` and
//! `sim explore BUNDLE --archive DIR --milestone NAME` fork from a raw bundle.
//! Suffixes admit 1..=16 and siblings admit 1..=4, defaulting to one sibling.
//! Milestones admit nonempty printable ASCII.
//! `sim session --archive DIR --manifest PATH` and `sim replay-session SESSION
//! --archive DIR` produce a windowed session. All four commands take optional
//! `--output DIR` and the artifact, run-id and watchdog options above.
//! Output defaults to the command-named directory under its artifact directory.
//! Other entries inside that artifact directory are refused before workers run.
//! Reduce requires an external output directory.
//! Malformed `sim` arguments exit 2. A failed write to standard output or
//! error leaves the exit code unchanged.

#![deny(unsafe_code)]

use std::ffi::OsString;
use std::process::ExitCode;

use campaign_supervisor::exit::{Exit, Sim, Supervisor};

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let exit = match args.first().and_then(|command| command.to_str()) {
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        Some(
            command @ ("admit" | "configure" | "show" | "status" | "dispatch" | "findings"
            | "dispose" | "triage" | "calibrate" | "report" | "corpus" | "collect"
            | "sweep" | "sweep-status" | "confirm" | "fuzz" | "fuzz-status"),
        ) => Exit::Supervisor(campaign_supervisor::campaign::run(command, &args[1..])),
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        Some("admission-probe") => Exit::Sim(admission_probe(&args[1..])),
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        Some("hardware") => Exit::Supervisor(campaign_supervisor::hardware::run(&args[1..])),
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        Some("hardware-gate") => campaign_supervisor::exit::Gate::hardware(&args[1..]),
        Some("sim") => Exit::Sim(sim(&args[1..])),
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        Some("gate") => campaign_supervisor::exit::Gate::run(&args[1..]),
        _ => {
            warn("campaign: no such command");
            Exit::Supervisor(Supervisor::Rejected)
        }
    };
    ExitCode::from(exit.code())
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn admission_probe(args: &[OsString]) -> Sim {
    let mut args = args.to_vec();
    args.insert(0, "capabilities".into());
    match launcher::launcher_args(&args) {
        Some(launcher::Command::Launch(input, options)) => {
            campaign_supervisor::sim::sim(&input, &options).class
        }
        _ => Sim::Rejected,
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn sim(args: &[OsString]) -> Sim {
    use launcher::{Command, launcher_args, say};
    match launcher_args(args) {
        Some(Command::Archive { output, cargo }) => launcher::archive(&output, &cargo),
        Some(Command::Launch(input, options)) => {
            let ended = campaign_supervisor::sim::sim(&input, &options);
            match &ended.artifact {
                Some(artifact) => say(&serde_json::json!({
                    "artifact": artifact.to_str(),
                    "class": ended.class.name(),
                    "capabilities": ended.capabilities,
                    "reason": ended.reason,
                })),
                None => warn(&format!("campaign sim: {}", ended.reason)),
            }
            ended.class
        }
        None => {
            warn(launcher::USAGE);
            Sim::Rejected
        }
    }
}

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
fn sim(_: &[OsString]) -> Sim {
    warn("campaign sim: the launcher runs on 64-bit Linux only");
    Sim::Rejected
}

/// Prints `line` to standard error; a failed write is ignored.
fn warn(line: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "{line}");
}

/// The `sim` subcommands' arguments and output.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod launcher {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    use campaign_supervisor::exit::Sim;
    use campaign_supervisor::sim::{Input, Options, seconds};

    use super::warn;

    pub(super) const USAGE: &str = "usage: campaign sim archive --output DIR [--cargo PATH]
       campaign sim run --archive DIR --manifest PATH [--artifacts DIR] [--run-id ID] [--watchdog SECONDS]
       campaign sim inspect BUNDLE --archive DIR [--artifacts DIR] [--run-id ID] [--watchdog SECONDS]
       campaign sim capabilities --archive DIR [--artifacts DIR] [--run-id ID] [--watchdog SECONDS]
       campaign sim replay BUNDLE --archive DIR [--artifacts DIR] [--run-id ID] [--watchdog SECONDS]
       campaign sim replay --from-run DIR [--artifacts DIR] [--run-id ID] [--watchdog SECONDS]
       campaign sim reduce --from-run DIR --output DIR [--artifacts DIR] [--run-id ID] [--watchdog SECONDS]
       campaign sim reduce BUNDLE --archive DIR --output DIR [--artifacts DIR] [--run-id ID] [--watchdog SECONDS]
       campaign sim branch BUNDLE --archive DIR --milestone NAME --suffixes N [--siblings M] [--output DIR] [--artifacts DIR] [--run-id ID] [--watchdog SECONDS]
       campaign sim explore BUNDLE --archive DIR --milestone NAME [--output DIR] [--artifacts DIR] [--run-id ID] [--watchdog SECONDS]
       campaign sim session --archive DIR --manifest PATH [--output DIR] [--artifacts DIR] [--run-id ID] [--watchdog SECONDS]
       campaign sim replay-session SESSION --archive DIR [--output DIR] [--artifacts DIR] [--run-id ID] [--watchdog SECONDS]";

    /// A `sim` subcommand's arguments.
    #[derive(Debug, PartialEq)]
    pub(super) enum Command {
        Archive { output: PathBuf, cargo: PathBuf },
        Launch(Input, Options),
    }

    /// Prints `line` to standard output; a failed write is ignored.
    pub(super) fn say(line: &impl std::fmt::Display) {
        let _ = writeln!(std::io::stdout(), "{line}");
    }

    pub(super) fn archive(output: &Path, cargo: &Path) -> Sim {
        match campaign_supervisor::archive::archive(cargo, output) {
            Ok(archive) => {
                let pins = archive.pins();
                say(&serde_json::json!({
                    "build": pins.build,
                    "executable": pins.executable,
                    "path": archive.path().to_str(),
                    "platform": pins.platform,
                    "toolchain": pins.toolchain,
                }));
                Sim::Counts
            }
            Err(error) => {
                warn(&format!("campaign sim archive: {error}"));
                error.exit()
            }
        }
    }

    /// Unknown, repeated, empty or missing required flags, stray arguments and
    /// a refused watchdog value return `None`.
    /// Parses one launcher command with its frozen input and output paths.
    pub(super) fn launcher_args(args: &[OsString]) -> Option<Command> {
        let (command, mut rest) = args.split_first()?;
        let command = command.to_str()?;
        let mut positional = None;
        if matches!(command, "inspect" | "branch" | "explore" | "replay-session")
            || (matches!(command, "replay" | "reduce")
                && rest
                    .first()
                    .is_some_and(|arg| !arg.as_encoded_bytes().starts_with(b"--")))
        {
            let (bundle, more) = rest.split_first()?;
            positional = Some(PathBuf::from(bundle));
            rest = more;
        }
        let flags: &[&str] = match command {
            "archive" => &["--output", "--cargo"],
            "session" => &[
                "--archive",
                "--manifest",
                "--output",
                "--artifacts",
                "--run-id",
                "--watchdog",
            ],
            "run" => &[
                "--archive",
                "--manifest",
                "--artifacts",
                "--run-id",
                "--watchdog",
            ],
            "inspect" | "capabilities" => &["--archive", "--artifacts", "--run-id", "--watchdog"],
            "replay" => &[
                "--archive",
                "--from-run",
                "--artifacts",
                "--run-id",
                "--watchdog",
            ],
            "branch" => &[
                "--archive",
                "--milestone",
                "--suffixes",
                "--siblings",
                "--output",
                "--artifacts",
                "--run-id",
                "--watchdog",
            ],
            "explore" => &[
                "--archive",
                "--milestone",
                "--output",
                "--artifacts",
                "--run-id",
                "--watchdog",
            ],
            "replay-session" => &[
                "--archive",
                "--output",
                "--artifacts",
                "--run-id",
                "--watchdog",
            ],
            "reduce" => &[
                "--archive",
                "--from-run",
                "--output",
                "--artifacts",
                "--run-id",
                "--watchdog",
            ],
            _ => return None,
        };
        let mut values = BTreeMap::new();
        while let [flag, value, more @ ..] = rest {
            let flag = flags.iter().find(|known| flag == **known)?;
            if value.is_empty() || values.insert(*flag, value.clone()).is_some() {
                return None;
            }
            rest = more;
        }
        if !rest.is_empty() {
            return None;
        }
        let archive = values.remove("--archive").map(PathBuf::from);
        let mut path = |flag| values.remove(flag).map(PathBuf::from);
        if command == "archive" {
            let output = path("--output")?;
            let cargo = path("--cargo").unwrap_or_else(|| PathBuf::from("cargo"));
            return Some(Command::Archive { output, cargo });
        }
        let input = match command {
            "run" => Input::Manifest {
                archive: archive?,
                manifest: path("--manifest")?,
            },
            "session" => Input::Session {
                archive: archive?,
                manifest: path("--manifest")?,
                output: path("--output"),
            },
            "replay-session" => Input::ReplaySession {
                archive: archive?,
                source: positional?,
                output: path("--output"),
            },
            "branch" => Input::Branch {
                archive: archive?,
                bundle: positional?,
                milestone: path("--milestone")?.into_os_string().into_string().ok()?,
                suffixes: path("--suffixes")?.to_str()?.parse().ok()?,
                siblings: path("--siblings")
                    .map(|value| value.to_str().and_then(|text| text.parse().ok()))
                    .unwrap_or(Some(1))?,
                output: path("--output"),
            },
            "explore" => Input::Explore {
                archive: archive?,
                bundle: positional?,
                milestone: path("--milestone")?.into_os_string().into_string().ok()?,
                output: path("--output"),
            },
            "inspect" => Input::Bundle {
                archive: archive?,
                bundle: positional?,
            },
            "capabilities" => Input::Capabilities(archive?),
            "reduce" => match (positional, path("--from-run")) {
                (Some(bundle), None) => Input::Reduce {
                    archive: archive?,
                    bundle,
                    output: path("--output")?,
                },
                (None, Some(source)) if archive.is_none() => Input::ReduceFromRun {
                    source,
                    output: path("--output")?,
                },
                _ => return None,
            },
            "replay" => match (positional, path("--from-run")) {
                (Some(bundle), None) => Input::Replay {
                    archive: archive?,
                    bundle,
                },
                (None, Some(dir)) if archive.is_none() => Input::FromRun(dir),
                _ => return None,
            },
            _ => return None,
        };
        let artifacts = path("--artifacts").unwrap_or_else(|| PathBuf::from("target/kestrike-sim"));
        let mut text = |flag| values.remove(flag).map(OsString::into_string).transpose();
        let run_id = text("--run-id").ok()?;
        let watchdog = match text("--watchdog").ok()? {
            Some(value) => Some(seconds(&value).ok()?),
            None => None,
        };
        let options = Options {
            artifacts,
            run_id,
            watchdog,
        };
        Some(Command::Launch(input, options))
    }

    #[cfg(test)]
    mod tests {
        use std::ffi::OsString;
        use std::path::PathBuf;
        use std::time::Duration;

        use super::{Command, Input, Options, launcher_args};

        fn parsed(args: &[&str]) -> Option<Command> {
            launcher_args(&args.iter().map(OsString::from).collect::<Vec<_>>())
        }

        /// `archive` requires `--output` and defaults `--cargo` to `cargo`.
        #[test]
        fn archive_arguments_name_one_output_and_at_most_one_cargo() {
            let archive = |output: &str, cargo: &str| {
                Some(Command::Archive {
                    output: output.into(),
                    cargo: cargo.into(),
                })
            };
            assert_eq!(parsed(&["archive", "--output", "a"]), archive("a", "cargo"));
            assert_eq!(
                parsed(&["archive", "--cargo", "c", "--output", "a"]),
                archive("a", "c")
            );
        }

        #[test]
        fn reduce_from_run_accepts_one_frozen_source_and_output() {
            assert_eq!(
                parsed(&["reduce", "--from-run", "run", "--output", "reduced"]),
                Some(Command::Launch(
                    Input::ReduceFromRun {
                        source: "run".into(),
                        output: "reduced".into()
                    },
                    Options {
                        artifacts: "target/kestrike-sim".into(),
                        run_id: None,
                        watchdog: None
                    }
                ))
            );
            for args in [
                vec!["reduce", "--from-run", "run"],
                vec!["reduce", "bundle", "--from-run", "run", "--output", "out"],
                vec![
                    "reduce",
                    "--from-run",
                    "run",
                    "--archive",
                    "build",
                    "--output",
                    "out",
                ],
            ] {
                assert_eq!(parsed(&args), None);
            }
        }

        /// `run` requires `--archive` and `--manifest`, `inspect` a bundle
        /// and `--archive`; both default the artifacts directory and leave
        /// the run id and the watchdog unset.
        #[test]
        fn run_and_inspect_arguments_name_their_input_and_archive() {
            let options = |run_id: Option<&str>, watchdog: Option<Duration>| Options {
                artifacts: PathBuf::from("target/kestrike-sim"),
                run_id: run_id.map(str::to_owned),
                watchdog,
            };
            assert_eq!(
                parsed(&["run", "--manifest", "m", "--archive", "a"]),
                Some(Command::Launch(
                    Input::Manifest {
                        archive: "a".into(),
                        manifest: "m".into()
                    },
                    options(None, None)
                ))
            );
            let watchdog = Some(Duration::from_millis(1500));
            assert_eq!(
                parsed(&[
                    "inspect",
                    "b",
                    "--archive",
                    "a",
                    "--run-id",
                    "r",
                    "--watchdog",
                    "1.5"
                ]),
                Some(Command::Launch(
                    Input::Bundle {
                        archive: "a".into(),
                        bundle: "b".into()
                    },
                    options(Some("r"), watchdog)
                ))
            );
            let Some(Command::Launch(_, given)) = parsed(&[
                "run",
                "--manifest",
                "m",
                "--archive",
                "a",
                "--artifacts",
                "x",
            ]) else {
                panic!("the arguments parse");
            };
            assert_eq!(given.artifacts, PathBuf::from("x"));
        }

        #[test]
        fn forked_and_session_arguments_preserve_their_inputs() {
            let Some(Command::Launch(
                Input::Branch {
                    suffixes,
                    siblings,
                    milestone,
                    output,
                    ..
                },
                _,
            )) = parsed(&[
                "branch",
                "b",
                "--archive",
                "a",
                "--milestone",
                "pending-put",
                "--suffixes",
                "2",
                "--siblings",
                "3",
                "--output",
                "x",
            ])
            else {
                panic!("branch parses");
            };
            assert_eq!(
                (suffixes, siblings, milestone, output),
                (2, 3, "pending-put".into(), Some("x".into()))
            );
            assert!(matches!(
                parsed(&[
                    "branch",
                    "b",
                    "--archive",
                    "a",
                    "--milestone",
                    "pending-put",
                    "--suffixes",
                    "1"
                ]),
                Some(Command::Launch(Input::Branch { siblings: 1, .. }, _))
            ));
            assert!(matches!(
                parsed(&[
                    "explore",
                    "b",
                    "--archive",
                    "a",
                    "--milestone",
                    "pending-put"
                ]),
                Some(Command::Launch(Input::Explore { .. }, _))
            ));
            assert!(matches!(
                parsed(&["session", "--archive", "a", "--manifest", "m"]),
                Some(Command::Launch(Input::Session { .. }, _))
            ));
            assert!(matches!(
                parsed(&["replay-session", "s", "--archive", "a"]),
                Some(Command::Launch(Input::ReplaySession { .. }, _))
            ));
        }

        /// A repeated, unknown, misplaced, valueless or empty flag, a
        /// missing required flag, a stray argument, a refused watchdog and
        /// another subcommand are refused.
        #[test]
        fn malformed_arguments_are_refused() {
            for refused in [
                &["archive"][..],
                &["archive", "--output"],
                &["archive", "--output", "a", "--output", "b"],
                &["archive", "--output", "a", "--watchdog", "1"],
                &["archive", "--output", "a", "extra"],
                &["archive", "--output", ""],
                &["archive", "--output", "a", "--cargo", ""],
                &["run", "--manifest", "m", "--archive", "a", "--run-id", ""],
                &["run", "--archive", "a"],
                &["run", "--archive", "a", "--manifest", "m", "--output", "x"],
                &[
                    "explore",
                    "b",
                    "--archive",
                    "a",
                    "--milestone",
                    "m",
                    "--suffixes",
                    "3",
                ],
                &[
                    "explore",
                    "b",
                    "--archive",
                    "a",
                    "--milestone",
                    "m",
                    "--siblings",
                    "2",
                ],
                &["run", "--manifest", "m"],
                &["run", "--manifest", "m", "--archive", "a", "--cargo", "c"],
                &[
                    "run",
                    "--manifest",
                    "m",
                    "--archive",
                    "a",
                    "--watchdog",
                    "0",
                ],
                &["inspect", "--archive", "a"],
                &["inspect", "b", "--manifest", "m", "--archive", "a"],
                &["inspect", "b", "c", "--archive", "a"],
                &["replay", "b", "--from-run", "r", "--archive", "a"],
                &["replay", "--from-run", "r", "--archive", "a"],
                &["reduce", "b", "--archive", "a"],
                &["capabilities", "b", "--archive", "a"],
                &["explore", "b", "--archive", "a"],
                &[],
            ] {
                assert_eq!(parsed(refused), None, "{refused:?}");
            }
        }
    }
}
