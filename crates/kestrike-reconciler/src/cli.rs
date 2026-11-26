//! The command line, `kestrike-reconciler <command> --config <file>`, and the process's exit codes.

use std::fmt;
use std::io::Write;
use std::path::PathBuf;

/// `init` recorded the watermark, or `run` stopped on SIGTERM or SIGINT after its tick in progress.
pub const EXIT_OK: u8 = 0;
/// The store table failed to open, the signal handlers failed to install, the boot clock failed to read, or the
/// status writer's draw from the operating system's entropy failed. A boot clock that fails to read at the end of
/// the withdrawing tick exits [`EXIT_WITHDRAWN`].
pub const EXIT_OPEN: u8 = 1;
/// The command line, the configuration or a file it names failed a check.
pub const EXIT_CONFIG: u8 = 2;
/// The store client withdrew under its alarm: `Regression`, `Checkpoint`, `Log` or `Namespace`
/// (`storage::store::Alarm`).
pub const EXIT_WITHDRAWN: u8 = 3;
/// The state directory failed a check or another process holds its lock. For `init`, it already holds a watermark,
/// or holds none and an entry other than `watermark.tmp`. For `run`, it holds no watermark, its watermark failed to
/// load or reload, or a status failed to publish into it on a tick after which the store client reads admitted; a
/// publish that fails on the withdrawing tick exits [`EXIT_WITHDRAWN`].
pub const EXIT_STATE: u8 = 4;

pub const USAGE: &str = "usage: kestrike-reconciler init --config <file>\n       kestrike-reconciler run --config <file>\n";

/// `report` ignores stderr write errors so the caller retains control of the exit code.
pub fn report(message: fmt::Arguments<'_>) {
    let _ = writeln!(std::io::stderr(), "kestrike-reconciler: {message}");
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Validates the configuration and the files it names, creates the state directory when absent, and records
    /// the empty watermark once.
    Init { config: PathBuf },
    /// Surveys the zone and publishes its status each tick until a stop request, a withdrawn store client, or a
    /// state directory or store table that fails to open.
    Run { config: PathBuf },
}

/// The command `args`, the arguments after the program name, name.
///
/// # Errors
///
/// A message naming an unknown command, or stating the expected `--config <file>` for any other refused shape.
pub fn parse(args: &[String]) -> Result<Command, String> {
    let Some(command) = args.first() else {
        return Err("expected `--config <file>` after the command".to_owned());
    };
    let make: fn(PathBuf) -> Command = match command.as_str() {
        "init" => |config| Command::Init { config },
        "run" => |config| Command::Run { config },
        other => return Err(format!("unknown command {other:?}")),
    };
    match &args[1..] {
        [flag, config] if flag == "--config" => Ok(make(PathBuf::from(config))),
        _ => Err("expected `--config <file>` after the command".to_owned()),
    }
}
