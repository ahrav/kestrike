//! `campaign-monitor`: parses the command line, then runs `check` once or
//! the terminal monitor until it quits.

use std::process::ExitCode;

use campaign_monitor::check;
use campaign_monitor::cli::{self, Mode, Usage};
use campaign_monitor::tui;

fn main() -> ExitCode {
    let args: Result<Vec<String>, _> = std::env::args_os()
        .skip(1)
        .map(std::ffi::OsString::into_string)
        .collect();
    let parsed = args
        .map_err(|arg| Usage::Error(format!("argument {arg:?} is not valid UTF-8")))
        .and_then(|args| cli::parse(&args, std::env::var_os("HOME").map(Into::into)));
    let options = match parsed {
        Ok(options) => options,
        Err(Usage::Help) => {
            print!("{}", cli::USAGE);
            return ExitCode::SUCCESS;
        }
        Err(Usage::Error(error)) => {
            eprint!(
                "campaign-monitor: {}\n{}",
                check::printable(&error),
                cli::USAGE
            );
            return ExitCode::from(cli::EXIT_USAGE);
        }
    };
    let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
    let history = match check::open_history(&options, &mut out, &mut err) {
        Ok(history) => history,
        Err(code) => return ExitCode::from(code),
    };
    if let Mode::Check { .. } = options.mode {
        return ExitCode::from(check::check(&options, history, &mut out, &mut err));
    }
    match tui::run(options, history) {
        Ok(None) => ExitCode::SUCCESS,
        Ok(Some(signal)) => ExitCode::from(u8::try_from(128 + signal).unwrap_or(u8::MAX)),
        Err(error) => {
            eprintln!("campaign-monitor: {}", check::printable(&error.to_string()));
            ExitCode::from(cli::EXIT_TERMINAL)
        }
    }
}
