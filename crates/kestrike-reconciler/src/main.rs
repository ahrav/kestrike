//! The `kestrike-reconciler` binary: parses the command line and runs one command, exiting with one of `cli`'s
//! codes.
//!
//! `run` constructs the store table and the EC2 zone listings from `kestrike_aws` ([`aws`]) and hands them to
//! `run::serve`. The run sends only `DescribeTable`, `GetItem`, `DescribeVolumes`, `DescribeVolumeStatus` and
//! `DescribeInstanceStatus`.

use std::io::Write;
use std::process::ExitCode;

use kestrike_reconciler::aws;
use kestrike_reconciler::cli::{self, Command};
use kestrike_reconciler::config::{self, Service};
use kestrike_reconciler::run::{self, Exit};
use kestrike_reconciler::signal;
use kestrike_reconciler::state::State;

fn main() -> ExitCode {
    let args: Result<Vec<String>, _> = std::env::args_os()
        .skip(1)
        .map(std::ffi::OsString::into_string)
        .collect();
    let parsed = args
        .map_err(|arg| format!("argument {arg:?} is not valid UTF-8"))
        .and_then(|args| cli::parse(&args));
    let command = match parsed {
        Ok(command) => command,
        Err(error) => {
            cli::report(format_args!("{error}\n{}", cli::USAGE.trim_end()));
            return ExitCode::from(cli::EXIT_CONFIG);
        }
    };
    let (Command::Init { config } | Command::Run { config }) = &command;
    let service = match config::load(config) {
        Ok(service) => service,
        Err(error) => {
            cli::report(format_args!("{}: {error}", config.display()));
            return ExitCode::from(cli::EXIT_CONFIG);
        }
    };
    ExitCode::from(match command {
        Command::Init { .. } => init(&service),
        Command::Run { .. } => run(&service),
    })
}

fn init(service: &Service) -> u8 {
    match State::create(service.state()).and_then(|state| state.init()) {
        Ok(()) => {
            let _ = writeln!(
                std::io::stdout(),
                "kestrike-reconciler: recorded the empty watermark in {}",
                service.state().display()
            );
            cli::EXIT_OK
        }
        Err(error) => {
            cli::report(format_args!(
                "state directory {}: {error}",
                service.state().display()
            ));
            cli::EXIT_STATE
        }
    }
}

fn run(service: &Service) -> u8 {
    let (instances, volumes) =
        aws::listings(service).expect("config::load accepted the zone's listings");
    let exit = run::serve(
        service,
        || aws::table(service),
        instances,
        volumes,
        signal::boot_us,
    );
    if !matches!(exit, Exit::Stopped) {
        cli::report(format_args!("{exit}"));
    }
    exit.code()
}
