//! The `sim-host` binary: parses the command line and runs one subcommand.
//! Its exit code is the subcommand's, or [`cli::EXIT_USAGE`] for a refused
//! command line.

use std::process::ExitCode;

use sim_host::cli::{self, Command};

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
            eprint!("sim-host: {error}\n{}", cli::USAGE);
            return ExitCode::from(cli::EXIT_USAGE);
        }
    };
    ExitCode::from(match command {
        Command::Run(run) => sim_host::runner::run(run),
        Command::Check(check) => match run_check(&check) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("sim-host check: {error}");
                2
            }
        },
        Command::Publish(options) => sim_host::publish::publish(&options),
        Command::Report { bucket, build } => sim_host::report::run(&bucket, build.as_deref()),
        Command::Watch(options) => sim_host::watch::run(&options),
        Command::Status { state } => {
            let verdict = sim_host::status::status(&state, sim_host::host::now_s());
            println!("{:#}", verdict.report);
            verdict.code
        }
    })
}

fn read_assignment(bucket: &str) -> Result<sim_host::assignment::Document, String> {
    let bucket = sim_host::store::Bucket::new(bucket);
    let scratch = sim_host::file::fresh_dir(&std::env::temp_dir(), "sim-host-check-")
        .map_err(|error| format!("a scratch directory: {error}"))?;
    let read = bucket.read(
        "assignment.json",
        &scratch,
        sim_host::assignment::BOUND,
        sim_host::store::SHORT,
    );
    let _ = std::fs::remove_dir_all(&scratch);
    let bytes = read.map_err(|error| format!("assignment.json: {error}"))?;
    sim_host::assignment::Document::parse(&bytes)
}

fn run_check(check: &cli::Check) -> Result<u8, String> {
    sim_host::signal::install().map_err(|error| format!("signal handlers: {error}"))?;
    let host = &check.host;
    let assignment = read_assignment(&host.bucket)?;
    let unit = host
        .cgroup
        .clone()
        .map_or_else(sim_host::cgroup::own, Ok)
        .map_err(|error| error.to_string())?;
    let usable =
        sim_host::host::usable_cpus().map_err(|error| format!("the affinity mask: {error}"))?;
    let memory = sim_host::host::memory_bytes().map_err(|error| error.to_string())?;
    let inputs = sim_host::check::Inputs {
        assignment: &assignment,
        unit: &unit,
        confirm_slots: host.confirm_slots,
        system_cores: host.system_cores,
        system_memory: check.system_memory,
        online: sim_host::host::online_cpus(),
        usable,
        memory,
        instance: sim_host::instance::instance_id(),
        metadata: sim_host::instance::address(),
    };
    let (code, report) = sim_host::check::judge(&inputs);
    println!("{report:#}");
    Ok(code)
}
