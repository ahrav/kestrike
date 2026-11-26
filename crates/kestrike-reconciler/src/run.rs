//! The run of `kestrike-reconciler run`. [`serve`] installs the stop handlers, opens and locks the state
//! directory, opens the store table, and runs the loop: one store client over the table and the state directory's
//! watermark, the zone's `Reconciler` and `ZoneLoop`, and one tick per tick period until a stop request or a
//! withdrawn client. Each tick publishes its status files into the state directory, then prints its status line
//! ([`status`]), so a printed line's files are in place. The loop core reads no clock: this module reads the clock
//! [`serve`] is given, in the binary `CLOCK_BOOTTIME` ([`signal::boot_us`]), which counts the time the host spends
//! suspended, for each tick's `now_us` and its end, reads the wall clock for each status's stamp, and sleeps on the
//! given clock until the loop's deadline. The loop checks the stop flag before it starts each tick.
//!
//! SURVEY-WRITES-NOTHING: each tick calls `ZoneLoop::tick`, whose survey makes store reads and source reads only.
//! The survey accesses its sources through the three read traits.
//!
//! WATERMARK: a tick after which the store client reads withdrawn ends the run with [`Exit::Withdrawn`], after the
//! tick's status names the client `ClientWithdrawn`; a publish failure on that tick, or a failed read of the
//! clock for the tick's end, is reported on standard error and the exit stays [`Exit::Withdrawn`].

use std::fmt;
use std::fs::File;
use std::io::{self, Write};
use std::num::NonZeroU64;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kestrike::failover::reconcile::Reconciler;
use kestrike::failover::report::status::{StatusWriter, StoreAlarm};
use kestrike::failover::standbys::Zone;
use kestrike::failover::zone_loop::ZoneLoop;
use kestrike::failover::zone_loop::directory::{Directory, ReconcilerProjection};
use kestrike::failover::zone_loop::evidence::LISTING_GAP_TICKS;
use kestrike::failover::zone_loop::observe::Source;
use kestrike::failover::zone_loop::sources::{InstanceSource, Unreachable, VolumeSource};
use kestrike::storage::store::dynamo::{Dynamo, Exchange};
use kestrike::storage::store::{Client, WatermarkLog};

use crate::config::Service;
use crate::sources::{NoReports, Sources};
use crate::state::{State, StateError, Watermarks};
use crate::{cli, directory, signal, status};

/// How a run ended.
#[derive(Debug)]
pub enum Exit {
    /// A stop request arrived; the tick in progress finished first.
    Stopped,
    /// The store client withdrew under this alarm.
    Withdrawn(StoreAlarm),
    /// The state directory failed a check, the store client failed to load or reload its watermark, or a status
    /// failed to publish into the state directory.
    State(StateError),
    /// The stop handlers failed to install, the store table failed to open, the boot clock failed to read, or the
    /// status writer's boot nonce draw failed; the text names which.
    Open(String),
}

impl Exit {
    /// The process exit code of this end: [`cli::EXIT_OK`], [`cli::EXIT_WITHDRAWN`], [`cli::EXIT_STATE`] or
    /// [`cli::EXIT_OPEN`].
    pub fn code(&self) -> u8 {
        match self {
            Self::Stopped => cli::EXIT_OK,
            Self::Withdrawn(_) => cli::EXIT_WITHDRAWN,
            Self::State(_) => cli::EXIT_STATE,
            Self::Open(_) => cli::EXIT_OPEN,
        }
    }
}

impl fmt::Display for Exit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stopped => f.write_str("stopped"),
            Self::Withdrawn(alarm) => {
                write!(
                    f,
                    "ClientWithdrawn: the store client's alarm reads {alarm:?}"
                )
            }
            Self::State(error) => write!(f, "state directory: {error}"),
            Self::Open(error) => f.write_str(error),
        }
    }
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

/// Microseconds since the Unix epoch on the wall clock, 0 for a clock before the epoch.
fn wall_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, micros)
}

/// `read_directory` rereads the file each tick and returns `Unreachable` if validation fails or the file's zone
/// differs from `zone`, naming the failed check on standard error, so an operator's edit takes effect at the next
/// tick and a broken edit leaves the shards unobserved.
fn read_directory(path: &Path, zone: Zone) -> Result<Directory<ReconcilerProjection>, Unreachable> {
    let refused = |error: &dyn fmt::Display| {
        cli::report(format_args!("directory file {}: {error}", path.display()));
        Unreachable
    };
    let directory = directory::read(path).map_err(|error| refused(&error))?;
    if directory.zone() != zone {
        let found = directory.zone().0;
        return Err(refused(&format_args!(
            "zone {found}, the configuration's zone is {}",
            zone.0
        )));
    }
    Ok(directory)
}

/// Microseconds on `clock` since `origin`.
///
/// # Errors
///
/// [`Exit::Open`] naming the clock when the read fails.
fn loop_us(clock: &mut impl FnMut() -> io::Result<u64>, origin: u64) -> Result<u64, Exit> {
    clock()
        .map(|now| now.saturating_sub(origin))
        .map_err(|error| Exit::Open(format!("the boot clock: {error}")))
}

/// Runs the zone `service` configures. It installs the stop handlers, opens and locks `service`'s state directory,
/// takes its watermark log and loads the watermark, then calls `table` for the store exchange, so a refused state
/// directory or a watermark that fails to load ends the run before any store request. `clock` reads the loop's
/// clock in microseconds; the binary passes [`signal::boot_us`].
pub fn serve<X, I, V>(
    service: &Service,
    table: impl FnOnce() -> Result<X, String>,
    instances: I,
    volumes: V,
    clock: impl FnMut() -> io::Result<u64>,
) -> Exit
where
    X: Exchange,
    I: InstanceSource,
    V: VolumeSource,
{
    if let Err(error) = signal::install() {
        return Exit::Open(format!("signal handlers: {error}"));
    }
    let state = match State::open(&service.state) {
        Ok(state) => state,
        Err(error) => return Exit::State(error),
    };
    let directory = match state.directory() {
        Ok(directory) => directory,
        Err(error) => return Exit::State(error),
    };
    let log = match state.log() {
        Ok(log) => log,
        Err(error) => return Exit::State(error),
    };
    if let Err(error) = log.load() {
        return Exit::State(StateError::Io(error));
    }
    let exchange = match table() {
        Ok(exchange) => exchange,
        Err(error) => return Exit::Open(error),
    };
    let mut sources = Sources {
        reports: NoReports,
        instances,
        volumes,
    };
    run(service, &directory, log, exchange, &mut sources, clock)
}

/// The store client uses `log` for its watermark. The loop publishes each tick's status to the state directory
/// `state` holds open, and reports a tick on standard error if its start follows the previous start by more than
/// `LISTING_GAP_TICKS` tick periods, its duration exceeds one tick period, or the loop refused its directory by
/// succession. The loop checks each reread against the directory it last admitted, so a refused file that stays
/// unchanged fails the same check on every tick. A tick refused by succession ends its observation before the
/// store reads.
fn run<X, I, V>(
    service: &Service,
    state: &File,
    log: Watermarks,
    exchange: X,
    sources: &mut Sources<NoReports, I, V>,
    mut clock: impl FnMut() -> io::Result<u64>,
) -> Exit
where
    X: Exchange,
    I: InstanceSource,
    V: VolumeSource,
{
    let client = match Client::open(Dynamo(exchange), log) {
        Ok(client) => client,
        Err(error) => return Exit::State(StateError::Io(error)),
    };
    let config = service.bounds.config();
    let (zone, tick_us) = (config.zone, config.tick_us);
    let gap_us = tick_us.saturating_mul(LISTING_GAP_TICKS);
    let period = NonZeroU64::new(tick_us).expect("ZoneConfig::validate refuses a zero tick_us");
    let mut writer = match StatusWriter::new(service.writer, service.status_key, period) {
        Ok(writer) => writer,
        Err(error) => return Exit::Open(format!("the status writer's nonce draw: {error:?}")),
    };
    let directory_path = config.directory.clone();
    let mut zone_loop = ZoneLoop::new(Reconciler::new(client), service.bounds.clone());
    let origin = match loop_us(&mut clock, 0) {
        Ok(origin) => origin,
        Err(exit) => return exit,
    };
    let mut previous: Option<u64> = None;
    loop {
        if signal::stopping() {
            return Exit::Stopped;
        }
        let now_us = match loop_us(&mut clock, origin) {
            Ok(now_us) => now_us,
            Err(exit) => return exit,
        };
        if let Some(previous) = previous
            && now_us.saturating_sub(previous) > gap_us
        {
            cli::report(format_args!(
                "tick started {} us after the previous one, more than {LISTING_GAP_TICKS} tick periods ({gap_us} us), \
                 so the zone's dwells and error runs restart",
                now_us - previous
            ));
        }
        previous = Some(now_us);
        let wall_us = wall_us();
        let tick = zone_loop.tick(read_directory(&directory_path, zone), sources, now_us);
        let sealed = writer.seal(std::slice::from_ref(&tick.part), wall_us, now_us);
        if let Err(error) = &sealed {
            cli::report(format_args!("the tick's status did not seal: {error:?}"));
        }
        let ended_us = match loop_us(&mut clock, origin) {
            Ok(ended_us) => ended_us,
            Err(exit) if tick.part.store.alarm == StoreAlarm::Clear => return exit,
            Err(exit) => {
                cli::report(format_args!("the tick's status did not publish: {exit}"));
                return Exit::Withdrawn(tick.part.store.alarm);
            }
        };
        let context = status::Context::of(&tick, zone.0, (now_us, ended_us), tick_us, wall_us);
        let status = &tick.survey.status;
        let document = status::document(status, &context);
        let alarm = context.alarm;
        match status::publish(state, &document, sealed.as_deref().ok()) {
            Ok(()) => {
                let _ = writeln!(std::io::stdout(), "{}", status::line(status, &context));
            }
            Err(error) if alarm == StoreAlarm::Clear => return Exit::State(StateError::Io(error)),
            Err(error) => cli::report(format_args!("the tick's status did not publish: {error}")),
        }
        if alarm != StoreAlarm::Clear {
            return Exit::Withdrawn(alarm);
        }
        if let Some(Source::Succession(refusal)) = tick.survey.observation.unobserved() {
            cli::report(format_args!(
                "directory file {}: refused by succession ({refusal:?}) over the directory last admitted, so the tick \
                 read no store record; the loop admits that listing and its report keys at its `version`, or a higher \
                 `version` that keeps every host it listed, with its instance and zone, and every retired host retired",
                directory_path.display()
            ));
        }
        if context.overran() {
            cli::report(format_args!(
                "tick {} took {} us, longer than tick_us ({tick_us} us)",
                tick.survey.status.tick,
                context.duration_us()
            ));
        }
        let deadline = zone_loop
            .deadline()
            .unwrap_or(now_us.saturating_add(tick_us));
        match signal::wait_until(origin.saturating_add(deadline), &mut clock) {
            Ok(true) => return Exit::Stopped,
            Ok(false) => {}
            Err(error) => return Exit::Open(format!("the boot clock: {error}")),
        }
    }
}
