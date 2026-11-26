//! Each tick's published status: one line on standard output, and two files the state directory holds, each
//! replaced whole by a rename so a reader sees one tick's complete file.
//!
//! - `status.json` (format [`FORMAT`]) renders the tick's `ZoneStatus`: per shard its state, blocker, closed
//!   cause, census target, exposure and overdue flag, and per zone the census length and cap, the cap below the
//!   shard count, in-flight count, holds, verdict counts, source completeness, count of unnamed volumes, tick and
//!   start time. The census length, the cap below the shard count, the in-flight count, the verdict counts and the
//!   count of unnamed volumes are `null` on a tick whose `ZoneStatus` holds `None` for them, and a shard's closed
//!   cause is `null` when its `ShardStatus` holds none. Its states, blockers and closed causes are `ZoneStatus`'s
//!   own values under their variant names; this module adds no classification. Beside them it names the zone, the tick's start and end on the loop's clock
//!   and whether the tick ran longer than `tick_us`, the tick's wall-clock time, the directory version the tick
//!   admitted, and the store client: `"Admitted"`, or `"ClientWithdrawn"` with the alarm that withdrew it.
//! - `status.sealed` holds the tick's reconciler status: the zone part the loop's builder returned for the tick,
//!   sealed by the status writer, in the encoding `failover::report::status` defines.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use kestrike::failover::loss::Phase;
use kestrike::failover::report::status::StoreAlarm;
use kestrike::failover::zone_loop::Tick;
use kestrike::failover::zone_loop::observe::Source;
use kestrike::failover::zone_loop::status::{ShardState, ShardStatus, ZoneStatus};
use serde_json::{Map, Value, json};

use crate::state::within;

pub const FORMAT: u32 = 2;
pub const JSON: &str = "status.json";
pub const SEALED: &str = "status.sealed";

/// The store client's state as the status names it: admitted while its alarm is clear, withdrawn after.
fn client(alarm: StoreAlarm) -> &'static str {
    match alarm {
        StoreAlarm::Clear => "Admitted",
        _ => "ClientWithdrawn",
    }
}

/// The variant name of `state`. The match names every variant, so a new state compiles only with a name.
pub fn name(state: &ShardState) -> &'static str {
    match state {
        ShardState::Protected => "Protected",
        ShardState::Initial => "Initial",
        ShardState::Enrolling { .. } => "Enrolling",
        ShardState::NoCandidate => "NoCandidate",
        ShardState::Closed => "Closed",
        ShardState::StandbyUnknown => "StandbyUnknown",
        ShardState::OwnerUnknown => "OwnerUnknown",
        ShardState::VolumeImpaired => "VolumeImpaired",
        ShardState::LossUnconfirmed => "LossUnconfirmed",
        ShardState::Replacing { .. } => "Replacing",
        ShardState::ReplacementHeld => "ReplacementHeld",
        ShardState::ReplacementExhausted => "ReplacementExhausted",
        ShardState::RetirementRequested => "RetirementRequested",
        ShardState::Unobserved(_) => "Unobserved",
    }
}

/// Writes the fields `state`'s variant carries into `row`: `need`, `phase` and `host` for `Enrolling`, `phase` and
/// `volume` for `Replacing`, `source` and `error` for `Unobserved`. The `error` of an `Unobserved` shard names the
/// store error of source `Store` or the refusal of source `Succession`, and is `null` for source `Directory`.
fn write_fields(state: &ShardState, row: &mut Map<String, Value>) {
    match *state {
        ShardState::Enrolling { need, phase, host } => {
            row.insert("need".into(), json!(format!("{need:?}")));
            row.insert("phase".into(), json!(format!("{phase:?}")));
            row.insert("host".into(), json!(host.get()));
        }
        ShardState::Replacing { phase } => {
            let (label, volume) = match phase {
                Phase::Open => ("Open", None),
                Phase::Issued => ("Issued", None),
                Phase::Created(volume) => ("Created", Some(volume.as_str().to_owned())),
            };
            row.insert("phase".into(), json!(label));
            row.insert("volume".into(), json!(volume));
        }
        ShardState::Unobserved(source) => {
            let (label, error) = match source {
                Source::Directory => ("Directory", None),
                Source::Succession(refusal) => ("Succession", Some(format!("{refusal:?}"))),
                Source::Store(error) => ("Store", Some(format!("{error:?}"))),
            };
            row.insert("source".into(), json!(label));
            row.insert("error".into(), json!(error));
        }
        ShardState::Protected
        | ShardState::Initial
        | ShardState::NoCandidate
        | ShardState::Closed
        | ShardState::StandbyUnknown
        | ShardState::OwnerUnknown
        | ShardState::VolumeImpaired
        | ShardState::LossUnconfirmed
        | ShardState::ReplacementHeld
        | ShardState::ReplacementExhausted
        | ShardState::RetirementRequested => {}
    }
}

fn shard(status: &ShardStatus) -> Value {
    let mut row = Map::new();
    row.insert("shard".into(), json!(status.shard.get()));
    row.insert("state".into(), json!(name(&status.state)));
    write_fields(&status.state, &mut row);
    let blocker = status.blocker.map(|blocker| format!("{blocker:?}"));
    row.insert("blocker".into(), json!(blocker));
    let closed = status.closed.map(|closed| format!("{closed:?}"));
    row.insert("closed".into(), json!(closed));
    let target = status.target.map(|target| {
        json!({
            "generation": target.generation.get(),
            "owner": target.owner.get(),
            "attempts": target.attempts,
        })
    });
    row.insert("target".into(), json!(target));
    row.insert("exposure_us".into(), json!(status.exposure_us));
    row.insert("overdue".into(), json!(status.overdue));
    Value::Object(row)
}

/// What one tick's status reports beside its `ZoneStatus`.
#[derive(Debug, Clone, Copy)]
pub struct Context {
    pub zone: u16,
    /// The store client's alarm after the tick.
    pub alarm: StoreAlarm,
    /// The version of the directory the tick admitted, `None` when it admitted none.
    pub directory: Option<u64>,
    /// The tick's start on the loop's clock.
    pub now_us: u64,
    /// The tick's end on the loop's clock: the reading after the tick's survey and seal.
    pub ended_us: u64,
    /// The configured tick period.
    pub tick_us: u64,
    /// The tick's wall-clock time, in microseconds since the Unix epoch.
    pub wall_us: u64,
}

impl Context {
    /// The context of `tick` in `zone`, which started at `now_us` and ended at `ended_us` on the loop's clock, under
    /// the tick period `tick_us`, and started at `wall_us` on the wall clock.
    pub fn of(
        tick: &Tick,
        zone: u16,
        (now_us, ended_us): (u64, u64),
        tick_us: u64,
        wall_us: u64,
    ) -> Self {
        let view = tick.survey.observation.zone.as_ref().ok();
        Self {
            zone,
            alarm: tick.part.store.alarm,
            directory: view.map(|view| view.directory.version()),
            now_us,
            ended_us,
            tick_us,
            wall_us,
        }
    }

    /// The tick's duration on the loop's clock.
    pub fn duration_us(&self) -> u64 {
        self.ended_us.saturating_sub(self.now_us)
    }

    /// Whether the tick ran longer than `tick_us`.
    pub fn overran(&self) -> bool {
        self.duration_us() > self.tick_us
    }
}

/// The `status.json` document of `status` in `context`.
pub fn document(status: &ZoneStatus, context: &Context) -> Value {
    let alarm = context.alarm;
    let complete = status.complete;
    let verdicts = status.verdicts.map(|verdicts| {
        json!({
            "live": verdicts.live,
            "lost": verdicts.lost,
            "conflict": verdicts.conflict,
            "unknown": verdicts.unknown,
        })
    });
    let cap_below = status
        .cap_below
        .map(|below| json!({ "cap": below.cap, "shards": below.shards }));
    json!({
        "format": FORMAT,
        "zone": context.zone,
        "tick": status.tick,
        "started_us": status.started_us,
        "ended_us": context.ended_us,
        "overran": context.overran(),
        "observed_us": context.now_us,
        "observed_at_us": context.wall_us,
        "directory_version": context.directory,
        "client": client(alarm),
        "store_alarm": format!("{alarm:?}"),
        "census": status.census,
        "cap": status.cap,
        "cap_below": cap_below,
        "inflight": status.inflight,
        "holds": {
            "warm_up": status.holds.warm_up,
            "zone_host": status.holds.zone_host,
            "operator": status.holds.operator,
        },
        "verdicts": verdicts,
        "complete": {
            "reports": complete.reports,
            "instances": complete.instances,
            "volumes": complete.volumes,
            "store": complete.store,
        },
        "unnamed_volumes": status.unnamed,
        "shards": status.shards.iter().map(shard).collect::<Vec<_>>(),
    })
}

/// `items` joined by commas, or `-` for none.
fn listed(items: impl Iterator<Item = String>) -> String {
    let items: Vec<String> = items.collect();
    if items.is_empty() {
        "-".to_owned()
    } else {
        items.join(",")
    }
}

/// The names of the flags that are set, as [`listed`] joins them.
fn set(flags: &[(&str, bool)]) -> String {
    listed(
        flags
            .iter()
            .filter(|(_, on)| *on)
            .map(|(name, _)| (*name).to_owned()),
    )
}

/// The status line of `status` in `context`: the tick, the zone, each state and blocker with its shard count, the
/// census, the cap, the in-flight count, the holds that apply, the complete sources and the store client, as
/// `key=value` fields. An unread census prints `-`, and an absent in-flight count prints `unread`, since the loop
/// counts in-flight slots only over a census it read.
pub fn line(status: &ZoneStatus, context: &Context) -> String {
    let zone = context.zone;
    let mut states: BTreeMap<&str, usize> = BTreeMap::new();
    let mut blockers: BTreeMap<String, usize> = BTreeMap::new();
    for row in &status.shards {
        *states.entry(name(&row.state)).or_insert(0) += 1;
        if let Some(blocker) = row.blocker {
            *blockers.entry(format!("{blocker:?}")).or_insert(0) += 1;
        }
    }
    let holds = status.holds;
    let complete = status.complete;
    let alarm = context.alarm;
    let store_client = match alarm {
        StoreAlarm::Clear => client(alarm).to_owned(),
        _ => format!("{}({alarm:?})", client(alarm)),
    };
    format!(
        "tick={} zone={zone} shards={} states={} blockers={} census={} cap={} inflight={} holds={} complete={} client={store_client}",
        status.tick,
        status.shards.len(),
        listed(states.iter().map(|(name, count)| format!("{name}:{count}"))),
        listed(
            blockers
                .iter()
                .map(|(name, count)| format!("{name}:{count}"))
        ),
        status
            .census
            .map_or("-".to_owned(), |census| census.to_string()),
        status.cap,
        status
            .inflight
            .map_or("unread".to_owned(), |inflight| inflight.to_string()),
        set(&[
            ("warm_up", holds.warm_up),
            ("zone_host", holds.zone_host),
            ("operator", holds.operator),
        ]),
        set(&[
            ("reports", complete.reports),
            ("instances", complete.instances),
            ("volumes", complete.volumes),
            ("store", complete.store),
        ]),
    )
}

/// `stage` writes and syncs `bytes` only to an inode it creates at the staged name of `name`, so an existing link
/// at the staged path cannot redirect the write.
fn stage(directory: &File, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
    let staged = within(directory, &format!(".{name}.staged"));
    match fs::remove_file(&staged) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&staged)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(staged)
}

fn named(name: &str) -> impl Fn(io::Error) -> io::Error + '_ {
    move |error| io::Error::new(error.kind(), format!("{name}: {error}"))
}

/// Publishes one tick's status into the open state directory `directory`. A sealed status there is the same tick
/// as `status.json` or a newer one: the new seal replaces the old before the new document does, and a tick without
/// a seal removes the old one first. `publish` returns `Ok(())` only after both directory syncs succeed.
///
/// # Errors
///
/// `publish` prefixes staging, rename, removal and directory sync errors with the affected status file's name.
/// Staging errors preserve the previously published files.
pub fn publish(directory: &File, document: &Value, sealed: Option<&[u8]>) -> io::Result<()> {
    let mut text = serde_json::to_vec_pretty(document).map_err(io::Error::other)?;
    text.push(b'\n');
    let json = stage(directory, JSON, &text).map_err(named(JSON))?;
    let seal = sealed
        .map(|bytes| stage(directory, SEALED, bytes).map_err(named(SEALED)))
        .transpose()?;
    match seal {
        Some(staged) => fs::rename(&staged, within(directory, SEALED)).map_err(named(SEALED))?,
        None => match fs::remove_file(within(directory, SEALED)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                return Err(named(SEALED)(error));
            }
            _ => {}
        },
    }
    directory.sync_all().map_err(named(SEALED))?;
    fs::rename(&json, within(directory, JSON)).map_err(named(JSON))?;
    directory.sync_all().map_err(named(JSON))
}

#[cfg(test)]
#[path = "status_tests.rs"]
mod tests;
