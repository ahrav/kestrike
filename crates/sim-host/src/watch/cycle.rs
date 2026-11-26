//! The watch loop and one cycle. A cycle runs six steps in order: read
//! the root objects, each root from the cache when its entry matches the
//! listing, and then every host record; fold the report document; replace
//! `reports/latest.json`; store the host event when an alert opened and
//! then save the open alerts; create up to [`decide::RECORDS`] failure
//! records; create the day's summary. The host section and the decision
//! step are judged at the clock reading taken at the start of the cycle.
//! Each root is judged at its own reading: a freshly read root at the
//! reading taken right after its `status.json` download, and a root from
//! the cache at the reading taken when its entry is folded. Each bucket
//! call returns its error before the next step runs, and the next cycle
//! that succeeds derives its writes from its own document and day.
//!
//! The watch holds the open alerts in memory and saves them to
//! `alerts.json` in every cycle that stores its event or needs none. A
//! cycle whose event is not stored keeps the alerts that were open and are
//! still shown, so the alerts it saw close stay closed and those that
//! opened stay due. When a save fails, the watch attempts to remove
//! `alerts.json`, so a restart stores the alerts still shown once more
//! instead of trusting an older open set; a removal that fails too is
//! printed.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufWriter, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::cache::Cache;
use super::decide::{self, Alert, Listing};
use crate::cli::Watch;
use crate::report::{self, Condition, Document, LISTED, Report, Root};
use crate::snapshot::LIST_BOUND;
use crate::store::{Bucket, Error, SHORT};
use crate::{file, host, hosts, signal};

const ALERTS_BOUND: u64 = 16 << 20;
/// The free bytes a cycle's other writes need on the state filesystem:
/// `LIST_BOUND + 1` bytes for the largest download, one byte past the
/// suspect list's bound, and `LIST_BOUND + 1` bytes for the staged
/// report, event and alert bodies together. A cycle that starts with
/// fewer free bytes removes every cache entry.
const CACHE_RESERVE: u64 = 2 * (LIST_BOUND + 1);
/// Cache admission requires this many free bytes beyond the entry's size:
/// [`CACHE_RESERVE`] for the cycle's other writes and [`CACHE_RESERVE`] of
/// margin above the cycle-start threshold that removes every entry.
const ENTRY_RESERVE: u64 = 2 * CACHE_RESERVE;

enum Failure {
    Start(String),
    Cycle(String),
}

impl From<String> for Failure {
    fn from(error: String) -> Self {
        Self::Cycle(error)
    }
}

struct Watcher {
    bucket: Bucket,
    state: PathBuf,
    cache: Cache,
    known: Option<BTreeSet<String>>,
    /// The alert state after the last cycle that decided its writes;
    /// `None` until `alerts.json` is first read.
    alerts: Option<Saved>,
    digested: Option<String>,
    /// The seconds of the last cycle this watch completed.
    completed: Option<f64>,
}

/// The stored `reports/latest.json`. Its fields are declared in name
/// order, the order in which a JSON object of them prints.
#[derive(Serialize)]
struct Latest<'a> {
    document: &'a Document,
    /// The whole seconds of the last cycle this watch completed before
    /// this one, `None` until one completed.
    previous_seconds: Option<f64>,
    /// This cycle's seconds from its start to just before this put.
    seconds: f64,
    written: u64,
}

/// The saved `alerts.json`.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct Saved {
    format: u64,
    open: BTreeSet<Alert>,
    /// The second of the last host event the watch stored. A cycle whose
    /// clock reads no later second leaves its alerts due, so a host event
    /// key is never one an earlier event of this state took.
    #[serde(default)]
    event: Option<u64>,
}

impl Saved {
    fn lost() -> Self {
        Self {
            format: 1,
            open: BTreeSet::new(),
            event: None,
        }
    }
}

/// How [`put`] stores its body.
type Store = fn(&Bucket, &str, &Path, Duration) -> Result<(), Error>;

/// What a [`put`] found.
enum Put {
    Stored,
    /// A create-once put found an object at the key.
    Present,
}

pub fn run(options: &Watch) -> u8 {
    if let Err(error) = signal::install() {
        eprintln!("sim-host watch: signal handlers: {error}");
        return 2;
    }
    let state = match std::path::absolute(&options.state) {
        Ok(state) => state,
        Err(error) => {
            eprintln!("sim-host watch: the working directory: {error}");
            return 2;
        }
    };
    if let Err(error) = file::private_dir(&state) {
        eprintln!("sim-host watch: {}: {error}", state.display());
        return 2;
    }
    let lock_path = state.join("watch.lock");
    let _lock = match file::lock(&lock_path) {
        Ok(lock) => lock,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            eprintln!("sim-host watch: another watch holds {}", state.display());
            return 2;
        }
        Err(error) => {
            eprintln!("sim-host watch: {}: {error}", lock_path.display());
            return 2;
        }
    };
    let mut watcher = Watcher {
        bucket: Bucket::new(&options.bucket),
        cache: Cache::new(&state),
        state,
        known: None,
        alerts: None,
        digested: None,
        completed: None,
    };
    while !signal::stopping() {
        match watcher.cycle() {
            Ok(line) => println!("{line}"),
            Err(Failure::Start(error)) => {
                eprintln!("sim-host watch: {error}");
                return 2;
            }
            Err(Failure::Cycle(error)) => eprintln!("sim-host watch: {error}"),
        }
        signal::wait(options.interval);
    }
    0
}

fn alerts_path(state: &Path) -> PathBuf {
    state.join("alerts.json")
}

/// The alert state `path` saves: none open when nothing is at `path`, and
/// an error when the file is a symlink, cannot be read, does not parse or
/// holds another format.
fn load_alerts(path: &Path) -> Result<Saved, String> {
    let Some(bytes) = file::read_plain(path, ALERTS_BOUND).map_err(|error| error.to_string())?
    else {
        return Ok(Saved::lost());
    };
    let saved: Saved = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if saved.format == 1 {
        Ok(saved)
    } else {
        Err(format!("its format {} is not 1", saved.format))
    }
}

/// Saves `saved` to `path`. When the save fails, it unlinks the file or
/// symlink at `path`, without following it, and syncs its directory, so a
/// later start reads the state as lost; a directory at `path` stays. Each
/// failure is printed.
fn save_alerts(path: &Path, saved: &Saved) {
    let Err(error) = file::save_json(path, saved, ALERTS_BOUND) else {
        return;
    };
    eprintln!("sim-host watch: {error}");
    let removed = match std::fs::remove_file(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(()) => path
            .parent()
            .map_or(Ok(()), |parent| File::open(parent)?.sync_all()),
    };
    if let Err(error) = removed {
        eprintln!("sim-host watch: {}: {error}", path.display());
    }
}

/// Writes `body` as JSON to a scratch file and stores that file at `key`
/// with `store`.
fn put(
    bucket: &Bucket,
    scratch: &Path,
    key: &str,
    body: &impl Serialize,
    store: Store,
) -> Result<Put, String> {
    let path = scratch.join(key.replace('/', "_"));
    file::replace_with(&path, |staged| {
        let mut out = BufWriter::new(staged);
        serde_json::to_writer(&mut out, body)?;
        out.flush()
    })
    .map_err(|error| format!("{}: {error}", path.display()))?;
    let stored = store(bucket, key, &path, SHORT);
    let _ = std::fs::remove_file(&path);
    match stored {
        Ok(()) => Ok(Put::Stored),
        Err(Error::Present) => Ok(Put::Present),
        Err(error) => Err(format!("{key}: {error}")),
    }
}

/// Whether a host event may be stored at the clock reading `now`, after
/// the last host event the saved state names at second `last`: only a
/// later second gives an event key that event did not take.
fn past_event(last: Option<u64>, now: u64) -> Result<(), String> {
    match last {
        Some(last) if now <= last => Err(format!(
            "the clock reads {now}, no later than {last}, the second of the last host event stored"
        )),
        _ => Ok(()),
    }
}

/// Stores the host event `body` at `key` once. An object already at `key`
/// counts as this event only when it holds `body`'s bytes, as after a call
/// retried past a lost reply; another object there fails the step, so the
/// event's alerts stay due for a later cycle.
fn store_event(bucket: &Bucket, scratch: &Path, key: &str, body: &Value) -> Result<(), String> {
    if let Put::Present = put(bucket, scratch, key, body, Bucket::put_once)? {
        let stored = bucket
            .read(key, scratch, ALERTS_BOUND, SHORT)
            .map_err(|error| format!("{key}: {error}"))?;
        let ours = serde_json::to_vec(body).map_err(|error| format!("{key}: {error}"))?;
        if stored != ours {
            return Err(format!("{key} holds another event"));
        }
    }
    Ok(())
}

impl Watcher {
    fn identities(&self) -> Result<BTreeSet<String>, Failure> {
        let listed = self
            .bucket
            .list("events/failure-", LISTED)
            .map_err(|error| match error {
                Error::Bound(reason) => {
                    Failure::Start(format!("listing events/failure-: {reason}"))
                }
                error => Failure::Cycle(format!("listing events/failure-: {error}")),
            })?;
        Ok(listed
            .iter()
            .filter_map(|object| decide::failure_id(&object.key).map(str::to_owned))
            .collect())
    }

    fn cycle(&mut self) -> Result<Value, Failure> {
        let started = Instant::now();
        let calls = self.bucket.calls();
        if self.known.is_none() {
            self.known = Some(self.identities()?);
        }
        if let Err(error) = self.cache.sweep() {
            eprintln!("sim-host watch: {error}");
        }
        let scratch = self.state.join("scratch");
        file::remove_entry(&scratch).map_err(|error| format!("{}: {error}", scratch.display()))?;
        let now = host::now_s();
        let roots = report::list(&self.bucket)?;
        // The free space is read after the scratch files a killed cycle
        // left are unlinked and after the listing call. A filesystem such
        // as xfs returns an unlinked file's blocks in the background,
        // shortly after the unlink, and the listing call gives it that
        // time. The cache keeps its entries when those files alone held
        // the missing space and their blocks are back by the reading. The
        // scratch directory is created after the reading, so a filesystem
        // too full to hold a new directory first gets the cache's space.
        match self.cache.reclaim(&self.state, CACHE_RESERVE) {
            Ok(false) => {}
            Ok(true) => eprintln!(
                "sim-host watch: {} holds fewer than {CACHE_RESERVE} free bytes; every cache entry is removed",
                self.state.display()
            ),
            Err(error) => eprintln!("sim-host watch: {error}"),
        }
        file::private_dir(&scratch).map_err(|error| format!("{}: {error}", scratch.display()))?;
        let mut report = Report::new(None, now);
        let (mut read, mut cached) = (0u64, 0u64);
        for (campaign, listed) in &roots {
            if signal::stopping() {
                return Err(Failure::Cycle(format!(
                    "a stop ends the cycle before root {campaign:?}"
                )));
            }
            let (observed, raw) = if let Some(raw) = self.cache.get(campaign, listed) {
                cached += 1;
                (host::now_s(), raw)
            } else {
                let reading = report::read_root(
                    &self.bucket,
                    &scratch,
                    campaign,
                    listed,
                    None,
                    Condition::Listed,
                )?;
                read += 1;
                if let Err(error) = self.cache.put(campaign, listed, &reading, ENTRY_RESERVE) {
                    eprintln!("sim-host watch: {error}");
                }
                (reading.observed, reading.raw)
            };
            report.add(&Root::of(campaign.clone(), observed, raw));
        }
        if let Err(error) = self.cache.retain(roots.keys().map(String::as_str)) {
            eprintln!("sim-host watch: {error}");
        }
        let records = hosts::fetch(&self.bucket, &scratch, LISTED, now)?;
        let (_, document) = report.finish(records);
        let known = self.known.as_mut().expect("the identities are listed");
        let latest = Latest {
            document: &document,
            previous_seconds: self.completed,
            seconds: started.elapsed().as_secs_f64(),
            written: host::now_s(),
        };
        put(
            &self.bucket,
            &scratch,
            "reports/latest.json",
            &latest,
            Bucket::replace,
        )?;
        let path = alerts_path(&self.state);
        let saved = self.alerts.get_or_insert_with(|| {
            load_alerts(&path).unwrap_or_else(|error| {
                eprintln!("sim-host watch: {}: {error}", path.display());
                Saved::lost()
            })
        });
        let view = document.decision_view();
        let listings = document.failures().map(|(build, group)| Listing {
            build,
            profile: &group.profile,
            key: &group.key,
            group,
        });
        let writes = decide::decide(
            &view,
            listings,
            known,
            &saved.open,
            self.digested.as_deref(),
            now,
        )
        .map_err(|error| format!("the report document: {error}"))?;
        drop(document);
        if let Some((key, body)) = &writes.hosts {
            let stored = past_event(saved.event, now)
                .map_err(|error| format!("{key}: {error}"))
                .and_then(|()| store_event(&self.bucket, &scratch, key, body));
            if let Err(error) = stored {
                saved.open.retain(|alert| writes.open.contains(alert));
                save_alerts(&path, saved);
                return Err(Failure::Cycle(error));
            }
            saved.event = Some(now);
        }
        saved.open = writes.open;
        save_alerts(&path, saved);
        for record in &writes.failures {
            let key = decide::failure_key(&record.id);
            put(&self.bucket, &scratch, &key, &record.body, Bucket::put_once)?;
            known.insert(record.id.clone());
        }
        if let Some(summary) = &writes.digest {
            let key = decide::digest_key(&summary.day);
            put(
                &self.bucket,
                &scratch,
                &key,
                &summary.body,
                Bucket::put_once,
            )?;
            self.digested = Some(summary.day.clone());
        }
        let _ = file::remove_entry(&scratch);
        let seconds = started.elapsed().as_secs_f64();
        self.completed = Some(seconds);
        Ok(json!({
            "roots": roots.len(), "read": read, "cached": cached,
            "calls": self.bucket.calls() - calls,
            "hosts_event": writes.hosts.map(|(key, _)| key),
            "failures": writes.failures.len(), "waiting": writes.waiting,
            "digest": writes.digest.map(|summary| decide::digest_key(&summary.day)),
            "seconds": seconds,
        }))
    }
}

#[cfg(test)]
#[path = "cycle_tests.rs"]
mod tests;
