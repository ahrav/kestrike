//! Failure intake of a fuzz root: each distinct failure becomes one
//! directory and one line, and a repeat raises its key's count.
//!
//! A base is the directory intake files under: the fuzz root, or its
//! `control/` for the planted control. `failures/ID/` holds the first
//! failure of the key whose SHA-256 is `ID`, `findings.jsonl` one line
//! per key, and the root's `fuzz.json` each key's count.
//!
//! A key is known when its directory exists. A new key is written in the
//! order directory, line, count, and only then are the failing input's
//! corpus copies and the worker's files removed. A process kill at any
//! point therefore leaves a failure that kept a claim, an input or a file
//! libFuzzer wrote for it in the worker's files or in a complete directory, from
//! which [`repaired`] derives a missing line and count. A kill after a
//! new key's directory exists or a repeat's count is stored, and before
//! the removal ends, leaves the worker's files, which the next start
//! files as a repeat: each such kill raises the key's count one past its
//! failures, and the directory and the line stay exact.
//!
//! A filing removes the files of its own input and leaves the file
//! libFuzzer wrote for another, which a merge's processes can leave in
//! their shared directory. [`Session::drained`] files such a directory
//! once per failing input; the worker keeps a claim for the first alone,
//! so a later input's key is its libFuzzer file's.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::super::pen::Pen;
use super::super::{Error, KEYS, OTHER, held, key};
use super::{Ended, Job, Session, Slot, form, store, tail};
use crate::record::{Digest, Provenance, Text};
use crate::sim::input::{RECORD, Tag};
use crate::store::typed_host as present;
use crate::store::{Unreadable, names_host, open_host, remove_tree, rename_host, replace_host};

/// How long a rerun, and the control worker, may run.
pub(super) const RERUN: Duration = Duration::from_secs(600);

/// The bytes of `findings.jsonl` and of one `record.json` a start reads.
const LIST_BOUND: u64 = 16 << 20;

/// The most bytes one worker file may hold for intake to read it.
const ARTIFACT_BOUND: u64 = 64 << 20;

/// The worker's files for a failing input, its bundle and its claim.
const KEPT: [&str; 3] = [
    "first-failure.input",
    "first-failure.bundle",
    "first-failure.claim",
];

/// One ended process whose failure intake files.
pub(super) struct Failure<'a> {
    /// The fuzz target it ran, its artifact directory, its output file
    /// and its arguments, which are empty for a killed run's process.
    pub target: &'a str,
    pub artifacts: &'a Path,
    pub log: &'a Path,
    pub arguments: &'a [OsString],
    /// The run killed its pen at a bound; the kernel killed it for memory.
    pub killed: bool,
    pub memory: bool,
}

impl<'a> Failure<'a> {
    /// The failure of `ended`, which ran `job` for `target`.
    pub(super) fn of(target: &'a str, artifacts: &'a Path, job: &'a Job, ended: &Ended) -> Self {
        Self {
            target,
            artifacts,
            log: &job.log,
            arguments: &job.arguments,
            killed: ended.killed.is_some(),
            memory: ended.out_of_memory,
        }
    }
}

/// The run a failure came from and its archive's build. `provenance` is
/// that build's record, present when the current archive is that build.
pub(super) struct Origin<'a> {
    pub run: u64,
    pub build: &'a Text,
    pub provenance: Option<&'a Provenance>,
}

/// The key intake counted a failure under and, for the first failure of
/// a key, its rerun's result.
#[derive(Debug)]
pub(super) struct Filed {
    pub key: String,
    pub rerun: Option<&'static str>,
    /// A stop kept the rerun of a kept input from running to its end.
    /// Its stored result is `not run`, as for a failure with no input.
    pub cut: bool,
}

/// The directory name of `key`: its SHA-256.
pub(super) fn id(key: &str) -> String {
    Digest::of(key.as_bytes()).to_string()
}

struct Evidence {
    key: String,
    /// The worker's kept input, else, without a claim, the file
    /// libFuzzer wrote: a claim's input is the kept one alone, so a claim
    /// a cut removal left never takes another input's file.
    input: Option<PathBuf>,
    claimed: bool,
    /// The directory's files in the order intake removes those of the
    /// filed input: the file the key rests on last, so a removal a kill
    /// cut leaves the same key.
    files: Vec<PathBuf>,
}

/// Reads the worker file at `path`; `None` when the path has no entry.
/// The entry's own type is checked before a nonblocking open, so a FIFO
/// or a symlink a worker left ends the read at once.
///
/// # Errors
///
/// [`Error::Held`] for a symlink, a FIFO, a directory or a device and
/// for a failed read; [`Error::Unreadable`] for a file past
/// [`ARTIFACT_BOUND`] and for a failed open.
fn artifact(path: &Path) -> Result<Option<Vec<u8>>, Error> {
    if !present(path, false).map_err(held)? {
        return Ok(None);
    }
    let opened = open_host(path)?;
    if opened.len() > ARTIFACT_BOUND {
        return Err(Unreadable::Oversize.into());
    }
    let mut bytes = vec![0; opened.len() as usize];
    opened.read_exact_at(&mut bytes, 0).map_err(held)?;
    Ok(Some(bytes))
}

const ESCAPE: &str = "claim: ";

/// Escapes reserved claim keys so a claim named [`OTHER`] stays distinct
/// from the overflow key, and one that starts as a key [`evidence`]
/// derives from a process's end or a libFuzzer file from that key. A
/// claim that starts with [`ESCAPE`] is escaped too, so it stays distinct
/// from an escaped claim.
fn claimed(claim: &str) -> String {
    let text = key(claim.strip_suffix('\n').unwrap_or(claim));
    let reserved = [ESCAPE, "worker: ", "libfuzzer: "];
    if text == OTHER || reserved.iter().any(|prefix| text.starts_with(prefix)) {
        key(&format!("{ESCAPE}{text}")).to_owned()
    } else {
        text.to_owned()
    }
}

/// The kinds of file libFuzzer writes for an input that ends its process
/// and that have a key of their own.
const KINDS: [&str; 3] = ["timeout", "oom", "crash"];

/// The one key of a failed process, the first that applies: its claim's
/// text; an input kept without a claim; the kind of file libFuzzer wrote,
/// a [`KINDS`] file before any other and a `slow-unit-` file never; a kill
/// at a bound; a kill for memory; else an end without an input. A claim
/// that reads [`OTHER`] has the key `claim: other`, so the key [`OTHER`]
/// names only failures past the key bound. Reading evidence requires a
/// directory at `artifacts` and a regular file for the bundle.
fn evidence(artifacts: &Path, killed: bool, memory: bool) -> Result<Evidence, Error> {
    present(artifacts, true).map_err(held)?;
    present(&artifacts.join(KEPT[1]), false).map_err(held)?;
    let claim = artifact(&artifacts.join(KEPT[2]))?
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
    let kept = present(&artifacts.join(KEPT[0]), false)
        .map_err(held)?
        .then(|| artifacts.join(KEPT[0]));
    let kind = |name: &str| {
        KINDS
            .iter()
            .position(|kind| name.starts_with(&format!("{kind}-")))
    };
    let mut written = Vec::new();
    // A name is read as text to rank it and kept as it is for its path.
    for name in names_host(artifacts).map_err(held)? {
        let rank = {
            let text = name.to_string_lossy();
            if KEPT.contains(&&*text) {
                continue;
            }
            let slow = usize::from(text.starts_with("slow-unit-"));
            kind(&text).unwrap_or(KINDS.len() + slow)
        };
        written.push((rank, name));
    }
    written.sort();
    let ending = written.first().filter(|(kind, _)| *kind <= KINDS.len());
    let key = match (&claim, &kept, ending) {
        (Some(claim), ..) => claimed(claim),
        (None, Some(_), _) => "worker: input without a claim".to_owned(),
        (None, None, Some((kind, _))) => KINDS
            .get(*kind)
            .map_or("libfuzzer: other artifact".to_owned(), |kind| {
                format!("libfuzzer: {kind}")
            }),
        (None, None, None) if killed => "worker: killed at a bound".to_owned(),
        (None, None, None) if memory => "worker: out of memory".to_owned(),
        (None, None, None) => "worker: ended without an input".to_owned(),
    };
    let input = kept.or(ending
        .filter(|_| claim.is_none())
        .map(|(_, name)| artifacts.join(name)));
    let names = written.iter().rev().map(|(_, name)| name.as_os_str());
    Ok(Evidence {
        key,
        files: names
            .chain([KEPT[1], KEPT[0], KEPT[2]].map(OsStr::new))
            .map(|name| artifacts.join(name))
            .collect(),
        input,
        claimed: claim.is_some(),
    })
}

/// Whether `artifacts` holds a failure's file: a claim, a kept input or a
/// file libFuzzer wrote for an input that ended its process.
pub(super) fn failing(artifacts: &Path) -> Result<bool, Error> {
    let found = evidence(artifacts, false, false)?;
    Ok(found.claimed || found.input.is_some())
}

/// Prints `line`; a closed standard output leaves the finding stored.
fn printed(line: &str) {
    let _ = io::Write::write_all(&mut io::stdout(), line.as_bytes());
}

/// The digest two runs of one input share: the SHA-256 of the records
/// of `bundle` other than checkpoints and diagnostics, as the worker
/// defines a bundle's semantic digest, then of any bytes after the last
/// whole record.
fn semantic(bundle: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    let mut kept = 0;
    for (index, record) in bundle.chunks(RECORD).enumerate() {
        if record.len() == RECORD && Tag::of(record[0]) == Tag::Skipped {
            let skipped = index * RECORD;
            hasher.update(&bundle[kept..skipped]);
            kept = skipped + RECORD;
        }
    }
    hasher.update(&bundle[kept..]);
    Digest::finish(hasher)
}

/// The `findings.jsonl` line of the failure directory `id`, built from
/// its `record.json` at intake and at a start's repair alike.
fn line(id: &str, record: &Value) -> String {
    let line = json!({
        "id": id,
        "key": record["key"],
        "build": record["build"],
        "revision": record["revision"],
        "run": record["run"],
        "directory": format!("failures/{id}"),
        "rerun": record["rerun"],
    });
    format!("{line}\n")
}

/// The IDs `findings.jsonl` under `base` lists.
fn listed(base: &Path) -> Result<BTreeSet<String>, Error> {
    let bytes = crate::store::read_host(&base.join("findings.jsonl"), LIST_BOUND)?;
    Ok(String::from_utf8_lossy(&bytes.unwrap_or_default())
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|line| line["id"].as_str().map(str::to_owned))
        .collect())
}

/// Makes the records under `base` agree with its failure directories:
/// cuts a last line of `findings.jsonl` a kill left without its newline,
/// appends the line of each directory that has none, once `failures/` is
/// synced as [`published`] syncs it, and gives each directory's key the
/// count 1 in `keys` when it has none.
pub(super) fn repaired(base: &Path, keys: &mut BTreeMap<String, u64>) -> Result<(), Error> {
    let list = base.join("findings.jsonl");
    crate::store::trim_host(&list).map_err(held)?;
    let listed = listed(base)?;
    let failures = base.join("failures");
    let entries = match names_host(&failures) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(held(error)),
    };
    for name in entries {
        let name = name.to_string_lossy();
        if name.ends_with(".tmp") {
            continue;
        }
        let unread = || Error::Held(format!("failures/{name}/record.json is no record"));
        let record = failures.join(&*name).join("record.json");
        let record: Value = crate::store::read_host(&record, LIST_BOUND)?
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or_else(unread)?;
        let key = record["key"].as_str().filter(|key| id(key) == *name);
        let whole =
            record["build"].is_string() && record["rerun"].is_string() && record["run"].is_u64();
        let key = key.filter(|_| whole).ok_or_else(unread)?.to_owned();
        if !listed.contains(&*name) {
            crate::store::sync_parent(&failures.join(&*name)).map_err(held)?;
            let line = line(&name, &record);
            crate::store::append_host(&list, line.as_bytes()).map_err(held)?;
            printed(&line);
        }
        keys.entry(key).or_insert(1);
    }
    Ok(())
}

/// Whether `base` holds the stored first failure of `key`.
pub(super) fn known(base: &Path, key: &str) -> Result<bool, Error> {
    present(&base.join("failures").join(id(key)), true).map_err(held)
}

/// Whether `filed`, the control's failure under `base`, is a complete
/// violation of the `planted` target, reproduced by its rerun and stored
/// with directory and line. The key holds the terminal's class and event
/// masks, and the stored bundle alone records the rule the run violated.
/// A caught control shows that a failure of the planted target reaches
/// its line through intake.
///
/// # Errors
///
/// [`Error::Held`] for a directory whose status cannot be read for a
/// cause other than its absence, and [`Error::Unreadable`] for a
/// `findings.jsonl` under `base` that cannot be read.
pub(super) fn caught(base: &Path, filed: &Filed) -> Result<bool, Error> {
    if !filed.key.starts_with("planted: complete violation") || filed.rerun != Some("reproduced") {
        return Ok(false);
    }
    let id = id(&filed.key);
    let stored = present(&base.join("failures").join(&id), true).map_err(held)?;
    Ok(stored && listed(base)?.contains(&id))
}

/// Removes each file of `corpus/` and `corpus.new/` under `base` whose
/// bytes equal the failing input of `found`, which would fail every
/// worker that loads it, then the worker's kept files and each file of
/// `artifacts` with those bytes, in the order of [`Evidence::files`]. A
/// file of other bytes stays: it is another input's, or no failure's. A
/// corpus file a running worker removed meanwhile and an absent corpus
/// directory are passed over; a corpus that is no directory or cannot be
/// listed, a corpus entry that cannot be read, or an `artifacts` that is
/// no directory any more holds the intake before it removes an artifact
/// file.
fn discarded(
    base: &Path,
    artifacts: &Path,
    found: &Evidence,
    bytes: Option<&[u8]>,
) -> Result<(), Error> {
    present(artifacts, true).map_err(held)?;
    // Whether the file at `path` holds the input's bytes; a path with no
    // entry does not.
    let same = |path: &Path| {
        let Some(bytes) = bytes else {
            return Ok(false);
        };
        let opened = match open_host(path) {
            Err(Unreadable::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(false);
            }
            opened => opened?,
        };
        if opened.len() != bytes.len() as u64 {
            return Ok(false);
        }
        let mut read = vec![0; bytes.len()];
        opened.read_exact_at(&mut read, 0).map_err(held)?;
        Ok::<_, Error>(read == bytes)
    };
    let corpora = ["corpus", "corpus.new"].map(|corpus| base.join(corpus));
    for corpus in corpora.iter().filter(|_| bytes.is_some()) {
        if !present(corpus, true).map_err(held)? {
            continue;
        }
        let entries = names_host(corpus).map_err(held)?;
        for path in entries.iter().map(|name| corpus.join(name)) {
            if same(&path)? {
                crate::store::remove_host(&path).map_err(held)?;
            }
        }
    }
    present(artifacts, true).map_err(held)?;
    let own = |file: &&PathBuf| {
        KEPT.iter().any(|kept| file.ends_with(kept))
            || found.input.as_ref() == Some(*file)
            || same(file).unwrap_or(false)
    };
    let removed = found
        .files
        .iter()
        .filter(own)
        .try_for_each(|file| crate::store::remove_host(file));
    removed.map_err(held)
}

/// Publishes the failure staged by [`Session::staged`], appends its
/// record's line to `findings.jsonl` and returns that line. The rename is synced to `failures/` before
/// the append, so the directory a line names outlasts a power loss with
/// the line. The caller holds the record lock across trim and append so
/// `trim_host` only removes partial lines from failed appends.
fn published(base: &Path, key: &str, record: &Value) -> Result<String, Error> {
    let id = id(key);
    let failures = base.join("failures");
    let directory = failures.join(&id);
    rename_host(&failures.join(format!("{id}.tmp")), &directory)
        .and_then(|()| crate::store::sync_parent(&directory))
        .map_err(held)?;
    let line = line(&id, record);
    let list = base.join("findings.jsonl");
    crate::store::trim_host(&list)
        .and_then(|()| crate::store::append_host(&list, line.as_bytes()))
        .map_err(held)?;
    Ok(line)
}

/// An intake's entry in [`super::Filing::storing`]. Its drop takes the
/// record lock, removes the entry and wakes the waiting intakes, so an
/// intake that returns an error or unwinds while it stages a key leaves
/// the key free for the next intake.
struct Reserved<'a> {
    session: &'a Session<'a>,
    entry: (PathBuf, String),
}

impl Drop for Reserved<'_> {
    fn drop(&mut self) {
        let filing = self.session.filing.lock();
        let mut filing = filing.unwrap_or_else(std::sync::PoisonError::into_inner);
        filing.storing.remove(&self.entry);
        self.session.stored.notify_all();
    }
}

impl Session<'_> {
    /// Files `failure` of run `origin` under `base`. A known key gains one
    /// count. A new key is rerun in `pen` when one is given and an input
    /// exists, then stored. A new key past [`KEYS`] keys is filed under
    /// [`OTHER`]: the first is stored as a new key is and stops the run,
    /// and a later one is counted with its files left in place. The
    /// record lock orders key selection, publication, and counting for
    /// each failure. Staging and rerunning a new key take place outside
    /// the lock. A failure equal to one being staged waits for its
    /// directory, so two equal failures give one line, and failures of
    /// other keys are filed during a rerun. Counts, the key bound with
    /// its stop, and the printed line of a new key are the root's: under
    /// another base `fuzz.json` and standard output stay as they are.
    /// `intake` reads the failing input before acquiring the record lock
    /// and retains its bytes through cleanup. If the read fails, `intake`
    /// holds the failure before incrementing its count.
    pub(super) fn intake(
        &self,
        base: &Path,
        origin: &Origin<'_>,
        failure: &Failure<'_>,
        pen: Option<(&Arc<Pen>, &Slot)>,
    ) -> Result<Filed, Error> {
        let found = evidence(failure.artifacts, failure.killed, failure.memory)?;
        let input = match &found.input {
            Some(input) => {
                Some(artifact(input)?.ok_or_else(|| held(io::ErrorKind::NotFound.into()))?)
            }
            None => None,
        };
        let rooted = base == self.plan.root;
        let entry = |key: &str| (base.to_owned(), key.to_owned());
        // `reserved` is declared before the lock guard `filing`, so on
        // every path out of this function the guard is dropped first and
        // the drop of `reserved` can take the lock.
        let mut reserved = None;
        let mut filing = self.filing.lock().expect("no thread panics holding it");
        let key = loop {
            let keys = &filing.record.keys;
            let staging = filing.storing.iter().filter(|(at, _)| at == base);
            let pending = staging.filter_map(|(_, key)| (!keys.contains_key(key)).then_some(key));
            let keyed = keys.keys().chain(pending).filter(|key| *key != OTHER);
            let admitted = !rooted || keyed.count() < KEYS;
            let stored = filing.storing.contains(&entry(&found.key)) || known(base, &found.key)?;
            let key = if admitted || stored {
                found.key.clone()
            } else {
                OTHER.to_owned()
            };
            if known(base, &key)? {
                break key;
            }
            if filing.storing.insert(entry(&key)) {
                reserved = Some(Reserved {
                    session: self,
                    entry: entry(&key),
                });
                break key;
            }
            filing = self
                .stored
                .wait(filing)
                .expect("no thread panics holding it");
        };
        let repeat = reserved.is_none();
        let rerun = if repeat {
            None
        } else {
            drop(filing);
            let (rerun, record) = self.staged(base, origin, failure, &found, &key, pen)?;
            filing = self.filing.lock().expect("no thread panics holding it");
            let line = published(base, &key, &record)?;
            if rooted {
                printed(&line);
            }
            Some(rerun)
        };
        if rooted {
            let keys = &mut filing.record.keys;
            let count = keys.entry(key.clone()).or_insert(1);
            *count = if repeat { count.saturating_add(1) } else { 1 };
            store(base, &filing.record).map_err(held)?;
        }
        drop(filing);
        drop(reserved);
        if key == OTHER {
            let _ = self.stop.set("key table full");
        }
        if !(repeat && key == OTHER) {
            discarded(base, failure.artifacts, &found, input.as_deref())?;
        }
        // With a pen and an input, a stop alone leaves a rerun `not run`.
        let cut = rerun == Some("not run") && pen.is_some() && found.input.is_some();
        Ok(Filed { key, rerun, cut })
    }

    /// Stages the first failure of `key` in `failures/ID.tmp`: its
    /// evidence, its rerun in `pen` and `record.json`. Returns the
    /// rerun's result and the record [`published`] takes.
    fn staged(
        &self,
        base: &Path,
        origin: &Origin<'_>,
        failure: &Failure<'_>,
        found: &Evidence,
        key: &str,
        pen: Option<(&Arc<Pen>, &Slot)>,
    ) -> Result<(&'static str, Value), Error> {
        let id = id(key);
        let (staged, directory) = (
            base.join("failures").join(format!("{id}.tmp")),
            base.join("failures").join(&id),
        );
        remove_tree(&staged)
            .and_then(|()| crate::store::create_dirs(&staged.join("rerun")))
            .map_err(held)?;
        let kept = |kept: &str| failure.artifacts.join(kept);
        for (source, name) in [
            (
                found.input.clone().unwrap_or_else(|| kept(KEPT[0])),
                "input",
            ),
            (kept(KEPT[1]), "bundle"),
            (kept(KEPT[2]), "claim"),
        ] {
            if let Some(bytes) = artifact(&source)? {
                replace_host(&staged.join(name), &bytes).map_err(held)?;
            }
        }
        let rerun = match pen.filter(|_| found.input.is_some()) {
            Some((pen, slot)) => self.rerun(failure.target, &staged, found, pen, slot)?,
            None => "not run",
        };
        let mut record = json!({
            "key": key,
            "run": origin.run,
            "build": origin.build.as_str(),
            "worker": failure.arguments.iter().map(|word| word.to_string_lossy()).collect::<Vec<_>>(),
            // The rerun's arguments as they read once the directory has
            // its name.
            "rerun_arguments": form(failure.target, &directory.join("rerun"), [directory.join("input").into()])
                .iter().map(|word| word.to_string_lossy().into_owned()).collect::<Vec<_>>(),
            "rerun": rerun,
        });
        if let Some(build) = origin.provenance {
            record["revision"] = json!(build.revision);
            record["toolchain"] = json!(build.toolchain);
            record["cargo"] = json!(build.cargo);
            record["environment"] = json!(build.environment);
            record["dirty"] = json!(build.dirty);
            record["untracked"] = json!(build.untracked);
        }
        let bytes = serde_json::to_vec(&record).expect("the record encodes");
        replace_host(
            &staged.join("stderr.tail"),
            &tail(failure.log).unwrap_or_default(),
        )
        .and_then(|()| replace_host(&staged.join("record.json"), &bytes))
        .map_err(held)?;
        Ok((rerun, record))
    }

    /// Runs the staged input again, alone, in a fresh process in `pen`
    /// with the staged directory's empty `rerun/` as its artifact
    /// directory, for at most [`RERUN`]. The result is `unreproduced` for
    /// exit 0, `not run` for a rerun a stop ended or kept from starting,
    /// `reproduced` for the same key and, when both runs kept a bundle,
    /// bundles of one [`semantic`] digest, and else `diverged`. For a key without a claim,
    /// `reproduced` means the rerun ended nonzero without a claim. The
    /// input is the rerun's only libFuzzer argument, so libFuzzer's own
    /// time and memory limits apply in place of the worker's: an input
    /// that failed at a worker's limit can read `unreproduced`, and a
    /// claimed one that passes libFuzzer's memory limit `diverged`.
    fn rerun(
        &self,
        target: &str,
        staged: &Path,
        found: &Evidence,
        pen: &Arc<Pen>,
        slot: &Slot,
    ) -> Result<&'static str, Error> {
        let artifacts = staged.join("rerun");
        let job = Job {
            arguments: form(target, &artifacts, [staged.join("input").into()]),
            log: staged.join("rerun.stderr"),
            limit: Instant::now() + RERUN,
        };
        let Some(ended) = self.waited(pen, &job, slot)?.filter(|ended| !ended.stopped) else {
            return Ok("not run");
        };
        if !ended.failed() {
            return Ok("unreproduced");
        }
        let again = evidence(&artifacts, ended.killed.is_some(), ended.out_of_memory)?;
        if !found.claimed || again.key != found.key {
            let reproduced = !found.claimed && !again.claimed;
            return Ok(if reproduced { "reproduced" } else { "diverged" });
        }
        // Each bundle is hashed and dropped before the next is read, so
        // threads that rerun at once hold one bundle each, beside the
        // input [`Session::intake`] retains.
        let digest =
            |bundle: PathBuf| Ok::<_, Error>(artifact(&bundle)?.map(|bytes| semantic(&bytes)));
        let same = match (
            digest(staged.join("bundle"))?,
            digest(artifacts.join(KEPT[1]))?,
        ) {
            (Some(first), Some(second)) => first == second,
            _ => true,
        };
        Ok(if same { "reproduced" } else { "diverged" })
    }

    /// Files what a run killed between a failure and its intake left in
    /// its artifact directories: a claim, a kept input or a failing
    /// input's libFuzzer file. A failure of the current archive's build
    /// is rerun in `pen` when one is given; one of another build is
    /// stored with `not run` and that build's digest alone. A killed
    /// run's exits are recorded nowhere, so a directory without such a
    /// file stays as the run left it, with its process's output file
    /// beside it until the run's directory is pruned.
    pub(super) fn leftover(&self, pen: Option<(&Arc<Pen>, &Slot)>) -> Result<(), Error> {
        let filing = self.filing.lock().expect("no thread panics holding it");
        let last = filing.record.last.clone();
        drop(filing);
        let Some(last) = last else {
            return Ok(());
        };
        let runs = self.plan.root.join("runs");
        let run = runs.join(last.run.to_string());
        if !(present(&runs, true).map_err(held)? && present(&run, true).map_err(held)?) {
            return Ok(());
        }
        let entries = crate::store::subdirectories(&run).map_err(held)?;
        let same = last.build == self.worker.build;
        let origin = Origin {
            run: last.run,
            build: &last.build,
            provenance: same.then_some(&self.worker.provenance),
        };
        // Checking each entry's own file type confines the intake to
        // the directories that are direct children of `run`.
        let mut directories = Vec::new();
        for name in entries {
            let name = name.to_string_lossy();
            let worker = name
                .strip_prefix('w')
                .is_some_and(|number| number.parse::<u64>().is_ok());
            if worker || name == "merge" {
                directories.push(run.join(&*name));
            }
        }
        directories.sort();
        for artifacts in directories {
            let failure = Failure {
                target: "campaign",
                artifacts: &artifacts,
                log: &artifacts.with_extension("stderr"),
                arguments: &[],
                killed: false,
                memory: false,
            };
            self.drained(&origin, &failure, pen.filter(|_| same))?;
        }
        Ok(())
    }

    /// Files `failure` under the root while its directory holds a
    /// failure's file, once per failing input, and returns the first
    /// filing. A filing under [`OTHER`] that left its files in place
    /// ends it.
    pub(super) fn drained(
        &self,
        origin: &Origin<'_>,
        failure: &Failure<'_>,
        pen: Option<(&Arc<Pen>, &Slot)>,
    ) -> Result<Option<Filed>, Error> {
        let mut first = None;
        while failing(failure.artifacts)? {
            let filed = self.intake(&self.plan.root, origin, failure, pen)?;
            let left = filed.key == OTHER && filed.rerun.is_none();
            first.get_or_insert(filed);
            if left {
                break;
            }
        }
        Ok(first)
    }
}

#[cfg(test)]
#[path = "intake_tests.rs"]
mod tests;
