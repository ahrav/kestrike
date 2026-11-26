//! A long cluster run streamed into durable windows.
//!
//! A session runs one cluster profile from its manifest's root into a new
//! directory, holding only the open window's records in memory. The
//! directory's own entry is synced in its parent first; the directory then
//! receives `manifest`, the run's manifest text, an empty `index` and
//! `windows/`, each synced with the directory that names it.
//! The `begin`, `clock`, `turn` and `end` callbacks of the turn controller
//! each become one record, `tag`, a little-endian `u32` length, then its
//! bytes: the run's record and opening choices (`BEGIN`), each clock move's
//! choices, time and events (`CLOCK`), each turn's choices, time,
//! candidate, outcome and events (`TURN`), and the closing choices
//! (`END`). `BEGIN` starts with the run record's `u32` length, and `CLOCK`
//! and `TURN` with their choices' `u32` length. An event is its kind then
//! its payload.
//!
//! A window closes after the record holding a cluster window event. Its
//! records are written to `windows/NNNNNN.chunk`, created new and synced
//! with `windows/`, and only then is its line appended to `index` and
//! synced. A failed append restores and syncs the prior index length before the
//! writer latches its failure. A rollback failure leaves the run incomplete and
//! the visible prefix's durability unknown. The line names the window's index, turns, the SHA-256 of its chunk, the chained
//! digest and the window event's verdict, marks and reached counts. The
//! chained digest of window `i` is the SHA-256 of the previous chained
//! digest, `i` as a little-endian `u32` and the chunk's digest; the chain
//! starts from the SHA-256 of the `manifest` file, so a changed input
//! breaks the chain of every window.
//!
//! A window whose line is absent is uncommitted; the records after the last
//! window go to `windows/tail.chunk`, and `end` records how the run ended
//! with the window count, the last chained digest and the tail chunk's
//! SHA-256. A session without its `end` is incomplete. A run that panicked
//! ends with an `end` naming the panic. A latched write failure or an
//! exhausted record or byte budget stops later callbacks from writing,
//! drops the open window, halts the run and
//! leaves the session incomplete. The byte budget counts every file the
//! session writes: the manifest, each chunk with its index line, the tail
//! chunk and `end`.

use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::sim::choice::CANDIDATE_LEN;
use crate::sim::trace::{Event, PAYLOAD};
use crate::sim::turn::{Hook, Turn};

use super::branch::hex;
use super::cluster::{WINDOW, WINDOW_VERDICT, window_words};

pub(crate) const BEGIN: u8 = 1;
pub(crate) const CLOCK: u8 = 2;
pub(crate) const TURN: u8 = 3;
pub(crate) const END: u8 = 4;

/// One committed window as its index line names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Window {
    pub(crate) index: u32,
    pub(crate) turns: u64,
    pub(crate) digest: [u8; 32],
    pub(crate) chain: [u8; 32],
    /// The window event's payload.
    pub(crate) event: [u8; PAYLOAD],
}

impl Window {
    /// The window's index line, without its newline.
    pub(crate) fn line(&self) -> String {
        let [
            _,
            carried,
            registry,
            outstanding,
            kept,
            published,
            hits,
            faults,
            reused,
            healed,
        ] = window_words(&self.event);
        format!(
            "window {} turns={} digest={} chain={} verdict={} carried={carried} registry={registry} outstanding={outstanding} kept={kept} published={published} hits={hits} faults={faults} reused={reused} healed={healed}",
            self.index,
            self.turns,
            hex(&self.digest),
            hex(&self.chain),
            if self.event[WINDOW_VERDICT] == 1 {
                "pass"
            } else {
                "failed"
            },
        )
    }
}

/// The chain's origin: the SHA-256 of the session's manifest text.
pub(crate) fn origin(manifest: &[u8]) -> [u8; 32] {
    Sha256::digest(manifest).into()
}

/// The chained digest after `previous` for window `index` whose chunk
/// digest is `digest`.
pub(crate) fn chained(previous: &[u8; 32], index: u32, digest: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(previous);
    hash.update(index.to_le_bytes());
    hash.update(digest);
    hash.finalize().into()
}

/// The most records and bytes a session may write, its manifest's
/// `records` and `bytes`. A session record is one `begin`, `clock`, `turn`
/// or `end` callback of any length, where a bundle's `records` counts
/// fixed 48-byte records; `bytes` counts every session file's bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Budget {
    pub(crate) records: u64,
    pub(crate) bytes: u64,
}

/// The session writer: the controller's hook that streams records into the
/// open window and commits each window as it closes.
pub(crate) struct Writer {
    dir: PathBuf,
    window: Vec<u8>,
    turns: u64,
    chain: [u8; 32],
    committed: u32,
    budget: Budget,
    /// Records pushed, and bytes of the manifest, committed chunks and
    /// their index lines written so far.
    spent: Budget,
    /// The first failure; nothing is written after it.
    failed: Option<String>,
    /// The largest allocation the window buffer held.
    pub(crate) high_water: usize,
}

impl Writer {
    /// A writer into `dir`, which must exist and hold no session, for the
    /// run of `manifest` within `budget`: syncs `dir`'s entry in its
    /// parent, writes and syncs `manifest`, an empty `index` and
    /// `windows/`, then syncs `dir`. A `manifest` longer than the byte
    /// budget writes no file and returns a writer whose failure is latched:
    /// every later callback writes nothing, and the controller ends the run
    /// `Halted` at its first halt poll, after `begin` and the first clock
    /// move and before any turn.
    ///
    /// # Errors
    ///
    /// The I/O error syncing `dir`'s parent, naming that step, or creating
    /// or syncing one of the files.
    pub(crate) fn new(dir: &Path, manifest: &str, budget: Budget) -> std::io::Result<Self> {
        sync_parent(dir).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("syncing the parent of {}: {error}", dir.display()),
            )
        })?;
        let mut writer = Self {
            dir: dir.to_path_buf(),
            window: Vec::new(),
            turns: 0,
            chain: origin(manifest.as_bytes()),
            committed: 0,
            budget,
            spent: Budget {
                records: 0,
                bytes: 0,
            },
            failed: None,
            high_water: 0,
        };
        if writer.fits(manifest.len() as u64) {
            durable(&dir.join("manifest"), manifest.as_bytes())?;
            durable(&dir.join("index"), &[])?;
            std::fs::create_dir(dir.join("windows"))?;
            sync_dir(dir)?;
            writer.spent.bytes = manifest.len() as u64;
        }
        Ok(writer)
    }

    /// Windows committed so far.
    pub(crate) fn committed(&self) -> u32 {
        self.committed
    }

    pub(crate) fn chain(&self) -> [u8; 32] {
        self.chain
    }

    pub(crate) fn failed(&self) -> Option<&str> {
        self.failed.as_deref()
    }

    /// Records the first failure and drops the open window, which no
    /// later write commits.
    fn fail(&mut self, reason: String) {
        self.failed.get_or_insert(reason);
        self.window = Vec::new();
    }

    /// Whether `more` bytes fit the byte budget beside those spent; when
    /// they do not, latches the spent budget as the writer's failure.
    fn fits(&mut self, more: u64) -> bool {
        if self.spent.bytes + more > self.budget.bytes {
            self.fail(format!(
                "the session's byte budget of {} is spent",
                self.budget.bytes
            ));
            return false;
        }
        true
    }

    fn push(&mut self, tag: u8, parts: &[&[u8]], events: &[Event]) {
        if self.failed.is_some() {
            return;
        }
        let len: usize =
            parts.iter().map(|part| part.len()).sum::<usize>() + events.len() * (1 + PAYLOAD);
        // Each inner length is at most `len`, so it fits too.
        let Ok(len32) = u32::try_from(len) else {
            return self.fail(format!("a record of {len} bytes passes u32::MAX"));
        };
        self.spent.records += 1;
        if self.spent.records > self.budget.records {
            return self.fail(format!(
                "the session's record budget of {} is spent",
                self.budget.records
            ));
        }
        if !self.fits((self.window.len() + 5 + len) as u64) {
            return;
        }
        self.window.push(tag);
        self.window.extend(len32.to_le_bytes());
        for part in parts {
            self.window.extend_from_slice(part);
        }
        for event in events {
            self.window.push(event.kind);
            self.window.extend_from_slice(&event.payload);
        }
        self.high_water = self.high_water.max(self.window.capacity());
        if let Some(event) = events.iter().rev().find(|event| event.kind == WINDOW) {
            self.commit(event.payload);
        }
    }

    fn append(
        &self,
        name: &str,
        line: &str,
        mut sync: impl FnMut(&std::fs::File) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(self.dir.join(name))?;
        let committed = file.metadata()?.len();
        if let Err(error) = file
            .write_all(format!("{line}\n").as_bytes())
            .and_then(|()| sync(&file))
        {
            let rollback = file.set_len(committed).and_then(|()| sync(&file));
            return Err(match rollback {
                Ok(()) => error,
                Err(rollback) => std::io::Error::new(
                    error.kind(),
                    format!("{error}; {name} rollback failed: {rollback}"),
                ),
            });
        }
        Ok(())
    }

    /// Commits the open window: its chunk, synced with `windows/`, then
    /// its index line.
    fn commit(&mut self, event: [u8; PAYLOAD]) {
        self.commit_with_sync(event, std::fs::File::sync_all);
    }

    /// Commits a window with an injected index-file sync operation for fault tests.
    /// An append failure restores and syncs the prior index length before latching.
    /// A failed rollback latches an incomplete run; the visible prefix's durability
    /// then remains unknown. Every later callback observes the latched failure.
    pub(crate) fn commit_with_sync(
        &mut self,
        event: [u8; PAYLOAD],
        sync: impl FnMut(&std::fs::File) -> std::io::Result<()>,
    ) {
        if self.failed.is_some() {
            return;
        }
        let index = self.committed;
        let digest: [u8; 32] = Sha256::digest(&self.window).into();
        let chain = chained(&self.chain, index, &digest);
        let window = Window {
            index,
            turns: self.turns,
            digest,
            chain,
            event,
        };
        let line = window.line();
        let bytes = (self.window.len() + line.len() + 1) as u64;
        if !self.fits(bytes) {
            return;
        }
        let windows = self.dir.join("windows");
        let written = durable(&windows.join(format!("{index:06}.chunk")), &self.window)
            .and_then(|()| sync_dir(&windows))
            .and_then(|()| self.append("index", &line, sync));
        match written {
            Ok(()) => {
                self.chain = chain;
                self.committed += 1;
                self.spent.bytes += bytes;
                self.window.clear();
                self.turns = 0;
            }
            Err(error) => self.fail(format!("window {index}: {error}")),
        }
    }

    /// If syncing the session directory fails, `finish` attempts to remove
    /// `end`; removal can fail and leave the file visible.
    pub(crate) fn finish(&mut self, end: &str) {
        if self.failed.is_some() {
            return;
        }
        let tail: [u8; 32] = Sha256::digest(&self.window).into();
        let line = format!(
            "{end} windows={} chain={} tail={}\n",
            self.committed,
            hex(&self.chain),
            hex(&tail)
        );
        if !self.fits((self.window.len() + line.len()) as u64) {
            return;
        }
        let windows = self.dir.join("windows");
        let end = self.dir.join("end");
        let written = durable(&windows.join("tail.chunk"), &self.window)
            .and_then(|()| sync_dir(&windows))
            .and_then(|()| durable(&end, line.as_bytes()))
            .and_then(|()| {
                sync_dir(&self.dir).inspect_err(|_| {
                    let _ = std::fs::remove_file(&end);
                })
            });
        if let Err(error) = written {
            self.fail(format!("end: {error}"));
        }
    }
}

/// If writing or syncing fails, `durable` attempts to remove the file it
/// created and returns the original error even if removal fails.
fn durable(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .inspect_err(|_| {
            let _ = std::fs::remove_file(path);
        })
}

/// Syncs the directory `path`, so the entries it names persist.
fn sync_dir(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

/// Syncs the directory holding `path`, the current directory for a path
/// of one component, so `path`'s own entry persists.
fn sync_parent(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => sync_dir(parent),
        _ => sync_dir(Path::new(".")),
    }
}

impl Hook for Writer {
    fn begin(&mut self, record: &[u8], choices: &[u8]) {
        let len = (record.len() as u32).to_le_bytes();
        self.push(BEGIN, &[&len, record, choices], &[]);
    }

    fn clock(&mut self, choices: &[u8], now: u64, events: &[Event]) {
        let len = (choices.len() as u32).to_le_bytes();
        self.push(CLOCK, &[&len, choices, &now.to_le_bytes()], events);
    }

    fn turn(&mut self, choices: &[u8], turn: &Turn, events: &[Event]) {
        self.turns += 1;
        let len = (choices.len() as u32).to_le_bytes();
        let parts: [&[u8]; 5] = [
            &len,
            choices,
            &turn.now.to_le_bytes(),
            &turn.event.0,
            &turn.outcome.to_le_bytes(),
        ];
        self.push(TURN, &parts, events);
    }

    fn end(&mut self, choices: &[u8]) {
        self.push(END, &[choices], &[]);
    }

    fn halted(&self) -> bool {
        self.failed.is_some()
    }
}

/// The first record at which two windows' chunks differ: its position in
/// the window and its tag, and for a turn record its time and candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Divergence {
    pub(crate) record: usize,
    pub(crate) tag: u8,
    pub(crate) turn: Option<(u64, [u8; CANDIDATE_LEN])>,
}

/// The records of a chunk: each tag and body.
pub(crate) fn records(chunk: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 5 <= chunk.len() {
        let len =
            u32::from_le_bytes(chunk[at + 1..at + 5].try_into().expect("four bytes")) as usize;
        let end = (at + 5).saturating_add(len).min(chunk.len());
        out.push((chunk[at], &chunk[at + 5..end]));
        at = end;
    }
    out
}

/// Where `replayed` first departs from `original`, `None` when they agree.
pub(crate) fn divergence(original: &[u8], replayed: &[u8]) -> Option<Divergence> {
    let (ours, theirs) = (records(original), records(replayed));
    let at = (0..ours.len().max(theirs.len())).find(|&at| ours.get(at) != theirs.get(at))?;
    let (tag, body) = ours.get(at).or_else(|| theirs.get(at)).copied()?;
    let turn = (tag == TURN).then(|| {
        let choices = u32::from_le_bytes(body.get(..4)?.try_into().ok()?) as usize;
        let rest = body.get(4usize.saturating_add(choices)..)?;
        let now = u64::from_le_bytes(rest.get(..8)?.try_into().ok()?);
        let candidate: [u8; CANDIDATE_LEN] = rest.get(8..8 + CANDIDATE_LEN)?.try_into().ok()?;
        Some((now, candidate))
    });
    Some(Divergence {
        record: at,
        tag,
        turn: turn.flatten(),
    })
}

/// The value of `line`'s last field `name`, so the fields the writer
/// appends after a panic's text read as written.
fn field<'l>(line: &'l str, name: &str) -> Option<&'l str> {
    line.rsplit(' ')
        .find_map(|field| field.strip_prefix(name)?.strip_prefix('='))
}

/// The first field name, lowercase letters and `_`, that `line` names
/// twice as `name=value`, so each field read through [`field`] has exactly
/// one value.
fn repeated(line: &str) -> Option<&str> {
    let names: Vec<&str> = line
        .split(' ')
        .filter_map(|field| Some(field.split_once('=')?.0))
        .filter(|name| {
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
        })
        .collect();
    names
        .iter()
        .enumerate()
        .find_map(|(at, name)| names[..at].contains(name).then_some(*name))
}

/// The SHA-256 of the file `path`, read in bounded pieces.
fn digest_of(path: &Path) -> std::io::Result<[u8; 32]> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut piece = vec![0; 1 << 16];
    loop {
        match file.read(&mut piece)? {
            0 => return Ok(hash.finalize().into()),
            read => hash.update(&piece[..read]),
        }
    }
}

/// The committed windows' index lines in `dir`, each chunk hashed in
/// bounded pieces and checked against its line's digest and the chain
/// from the session's manifest, and the last chained digest.
///
/// # Errors
///
/// A missing or unreadable manifest, index or chunk, an index whose last
/// line is torn or that holds a carriage return, a chunk whose digest
/// differs, or a line out of order, naming a field twice or out of its
/// chain.
pub(crate) fn committed(dir: &Path) -> Result<(Vec<String>, [u8; 32]), String> {
    let manifest = std::fs::read(dir.join("manifest"))
        .map_err(|error| format!("the session manifest: {error}"))?;
    let index = std::fs::read_to_string(dir.join("index"))
        .map_err(|error| format!("the session index: {error}"))?;
    if !index.is_empty() && !index.ends_with('\n') {
        return Err("the session index ends in a torn line".to_owned());
    }
    // `lines` drops a carriage return before each newline, which would let
    // a rewritten index read as the one the writer committed.
    if index.contains('\r') {
        return Err("the session index holds a carriage return".to_owned());
    }
    let mut chain = origin(&manifest);
    let mut out = Vec::new();
    for (at, line) in index.lines().enumerate() {
        if !line.starts_with(&format!("window {at} ")) {
            return Err(format!("index line {at} is out of order"));
        }
        if let Some(name) = repeated(line) {
            return Err(format!("window {at} names {name} twice"));
        }
        let named = |name| field(line, name).ok_or_else(|| format!("window {at} names no {name}"));
        let digest = digest_of(&dir.join("windows").join(format!("{at:06}.chunk")))
            .map_err(|error| format!("window {at}'s chunk: {error}"))?;
        if hex(&digest) != named("digest")? {
            return Err(format!("window {at}'s chunk is truncated or changed"));
        }
        chain = chained(&chain, at as u32, &digest);
        if hex(&chain) != named("chain")? {
            return Err(format!("window {at} is out of its chain"));
        }
        out.push(line.to_owned());
    }
    Ok((out, chain))
}

/// The `end` line of the session in `dir` whose committed windows are
/// `windows` lines chaining to `chain`, checked against them and against
/// the tail chunk's digest.
///
/// # Errors
///
/// A missing or torn `end`, one holding a carriage return, naming a field
/// twice or another window count or chain, or a missing, truncated or
/// changed tail chunk.
/// The end of a panicked run carries the panic's text, so its fields may
/// repeat; its window count, chain and tail are read from the fields the
/// writer appends last.
pub(crate) fn ended(dir: &Path, windows: usize, chain: &[u8; 32]) -> Result<String, String> {
    let text = std::fs::read_to_string(dir.join("end"))
        .map_err(|error| format!("the session is incomplete: its end: {error}"))?;
    if text.contains('\r') {
        return Err("the session's end holds a carriage return".to_owned());
    }
    let Some(line) = text
        .strip_suffix('\n')
        .filter(|line| line.starts_with("end: ") && !line.contains('\n'))
    else {
        return Err("the session is incomplete: its end line is torn".to_owned());
    };
    if let Some(name) = repeated(line).filter(|_| !line.starts_with("end: panicked ")) {
        return Err(format!("the session's end names {name} twice"));
    }
    if field(line, "windows") != Some(&windows.to_string())
        || field(line, "chain") != Some(&hex(chain))
    {
        return Err("the session's end names other windows than its index".to_owned());
    }
    let tail = digest_of(&dir.join("windows").join("tail.chunk"))
        .map_err(|error| format!("the session's tail chunk: {error}"))?;
    if field(line, "tail") != Some(&hex(&tail)) {
        return Err("the session's tail chunk is truncated or changed".to_owned());
    }
    Ok(line.to_owned())
}

/// The chunk of window `at` in `dir` whose index line is `line`, checked
/// against the line's digest.
///
/// # Errors
///
/// An unreadable chunk or one whose digest differs from the line's.
pub(crate) fn chunk(dir: &Path, at: usize, line: &str) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(dir.join("windows").join(format!("{at:06}.chunk")))
        .map_err(|error| format!("window {at}'s chunk: {error}"))?;
    if Some(hex(&Sha256::digest(&bytes)).as_str()) != field(line, "digest") {
        return Err(format!("window {at}'s chunk is truncated or changed"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
