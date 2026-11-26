//! The monitor's history: one [`Sample`] per snapshot, appended as a JSON
//! line, for snapshots of one state directory read on one host.
//!
//! Samples run oldest first with strictly increasing `observed_ms`. Loading
//! and recording place a sample by one rule. A sample at or within
//! [`LATE_MS`] before the newest is a re-read or a late record from a
//! concurrent monitor and is skipped. A sample further back marks a clock
//! step and starts the history over from that sample, so no trend spans a
//! step and a far-future stamp stops blocking later samples. The file
//! replays to the samples a handle holds in memory.
//!
//! Writers hold an exclusive lock on `<path>.lock` for each record, waiting
//! at most [`LOCK_WAIT`] for it, and reload a file another writer changed,
//! so concurrent monitors on one history keep each other's samples. The
//! history, its lock and its compaction staging files are opened without
//! following a symlink at their last path component, and the history and
//! its lock must be regular files with at most one link.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::parallel::{self, THREADS};
use crate::snapshot::Snapshot;
use crate::source::printable;

/// The most samples [`History::samples`] returns and a compaction keeps.
pub const KEPT: usize = 10_000;

/// The longest history line, newline included. Loading skips a longer line
/// like a torn one, and recording refuses a sample that encodes longer.
pub const LINE_BYTES: u64 = 1 << 20;

/// How far before the newest sample a sample still reads as a late record
/// from a concurrent monitor: three default fetch timeouts. A sample
/// further back marks a clock step.
pub const LATE_MS: u64 = 15 * 60_000;

/// The longest a record waits for another writer's history lock.
pub const LOCK_WAIT: Duration = Duration::from_secs(10);

/// The facts of one snapshot that trend views and detectors compare over
/// time. `attempts` counts finished attempts; `identities` holds each
/// failure group's [`key`](crate::snapshot::FailureGroup::key). Samples
/// compare only with samples of the same state directory read on the same
/// host, because `observed_ms` is that host's wall clock.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sample {
    pub observed_ms: u64,
    pub attempts: u64,
    pub identities: Identities,
    #[serde(default)]
    pub free_bytes: Option<u64>,
}

/// The failure-group keys of one sample.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Identities(Arc<BTreeSet<String>>);

impl std::ops::Deref for Identities {
    type Target = BTreeSet<String>;

    fn deref(&self) -> &BTreeSet<String> {
        &self.0
    }
}

impl From<BTreeSet<String>> for Identities {
    fn from(keys: BTreeSet<String>) -> Self {
        Self(Arc::new(keys))
    }
}

impl FromIterator<String> for Identities {
    fn from_iter<I: IntoIterator<Item = String>>(keys: I) -> Self {
        Self::from(keys.into_iter().collect::<BTreeSet<_>>())
    }
}

impl std::fmt::Debug for Identities {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Serialize for Identities {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Identities {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        BTreeSet::deserialize(deserializer).map(Self::from)
    }
}

/// One history line as [`Sample`] reads it, with the keys left as the raw
/// JSON of the line. Its fields and attributes match [`Sample`]'s, so a line
/// parses here and its keys parse as a set exactly when it parses as a
/// [`Sample`].
#[derive(Deserialize)]
struct Line<'a> {
    observed_ms: u64,
    attempts: u64,
    #[serde(borrow)]
    identities: &'a RawValue,
    #[serde(default)]
    free_bytes: Option<u64>,
}

/// The keys of the last line one [`parse_run`] read: their raw JSON and
/// their set.
/// A line whose raw keys equal these bytes shares the set without parsing
/// the keys again.
#[derive(Default)]
struct LastKeys {
    raw: String,
    identities: Identities,
}

impl LastKeys {
    /// The set `raw` encodes, or `None` when `raw` is not a list of
    /// strings.
    fn read(&mut self, raw: &RawValue) -> Option<Identities> {
        if raw.get() != self.raw {
            self.identities = serde_json::from_str(raw.get()).ok()?;
            raw.get().clone_into(&mut self.raw);
        }
        Some(self.identities.clone())
    }
}

impl Sample {
    pub fn of(snapshot: &Snapshot) -> Self {
        Self {
            observed_ms: snapshot.observed_ms,
            attempts: snapshot
                .jobs
                .iter()
                .flat_map(|job| &job.attempts)
                .filter(|row| row.finished_ms.is_some())
                .count() as u64,
            identities: snapshot
                .failure_groups
                .iter()
                .map(|group| group.key())
                .collect(),
            free_bytes: snapshot.space.map(|space| space.free_bytes),
        }
    }
}

/// A history file as a handle last read or wrote it. Another writer's
/// append or replacement changes the length, the inode or the modification
/// time. A rename keeps the modification time, so the state a compaction
/// takes of its staging file matches the history it publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileState {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
}

impl FileState {
    fn of(metadata: &std::fs::Metadata, length: u64) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length,
            modified: (metadata.mtime(), metadata.mtime_nsec()),
        }
    }
}

/// Where a new sample goes, by the placement rule in the module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    Skip,
    Append,
    Reset,
}

/// The samples of one history file, or of memory alone for
/// [`History::in_memory`]. Memory holds up to twice [`KEPT`] samples so
/// trimming runs once per [`KEPT`] records; [`History::samples`] shows the
/// newest [`KEPT`].
pub struct History {
    path: Option<PathBuf>,
    samples: Vec<Sample>,
    /// The lines in the file at `path` as of this handle's last load or write.
    lines: usize,
    /// The file at `path` as of this handle's last load or write; `None`
    /// when no file existed then.
    seen: Option<FileState>,
}

impl History {
    /// A history that records samples in memory and writes no file.
    pub fn in_memory() -> Self {
        Self {
            path: None,
            samples: Vec::new(),
            lines: 0,
            seen: None,
        }
    }

    /// Loads the history at `path`, or an empty one when no file exists.
    /// A line that fails to parse, such as one torn by a crash mid-append
    /// or one longer than [`LINE_BYTES`], is skipped. Loading takes no lock
    /// and writes nothing, so it can see part of another writer's append.
    /// The rest of that append changes the file's length, and the next
    /// record then loads the file again under the lock. The file must hold
    /// samples of one state directory read on one host.
    ///
    /// # Errors
    ///
    /// A message when the file fails to open or read, or when `path` is a
    /// symlink or names something other than a regular file with at most
    /// one link.
    pub fn open(path: &Path) -> Result<Self, String> {
        let (samples, lines, seen) = load(path).map_err(|error| failed(path, &error))?;
        Ok(Self {
            path: Some(path.to_owned()),
            samples,
            lines,
            seen,
        })
    }

    /// The newest [`KEPT`] samples, oldest first.
    pub fn samples(&self) -> &[Sample] {
        &self.samples[self.samples.len().saturating_sub(KEPT)..]
    }

    /// Records `sample` by the placement rule in the module doc, creating
    /// the file and its parent directories as needed. Under the history
    /// lock, a file another writer changed since this handle's last load or
    /// write is loaded again first. The sample is appended as one
    /// line; once the file holds twice [`KEPT`] lines, the file is instead
    /// rewritten with the newest [`KEPT`] samples, this one included,
    /// through a staging file this record creates, which is synced and
    /// renamed over the history before the directory is synced. The
    /// rewritten history is owned by this process and keeps the history's
    /// mode; it keeps the history's group when this process may set it, and
    /// otherwise loses its group permissions.
    ///
    /// # Errors
    ///
    /// A message when the sample encodes longer than [`LINE_BYTES`]; when
    /// another writer holds the lock past [`LOCK_WAIT`]; when the
    /// directory, lock or a file fails to create, open, lock, write, sync
    /// or rename; or when the history path or its lock is a symlink or not
    /// a regular file with at most one link. Memory then keeps its samples.
    pub fn record(&mut self, sample: Sample) -> Result<(), String> {
        let Some(path) = self.path.clone() else {
            let placement = placement(&self.samples, sample.observed_ms);
            let sample = sharing_keys(&self.samples, sample);
            place(&mut self.samples, placement, sample);
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| failed(parent, &error))?;
        }
        let lock_name = lock_path(&path);
        let lock = open_regular(
            &lock_name,
            OpenOptions::new().create(true).write(true).mode(0o600),
        )
        .and_then(|file| lock_within(&file, LOCK_WAIT).map(|()| file))
        .map_err(|error| failed(&lock_name, &error))?;
        let recorded = self.record_locked(&path, sample);
        drop(lock);
        recorded
    }

    fn record_locked(&mut self, path: &Path, sample: Sample) -> Result<(), String> {
        let current = match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() && metadata.nlink() <= 1 => {
                Some(FileState::of(&metadata, metadata.len()))
            }
            Ok(_) => return Err(failed(path, &not_regular())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(failed(path, &error)),
        };
        if current != self.seen {
            (self.samples, self.lines, self.seen) =
                load(path).map_err(|error| failed(path, &error))?;
        }
        let placement = placement(&self.samples, sample.observed_ms);
        let kept = match placement {
            Placement::Skip => return Ok(()),
            Placement::Append => self.samples.len(),
            Placement::Reset => 0,
        };
        let sample = sharing_keys(&self.samples, sample);
        let line = encode(&sample).map_err(|error| failed(path, &error))?;
        if self.lines >= 2 * KEPT {
            let start = kept.saturating_sub(KEPT - 1);
            let seen = compact(path, self.samples[start..kept].iter().chain([&sample]))
                .map_err(|error| failed(path, &error))?;
            self.samples.truncate(kept);
            self.samples.drain(..start);
            self.samples.push(sample);
            self.lines = self.samples.len();
            self.seen = Some(seen);
        } else {
            self.seen = Some(append(path, &line).map_err(|error| failed(path, &error))?);
            self.lines += 1;
            place(&mut self.samples, placement, sample);
        }
        Ok(())
    }
}

fn sharing_keys(samples: &[Sample], mut sample: Sample) -> Sample {
    if let Some(last) = samples.last()
        && last.identities == sample.identities
    {
        sample.identities = last.identities.clone();
    }
    sample
}

fn placement(samples: &[Sample], observed_ms: u64) -> Placement {
    match samples.last() {
        None => Placement::Append,
        Some(last) if observed_ms > last.observed_ms => Placement::Append,
        Some(last) if last.observed_ms - observed_ms <= LATE_MS => Placement::Skip,
        Some(_) => Placement::Reset,
    }
}

fn place(samples: &mut Vec<Sample>, placement: Placement, sample: Sample) {
    match placement {
        Placement::Skip => return,
        Placement::Append => {}
        Placement::Reset => samples.clear(),
    }
    samples.push(sample);
    if samples.len() >= 2 * KEPT {
        samples.drain(..samples.len() - KEPT);
    }
}

/// Replays the file at `path` through the placement rule: its samples, its
/// line count, and the state of the bytes read. A missing file loads
/// empty. A line whose bytes before its newline number [`LINE_BYTES`] or
/// more is skipped, and so is a sample whose encoding exceeds
/// [`LINE_BYTES`], as a writer refuses it, so every loaded sample can be
/// compacted. The whole lines up to the file's length when it opened split
/// at line starts into up to [`THREADS`] ranges, aiming for [`PARSE_BYTES`]
/// per range, each read and parsed on its own thread when there is more
/// than one. The calling thread then reads the bytes after them to the end
/// of the file. Samples are placed in file order.
fn load(path: &Path) -> std::io::Result<(Vec<Sample>, usize, Option<FileState>)> {
    let file = match open_regular(path, OpenOptions::new().read(true)) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Vec::new(), 0, None));
        }
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    let whole = whole_lines(&file, metadata.len())?;
    let count = usize::try_from(whole / PARSE_BYTES as u64)
        .unwrap_or(THREADS)
        .clamp(1, THREADS) as u64;
    let mut starts = Vec::with_capacity(count as usize + 1);
    for part in 0..=count {
        starts.push(line_start(&file, whole * part / count, whole)?);
    }
    let ranges: Vec<(u64, u64)> = starts.windows(2).map(|pair| (pair[0], pair[1])).collect();
    let mut scanned = parallel::each(&ranges, |&(start, end)| scan(&file, start, Some(end)));
    scanned.push(scan(&file, whole, None));
    let mut samples = Vec::new();
    let mut lines = 0usize;
    let mut consumed = 0u64;
    for range in scanned {
        let (counted, read, parsed) = range?;
        lines += counted;
        consumed += read;
        for sample in parsed {
            let placement = placement(&samples, sample.observed_ms);
            place(&mut samples, placement, sample);
        }
    }
    Ok((samples, lines, Some(FileState::of(&metadata, consumed))))
}

/// The bytes [`scan`] reads at a time.
const READ_BYTES: usize = 16 << 20;

/// The bytes of whole lines per load thread that [`load`] aims for, so a
/// history under twice this size loads on the calling thread alone.
const PARSE_BYTES: usize = 256 << 10;

/// The offset just past the last newline before `length`, or zero when
/// there is none or the file holds fewer than `length` bytes by the time
/// it is read.
fn whole_lines(file: &File, length: u64) -> std::io::Result<u64> {
    let mut block = vec![0; 64 << 10];
    let mut end = length;
    while end > 0 {
        let start = end.saturating_sub(block.len() as u64);
        let wanted = (end - start) as usize;
        let held = read_at_most(file, &mut block[..wanted], start)?;
        if held.len() < wanted {
            return Ok(0);
        }
        if let Some(newline) = held.iter().rposition(|&byte| byte == b'\n') {
            return Ok(start + newline as u64 + 1);
        }
        end = start;
    }
    Ok(0)
}

/// The first line start at or after `at`, where `at <= whole` and a line
/// ends just before `whole`; `whole` when the file ends first.
fn line_start(file: &File, at: u64, whole: u64) -> std::io::Result<u64> {
    if at == 0 || at == whole {
        return Ok(at);
    }
    let mut block = vec![0; 64 << 10];
    let mut start = at - 1;
    while start < whole {
        let wanted = block.len().min((whole - start) as usize);
        let held = read_at_most(file, &mut block[..wanted], start)?;
        if let Some(newline) = held.iter().position(|&byte| byte == b'\n') {
            return Ok(start + newline as u64 + 1);
        }
        if held.len() < wanted {
            break;
        }
        start += wanted as u64;
    }
    Ok(whole)
}

/// The bytes of `file` from `at` that fit in `buffer`, fewer only at the
/// end of the file.
fn read_at_most<'a>(file: &File, buffer: &'a mut [u8], at: u64) -> std::io::Result<&'a [u8]> {
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read_at(&mut buffer[filled..], at + filled as u64) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(&buffer[..filled])
}

/// Reads `file` from `at` to `end`, or to the end of the file for `None`,
/// without moving the file's offset.
struct Range<'a> {
    file: &'a File,
    at: u64,
    end: Option<u64>,
}

impl Read for Range<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let left = self.end.map_or(buffer.len() as u64, |end| end - self.at);
        let length = buffer
            .len()
            .min(usize::try_from(left).unwrap_or(usize::MAX));
        let read = self.file.read_at(&mut buffer[..length], self.at)?;
        self.at += read as u64;
        Ok(read)
    }
}

/// The line count, the bytes read, and the samples in order of the lines
/// from `start`, a line start, to `end`, read [`READ_BYTES`] at a time.
fn scan(file: &File, start: u64, end: Option<u64>) -> std::io::Result<(usize, u64, Vec<Sample>)> {
    let mut range = Range {
        file,
        at: start,
        end,
    };
    let mut samples = Vec::new();
    let mut lines = 0usize;
    let mut consumed = 0u64;
    let mut buffer = Vec::new();
    let mut skipping = false;
    loop {
        let read = (&mut range)
            .take(READ_BYTES as u64)
            .read_to_end(&mut buffer)?;
        consumed += read as u64;
        let last = read < READ_BYTES;
        if skipping {
            match buffer.iter().position(|&byte| byte == b'\n') {
                Some(newline) => {
                    buffer.drain(..=newline);
                    skipping = false;
                }
                None => buffer.clear(),
            }
        }
        let complete = match buffer.iter().rposition(|&byte| byte == b'\n') {
            _ if last => buffer.len(),
            Some(newline) => newline + 1,
            None => 0,
        };
        let (counted, parsed) = parse_run(&buffer[..complete]);
        lines += counted;
        samples.extend(parsed);
        buffer.drain(..complete);
        if buffer.len() as u64 >= LINE_BYTES {
            lines += 1;
            buffer.clear();
            skipping = true;
        }
        if last {
            return Ok((lines, consumed, samples));
        }
    }
}

/// The line count and the samples of the whole lines in `bytes`, parsed in
/// order on the calling thread.
fn parse_run(bytes: &[u8]) -> (usize, Vec<Sample>) {
    let mut lines = 0;
    let mut samples = Vec::new();
    let mut last = LastKeys::default();
    for line in bytes.split_inclusive(|&byte| byte == b'\n') {
        lines += 1;
        let content = line.len() - usize::from(line.last() == Some(&b'\n'));
        if content as u64 >= LINE_BYTES {
            continue;
        }
        let Ok(read_line) = serde_json::from_slice::<Line>(line) else {
            continue;
        };
        let Some(identities) = last.read(read_line.identities) else {
            continue;
        };
        let sample = Sample {
            observed_ms: read_line.observed_ms,
            attempts: read_line.attempts,
            identities,
            free_bytes: read_line.free_bytes,
        };
        if line.len() as u64 > LINE_BYTES / 2 && encode(&sample).is_err() {
            continue;
        }
        samples.push(sample);
    }
    (lines, samples)
}

/// `sample` as one history line, newline included.
fn encode(sample: &Sample) -> std::io::Result<String> {
    let mut line = serde_json::to_string(sample).expect("a sample encodes");
    line.push('\n');
    if line.len() as u64 > LINE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("the sample encodes to more than the {LINE_BYTES}-byte line bound"),
        ));
    }
    Ok(line)
}

fn lock_path(path: &Path) -> PathBuf {
    let mut lock = path.as_os_str().to_owned();
    lock.push(".lock");
    PathBuf::from(lock)
}

/// Takes the exclusive lock on `file`, retrying until `wait` passes.
fn lock_within(file: &File, wait: Duration) -> std::io::Result<()> {
    let deadline = Instant::now() + wait;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(TryLockError::WouldBlock) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    format!("another writer held the history lock past {wait:?}"),
                ));
            }
            Err(TryLockError::Error(error)) => return Err(error),
        }
    }
}

fn failed(path: &Path, error: &std::io::Error) -> String {
    printable(&format!("{}: {error}", path.display()))
}

fn not_regular() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "not a singly linked regular file",
    )
}

/// Opens `path` with `options`, refusing a symlink at its last component
/// and anything other than a regular file with at most one link. A file a
/// compaction unlinked after this open has no link and still reads whole.
/// `O_NONBLOCK` keeps the open of a FIFO from waiting for a peer before the
/// file-type check refuses it.
fn open_regular(path: &Path, options: &mut OpenOptions) -> std::io::Result<File> {
    let file = options
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() > 1 {
        return Err(not_regular());
    }
    Ok(file)
}

/// Appends `line`, first ending a torn last line with a newline, and
/// returns the file's state after the write.
fn append(path: &Path, line: &str) -> std::io::Result<FileState> {
    let mut file = open_regular(
        path,
        OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .mode(0o600),
    )?;
    let mut text = String::with_capacity(line.len() + 1);
    if !ends_with_newline(&mut file)? {
        text.push('\n');
    }
    text.push_str(line);
    file.write_all(text.as_bytes())?;
    let metadata = file.metadata()?;
    Ok(FileState::of(&metadata, metadata.len()))
}

/// Counts the staging files this process creates, so each compaction
/// stages under a name no other compaction used.
static STAGED: AtomicU64 = AtomicU64::new(0);

/// Creates `<path>.compact.<pid>.<n>` exclusively, trying the next `n` when
/// an entry already holds a name, so a compaction writes, publishes and
/// removes only an entry it created.
fn create_staging(path: &Path) -> std::io::Result<(PathBuf, File)> {
    let mut last = None;
    for _ in 0..16 {
        let mut staged = path.as_os_str().to_owned();
        let n = STAGED.fetch_add(1, Ordering::Relaxed);
        staged.push(format!(".compact.{}.{n}", std::process::id()));
        let staged = PathBuf::from(staged);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staged)
        {
            Ok(file) => return Ok((staged, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last = Some(error);
            }
            Err(error) => {
                return Err(std::io::Error::new(
                    error.kind(),
                    format!("{}: {error}", staged.display()),
                ));
            }
        }
    }
    Err(last.expect("every staging attempt failed"))
}

/// Streams `samples` to a new staging file, syncs it, renames it over
/// `path`, and syncs the directory. A failed write removes the staging
/// file. Returns the state of the new history.
fn compact<'a>(
    path: &Path,
    samples: impl Iterator<Item = &'a Sample>,
) -> std::io::Result<FileState> {
    let (staged, file) = create_staging(path)?;
    let written = (|| -> std::io::Result<FileState> {
        if let Ok(current) = std::fs::symlink_metadata(path)
            && current.is_file()
        {
            let mut mode = current.permissions().mode();
            if std::os::unix::fs::fchown(&file, None, Some(current.gid())).is_err() {
                mode &= !0o070;
            }
            file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
        let mut writer = BufWriter::new(file);
        for sample in samples {
            writer.write_all(encode(sample)?.as_bytes())?;
        }
        let file = writer.into_inner().map_err(|error| error.into_error())?;
        file.sync_all()?;
        let metadata = file.metadata()?;
        std::fs::rename(&staged, path)?;
        Ok(FileState::of(&metadata, metadata.len()))
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    let seen = written?;
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    File::open(parent)?.sync_all()?;
    Ok(seen)
}

fn ends_with_newline(file: &mut File) -> std::io::Result<bool> {
    if file.metadata()?.len() == 0 {
        return Ok(true);
    }
    let mut last = [0u8];
    file.seek(SeekFrom::End(-1))?;
    file.read_exact(&mut last)?;
    Ok(last[0] == b'\n')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(observed_ms: u64, free_bytes: u64) -> Sample {
        Sample {
            observed_ms,
            free_bytes: Some(free_bytes),
            ..Sample::default()
        }
    }

    fn line(recorded: &Sample) -> String {
        serde_json::to_string(recorded).unwrap() + "\n"
    }

    fn scratch(name: &str) -> PathBuf {
        let scratch =
            std::env::temp_dir().join(format!("campaign-monitor-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        scratch
    }

    fn times(samples: &[Sample]) -> Vec<u64> {
        samples.iter().map(|held| held.observed_ms).collect()
    }

    fn mkfifo(path: &Path) {
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `name` is a NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    }

    #[test]
    fn recording_into_a_file_past_twice_the_kept_samples_rewrites_it_with_the_newest() {
        let dir = scratch("compact");
        let path = dir.join("history.jsonl");
        let lines: String = (1..=2 * KEPT as u64 + 5)
            .map(|n| line(&sample(n, n)))
            .collect();
        std::fs::write(&path, &lines).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut history = History::open(&path).unwrap();
        assert_eq!(history.samples().len(), KEPT);
        assert_eq!(history.samples()[0].observed_ms, KEPT as u64 + 6);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), lines);
        history.record(sample(2 * KEPT as u64 + 6, 0)).unwrap();
        let rewritten = std::fs::read_to_string(&path).unwrap();
        assert_eq!(rewritten.lines().count(), KEPT);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "compaction keeps the history's mode");
        assert_eq!(history.lines, KEPT);
        assert_eq!(history.samples()[0].observed_ms, KEPT as u64 + 7);
        assert_eq!(History::open(&path).unwrap().samples(), history.samples());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_new_history_file_starts_owner_only() {
        let dir = scratch("history-mode");
        let path = dir.join("history.jsonl");
        let mut history = History::open(&path).unwrap();
        history.record(sample(1_000, 10)).unwrap();
        for created in [path.clone(), lock_path(&path)] {
            let mode = std::fs::metadata(&created).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}: {mode:o}", created.display());
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_staging_file_starts_owner_only() {
        let dir = scratch("staging-mode");
        let (staged, file) = create_staging(&dir.join("history.jsonl")).unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        drop(file);
        std::fs::remove_file(staged).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn compaction_keeps_the_history_in_its_group() {
        // SAFETY: `getegid` and `getgroups` read process identity only; the
        // buffer is sized by the first call's count.
        let (egid, groups) = unsafe {
            let count = libc::getgroups(0, std::ptr::null_mut());
            let mut groups = vec![0 as libc::gid_t; usize::try_from(count).unwrap_or(0)];
            let filled = libc::getgroups(count, groups.as_mut_ptr());
            groups.truncate(usize::try_from(filled).unwrap_or(0));
            (libc::getegid(), groups)
        };
        let Some(other) = groups.into_iter().find(|group| *group != egid) else {
            return;
        };
        let dir = scratch("compact-group");
        let path = dir.join("history.jsonl");
        let lines: String = (1..=2 * KEPT as u64 + 5)
            .map(|n| line(&sample(n, n)))
            .collect();
        std::fs::write(&path, &lines).unwrap();
        std::os::unix::fs::chown(&path, None, Some(other)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let mut history = History::open(&path).unwrap();
        history.record(sample(2 * KEPT as u64 + 6, 0)).unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(
            metadata.gid(),
            other,
            "compaction keeps the history's group"
        );
        assert_eq!(metadata.permissions().mode() & 0o777, 0o640);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn one_handle_compacts_its_own_appends_and_keeps_appending_after() {
        let dir = scratch("long-lived");
        let path = dir.join("history.jsonl");
        let mut history = History::open(&path).unwrap();
        for n in 1..=2 * KEPT as u64 {
            history.record(sample(n, n)).unwrap();
        }
        let count = || std::fs::read_to_string(&path).unwrap().lines().count();
        assert_eq!(count(), 2 * KEPT);
        assert!(history.samples.len() <= 2 * KEPT);
        history.record(sample(2 * KEPT as u64 + 1, 0)).unwrap();
        assert_eq!(count(), KEPT);
        assert_eq!(history.lines, KEPT);
        assert_eq!(history.samples.len(), KEPT);
        history.record(sample(2 * KEPT as u64 + 2, 0)).unwrap();
        assert_eq!(count(), KEPT + 1);
        assert_eq!(history.lines, KEPT + 1);
        assert_eq!(history.samples()[0].observed_ms, KEPT as u64 + 3);
        assert_eq!(History::open(&path).unwrap().samples(), history.samples());

        let mut memory = History::in_memory();
        for n in 1..=2 * KEPT as u64 {
            memory.record(sample(n, n)).unwrap();
        }
        assert_eq!(memory.samples.len(), KEPT);
        assert_eq!(memory.samples()[0].observed_ms, KEPT as u64 + 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn two_handles_on_one_history_keep_each_others_samples_through_a_compaction() {
        let dir = scratch("two-writers");
        let path = dir.join("history.jsonl");
        let full = 2 * KEPT as u64;
        let lines: String = (1..=full - 2).map(|n| line(&sample(n, n))).collect();
        std::fs::write(&path, &lines).unwrap();
        let mut first = History::open(&path).unwrap();
        let mut second = History::open(&path).unwrap();
        first.record(sample(full - 1, 0)).unwrap();
        second.record(sample(full, 0)).unwrap();
        first.record(sample(full + 1, 0)).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), KEPT);
        let reopened = History::open(&path).unwrap();
        assert_eq!(reopened.samples(), first.samples());
        let newest = &times(reopened.samples())[KEPT - 3..];
        assert_eq!(newest, [full - 1, full, full + 1]);
        second.record(sample(full + 2, 0)).unwrap();
        assert_eq!(second.samples()[KEPT - 1].observed_ms, full + 2);
        assert_eq!(second.samples()[KEPT - 2].observed_ms, full + 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_late_record_from_another_monitor_keeps_the_newer_sample() {
        let dir = scratch("late-writer");
        let path = dir.join("history.jsonl");
        let mut fast = History::open(&path).unwrap();
        let mut slow = History::open(&path).unwrap();
        fast.record(sample(1_000_000, 1)).unwrap();
        fast.record(sample(2_000_000, 2)).unwrap();
        slow.record(sample(2_000_000 - LATE_MS, 3)).unwrap();
        assert_eq!(times(slow.samples()), [1_000_000, 2_000_000]);
        let reopened = History::open(&path).unwrap();
        assert_eq!(times(reopened.samples()), [1_000_000, 2_000_000]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_record_waits_while_another_writer_holds_the_lock() {
        let dir = scratch("lock");
        let path = dir.join("history.jsonl");
        let holder = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(lock_path(&path))
            .unwrap();
        holder.lock().unwrap();
        let worker = {
            let path = path.clone();
            std::thread::spawn(move || History::open(&path).unwrap().record(sample(1, 1)))
        };
        std::thread::sleep(Duration::from_millis(300));
        assert!(!worker.is_finished());
        assert!(!path.exists());
        holder.unlock().unwrap();
        worker.join().unwrap().unwrap();
        assert_eq!(times(History::open(&path).unwrap().samples()), [1]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_link_or_non_regular_file_at_the_history_or_lock_path_is_refused() {
        let dir = scratch("symlink");
        let target = dir.join("target");
        std::fs::write(&target, "kept\n").unwrap();
        let linked = dir.join("linked.jsonl");
        std::os::unix::fs::symlink(&target, &linked).unwrap();
        assert!(History::open(&linked).is_err());
        let mut history = History::in_memory();
        history.path = Some(linked.clone());
        assert!(history.record(sample(1, 1)).is_err());
        assert!(history.samples().is_empty());

        let hard = dir.join("hard.jsonl");
        std::fs::hard_link(&target, &hard).unwrap();
        let error = History::open(&hard).err().unwrap();
        assert!(
            error.contains("not a singly linked regular file"),
            "{error}"
        );

        let path = dir.join("history.jsonl");
        let mut history = History::open(&path).unwrap();
        history.record(sample(1, 1)).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();
        std::fs::hard_link(&path, dir.join("alias.jsonl")).unwrap();
        assert!(history.record(sample(2, 2)).is_err());
        assert!(history.record(sample(1, 1)).is_err());
        history.lines = 2 * KEPT;
        assert!(history.record(sample(3, 3)).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        assert_eq!(
            std::fs::read_to_string(dir.join("alias.jsonl")).unwrap(),
            before
        );

        let locked = dir.join("locked.jsonl");
        std::os::unix::fs::symlink(&target, lock_path(&locked)).unwrap();
        assert!(
            History::open(&locked)
                .unwrap()
                .record(sample(1, 1))
                .is_err()
        );

        let fifo = dir.join("fifo\u{1b}]0;x.jsonl");
        mkfifo(&fifo);
        let error = History::open(&fifo).err().unwrap();
        assert!(
            error.contains("fifo?]0;x.jsonl: not a singly linked regular file"),
            "{error}"
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "kept\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn compaction_keeps_other_entries_and_refuses_a_linked_history() {
        let dir = scratch("staging");
        let target = dir.join("target");
        std::fs::write(&target, "kept\n").unwrap();
        let path = dir.join("history.jsonl");
        let other = dir.join("history.jsonl.compact");
        std::fs::write(&other, "another history\n").unwrap();
        let mut history = History::open(&path).unwrap();
        history.lines = 2 * KEPT;
        history.record(sample(1, 1)).unwrap();
        history.lines = 2 * KEPT;
        history.record(sample(2, 2)).unwrap();
        assert_eq!(times(History::open(&path).unwrap().samples()), [1, 2]);
        assert_eq!(
            std::fs::read_to_string(&other).unwrap(),
            "another history\n"
        );
        let entries = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(
            entries, 4,
            "the history, its lock, the target and the other entry"
        );

        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        history.lines = 2 * KEPT;
        assert!(history.record(sample(3, 3)).is_err());
        assert!(std::fs::symlink_metadata(&path).unwrap().is_symlink());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "kept\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn recorded_samples_survive_a_reopen_and_a_torn_or_invalid_line_costs_only_itself() {
        let dir = scratch("history");
        let path = dir.join("history.jsonl");
        std::fs::remove_dir_all(&dir).unwrap();
        let mut history = History::open(&path).unwrap();
        history.record(sample(1_000, 9)).unwrap();
        history.record(sample(2_000, 8)).unwrap();
        history.record(sample(2_000, 7)).unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"\xff\xfe\n").unwrap();
        file.write_all(line(&sample(2_000, 6)).as_bytes()).unwrap();
        file.write_all(b"{\"observed_ms\": 3").unwrap();
        drop(file);
        let mut torn = History::open(&path).unwrap();
        torn.record(sample(3_000, 6)).unwrap();
        let reopened = History::open(&path).unwrap();
        assert_eq!(
            reopened.samples(),
            &[sample(1_000, 9), sample(2_000, 8), sample(3_000, 6)]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_clock_step_starts_the_history_over_and_a_late_stamp_is_skipped() {
        let dir = scratch("clock-step");
        let path = dir.join("history.jsonl");
        let mut history = History::open(&path).unwrap();
        let step = 10 * LATE_MS;
        for observed_ms in [step, step + 1_000, u64::MAX / 2, step + 2_000, step + 1_500] {
            history.record(sample(observed_ms, 1)).unwrap();
        }
        assert_eq!(times(history.samples()), [step + 2_000]);
        history.record(sample(step + 3_000, 1)).unwrap();
        history.record(sample(step + 3_000 - LATE_MS, 1)).unwrap();
        assert_eq!(times(history.samples()), [step + 2_000, step + 3_000]);
        assert_eq!(History::open(&path).unwrap().samples(), history.samples());
        let lines = std::fs::read_to_string(&path).unwrap().lines().count();
        history.record(sample(step + 3_000, 1)).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().lines().count(),
            lines
        );

        history.lines = 2 * KEPT;
        history.record(sample(step / 2, 1)).unwrap();
        assert_eq!(times(history.samples()), [step / 2]);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            line(&sample(step / 2, 1))
        );
        assert_eq!(history.lines, 1);

        let mut memory = History::in_memory();
        for observed_ms in [step, step, step - LATE_MS, step + 1, step - LATE_MS] {
            memory.record(sample(observed_ms, 1)).unwrap();
        }
        assert_eq!(times(memory.samples()), [step - LATE_MS]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn loading_reads_each_line_as_a_sample_decodes_it_and_shares_equal_keys() {
        let dir = scratch("shapes");
        let path = dir.join("history.jsonl");
        let shapes = [
            r#"{"observed_ms":1,"attempts":2,"identities":["a","b"],"free_bytes":3}"#,
            r#"{"observed_ms":2,"attempts":2,"identities":["a","b"]}"#,
            r#"{"observed_ms":3,"attempts":2,"identities":["b","a","a"],"free_bytes":null}"#,
            r#"{"observed_ms":4,"attempts":2,"identities":["\u0061","b"],"x":[1]}"#,
            r#"[5,2,["a","b"],7]"#,
            r#"[6,2,["a"]]"#,
            r#"[7,2,["a"],7,8]"#,
            r#"{"observed_ms":8,"observed_ms":9,"attempts":2,"identities":[]}"#,
            r#"{"observed_ms":10,"attempts":2}"#,
            r#"{"observed_ms":11,"attempts":2,"identities":[1]}"#,
            r#"{"observed_ms":12,"attempts":-2,"identities":[]}"#,
            r#"{"observed_ms":13,"attempts":2,"identities":"a"}"#,
            r#"{"observed_ms":14,"attempts":2,"identities":["a","b"]}"#,
        ];
        std::fs::write(&path, shapes.join("\n") + "\n").unwrap();
        let expected: Vec<Sample> = shapes
            .iter()
            .filter_map(|shape| serde_json::from_str::<Sample>(shape).ok())
            .collect();
        let loaded = History::open(&path).unwrap();
        assert_eq!(loaded.samples(), expected);
        assert_eq!(times(loaded.samples()), [1, 2, 3, 4, 5, 6, 14]);
        let shared = |a: usize, b: usize| {
            Arc::ptr_eq(
                &loaded.samples()[a].identities.0,
                &loaded.samples()[b].identities.0,
            )
        };
        assert!(shared(0, 1));
        assert!(shared(0, 1) && !shared(1, 2) && !shared(5, 6));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn recorded_samples_with_equal_keys_share_one_set() {
        let keyed = |observed_ms| Sample {
            observed_ms,
            identities: ["a".to_owned(), "b".to_owned()].into_iter().collect(),
            ..Sample::default()
        };
        let shared = |history: &History| {
            let held = history.samples();
            held.windows(2)
                .all(|pair| Arc::ptr_eq(&pair[0].identities.0, &pair[1].identities.0))
        };
        let mut memory = History::in_memory();
        memory.record(keyed(1)).unwrap();
        memory.record(keyed(2)).unwrap();
        assert!(shared(&memory));

        let dir = scratch("shared-keys");
        let path = dir.join("history.jsonl");
        let mut history = History::open(&path).unwrap();
        history.record(keyed(1)).unwrap();
        history.record(keyed(2)).unwrap();
        assert!(shared(&history));
        history.lines = 2 * KEPT;
        history.record(keyed(3)).unwrap();
        assert_eq!(times(history.samples()), [1, 2, 3]);
        assert!(shared(&history));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_line_past_the_line_bound_or_one_that_encodes_past_it_is_skipped() {
        let dir = scratch("line-bound");
        let path = dir.join("history.jsonl");
        let at_bound = line(&sample(2, 2));
        let at_bound = " ".repeat(LINE_BYTES as usize - at_bound.len()) + &at_bound;
        assert_eq!(at_bound.len() as u64, LINE_BYTES);
        let past_bound = " ".repeat(LINE_BYTES as usize) + &line(&sample(3, 3));
        let bare = r#"{"observed_ms":5,"attempts":0,"identities":[""]}"#.len() + 1;
        let grows = format!(
            "{{\"observed_ms\":5,\"attempts\":0,\"identities\":[\"{}\"]}}\n",
            "x".repeat(LINE_BYTES as usize - bare)
        );
        assert_eq!(grows.len() as u64, LINE_BYTES);
        let text = line(&sample(1, 1)) + &at_bound + &past_bound + &line(&sample(4, 4)) + &grows;
        std::fs::write(&path, text).unwrap();
        let history = History::open(&path).unwrap();
        assert_eq!(times(history.samples()), [1, 2, 4]);
        assert_eq!(history.lines, 5);

        let mut history = History::open(&path).unwrap();
        let identities = (0..LINE_BYTES / 8).map(|n| format!("{n:07}")).collect();
        let error = history
            .record(Sample {
                observed_ms: 6,
                identities,
                ..Sample::default()
            })
            .unwrap_err();
        assert!(error.contains("line bound"), "{error}");
        assert_eq!(times(history.samples()), [1, 2, 4]);
        history.lines = 2 * KEPT;
        history.record(sample(7, 7)).unwrap();
        assert_eq!(times(History::open(&path).unwrap().samples()), [1, 2, 4, 7]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
