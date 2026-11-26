//! The client's durable watermark: per shard record and coverage page, the highest version and value the client
//! observed, and per shard the checkpoint it adopted at its generation.
//!
//! Versions, `(g, E)` and page fences only rise under the store contract, and the client raises the watermark to
//! every value it reads or commits, except the pages `Client::create_shard` creates, which the reconciler never
//! reads or writes again. A later result at a lower version, with a lower `(g, E)` or fence, or at an
//! equal version with a different one is evidence of a lost, rolled-back or doubly won write or of a stale read;
//! [`Regression`] names it, and the client refuses, withdraws and alarms. Volume records have no watermark entry.
//!
//! The encoding is a 64-byte header and a table of 64-byte slots. Each slot holds one mark or the free marker and
//! closes with a digest of its index and bytes; the marks fill a prefix of the table. [`FileLog`] raises a set of marks
//! by rewriting their slots in place, then one data sync, and replaces the file whole on a record, on a raise that
//! brings two or more new marks, and when a new mark finds no free slot. A reload writes the bytes it read back over
//! themselves with one write, one
//! data sync and a directory sync, so a crash during it leaves each sector holding the bytes the device held or the
//! bytes the reload read. Outside a failed writeback, either the path names the file the reload read and those bytes
//! differ at most in the slots of the one raise whose sync did not return, or the path names the previous file of a
//! record whose directory sync was unconfirmed; either way the file loads a watermark whose every mark is its value
//! before or after that raise or record. A slot at a
//! multiple of 64 bytes lies inside one 512-byte sector of the file,
//! and the log relies on the device writing a sector atomically: NVMe specifies atomic writes in whole logical
//! blocks of at least 512 bytes. A crash during a raise then leaves each written slot's previous or new bytes, and
//! the one new mark a raise writes in place takes the next free slot, so the marks still fill a prefix and the file
//! loads each raised mark before or after the raise. A load refuses a header or slot that fails its digest, a torn or
//! zeroed slot included, and a mark after a free slot. The file format carries its own format version, so the store
//! records' format and the watermark's change independently.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{Key, Version};
use crate::failover::records::{
    CHECKPOINT, CodecError, NamedCheckpoint, Reader, ShardRecord, head, put_checkpoint,
};
use crate::net::ownership::{Shard, ShardGeneration};

/// The watermark entry a result fell below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Regression {
    /// The record's version or value fell below or reused its mark, the record of a held mark is absent, or a
    /// create or exact-version write of the record committed at a version other than the one it names.
    Value(Key),
    /// At the adopted checkpoint's generation, the shard record names no checkpoint, an older one, or another
    /// checkpoint with the adopted one's `(session, capture)`.
    Checkpoint(Shard),
}

/// The watermark file's format version.
const FORMAT: u16 = 2;
/// The bytes in the header and in each slot. 64 divides 512, so a slot at a multiple of 64 lies inside one
/// 512-byte sector.
const SLOT: usize = 64;
/// One entry: the key's kind, shard and page, the version, the value, the checkpoint after its flag and its
/// generation.
const ENTRY: usize = 1 + 4 + 2 + 8 + 8 + 4 + 1 + CHECKPOINT + 4;
/// The slot's 12 bytes after its entry, which hold the leading bytes of the slot's SHA-256; a slot corrupted at
/// random matches its digest with probability `2^-96`.
const SLOT_DIGEST: usize = SLOT - ENTRY;
/// The kind byte of a free slot, whose other entry bytes are zero.
const FREE: u8 = 0xFF;
/// The header's bytes before its SHA-256: the magic, the format version, the slot count and zeros.
const HEAD_BODY: usize = 32;
/// The fewest slots an encoding holds. An encoding holds at least twice as many slots as marks, so after a whole
/// replace at `m` marks, at least `m` new marks take free slots in place.
const MIN_SLOTS: usize = 64;

/// A record's value as the watermark orders it: `(g, E)` for a shard record, `(fence, 0)` for a page.
pub(super) type Value = (u64, u32);

/// The record a watermark entry is for: a shard record or a coverage page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Entry {
    Shard(Shard),
    Page(Shard, u16),
}

impl Entry {
    /// The entry of `key`, or `None` for a volume record, a standby census or a replacement receipt, which have
    /// none.
    fn of(key: Key) -> Option<Self> {
        match key {
            Key::Shard(shard) => Some(Self::Shard(shard)),
            Key::Page(shard, page) => Some(Self::Page(shard, page)),
            Key::Volume(_) | Key::Standbys(_) | Key::Replacement(_) => None,
        }
    }
}

/// A record's highest version and value, and for a shard record the checkpoint adopted at its generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Mark {
    version: Version,
    value: Value,
    adopted: Option<(ShardGeneration, NamedCheckpoint)>,
}

/// The highest store values one host observed or adopted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Watermark {
    marks: BTreeMap<Entry, Mark>,
}

/// Host-local durable storage for the watermark. One client process writes a log.
pub trait WatermarkLog {
    /// The recorded watermark.
    ///
    /// # Errors
    ///
    /// `NotFound` when the log holds no watermark, `InvalidData` for a record that does not decode, or the read's
    /// I/O error. A host records [`Watermark::default`] before its first client opens, and only then; a later
    /// `NotFound` is a lost log.
    fn load(&self) -> io::Result<Watermark>;

    /// Makes `mark` durable, replacing the previous record whole; the client adopts nothing until this returns.
    ///
    /// # Errors
    ///
    /// The I/O error of the first failed step. A failure before the record is replaced leaves the previous record;
    /// a failure after it leaves the new record in place, its durability unconfirmed. The client withdraws on
    /// either.
    fn record(&mut self, mark: &Watermark) -> io::Result<()>;

    /// Makes `mark` durable with one log write; the client adopts nothing until this returns. The caller guarantees
    /// that `mark` differs from the watermark this log last made durable only in the marks of `keys`. [`FileLog`]
    /// writes those marks in place with one data sync when the log holds an open file, `mark` contains every raised
    /// entry, and the raise introduces at most one new mark with a free slot available for it; otherwise, [`FileLog`]
    /// records `mark` whole.
    ///
    /// # Errors
    ///
    /// The I/O error of the first failed step, as for [`WatermarkLog::record`]: the log holds the previous
    /// watermark, the new one with its durability unconfirmed, or, after an in-place write, each raised mark's
    /// previous or new value. The client withdraws on any of these.
    fn raise(&mut self, mark: &Watermark, keys: &[Key]) -> io::Result<()> {
        let _ = keys;
        self.record(mark)
    }

    /// `reload` makes the loaded watermark durable before returning successfully, including after a record whose
    /// directory sync was unconfirmed or a raise whose sync did not return.
    ///
    /// # Errors
    ///
    /// The load's error, as for [`WatermarkLog::load`], then the error of the first failed step that makes the
    /// loaded bytes durable, which leaves the loaded watermark in place with its durability unconfirmed.
    fn reload(&mut self) -> io::Result<Watermark> {
        let mark = self.load()?;
        self.record(&mark)?;
        Ok(mark)
    }
}

impl Watermark {
    /// Checks a result of `key` at `version` holding `value` and raises the mark to it, returning whether the mark
    /// changed. A volume key has no entry, so its result checks nothing.
    pub(super) fn observe(&mut self, key: Key, at: (Version, Value)) -> Result<bool, Regression> {
        let Some(entry) = Entry::of(key) else {
            return Ok(false);
        };
        self.check(key, at)?;
        let (version, value) = at;
        let adopted = self.marks.get(&entry).and_then(|held| held.adopted);
        let mark = Mark {
            version,
            value,
            adopted,
        };
        Ok(self.marks.insert(entry, mark) != Some(mark))
    }

    /// Refuses a result of `key` at `version` holding `value` that falls below the mark, or that holds the mark's
    /// version with another value, and leaves the mark as it is.
    pub(super) fn check(&self, key: Key, at: (Version, Value)) -> Result<(), Regression> {
        let (version, value) = at;
        let held = Entry::of(key).and_then(|entry| self.marks.get(&entry));
        let regressed = held.is_some_and(|held| {
            let reused = version == held.version && value != held.value;
            version < held.version || value < held.value || reused
        });
        (!regressed).then_some(()).ok_or(Regression::Value(key))
    }

    /// Refuses an absent record of `key` when the watermark holds a mark for it: shard records and pages are never
    /// deleted, so the record's absence is a lost or rolled-back write.
    pub(super) fn absent(&self, key: Key) -> Result<(), Regression> {
        let held = Entry::of(key).is_some_and(|entry| self.marks.contains_key(&entry));
        (!held).then_some(()).ok_or(Regression::Value(key))
    }

    /// Refuses `record` at the generation of the checkpoint adopted for its shard when it names an earlier
    /// `(session, capture)` than the adopted checkpoint, or the same `(session, capture)` with another slot or unit
    /// count.
    pub(super) fn check_checkpoint(&self, record: &ShardRecord) -> Result<(), Regression> {
        let adopted = self
            .marks
            .get(&Entry::Shard(record.shard))
            .and_then(|mark| mark.adopted);
        let Some((generation, ck)) = adopted else {
            return Ok(());
        };
        let (named, identity) = (
            record.checkpoint.map(|n| (n.session, n.capture)),
            Some((ck.session, ck.capture)),
        );
        let renamed = named == identity && record.checkpoint != Some(ck);
        match generation == record.generation && (named < identity || renamed) {
            true => Err(Regression::Checkpoint(record.shard)),
            false => Ok(()),
        }
    }

    /// Records the checkpoint `record` names as adopted at its generation.
    pub(super) fn adopt_checkpoint(&mut self, record: &ShardRecord) {
        let mark = self.marks.get_mut(&Entry::Shard(record.shard));
        if let (Some(mark), Some(named)) = (mark, record.checkpoint) {
            mark.adopted = Some((record.generation, named));
        }
    }

    /// The version the watermark holds for `key`.
    pub(super) fn held(&self, key: &Key) -> Option<Version> {
        let entry = Entry::of(*key)?;
        self.marks.get(&entry).map(|mark| mark.version)
    }

    /// The `(version, (g, E))` the watermark holds for `shard`.
    pub(crate) fn shard_mark(&self, shard: Shard) -> Option<(Version, Value)> {
        self.marks
            .get(&Entry::Shard(shard))
            .map(|mark| (mark.version, mark.value))
    }

    /// The 64-byte header, then the slots. The header is magic `WMRK`, format version `u16` and the slot count
    /// `u32`, zeros to byte 32 and the SHA-256 of those 32 bytes. The slots hold each mark in key order, one per
    /// slot, then free slots, at least `MIN_SLOTS` and twice the marks in all. A slot is its entry, or the free
    /// marker `FREE` and zeros, followed by the leading `SLOT_DIGEST` bytes of the SHA-256 of its index `u32` and
    /// those entry bytes. An entry is the key's kind (0 shard, 1 page), shard `u32` and page `u16` (zero for a
    /// shard), the version `u64`, the value `(u64, u32)`, the adopted checkpoint after its flag, and its generation
    /// `u32` (zero when absent). All integers are big-endian.
    pub fn encode(&self) -> Vec<u8> {
        let slots = (2 * self.marks.len()).max(MIN_SLOTS);
        let mut out = head(b"WMRK", FORMAT, SLOT * (1 + slots));
        out.extend((slots as u32).to_be_bytes());
        out.resize(HEAD_BODY, 0);
        out.extend_from_slice(&Sha256::digest(&out));
        for (index, (entry, mark)) in self.marks.iter().enumerate() {
            out.extend(slot(index, *entry, mark));
        }
        for index in self.marks.len()..slots {
            out.extend(sealed(index, [FREE]));
        }
        out
    }

    /// Decodes a watermark file with its marks in any slot order, as [`Watermark::encode`] writes it and
    /// [`FileLog`]'s in-place raises rewrite it.
    ///
    /// # Errors
    ///
    /// - [`CodecError::Checksum`] for a header or slot whose digest does not match its bytes and index, a torn,
    ///   zeroed or moved slot included. The header's digest is checked before any header field is read.
    /// - `Length` for input shorter than the header, or other than the header's slot count of whole slots.
    /// - `Magic` or `Version` for a header of another magic or format version.
    /// - `Flag` for nonzero header padding, a mark after a free slot, a free slot with nonzero bytes, a kind or flag
    ///   byte outside its values, a shard entry with a nonzero page, or nonzero bytes of an absent part.
    /// - `Field` for a zero shard or version, an adopted checkpoint at generation zero, or two slots of one key.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        Self::decode_slots(bytes).map(|(mark, _, _)| mark)
    }

    /// Decodes as [`Watermark::decode`] does, and also returns each mark's slot index and the slot count, which a
    /// [`FileLog`] reload keeps for in-place raises.
    fn decode_slots(bytes: &[u8]) -> Result<(Self, BTreeMap<Entry, usize>, usize), CodecError> {
        let (header, slots) = bytes.split_at_checked(SLOT).ok_or(CodecError::Length)?;
        let (body, digest) = header.split_at(HEAD_BODY);
        if Sha256::digest(body).as_slice() != digest {
            return Err(CodecError::Checksum);
        }
        let mut r = Reader::open(body, b"WMRK", FORMAT)?;
        let count = r.u32()? as usize;
        if r.0.iter().any(|&byte| byte != 0) {
            return Err(CodecError::Flag);
        }
        let (slots, rest) = slots.as_chunks::<SLOT>();
        if slots.len() != count || !rest.is_empty() {
            return Err(CodecError::Length);
        }
        let mut mark = Self::default();
        let mut indices = BTreeMap::new();
        let mut free = false;
        for (index, bytes) in slots.iter().enumerate() {
            match read_slot(index, bytes)? {
                None => free = true,
                Some(_) if free => return Err(CodecError::Flag),
                Some((entry, held)) => {
                    if mark.marks.insert(entry, held).is_some() {
                        return Err(CodecError::Field);
                    }
                    indices.insert(entry, index);
                }
            }
        }
        Ok((mark, indices, count))
    }
}

/// The longest watermark file a [`FileLog`] loads, 64 MiB, room for every mark of hundreds of thousands of records.
pub(crate) const LOAD_LIMIT: u64 = 64 << 20;

/// The slot holding `entry`'s `mark` at `index`.
fn slot(index: usize, entry: Entry, mark: &Mark) -> [u8; SLOT] {
    let (kind, shard, page) = match entry {
        Entry::Shard(shard) => (0, shard, 0),
        Entry::Page(shard, page) => (1, shard, page),
    };
    let mut out = Vec::with_capacity(ENTRY);
    out.push(kind);
    out.extend(shard.get().to_be_bytes());
    out.extend(page.to_be_bytes());
    out.extend(mark.version.get().to_be_bytes());
    out.extend(mark.value.0.to_be_bytes());
    out.extend(mark.value.1.to_be_bytes());
    let (generation, named) = mark.adopted.unzip();
    put_checkpoint(&mut out, named);
    out.extend((generation.map_or(0, |g| g.get()) as u32).to_be_bytes());
    sealed(index, out)
}

/// The slot at `index` holding `body`, at most an entry's bytes, zero-padded to an entry and closed by the leading
/// bytes of the SHA-256 of the index and the entry bytes. The digest binds the slot to its index, so a slot copied
/// to another index fails its check.
fn sealed(index: usize, body: impl AsRef<[u8]>) -> [u8; SLOT] {
    let mut slot = [0; SLOT];
    let body = body.as_ref();
    slot[..body.len()].copy_from_slice(body);
    let digest = slot_digest(index, &slot[..ENTRY]);
    slot[ENTRY..].copy_from_slice(&digest);
    slot
}

fn slot_digest(index: usize, entry: &[u8]) -> [u8; SLOT_DIGEST] {
    let digest = Sha256::new()
        .chain_update((index as u32).to_be_bytes())
        .chain_update(entry)
        .finalize();
    let mut out = [0; SLOT_DIGEST];
    out.copy_from_slice(&digest[..SLOT_DIGEST]);
    out
}

/// The entry and mark the slot at `index` holds, or `None` for a free slot, after its digest and every field are
/// checked.
fn read_slot(index: usize, bytes: &[u8; SLOT]) -> Result<Option<(Entry, Mark)>, CodecError> {
    let (body, digest) = bytes.split_at(ENTRY);
    if slot_digest(index, body) != digest {
        return Err(CodecError::Checksum);
    }
    if body[0] == FREE {
        let zeroed = body[1..].iter().all(|&byte| byte == 0);
        return zeroed.then_some(None).ok_or(CodecError::Flag);
    }
    let mut r = Reader(body);
    let (kind, shard, page) = (r.u8()?, r.u32()?, r.u16()?);
    let shard = Shard::new(shard).ok_or(CodecError::Field)?;
    let entry = match (kind, page) {
        (0, 0) => Entry::Shard(shard),
        (1, page) => Entry::Page(shard, page),
        _ => return Err(CodecError::Flag),
    };
    let version = Version::new(r.u64()?).ok_or(CodecError::Field)?;
    let value = (r.u64()?, r.u32()?);
    let (named, generation) = (r.checkpoint()?, r.u32()?);
    let adopted = match (named, ShardGeneration::new(generation.into())) {
        (Some(ck), Some(generation)) => Some((generation, ck)),
        (None, None) => None,
        (Some(_), None) => return Err(CodecError::Field),
        (None, Some(_)) => return Err(CodecError::Flag),
    };
    let mark = Mark {
        version,
        value,
        adopted,
    };
    Ok(Some((entry, mark)))
}

/// The production watermark log: one file, mode 0600. [`WatermarkLog::record`] replaces it whole through the
/// crate's atomic writer, which creates a fresh temporary sibling without following links, syncs it, renames it
/// over the record and syncs the directory, so a crash leaves the previous or the new watermark; the log keeps the
/// writer's handle on the new file for in-place raises, so a file another writer renames over the path never
/// receives them. [`WatermarkLog::reload`] reads the file through a handle open for writing,
/// writes the bytes it read back where they lie, syncs them and the directory, refuses when the path then names
/// another file, and keeps that handle for in-place raises. [`WatermarkLog::raise`] rewrites the raised marks' slots in that file and syncs its data once, and
/// at most one new mark takes the next free slot, so a crash during the raise leaves each slot's previous or new
/// bytes and the marks still fill a prefix of the slots. A raise replaces the file whole when it brings two or more
/// new marks, when a new mark finds no free slot, and when the log holds no open file: before its first record or
/// reload and after a failed record, reload or raise.
pub struct FileLog {
    path: PathBuf,
    table: Option<Table>,
}

/// The file a [`FileLog`] last recorded or reloaded, open for writing, and the slot of each mark it holds. The marks
/// fill a prefix of the slots, so a new mark's slot is the number of marks.
struct Table {
    file: File,
    slots: BTreeMap<Entry, usize>,
    /// The file's slot count.
    capacity: usize,
}

impl FileLog {
    /// A log at `path`.
    ///
    /// # Errors
    ///
    /// `InvalidInput` for a path with no file name or a name ending in `.tmp`: the writer stages a log at its path
    /// with `.tmp` appended, so no log's path is another log's staging name.
    pub fn new(path: PathBuf) -> io::Result<Self> {
        let name = path.file_name().map(|name| name.as_encoded_bytes());
        let staging = name.is_none_or(|name| name.ends_with(b".tmp"));
        (!staging)
            .then_some(Self { path, table: None })
            .ok_or(io::ErrorKind::InvalidInput.into())
    }

    /// Writes `mark`'s mark of each of `entries` into the entry's slot, and a new entry's mark into the next free
    /// slot, and syncs the file's data once. Returns `false`, having written nothing, when the log holds no open file,
    /// `entries` holds two or more new entries, a new entry finds no free slot, or `mark` holds no mark of an entry.
    ///
    /// # Errors
    ///
    /// The write's, the sync's or a metadata read's error, or `NotFound` when the path no longer names the written
    /// file, as after another writer removed it, renamed it aside or renamed a file over it, whether or not the
    /// written file keeps a link under another name: a later load of the path reads none of this write.
    fn write_slots(&mut self, mark: &Watermark, entries: &BTreeSet<Entry>) -> io::Result<bool> {
        let Some(table) = &mut self.table else {
            return Ok(false);
        };
        let new = entries
            .iter()
            .filter(|entry| !table.slots.contains_key(entry))
            .count();
        let next = table.slots.len();
        if new > 1 || (new == 1 && next >= table.capacity) {
            return Ok(false);
        }
        let mut slots = Vec::with_capacity(entries.len());
        for &entry in entries {
            let Some(held) = mark.marks.get(&entry) else {
                return Ok(false);
            };
            let index = table.slots.get(&entry).copied().unwrap_or(next);
            slots.push((entry, index, held));
        }
        for &(entry, index, held) in &slots {
            let offset = SLOT * (1 + index);
            table
                .file
                .write_all_at(&slot(index, entry, held), offset as u64)?;
        }
        table.file.sync_data()?;
        if !names(&self.path, &table.file)? {
            return Err(io::ErrorKind::NotFound.into());
        }
        table
            .slots
            .extend(slots.into_iter().map(|(entry, index, _)| (entry, index)));
        Ok(true)
    }
}

impl WatermarkLog for FileLog {
    /// Loads a log file of this process's user with mode 0600 and at most [`LOAD_LIMIT`] bytes; any other file
    /// refuses with `InvalidData`.
    fn load(&self) -> io::Result<Watermark> {
        let owner = std::fs::metadata("/proc/self")?.uid();
        let bytes =
            crate::bind::Mappings::read_bytes(&self.path, LOAD_LIMIT, |meta| private(meta, owner))?;
        Watermark::decode(&bytes).map_err(|_| io::ErrorKind::InvalidData.into())
    }

    /// Refuses with `InvalidInput` an encoding longer than [`LOAD_LIMIT`], which [`load`](Self::load) would
    /// refuse, before it replaces the file.
    fn record(&mut self, mark: &Watermark) -> io::Result<()> {
        self.table = None;
        let bytes = mark.encode();
        if bytes.len() as u64 > LOAD_LIMIT {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let file = crate::bind::Mappings::write_kept(&self.path, &bytes)?;
        let slots = mark
            .marks
            .keys()
            .enumerate()
            .map(|(index, entry)| (*entry, index));
        self.table = Some(Table {
            file,
            slots: slots.collect(),
            capacity: bytes.len() / SLOT - 1,
        });
        Ok(())
    }

    fn raise(&mut self, mark: &Watermark, keys: &[Key]) -> io::Result<()> {
        let entries: BTreeSet<Entry> = keys.iter().copied().filter_map(Entry::of).collect();
        if entries.is_empty() {
            return Ok(());
        }
        match self.write_slots(mark, &entries) {
            Ok(true) => Ok(()),
            Ok(false) => self.record(mark),
            Err(error) => {
                self.table = None;
                Err(error)
            }
        }
    }

    /// Returns `InvalidData` for a file it opens for reading and writing that [`load`](Self::load) refuses on its
    /// metadata or decoding, and `NotFound` when the path no longer names the file it read once the directory is
    /// synced, as after another writer renamed a file over it: a later load of the path reads another watermark. A path it cannot open for reading and writing, such as a directory or a file without
    /// owner write permission, returns the open error, and later I/O errors propagate. Writing the bytes back before the sync
    /// sends them to the device even when the page cache holds them clean after a failed writeback.
    fn reload(&mut self) -> io::Result<Watermark> {
        self.table = None;
        let owner = std::fs::metadata("/proc/self")?.uid();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.path)?;
        let meta = file.metadata()?;
        if !meta.is_file() || !private(&meta, owner) || meta.len() > LOAD_LIMIT {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
        (&file).take(LOAD_LIMIT + 1).read_to_end(&mut bytes)?;
        let (mark, slots, capacity) = Watermark::decode_slots(&bytes)
            .ok()
            .filter(|_| bytes.len() as u64 <= LOAD_LIMIT)
            .ok_or(io::ErrorKind::InvalidData)?;
        file.write_all_at(&bytes, 0)?;
        file.sync_data()?;
        crate::bind::Mappings::sync_directory_of(&self.path)?;
        if !names(&self.path, &file)? {
            return Err(io::ErrorKind::NotFound.into());
        }
        self.table = Some(Table {
            file,
            slots,
            capacity,
        });
        Ok(mark)
    }
}

/// Whether `path` names `file` now, by device and inode: a file renamed over the path, or the path's removal or
/// rename aside, leaves the open file under no name a later load of the path reads.
///
/// # Errors
///
/// A metadata read's error, `NotFound` among them for a path that names nothing.
fn names(path: &Path, file: &File) -> io::Result<bool> {
    let (held, named) = (file.metadata()?, std::fs::symlink_metadata(path)?);
    Ok((held.dev(), held.ino()) == (named.dev(), named.ino()))
}

fn private(meta: &std::fs::Metadata, owner: u32) -> bool {
    meta.mode() & 0o777 == 0o600 && meta.uid() == owner
}

#[cfg(test)]
#[path = "watermark_decode_tests.rs"]
mod decode_tests;
