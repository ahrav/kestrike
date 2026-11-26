//! The soak's host-local store and the session it derives from it.
//!
//! The soak attaches one volume with no off-volume store, so it keeps the shard record in its own state
//! directory: one file per record under `soak-store`, a private directory of the state directory's owner, each
//! file holding the record's version and encoding in one of its two slots. A create writes the file through the
//! crate's atomic writer. An exact-version write syncs the file's data, loads the record, checks its version and
//! overwrites the other slot in place with one write and one data sync, so it is a conditional write on one record
//! while one process writes the files; [`session`] takes the state directory's held owner lock, which gives the soak
//! that exclusion for its whole run. Each run bumps `E` through the store client and takes its session from that
//! acknowledged bump, so no two runs that share the store share a session (`NoEpochReuse`).
//!
//! The store stays with the volume for the volume's whole life. The first run over a state directory with no
//! shard record and no watermark creates shard 1 at `g = 1`, `E = 0`, and so does a run that finds an absent shard
//! record beside a watermark holding no mark for it, the state a first run leaves when it stops before its shard
//! create. A shard record without its watermark, or a watermark that holds a mark for the absent shard record,
//! refuses. Every record and the watermark must be a file of this user with mode 0600. A volume whose roots hold a session at or
//! above the store's next one refuses its bootstrap `StaleSession`.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io;
use std::num::{NonZeroU16, NonZeroU32};
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::bind::{Mappings, OwnerLock};
use crate::failover::records::{Ancestry, Host, Namespace, ShardRecord, VolumeId};
use crate::net::ownership::{Shard, ShardGeneration};
use crate::storage::Session;
use crate::storage::store::{
    Client, FileLog, ITEM_LIMIT, Item, Key, Outcome, Refusal, Store, StoreError, Unavailable,
    Version, Watermark, WatermarkLog, Write,
};

/// The soak store's directory under the state directory.
pub const STORE_DIR: &str = "soak-store";

/// The operator step for a store refusal that every later run repeats.
const RESTORE: &str = "restore the soak store that last attached this volume, or bind a replacement volume into a new state directory";

/// The step for a shard record this binary's codec refuses. A record of another format version refuses by its length
/// or version, and restoring the store keeps that format, so the run needs the binary that wrote it or a new state
/// directory; a record of this format that refuses is damaged, and only a new state directory replaces it.
const FORMAT: &str = "if another format version wrote the record, run the binary that wrote it; otherwise bind a replacement volume into a new state directory";

/// The bytes of a slot before its value: the version `u64`, the value's length `u32` and the SHA-256 of the slot's
/// offset `u64`, the version, the length and the value, integers big-endian.
const SLOT_HEAD: usize = 8 + 4 + 32;

/// The offset of a record file's second slot: the first 64 KiB boundary past the longest first slot, so on a system
/// whose page and filesystem block are at most 64 KiB the two slots share no page or block, and a write to one leaves
/// every byte of the other.
const SECOND: u64 = (SLOT_HEAD + ITEM_LIMIT).next_multiple_of(64 << 10) as u64;

/// Records under `dir`, one file per key named by the key, each a file of the user `owner` with mode 0600 holding two
/// slots, at offset zero and at [`SECOND`]. A slot the file ends before or inside, or one whose version is zero,
/// whose length passes [`ITEM_LIMIT`] or whose digest fails, holds no item; the record is the item of the highest
/// version among the slots that hold one, and a file whose slots hold no item fails to load with `InvalidData`.
struct LocalStore {
    dir: PathBuf,
    owner: u32,
}

impl LocalStore {
    fn path(&self, key: &Key) -> PathBuf {
        let name = match key {
            Key::Shard(shard) => format!("shard-{}", shard.get()),
            Key::Volume(volume) => format!("volume-{}", volume.as_str()),
            Key::Page(shard, page) => format!("page-{}-{page}", shard.get()),
            Key::Standbys(zone) => format!("standbys-{}", zone.0),
            Key::Replacement(shard) => format!("replacement-{}", shard.get()),
        };
        self.dir.join(name)
    }

    /// The record file at `path`, open for reading and, with `write`, for writing, or `None` when no file is there.
    /// Opening a final symbolic link fails with `ELOOP`, a FIFO opens without blocking, and an opened file other than
    /// a regular file of the user `owner` with mode 0600 and at most [`SECOND`] plus the longest slot's bytes fails
    /// with `InvalidData`. Any other open error returns unchanged: with `write`, that includes EISDIR for a directory
    /// and EACCES for a file without write permission, and without `write` a directory returns `InvalidData`.
    fn open(&self, path: &Path, write: bool) -> io::Result<Option<File>> {
        let file = match OpenOptions::new()
            .read(true)
            .write(write)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let meta = file.metadata()?;
        let private = meta.mode() & 0o777 == 0o600 && meta.uid() == self.owner;
        if !meta.is_file() || !private || meta.len() > SECOND + (SLOT_HEAD + ITEM_LIMIT) as u64 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(Some(file))
    }

    /// The record at `path`, or `None` when no file is there.
    fn load(&self, path: &Path) -> io::Result<Option<Item>> {
        self.open(path, false)?
            .map(|file| current(&file).map(|(_, item)| item))
            .transpose()
    }
}

/// The offset of the slot of `file` that holds the record, and its item. Syncing the file's data before reading its
/// slots sends a slot written by a process that exited before its own sync returned to the device before an
/// exact-version write overwrites the other slot.
fn current(file: &File) -> io::Result<(u64, Item)> {
    file.sync_data()?;
    let mut held: Option<(u64, Item)> = None;
    for at in [0, SECOND] {
        if let Some(item) = read_slot(file, at)?
            && held
                .as_ref()
                .is_none_or(|(_, kept)| item.version > kept.version)
        {
            held = Some((at, item));
        }
    }
    held.ok_or(io::ErrorKind::InvalidData.into())
}

/// The item the slot at offset `at` holds, or `None` when it holds none.
fn read_slot(file: &File, at: u64) -> io::Result<Option<Item>> {
    let mut head = [0; SLOT_HEAD];
    if !read_exact_at(file, &mut head, at)? {
        return Ok(None);
    }
    let (mut version, mut len, mut digest) = ([0; 8], [0; 4], [0; 32]);
    version.copy_from_slice(&head[..8]);
    len.copy_from_slice(&head[8..12]);
    digest.copy_from_slice(&head[12..]);
    let len = u32::from_be_bytes(len) as usize;
    let Some(version) = Version::new(u64::from_be_bytes(version)).filter(|_| len <= ITEM_LIMIT)
    else {
        return Ok(None);
    };
    let mut value = vec![0; len];
    if !read_exact_at(file, &mut value, at + SLOT_HEAD as u64)? {
        return Ok(None);
    }
    let item = Item { version, value };
    Ok((slot_digest(at, &item) == digest).then_some(item))
}

/// Fills `buf` from offset `at` of `file`, returning `false` when the file ends first.
fn read_exact_at(file: &File, buf: &mut [u8], at: u64) -> io::Result<bool> {
    match file.read_exact_at(buf, at) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
}

fn slot_digest(at: u64, item: &Item) -> [u8; 32] {
    Sha256::new()
        .chain_update(at.to_be_bytes())
        .chain_update(item.version.get().to_be_bytes())
        .chain_update((item.value.len() as u32).to_be_bytes())
        .chain_update(&item.value)
        .finalize()
        .into()
}

/// The bytes of the slot at offset `at` holding `item`.
fn slot(at: u64, item: &Item) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SLOT_HEAD + item.value.len());
    bytes.extend(item.version.get().to_be_bytes());
    bytes.extend((item.value.len() as u32).to_be_bytes());
    bytes.extend(slot_digest(at, item));
    bytes.extend_from_slice(&item.value);
    bytes
}

impl Store for LocalStore {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        self.load(&self.path(key)).map_err(|_| Unavailable)
    }

    /// One class-wide value. The locked state directory is the soak store's instance boundary, and the watermark,
    /// active-volume and owner checks of [`session`] refuse a record from another directory below its mark.
    fn namespace(&self) -> Namespace {
        NAMESPACE
    }

    /// A create writes the first slot through the crate's atomic writer. An exact-version write overwrites the slot
    /// that does not hold the record and syncs the file's data. Unless an earlier writeback of the record's slot
    /// failed, a crash leaves that slot's previous, torn or new bytes beside the intact record, and the file loads
    /// the record before or after the write.
    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        let path = self.path(key);
        let Ok(file) = self.open(&path, true) else {
            return Outcome::NotCommitted(Refusal::Rejected);
        };
        let Ok(held) = file.as_ref().map(current).transpose() else {
            return Outcome::NotCommitted(Refusal::Rejected);
        };
        let done = match (write, file, held) {
            (Write::Create(value) | Write::Exact { value, .. }, ..) if value.len() > ITEM_LIMIT => {
                return Outcome::NotCommitted(Refusal::Rejected);
            }
            (Write::Create(value), None, None) => {
                let item = Item {
                    version: Version::FIRST,
                    value: value.clone(),
                };
                Mappings::write_bytes(&path, &slot(0, &item)).map(|()| item.version)
            }
            (Write::Exact { expect, value }, Some(file), Some((at, held)))
                if held.version == *expect =>
            {
                let Some(version) = expect.next() else {
                    return Outcome::NotCommitted(Refusal::Rejected);
                };
                let target = if at == 0 { SECOND } else { 0 };
                let item = Item {
                    version,
                    value: value.clone(),
                };
                file.write_all_at(&slot(target, &item), target)
                    .and_then(|()| file.sync_data())
                    .map(|()| version)
            }
            (Write::Create(_) | Write::Exact { .. }, ..) => {
                return Outcome::NotCommitted(Refusal::Condition);
            }
        };
        // A failed create may leave the new record after its rename, and a failed overwrite its new slot, so a
        // failed write is an unknown outcome.
        match done {
            Ok(version) => Outcome::Committed(version),
            Err(_) => Outcome::Unknown,
        }
    }
}

const SHARD: u32 = 1;
const HOST: u64 = 1;
const NAMESPACE: Namespace = Namespace::new(*b"kestrike-soak-v1").expect("nonzero namespace");

/// The store directory `soak-store` of the locked state directory and the user that owns it. The state directory
/// must first pass the owner lock's state-directory rule, the one attach applies to the authority files: a 0700
/// directory of this user, under ancestors only root or this user can write, with a canonical path outside `/run`
/// and `/var/run`, whose contents survive a reboot. The store directory is created with mode `0o700` when absent,
/// then required to be a directory, not a symbolic link, owned by this process's user with no group or other
/// permission bits. The state directory is synced, so the directory's entry is durable before any record write.
fn store_dir(lock: &OwnerLock) -> Result<(PathBuf, u32), String> {
    let failed = |error: io::Error| format!("soak store: {error}");
    let owner = lock.check_authority_directory().map_err(|error| {
        format!(
            "soak store: the state directory must be a 0700 directory of this user under ancestors only root or this user can write, outside /run and /var/run: {error:?}"
        )
    })?;
    let dir = lock.state_dir().join(STORE_DIR);
    match DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(failed(error)),
    }
    let meta = std::fs::symlink_metadata(&dir).map_err(failed)?;
    if !meta.is_dir() || meta.uid() != owner || meta.mode() & 0o077 != 0 {
        return Err(format!(
            "soak store: {} is not a private directory of this user",
            dir.display()
        ));
    }
    Mappings::sync_directory_of(&dir).map_err(failed)?;
    Ok((dir, owner))
}

/// The session of this run on `volume`, from the store in the state directory `lock` holds. The first run
/// creates shard 1 at `g = 1`, `E = 0` with an empty watermark; every run bumps `E` from the value it reads. The
/// lock keeps other processes off the store, and the exclusive borrow keeps a second call in this process from
/// interleaving its conditional writes with this one's.
///
/// # Errors
///
/// A state directory outside the rule [`store_dir`] states, or a store directory that is not private to this user; a shard record absent while the watermark holds
/// a mark for it, or present while the watermark is lost; a shard record below the watermark, as a rolled-back
/// record is; a watermark or record that does not load; a mappings volume ID that does not parse, or a shard
/// record naming another volume or another host as owner; a shard record the codec refuses, as one of another format
/// version is; a refused or unknown store result; an exhausted session.
pub(super) fn session(lock: &mut OwnerLock, volume: &str) -> Result<Session, String> {
    let (dir, owner) = store_dir(lock)?;
    let store = LocalStore {
        dir: dir.clone(),
        owner,
    };
    let mut log =
        FileLog::new(dir.join("watermark")).map_err(|error| format!("soak watermark: {error}"))?;
    let shard = Shard::new(SHARD).expect("nonzero shard");
    let host = Host::new(HOST).expect("nonzero host");
    let volume_id = VolumeId::new(volume).ok_or("soak store: the mappings' volume ID")?;
    // A first run seeds the watermark before the client opens over it, so a shard record with no watermark
    // always means a lost log, which the client refuses.
    let first = store
        .load(&store.path(&Key::Shard(shard)))
        .map_err(|error| format!("soak store: {error}"))?
        .is_none();
    if first {
        match log.load() {
            Err(error) if error.kind() == io::ErrorKind::NotFound => log
                .record(&Watermark::default())
                .map_err(|error| format!("soak watermark: {error}"))?,
            Ok(mark) if mark.shard_mark(shard).is_some() => {
                return Err(format!(
                    "soak store: shard {SHARD} is absent while the watermark holds its mark; {RESTORE}"
                ));
            }
            Ok(_) => {}
            Err(error) => return Err(format!("soak watermark: {error}")),
        }
    }
    let mut client =
        Client::open(store, log).map_err(|error| format!("soak watermark: {error}; {RESTORE}"))?;
    let failed = |error: StoreError| format!("soak store: {error:?}");
    let read = if first {
        client
            .create_shard(ShardRecord {
                shard,
                generation: ShardGeneration::new(1).expect("generation 1"),
                active: volume_id,
                owner: host,
                attempts: 0,
                spare: None,
                checkpoint: None,
                cut: 0,
                pages: NonZeroU16::MIN,
                page_cap: NonZeroU32::MIN,
                namespace: NAMESPACE,
                ancestry: Ancestry::default(),
                standby: None,
            })
            .map_err(failed)?
    } else {
        client
            .read::<ShardRecord>(Key::Shard(shard))
            .map_err(|error| match error {
                StoreError::Codec(codec) => {
                    format!("soak store: shard {SHARD} does not decode ({codec:?}); {FORMAT}")
                }
                error => failed(error),
            })?
    };
    if read.value().active.as_str() != volume {
        return Err(format!(
            "soak store: shard {SHARD} names {:?}, not {volume}; {RESTORE}",
            read.value().active
        ));
    }
    if read.value().owner != host {
        return Err(format!(
            "soak store: shard {SHARD} names host {} as owner, not host {HOST}; {RESTORE}",
            read.value().owner.get()
        ));
    }
    let bumped = client.bump(&read).map_err(failed)?;
    Session::activate(bumped).map_err(|error| format!("soak session: {error:?}"))
}

/// A fixture authority under the next session of the soak store in the locked state directory, so attaches of the
/// bound volume take increasing sessions across processes and across soak runs.
#[cfg(test)]
pub(crate) fn tenure_authority(lock: &mut OwnerLock) -> crate::storage::ServingAuthority {
    crate::storage::ServingAuthority::fixture_limits_under(
        crate::storage::ReservationLimits::new(2, 2, 10, 10).unwrap(),
        tenure_session(lock),
    )
}

/// The fixture authority of [`tenure_authority`] whose machine serves the pair of the state directory's local
/// record, the pair a production attach registers and holds on the device.
#[cfg(test)]
pub(crate) fn recorded_tenure_authority(
    lock: &mut OwnerLock,
    host: &crate::bind::Host,
) -> crate::storage::ServingAuthority {
    let pair = lock
        .prepare_authority(host, &crate::bind::Imds::connect(60).unwrap())
        .unwrap()
        .pair();
    crate::storage::ServingAuthority::fixture_pair_under(
        crate::storage::ReservationLimits::new(2, 2, 10, 10).unwrap(),
        tenure_session(lock),
        pair,
    )
}

#[cfg(test)]
fn tenure_session(lock: &mut OwnerLock) -> Session {
    let volume = lock
        .mappings()
        .unwrap()
        .nvme
        .expect("the mappings record a volume")
        .volume;
    session(lock, &volume).unwrap()
}

#[cfg(test)]
#[path = "store_tests.rs"]
pub(super) mod tests;
