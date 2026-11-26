//! Cases over the soak store, each in a state directory the test creates: successive runs take increasing
//! sessions, a lost or rolled-back record refuses with no write, a record or directory other than a private file
//! refuses, and each write arm commits only on its condition.

use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::*;
use crate::failover::records::Record;
use crate::storage::store::Tracked;

/// A fresh private state directory: created exclusively, so the test owns everything under it.
pub(in crate::soak) fn state(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    // The state directory check refuses a parent writable by others, as a shared temporary directory is.
    let base = std::env::var_os("HOME")
        .map_or_else(|| std::env::current_dir().unwrap(), PathBuf::from)
        .join(".tmp/kestrike-soak-store-tests");
    let owner = fs::metadata("/proc/self").unwrap().uid();
    crate::bind::prepare_state_dir(&base, owner).unwrap();
    let dir = base.join(format!("{name}-{}-{nanos}", std::process::id()));
    DirBuilder::new().mode(0o700).create(&dir).unwrap();
    dir
}

/// Removes the files the cases leave, one level under `state` and its store directory, then both directories.
pub(in crate::soak) fn remove(state: &Path) {
    let store = state.join("soak-store");
    if fs::symlink_metadata(&store).is_ok_and(|meta| meta.is_dir()) {
        for entry in fs::read_dir(&store).unwrap() {
            fs::remove_file(entry.unwrap().path()).unwrap();
        }
        fs::remove_dir(&store).unwrap();
    }
    for entry in fs::read_dir(state).unwrap() {
        fs::remove_file(entry.unwrap().path()).unwrap();
    }
    fs::remove_dir(state).unwrap();
}

fn lock(state: &Path) -> OwnerLock {
    OwnerLock::acquire(state).unwrap()
}

fn owner() -> u32 {
    fs::metadata("/proc/self").unwrap().uid()
}

/// Successive runs over one state directory take strictly increasing sessions at generation 1, each from the
/// bump that run made, in a store directory of mode `0o700`; another volume ID refuses, and a lost watermark log
/// refuses.
#[test]
fn successive_soak_runs_take_increasing_sessions() {
    let state = state("runs");
    let mut lock = lock(&state);
    let sessions: Vec<Session> = (0..3)
        .map(|_| session(&mut lock, "vol-0a").unwrap())
        .collect();
    assert!(sessions.iter().all(|s| s.generation().get() == 1));
    assert_eq!(
        sessions.iter().map(|s| s.epoch().get()).collect::<Vec<_>>(),
        [2, 4, 6]
    );
    let dir = fs::symlink_metadata(state.join("soak-store")).unwrap();
    assert!(dir.is_dir() && dir.mode() & 0o777 == 0o700);
    assert!(
        session(&mut lock, "vol-0b")
            .unwrap_err()
            .contains("not vol-0b")
    );
    fs::remove_file(state.join("soak-store/watermark")).unwrap();
    assert!(
        session(&mut lock, "vol-0a")
            .unwrap_err()
            .contains("soak watermark")
    );
    drop(lock);
    remove(&state);
}

/// With the shard record absent, a watermark holding the shard's mark and a watermark that fails its digest each
/// refuse before any write: the watermark keeps its bytes and no shard record appears.
#[test]
fn an_absent_shard_beside_a_watermark_refuses_with_no_write() {
    let state = state("absent");
    let mut lock = lock(&state);
    session(&mut lock, "vol-0a").unwrap();
    let shard = state.join("soak-store/shard-1");
    let watermark = state.join("soak-store/watermark");
    fs::remove_file(&shard).unwrap();
    let held = fs::read(&watermark).unwrap();
    let error = session(&mut lock, "vol-0a").unwrap_err();
    assert!(error.contains("holds its mark"), "{error}");
    assert_eq!(fs::read(&watermark).unwrap(), held);
    assert!(!shard.exists());

    let mut corrupt = held.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    fs::write(&watermark, &corrupt).unwrap();
    let error = session(&mut lock, "vol-0a").unwrap_err();
    assert!(error.contains("soak watermark"), "{error}");
    assert_eq!(fs::read(&watermark).unwrap(), corrupt);
    assert!(!shard.exists());
    drop(lock);
    remove(&state);
}

/// The refusal of the run after the first one, whose stored shard record `rewrite` replaced, asserting that the
/// refusal left the record's bytes.
fn refusal_after_rewrite(name: &str, rewrite: impl FnOnce(&[u8]) -> Vec<u8>) -> String {
    let state = state(name);
    let mut lock = lock(&state);
    session(&mut lock, "vol-0a").unwrap();
    let (dir, owner) = store_dir(&lock).unwrap();
    let mut store = LocalStore { dir, owner };
    let key = Key::Shard(Shard::new(SHARD).unwrap());
    let item = store.read(&key).unwrap().unwrap();
    assert_eq!(
        store.write(
            &key,
            &Write::Exact {
                expect: item.version,
                value: rewrite(&item.value),
            },
        ),
        Outcome::Committed(item.version.next().unwrap())
    );
    let shard = state.join("soak-store/shard-1");
    let held = fs::read(&shard).unwrap();
    let error = session(&mut lock, "vol-0a").unwrap_err();
    assert_eq!(fs::read(&shard).unwrap(), held);
    drop(lock);
    remove(&state);
    error
}

/// A shard record naming another host as owner refuses before the bump: the error names the owner and the restore
/// step, and the record keeps its bytes.
#[test]
fn a_shard_record_of_another_owner_refuses_without_a_bump() {
    let error = refusal_after_rewrite("foreign", |value| {
        let mut record = ShardRecord::decode(value).unwrap();
        record.owner = Host::new(HOST + 1).unwrap();
        record
            .encoded(&Key::Shard(Shard::new(SHARD).unwrap()))
            .unwrap()
    });
    assert!(error.contains("owner"), "{error}");
    assert!(error.contains(RESTORE), "{error}");
}

/// A shard record in the version-1 layout, the same fields with `beat` in place of the cut, namespace and
/// ancestry, refuses the run with the conditional format step before any write, and the record keeps its bytes.
#[test]
fn a_shard_record_of_the_previous_format_refuses_with_the_format_step() {
    let error = refusal_after_rewrite("format", |value| {
        let mut v1 = value[..100].to_vec();
        v1[4..6].copy_from_slice(&1u16.to_be_bytes());
        v1.extend(0u64.to_be_bytes());
        v1.extend(&value[108..114]);
        assert_eq!(v1.len(), 114);
        v1
    });
    assert!(error.contains("(Length)"), "{error}");
    assert!(
        error.contains("if another format version wrote the record, run the binary that wrote it"),
        "{error}"
    );
    assert!(
        !error.contains("the record is of another format version"),
        "{error}"
    );
}

/// A current-format shard record with a zero owner refuses the run with the codec error it fails and the conditional
/// format step, which claims no format mismatch, before any write, and the record keeps its bytes.
#[test]
fn a_damaged_current_format_shard_record_refuses_with_its_codec_error() {
    let error = refusal_after_rewrite("damaged", |value| {
        let mut damaged = value.to_vec();
        damaged[36..44].fill(0);
        damaged
    });
    assert!(error.contains("(Field)"), "{error}");
    assert!(
        error.contains("otherwise bind a replacement volume into a new state directory"),
        "{error}"
    );
    assert!(
        !error.contains("the record is of another format version"),
        "{error}"
    );
}

/// A shard record rolled back to an earlier run's bytes falls below the watermark, so the run refuses and the
/// record keeps the rolled-back bytes.
#[test]
fn a_rolled_back_shard_record_refuses() {
    let state = state("rolled");
    let mut lock = lock(&state);
    session(&mut lock, "vol-0a").unwrap();
    let shard = state.join("soak-store/shard-1");
    let earlier = fs::read(&shard).unwrap();
    session(&mut lock, "vol-0a").unwrap();
    fs::write(&shard, &earlier).unwrap();
    let error = session(&mut lock, "vol-0a").unwrap_err();
    assert!(error.contains("Regression"), "{error}");
    assert_eq!(fs::read(&shard).unwrap(), earlier);
    drop(lock);
    remove(&state);
}

/// A FIFO, a symbolic link or an oversized file at the shard record's path refuses the run, the FIFO without
/// blocking, and a store directory open to its group or replaced by a symbolic link refuses.
#[test]
fn records_and_directories_other_than_private_files_refuse() {
    let state = state("entries");
    let mut lock = lock(&state);
    session(&mut lock, "vol-0a").unwrap();
    let shard = state.join("soak-store/shard-1");
    let held = fs::read(&shard).unwrap();
    fs::remove_file(&shard).unwrap();
    let fifo = std::ffi::CString::new(shard.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: `fifo` is a NUL-terminated path that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(session(&mut lock, "vol-0a").is_err(), "a FIFO record");
    fs::remove_file(&shard).unwrap();
    let elsewhere = state.join("elsewhere");
    fs::write(&elsewhere, &held).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &shard).unwrap();
    assert!(session(&mut lock, "vol-0a").is_err(), "a linked record");
    fs::remove_file(&shard).unwrap();
    let past = SECOND as usize + SLOT_HEAD + ITEM_LIMIT + 1;
    Mappings::write_bytes(&shard, &vec![0; past]).unwrap();
    assert!(session(&mut lock, "vol-0a").is_err(), "an oversized record");
    Mappings::write_bytes(&shard, &held).unwrap();
    fs::set_permissions(&shard, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        session(&mut lock, "vol-0a").is_err(),
        "a record of another mode"
    );
    fs::set_permissions(&shard, fs::Permissions::from_mode(0o600)).unwrap();
    session(&mut lock, "vol-0a").unwrap();

    let store = state.join("soak-store");
    fs::set_permissions(&store, fs::Permissions::from_mode(0o750)).unwrap();
    let error = session(&mut lock, "vol-0a").unwrap_err();
    assert!(error.contains("private directory"), "{error}");
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    let moved = state.join("moved");
    fs::rename(&store, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &store).unwrap();
    let error = session(&mut lock, "vol-0a").unwrap_err();
    assert!(error.contains("private directory"), "{error}");
    fs::remove_file(&store).unwrap();
    fs::rename(&moved, &store).unwrap();
    drop(lock);
    remove(&state);
}

/// A create over an existing record, an exact write at a stale version and one over an absent record refuse on
/// their condition and leave the bytes; a value past the item limit and a write over a malformed record refuse as
/// rejected; a create whose staging file cannot be created is an unknown outcome.
#[test]
fn local_store_writes_commit_only_on_their_condition() {
    let state = state("writes");
    let mut store = LocalStore {
        dir: state.clone(),
        owner: owner(),
    };
    let key = Key::Shard(Shard::new(SHARD).unwrap());
    let path = store.path(&key);
    let create = |value: &[u8]| Write::Create(value.to_vec());
    let exact = |expect: Version, value: &[u8]| Write::Exact {
        expect,
        value: value.to_vec(),
    };
    assert_eq!(
        store.write(&key, &exact(Version::FIRST, b"a")),
        Outcome::NotCommitted(Refusal::Condition)
    );
    assert!(!path.exists());
    assert_eq!(
        store.write(&key, &create(b"a")),
        Outcome::Committed(Version::FIRST)
    );
    let first = fs::read(&path).unwrap();
    assert_eq!(
        store.write(&key, &create(b"b")),
        Outcome::NotCommitted(Refusal::Condition)
    );
    let second = Version::FIRST.next().unwrap();
    assert_eq!(
        store.write(&key, &exact(second, b"b")),
        Outcome::NotCommitted(Refusal::Condition)
    );
    assert_eq!(fs::read(&path).unwrap(), first);
    assert_eq!(
        store.write(&key, &exact(Version::FIRST, &vec![0; ITEM_LIMIT + 1])),
        Outcome::NotCommitted(Refusal::Rejected)
    );
    assert_eq!(fs::read(&path).unwrap(), first);
    assert_eq!(
        store.write(&key, &exact(Version::FIRST, b"b")),
        Outcome::Committed(second)
    );
    assert_eq!(
        store.read(&key),
        Ok(Some(Item {
            version: second,
            value: b"b".to_vec()
        }))
    );

    let other = Key::Shard(Shard::new(SHARD + 1).unwrap());
    let staging = state.join("shard-2.tmp");
    fs::create_dir(&staging).unwrap();
    assert_eq!(store.write(&other, &create(b"c")), Outcome::Unknown);
    fs::remove_dir(&staging).unwrap();
    assert!(!store.path(&other).exists());

    fs::write(&path, [0; 7]).unwrap();
    assert_eq!(store.read(&key), Err(Unavailable));
    assert_eq!(
        store.write(&key, &exact(second, b"c")),
        Outcome::NotCommitted(Refusal::Rejected)
    );
    assert_eq!(fs::read(&path).unwrap(), [0; 7]);
    remove(&state);
}

/// A state directory whose parent the group can write fails the owner lock's private-directory check, and the run
/// refuses before it creates the store directory.
#[test]
fn a_state_directory_under_a_shared_parent_refuses_before_the_store() {
    let parent = state("shared");
    let state = parent.join("state");
    DirBuilder::new().mode(0o700).create(&state).unwrap();
    let mut lock = lock(&state);
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o770)).unwrap();
    let error = session(&mut lock, "vol-0a").unwrap_err();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(error.contains("state directory"), "{error}");
    assert!(!state.join(STORE_DIR).exists());
    drop(lock);
    remove(&state);
    fs::remove_dir(&parent).unwrap();
}

/// A FIFO, a symbolic link or a file past the load limit in the watermark's place refuses the run, the FIFO
/// without blocking, and the shard record keeps its bytes.
#[test]
fn a_fifo_link_or_oversized_watermark_refuses() {
    let state = state("watermark");
    let mut lock = lock(&state);
    session(&mut lock, "vol-0a").unwrap();
    let watermark = state.join("soak-store/watermark");
    let shard = state.join("soak-store/shard-1");
    let held = (fs::read(&watermark).unwrap(), fs::read(&shard).unwrap());
    fs::remove_file(&watermark).unwrap();
    let fifo = std::ffi::CString::new(watermark.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: `fifo` is a NUL-terminated path that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(session(&mut lock, "vol-0a").is_err(), "a FIFO watermark");
    fs::remove_file(&watermark).unwrap();
    let elsewhere = state.join("elsewhere");
    fs::write(&elsewhere, &held.0).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &watermark).unwrap();
    assert!(session(&mut lock, "vol-0a").is_err(), "a linked watermark");
    fs::remove_file(&watermark).unwrap();
    let oversized = fs::File::create(&watermark).unwrap();
    oversized
        .set_len(crate::storage::store::LOAD_LIMIT + 1)
        .unwrap();
    oversized
        .set_permissions(fs::Permissions::from_mode(0o600))
        .unwrap();
    drop(oversized);
    assert!(
        session(&mut lock, "vol-0a").is_err(),
        "an oversized watermark"
    );
    assert_eq!(fs::read(&shard).unwrap(), held.1);
    Mappings::write_bytes(&watermark, &held.0).unwrap();
    assert_eq!(session(&mut lock, "vol-0a").unwrap().epoch().get(), 4);
    drop(lock);
    remove(&state);
}

/// A record of exactly the item limit loads from either slot, so a file of two full slots loads, and a slot naming
/// one byte more holds no item, so a file holding only that slot is unavailable.
#[test]
fn a_record_loads_up_to_the_item_limit() {
    let state = state("limit");
    let mut store = LocalStore {
        dir: state.clone(),
        owner: owner(),
    };
    let key = Key::Shard(Shard::new(SHARD).unwrap());
    let full = |version: Version| Item {
        version,
        value: vec![7; ITEM_LIMIT],
    };
    let second = Version::FIRST.next().unwrap();
    assert_eq!(
        store.write(&key, &Write::Create(vec![7; ITEM_LIMIT])),
        Outcome::Committed(Version::FIRST)
    );
    assert_eq!(store.read(&key), Ok(Some(full(Version::FIRST))));
    assert_eq!(
        store.write(
            &key,
            &Write::Exact {
                expect: Version::FIRST,
                value: vec![7; ITEM_LIMIT]
            }
        ),
        Outcome::Committed(second)
    );
    let path = store.path(&key);
    assert_eq!(
        fs::metadata(&path).unwrap().len(),
        SECOND + (SLOT_HEAD + ITEM_LIMIT) as u64
    );
    assert_eq!(store.read(&key), Ok(Some(full(second))));
    let past = Item {
        version: Version::FIRST,
        value: vec![7; ITEM_LIMIT + 1],
    };
    Mappings::write_bytes(&path, &slot(0, &past)).unwrap();
    assert_eq!(store.read(&key), Err(Unavailable));
    remove(&state);
}

/// An exact-version write overwrites the slot that does not hold the record, in the same file, so a slot the next
/// write tears or corrupts leaves the record the other slot holds: the file loads the record before that write, and
/// the next write commits over the damaged slot. A file whose slots hold no item is unavailable.
#[test]
fn an_overwrite_leaves_the_other_slot_intact() {
    let state = state("slots");
    let mut store = LocalStore {
        dir: state.clone(),
        owner: owner(),
    };
    let key = Key::Shard(Shard::new(SHARD).unwrap());
    let path = store.path(&key);
    let item = |version: u64, value: &[u8]| Item {
        version: Version::new(version).unwrap(),
        value: value.to_vec(),
    };
    let exact = |expect: u64, value: &[u8]| Write::Exact {
        expect: Version::new(expect).unwrap(),
        value: value.to_vec(),
    };
    assert_eq!(
        store.write(&key, &Write::Create(b"a".to_vec())),
        Outcome::Committed(Version::FIRST)
    );
    let inode = fs::metadata(&path).unwrap().ino();
    for (version, value) in [(2, b"b"), (3, b"c")] {
        assert_eq!(
            store.write(&key, &exact(version - 1, value)),
            Outcome::Committed(Version::new(version).unwrap())
        );
        assert_eq!(store.read(&key), Ok(Some(item(version, value))));
    }
    assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
    let bytes = fs::read(&path).unwrap();
    let second = SECOND as usize;
    assert_eq!(&bytes[..SLOT_HEAD + 1], slot(0, &item(3, b"c")));
    assert_eq!(&bytes[second..], slot(SECOND, &item(2, b"b")));

    let mut torn = bytes.clone();
    torn[SLOT_HEAD] ^= 1;
    fs::write(&path, &torn).unwrap();
    assert_eq!(store.read(&key), Ok(Some(item(2, b"b"))));
    assert_eq!(
        store.write(&key, &exact(2, b"d")),
        Outcome::Committed(Version::new(3).unwrap())
    );
    assert_eq!(store.read(&key), Ok(Some(item(3, b"d"))));

    let mut moved = fs::read(&path).unwrap();
    let first = moved[..SLOT_HEAD + 1].to_vec();
    moved[second..].copy_from_slice(&first);
    moved[..SLOT_HEAD + 1].fill(0);
    fs::write(&path, &moved).unwrap();
    assert_eq!(
        store.read(&key),
        Err(Unavailable),
        "a slot copied to the other offset fails its digest"
    );
    remove(&state);
}

/// An exact write at the last version refuses as rejected and leaves the record's bytes.
#[test]
fn an_exact_write_at_the_last_version_refuses() {
    let state = state("last-version");
    let mut store = LocalStore {
        dir: state.clone(),
        owner: owner(),
    };
    let key = Key::Shard(Shard::new(SHARD).unwrap());
    let last = Version::new(u64::MAX).unwrap();
    let bytes = slot(
        0,
        &Item {
            version: last,
            value: vec![1],
        },
    );
    Mappings::write_bytes(&store.path(&key), &bytes).unwrap();
    assert_eq!(
        store.write(
            &key,
            &Write::Exact {
                expect: last,
                value: vec![2]
            }
        ),
        Outcome::NotCommitted(Refusal::Rejected)
    );
    assert_eq!(fs::read(store.path(&key)).unwrap(), bytes);
    remove(&state);
}

/// A first run that stopped after seeding the empty watermark resumes: the next run creates shard 1 and takes the
/// first session.
#[test]
fn a_seeded_watermark_without_a_shard_record_resumes_the_first_run() {
    let state = state("seeded");
    let mut lock = lock(&state);
    let (dir, _) = store_dir(&lock).unwrap();
    FileLog::new(dir.join("watermark"))
        .unwrap()
        .record(&Watermark::default())
        .unwrap();
    let first = session(&mut lock, "vol-0a").unwrap();
    assert_eq!((first.generation().get(), first.epoch().get()), (1, 2));
    assert!(dir.join("shard-1").exists());
    drop(lock);
    remove(&state);
}

/// A watermark older than the shard record, as a run that stopped after its shard write and before its watermark
/// write leaves, admits the next run, whose session is above every earlier one.
#[test]
fn a_shard_record_ahead_of_its_watermark_keeps_sessions_rising() {
    let state = state("ahead");
    let mut lock = lock(&state);
    let watermark = state.join("soak-store/watermark");
    let first = session(&mut lock, "vol-0a").unwrap().get();
    let earlier = fs::read(&watermark).unwrap();
    let second = session(&mut lock, "vol-0a").unwrap().get();
    fs::write(&watermark, &earlier).unwrap();
    let third = session(&mut lock, "vol-0a").unwrap().get();
    assert!(first < second && second < third, "{first} {second} {third}");
    drop(lock);
    remove(&state);
}

/// The bounded reader admits a regular file of exactly its bound and refuses one byte more, a FIFO, a directory
/// and metadata its predicate refuses, each as `InvalidData`.
#[test]
fn the_bounded_reader_admits_regular_files_up_to_its_bound() {
    let state = state("reader");
    let file = state.join("file");
    Mappings::write_bytes(&file, &[1; 16]).unwrap();
    assert_eq!(Mappings::read_bytes(&file, 16, |_| true).unwrap(), [1; 16]);
    let refused = |path: &Path, bound, accept: bool| {
        Mappings::read_bytes(path, bound, |_| accept).map_err(|error| error.kind())
    };
    assert_eq!(refused(&file, 15, true), Err(io::ErrorKind::InvalidData));
    assert_eq!(refused(&file, 16, false), Err(io::ErrorKind::InvalidData));
    assert_eq!(refused(&state, 16, true), Err(io::ErrorKind::InvalidData));
    let fifo_path = state.join("fifo");
    let fifo = std::ffi::CString::new(fifo_path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: `fifo` is a NUL-terminated path that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert_eq!(
        refused(&fifo_path, 16, true),
        Err(io::ErrorKind::InvalidData)
    );
    remove(&state);
}
