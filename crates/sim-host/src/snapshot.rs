//! A root's snapshot: the three objects the runner stores under
//! `roots/<campaign>/` and the facts that decide its deletion. A snapshot
//! reads `confirm/confirmed` before `campaign findings`, so a confirmed
//! count that covers every suspect line was written before the listing was
//! read. The upload writes a local copy of each object before its put and
//! records the snapshot's digest in `receipt` only after all three puts
//! succeed; the receipt is removed before the first copy changes, so a
//! receipt always names the copies beside it.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};

use crate::capture::{self, Halt};
use crate::state::Root;
use crate::store::{Bucket, Error, LONG};
use crate::{build, file, host, state};

pub const STATUS: &str = "status.json";
pub const SUSPECTS: &str = "suspects.jsonl";
pub const FINDINGS: &str = "findings.json";
pub const OBJECTS: [&str; 3] = [STATUS, SUSPECTS, FINDINGS];
pub const LIST_BOUND: u64 = 1 << 30;
pub const OUTPUT_BOUND: u64 = 256 << 20;
const WAIT: Duration = Duration::from_secs(600);
const CHUNK: usize = 1 << 20;
const COUNT_BOUND: u64 = 64;
pub const NO_FINDINGS: &str = r#"{"findings":[],"release_blockers":[]}"#;

pub fn key(campaign: &str, name: &str) -> String {
    format!("roots/{campaign}/{name}")
}

pub fn uploads(state: &Path) -> PathBuf {
    state.join("uploads")
}

fn receipt_path(state: &Path, campaign: &str) -> PathBuf {
    uploads(state).join(campaign).join("receipt")
}

fn list_path(state: &Path, campaign: &str) -> PathBuf {
    state::roots(state).join(campaign).join(SUSPECTS)
}

/// The part of `suspects.jsonl` that ends with its last complete line.
#[derive(Clone, Debug, PartialEq)]
pub struct Suspects {
    pub length: u64,
    pub lines: u64,
    pub sha256: String,
}

#[derive(Clone, Debug)]
pub struct Observation {
    pub root: Root,
    pub sweep_status: Value,
    pub list_length: u64,
    /// The root's [`Stamp`], taken before `sweep-status` ran.
    pub stamp: Stamp,
}

/// The entries of a root directory that a deletion decision reads.
const STAMPED: [&str; 5] = [
    "sweep.json",
    SUSPECTS,
    "confirm",
    "confirm/confirmed",
    "confirm/state",
];

/// The most directories below `confirm/state` a [`Stamp`] records.
const STAMPED_DIRS: usize = crate::lenient::ELEMENTS;

/// The metadata of what a deletion decision reads in a root: each entry in
/// [`STAMPED`] and every directory below `confirm/state`, each keyed by
/// device, inode, length and modification and status-change times, or
/// `None` for an absent entry. A store pass takes it before it reads a
/// root, and the runner takes it again under the root's lock and the lock
/// of `confirm/state` before it marks the root deleting. A sweep, a
/// confirm or a `campaign` command that created, replaced or renamed one of
/// these entries, or created, removed or renamed an entry of a directory
/// below `confirm/state`, changes the stamp, so the root stays. A file
/// below `confirm/state` rewritten in place leaves the stamp equal.
/// Metadata equality does not prove equal bytes.
///
/// A stamp whose walk met an unreadable entry or more than
/// [`STAMPED_DIRS`] directories is incomplete and equals no stamp.
#[derive(Clone, Debug)]
pub struct Stamp {
    entries: Vec<(PathBuf, Option<build::Stamp>)>,
    complete: bool,
}

impl PartialEq for Stamp {
    fn eq(&self, other: &Self) -> bool {
        self.complete && other.complete && self.entries == other.entries
    }
}

pub fn stamp(dir: &Path) -> Stamp {
    let read = |path: &Path| match std::fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    };
    let mut entries = Vec::new();
    let mut complete = true;
    for name in STAMPED {
        match read(&dir.join(name)) {
            Ok(meta) => entries.push((PathBuf::from(name), meta.as_ref().map(build::stamp))),
            Err(_) => complete = false,
        }
    }
    let state = dir.join("confirm/state");
    let mut pending = vec![state.clone()];
    let mut dirs = 0;
    while let Some(next) = pending.pop() {
        let listed = match std::fs::read_dir(&next) {
            Ok(listed) => listed,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && next == state => break,
            Err(_) => {
                complete = false;
                break;
            }
        };
        let mut children = Vec::new();
        for entry in listed {
            let Ok(entry) = entry else {
                complete = false;
                break;
            };
            let path = entry.path();
            match read(&path) {
                Ok(Some(meta)) if meta.file_type().is_dir() => {
                    children.push((path, build::stamp(&meta)));
                }
                Ok(_) => {}
                Err(_) => complete = false,
            }
        }
        children.sort();
        dirs += children.len();
        if dirs > STAMPED_DIRS {
            complete = false;
            break;
        }
        for (path, meta) in children {
            let relative = path.strip_prefix(dir).unwrap_or(&path).to_owned();
            entries.push((relative, Some(meta)));
            pending.push(path);
        }
    }
    Stamp { entries, complete }
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub campaign: String,
    pub inner: String,
    pub status: Vec<u8>,
    pub suspects: Suspects,
    pub findings: Vec<u8>,
    pub confirmed: u64,
    pub resolved: bool,
}

/// The error a local scan returns when its [`Halt`] fires between two
/// chunks. A blocked read call runs to its end before the check.
fn halted() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Interrupted,
        "the scan stopped when its time ran out or a stop was requested",
    )
}

fn hash_prefix(
    list: &Path,
    length: u64,
    mut copy: Option<&mut File>,
    halt: Halt,
) -> std::io::Result<(String, u64)> {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    let mut lines = 0;
    if length > 0 {
        let file = file::open_plain(list)?
            .ok_or_else(|| std::io::Error::other(format!("{} vanished", list.display())))?;
        let mut file = file.take(length);
        let mut chunk = vec![0u8; CHUNK];
        let mut total = 0;
        loop {
            if halt.halted() {
                return Err(halted());
            }
            let read = file.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            hasher.update(&chunk[..read]);
            lines += chunk[..read].iter().filter(|byte| **byte == b'\n').count() as u64;
            if let Some(copy) = copy.as_deref_mut() {
                copy.write_all(&chunk[..read])?;
            }
            total += read as u64;
        }
        if total != length {
            return Err(std::io::Error::other(format!(
                "{} is shorter than {length} bytes",
                list.display()
            )));
        }
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok((file::hex(&digest), lines))
}

fn complete_end(list: &Path, length: u64, halt: Halt) -> std::io::Result<u64> {
    let Some(mut file) = file::open_plain(list)? else {
        return if length == 0 {
            Ok(0)
        } else {
            Err(std::io::Error::other(format!(
                "{} vanished",
                list.display()
            )))
        };
    };
    let mut chunk = vec![0u8; 64 << 10];
    let mut end = length;
    while end > 0 {
        if halt.halted() {
            return Err(halted());
        }
        let start = end.saturating_sub(chunk.len() as u64);
        let want = usize::try_from(end - start).unwrap_or(chunk.len());
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut chunk[..want])?;
        if let Some(at) = chunk[..want].iter().rposition(|byte| *byte == b'\n') {
            return Ok(start + at as u64 + 1);
        }
        end = start;
    }
    Ok(0)
}

/// Reads the prefix of `list` through its last complete line within its
/// first `length` bytes, refused when that prefix is longer than
/// [`LIST_BOUND`], the bound the report reads a stored list with.
pub fn suspects(list: &Path, length: u64, halt: Halt) -> Result<Suspects, String> {
    let shown = |error: std::io::Error| format!("{}: {error}", list.display());
    let end = complete_end(list, length, halt).map_err(shown)?;
    if end > LIST_BOUND {
        return Err(format!(
            "{} holds {end} bytes of complete lines, past the stored list's bound of {LIST_BOUND}",
            list.display()
        ));
    }
    let (sha256, lines) = hash_prefix(list, end, None, halt).map_err(shown)?;
    Ok(Suspects {
        length: end,
        lines,
        sha256,
    })
}

/// The count in `confirm/confirmed`, 0 when the file is absent.
pub fn confirmed(root: &Path) -> Result<u64, String> {
    let path = root.join("confirm/confirmed");
    let bytes = file::open_plain(&path)
        .and_then(|opened| {
            opened
                .map(|file| {
                    let mut bytes = Vec::new();
                    file.take(COUNT_BOUND + 1)
                        .read_to_end(&mut bytes)
                        .map(|_| bytes)
                })
                .transpose()
        })
        .map_err(|error| format!("{}: {error}", path.display()))?;
    match bytes {
        None => Ok(0),
        Some(bytes) if bytes.len() as u64 > COUNT_BOUND => Err(format!(
            "{} holds more than {COUNT_BOUND} bytes",
            path.display()
        )),
        Some(bytes) => String::from_utf8_lossy(&bytes)
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("{} holds no count", path.display())),
    }
}

/// Whether a `campaign findings` listing shows every finding resolved and
/// no release blocker. A listing without both arrays is unresolved.
pub fn resolved(listing: &Value) -> bool {
    let rows = listing["findings"].as_array();
    let blockers = listing["release_blockers"].as_array();
    match (rows, blockers) {
        (Some(rows), Some(blockers)) => {
            blockers.is_empty()
                && rows
                    .iter()
                    .all(|row| row["resolved"].as_bool() == Some(true))
        }
        _ => false,
    }
}

fn report(program: &Path, args: &[&str], halt: Halt) -> Result<(Vec<u8>, Value), String> {
    let mut command = Command::new(program);
    command.args(args);
    let name = format!("campaign {}", args[0]);
    let output = capture::run(&name, &mut command, WAIT, OUTPUT_BOUND, halt)?;
    if !output.success() {
        return Err(format!(
            "{name} exited {}: {}",
            output.code,
            output.reason()
        ));
    }
    match serde_json::from_slice::<Value>(&output.stdout) {
        Ok(value) if value.is_object() => Ok((output.stdout, value)),
        _ => Err(format!("{name} printed no JSON object")),
    }
}

pub fn observe(state: &Path, root: &Root, halt: Halt) -> Result<Observation, String> {
    build::verify_recorded(state, &root.build)?;
    let dir = state::roots(state).join(root.campaign());
    let stamp = stamp(&dir);
    let program = build::campaign(state, &root.build);
    let (_, sweep_status) = report(
        &program,
        &["sweep-status", "--root", &dir.to_string_lossy()],
        halt,
    )?;
    let list = dir.join(SUSPECTS);
    let list_length = file::open_plain(&list)
        .and_then(|opened| {
            opened
                .map(|file| file.metadata().map(|meta| meta.len()))
                .transpose()
        })
        .map_err(|error| format!("{}: {error}", list.display()))?
        .unwrap_or(0);
    Ok(Observation {
        root: root.clone(),
        sweep_status,
        list_length,
        stamp,
    })
}

pub fn take(
    state: &Path,
    instance: &str,
    observed: &Observation,
    stint_seconds: Option<u64>,
    halt: Halt,
) -> Result<Snapshot, String> {
    let root = &observed.root;
    build::verify_recorded(state, &root.build)?;
    let campaign = root.campaign();
    let dir = state::roots(state).join(&campaign);
    let program = build::campaign(state, &root.build);
    let confirmed = confirmed(&dir)?;
    let list = dir.join(SUSPECTS);
    let suspects = suspects(&list, observed.list_length, halt)?;
    if confirmed > suspects.lines {
        return Err(format!(
            "confirm counts {confirmed} lines and {} holds {}",
            list.display(),
            suspects.lines
        ));
    }
    let confirm = dir.join("confirm/state");
    let (findings, listing) = match std::fs::symlink_metadata(&confirm) {
        Ok(meta) if meta.file_type().is_dir() => report(
            &program,
            &["findings", "--state", &confirm.to_string_lossy()],
            halt,
        )?,
        Ok(_) => return Err(format!("{} is not a directory", confirm.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && confirmed == 0 => (
            NO_FINDINGS.as_bytes().to_vec(),
            json!({"findings": [], "release_blockers": []}),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "{} is missing and confirm counts {confirmed} lines",
                confirm.display()
            ));
        }
        Err(error) => return Err(format!("{}: {error}", confirm.display())),
    };
    let sweep_status = &observed.sweep_status;
    let measured = format!(
        "{} {} {} {stint_seconds:?}",
        root.stints, root.cpu_usec, root.capacity_usec
    );
    let inner = file::sha256(
        [
            file::sha256(sweep_status.to_string().as_bytes()),
            suspects.sha256.clone(),
            file::sha256(&findings),
            file::sha256(measured.as_bytes()),
        ]
        .concat()
        .as_bytes(),
    );
    let envelope = json!({
        "format": 1,
        "build": root.build,
        "host": instance,
        "campaign": campaign,
        "stint": root.stints,
        "stint_seconds": stint_seconds,
        "written": host::now_s(),
        "cpu_usec": root.cpu_usec,
        "capacity_usec": root.capacity_usec,
        "sweep_status": sweep_status,
    });
    let status = serde_json::to_vec_pretty(&envelope).map_err(|error| error.to_string())?;
    if status.len() as u64 > OUTPUT_BOUND {
        return Err(format!(
            "status.json would hold {} bytes, past its bound of {OUTPUT_BOUND}",
            status.len()
        ));
    }
    Ok(Snapshot {
        campaign,
        inner,
        status,
        suspects,
        findings,
        confirmed,
        resolved: resolved(&listing),
    })
}

/// The snapshot digest of the copies under `uploads/<campaign>/`, or
/// `None` when no upload of them completed.
pub fn receipt(state: &Path, campaign: &str) -> Option<String> {
    file::read(&receipt_path(state, campaign), 64)
        .ok()
        .flatten()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

fn extends(copy: &Path, list: &Path, length: u64, halt: Halt) -> Result<bool, String> {
    let shown = |path: &Path, error: std::io::Error| format!("{}: {error}", path.display());
    let Some(copy_file) = file::open_plain(copy).map_err(|error| shown(copy, error))? else {
        return Ok(true);
    };
    let copied = copy_file
        .metadata()
        .map_err(|error| shown(copy, error))?
        .len();
    if copied > length {
        return Ok(false);
    }
    let Some(list_file) = file::open_plain(list).map_err(|error| shown(list, error))? else {
        return Ok(copied == 0);
    };
    let mut ours = copy_file.take(copied);
    let mut theirs = list_file.take(copied);
    let mut left = vec![0u8; 64 << 10];
    let mut right = vec![0u8; 64 << 10];
    loop {
        if halt.halted() {
            return Err(shown(copy, halted()));
        }
        let read = ours.read(&mut left).map_err(|error| shown(copy, error))?;
        if read == 0 {
            return Ok(true);
        }
        theirs
            .read_exact(&mut right[..read])
            .map_err(|error| shown(list, error))?;
        if left[..read] != right[..read] {
            return Ok(false);
        }
    }
}

/// Stores `snapshot`: the suspect list, then the findings, then the
/// status that summarizes both, each from a local copy.
///
/// # Errors
///
/// A failed local write or put. A failure before or during the receipt's
/// removal, such as a list that no longer extends its stored copy, leaves
/// the receipt as it was. A failure after its removal and before the new
/// receipt's rename leaves it absent, so the next pass uploads all three
/// objects again. A failed sync of the directory after that rename leaves
/// the new receipt, which names the copies beside it.
pub fn upload(bucket: &Bucket, state: &Path, snapshot: &Snapshot) -> Result<(), String> {
    let campaign = &snapshot.campaign;
    let local = uploads(state).join(campaign);
    file::private_dir(&local).map_err(|error| format!("{}: {error}", local.display()))?;
    let list = list_path(state, campaign);
    if !extends(
        &local.join(SUSPECTS),
        &list,
        snapshot.suspects.length,
        bucket.halt,
    )? {
        return Err(format!(
            "{} no longer starts with the list stored for {campaign}",
            list.display()
        ));
    }
    let receipt = receipt_path(state, campaign);
    file::remove_file(&receipt).map_err(|error| format!("{}: {error}", receipt.display()))?;
    File::open(&local)
        .and_then(|dir| dir.sync_all())
        .map_err(|error| format!("{}: {error}", local.display()))?;
    let staged = local.join(format!(".{SUSPECTS}.staged"));
    let mut copy =
        file::create_fresh(&staged).map_err(|error| format!("{}: {error}", staged.display()))?;
    let (copied, _) = hash_prefix(
        &list,
        snapshot.suspects.length,
        Some(&mut copy),
        bucket.halt,
    )
    .and_then(|copied| copy.sync_all().map(|()| copied))
    .map_err(|error| format!("{}: {error}", list.display()))?;
    drop(copy);
    if copied != snapshot.suspects.sha256 {
        return Err(format!("{} changed under the upload", list.display()));
    }
    std::fs::rename(&staged, local.join(SUSPECTS))
        .and_then(|()| File::open(&local)?.sync_all())
        .map_err(|error| format!("{}: {error}", local.display()))?;
    let put = |name: &str, wait: Duration| -> Result<(), String> {
        bucket
            .replace(&key(campaign, name), &local.join(name), wait)
            .map_err(|error| format!("{}: {error}", key(campaign, name)))
    };
    put(SUSPECTS, LONG)?;
    for (name, bytes) in [(FINDINGS, &snapshot.findings), (STATUS, &snapshot.status)] {
        let path = local.join(name);
        file::replace(&path, bytes).map_err(|error| format!("{}: {error}", path.display()))?;
        put(name, crate::store::SHORT)?;
    }
    file::replace(&receipt, snapshot.inner.as_bytes())
        .map_err(|error| format!("{}: {error}", receipt.display()))
}

/// Whether each of the three stored objects has the SHA-256 of its local
/// copy. `Ok(false)` for a missing or differing object or copy.
///
/// # Errors
///
/// A local read or a header request that failed, so the answer is
/// unknown.
pub fn in_store(bucket: &Bucket, state: &Path, campaign: &str) -> Result<bool, String> {
    for name in OBJECTS {
        let path = uploads(state).join(campaign).join(name);
        let local = file::open_plain(&path)
            .and_then(|opened| {
                opened
                    .map(|file| file.metadata().map(|meta| meta.len()))
                    .transpose()
            })
            .and_then(|length| {
                length
                    .map(|length| hash_prefix(&path, length, None, bucket.halt))
                    .transpose()
            })
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let Some((local, _)) = local else {
            return Ok(false);
        };
        let key = key(campaign, name);
        match bucket.sha256(&key) {
            Ok(stored) if stored == local => {}
            Ok(_) | Err(Error::Missing) => return Ok(false),
            Err(error) => return Err(format!("{key}: {error}")),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::capture::Halt;

    use crate::file::scratch;

    #[test]
    fn only_a_listing_with_every_row_resolved_and_no_blocker_is_resolved() {
        assert!(super::resolved(
            &json!({"findings": [], "release_blockers": []})
        ));
        assert!(super::resolved(
            &json!({"findings": [{"id": "a", "resolved": true}], "release_blockers": []})
        ));
        for listing in [
            json!({"findings": [{"id": "a", "resolved": false}], "release_blockers": []}),
            json!({"findings": [{"id": "a", "triage": {"held": "x"}}], "release_blockers": []}),
            json!({"findings": [{"id": "a", "resolved": true}, {"id": "b"}],
                   "release_blockers": []}),
            json!({"findings": [], "release_blockers": ["a"]}),
            json!({"findings": []}),
            json!({"release_blockers": []}),
            json!({"error": "campaign findings exited 4"}),
            json!({"findings": {}, "release_blockers": []}),
        ] {
            assert!(!super::resolved(&listing), "{listing}");
        }
    }

    #[test]
    fn the_suspect_prefix_ends_at_the_last_complete_line_of_the_observed_length() {
        let dir = scratch("prefix");
        let list = dir.join("suspects.jsonl");
        let absent = super::suspects(&list, 0, Halt::OnStop).expect("an absent list");
        assert_eq!((absent.length, absent.lines), (0, 0));
        assert_eq!(absent.sha256, crate::file::sha256(b""));
        std::fs::write(&list, "a\nbb\ntorn").expect("a list with a torn tail");
        let prefix = super::suspects(&list, 9, Halt::OnStop).expect("a list");
        assert_eq!((prefix.length, prefix.lines), (5, 2));
        assert_eq!(prefix.sha256, crate::file::sha256(b"a\nbb\n"));
        let observed = super::suspects(&list, 4, Halt::OnStop).expect("an earlier observation");
        assert_eq!((observed.length, observed.lines), (2, 1));
        let copy = dir.join("copy");
        let mut out = std::fs::File::create(&copy).expect("a copy");
        let (copied, lines) =
            super::hash_prefix(&list, prefix.length, Some(&mut out), Halt::OnStop).expect("a copy");
        assert_eq!((copied, lines), (prefix.sha256.clone(), 2));
        assert_eq!(std::fs::read(&copy).expect("the copy"), b"a\nbb\n");
        assert!(super::extends(&copy, &list, 5, Halt::OnStop).expect("a comparison"));
        assert!(!super::extends(&copy, &list, 2, Halt::OnStop).expect("a shorter list"));
        let expired = Halt::At(std::time::Instant::now());
        let refused = super::suspects(&list, 5, expired).expect_err("an expired scan");
        assert!(refused.contains("time ran out"), "{refused}");
        assert!(super::extends(&copy, &list, 5, expired).is_err());
        std::fs::write(&list, "a\nXX\n").expect("a rewritten list");
        assert!(!super::extends(&copy, &list, 5, Halt::OnStop).expect("a changed list"));
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn an_expired_halt_stops_the_prefix_hash_and_its_copy() {
        let dir = scratch("hash-halt");
        let list = dir.join("suspects.jsonl");
        std::fs::write(&list, "a\n").expect("a list");
        let copy = dir.join("copy");
        let mut out = std::fs::File::create(&copy).expect("a copy");
        let expired = Halt::At(std::time::Instant::now());
        let error =
            super::hash_prefix(&list, 2, Some(&mut out), expired).expect_err("an expired hash");
        assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
        assert_eq!(
            std::fs::read(&copy).expect("the copy"),
            b"",
            "nothing is copied"
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn complete_lines_past_the_stored_lists_bound_are_refused() {
        let dir = scratch("list-bound");
        let list = dir.join("suspects.jsonl");
        let file = std::fs::File::create(&list).expect("a list");
        // A sparse list whose last byte is a newline ends its complete
        // lines at its length, so the search reads one chunk.
        for (length, accepted) in [(super::LIST_BOUND, true), (super::LIST_BOUND + 1, false)] {
            file.set_len(length - 1).expect("a sparse list");
            std::io::Write::write_all(
                &mut std::fs::OpenOptions::new()
                    .append(true)
                    .open(&list)
                    .expect("the list"),
                b"\n",
            )
            .expect("its newline");
            // `suspects` hashes the list after its bound check, so a list at
            // the bound returns its hash, or the halt's error after 2 seconds.
            let halt = Halt::At(std::time::Instant::now() + std::time::Duration::from_secs(2));
            match super::suspects(&list, length, halt) {
                Ok(suspects) if accepted => {
                    assert_eq!((suspects.length, suspects.lines), (length, 1));
                }
                Err(error) if accepted => assert!(error.contains("time ran out"), "{error}"),
                Err(error) => {
                    assert!(error.contains("past the stored list's bound"), "{error}");
                }
                other => panic!("{length}: {other:?}"),
            }
        }
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_directory_at_the_receipt_fails_the_upload_before_any_put() {
        let state = scratch("receipt-dir");
        let campaign = "sim.i-0123abcd.00".to_owned();
        let receipt = super::receipt_path(&state, &campaign);
        std::fs::create_dir_all(&receipt).expect("a directory at the receipt");
        std::fs::write(receipt.join("sentinel"), b"x").expect("a sentinel");
        std::fs::create_dir_all(crate::state::roots(&state).join(&campaign))
            .expect("the root directory");
        let snapshot = super::Snapshot {
            campaign: campaign.clone(),
            inner: "0".repeat(64),
            status: Vec::new(),
            suspects: super::Suspects {
                length: 0,
                lines: 0,
                sha256: crate::file::sha256(b""),
            },
            findings: Vec::new(),
            confirmed: 0,
            resolved: true,
        };
        // A bucket whose deadline has passed fails any put it is asked for.
        let bucket =
            crate::store::Bucket::new("bucket").halted_by(Halt::At(std::time::Instant::now()));
        let error = super::upload(&bucket, &state, &snapshot).expect_err("the receipt is refused");
        assert!(error.contains(&receipt.display().to_string()), "{error}");
        assert_eq!(
            std::fs::read(receipt.join("sentinel")).expect("the sentinel"),
            b"x"
        );
        std::fs::remove_dir_all(&state).expect("cleanup");
    }

    #[test]
    fn a_linked_list_or_count_is_refused_and_a_count_parses() {
        let dir = scratch("linked");
        let sentinel = dir.join("sentinel");
        std::fs::write(&sentinel, "a\nb\n").expect("a sentinel");
        let list = dir.join("suspects.jsonl");
        std::os::unix::fs::symlink(&sentinel, &list).expect("a link");
        assert!(
            super::suspects(&list, 4, Halt::OnStop).is_err(),
            "a linked list"
        );
        std::fs::remove_file(&list).expect("the link");
        std::os::unix::fs::symlink(dir.join("absent"), &list).expect("a dangling link");
        assert!(
            super::suspects(&list, 4, Halt::OnStop).is_err(),
            "a dangling link"
        );
        let root = dir.join("root");
        std::fs::create_dir_all(root.join("confirm")).expect("a confirm directory");
        assert_eq!(super::confirmed(&root), Ok(0));
        std::fs::write(root.join("confirm/confirmed"), "7\n").expect("a count");
        assert_eq!(super::confirmed(&root), Ok(7));
        std::fs::write(root.join("confirm/confirmed"), "x").expect("a damaged count");
        assert!(super::confirmed(&root).is_err());
        let padded = |spaces: usize| format!("7{}", " ".repeat(spaces));
        std::fs::write(root.join("confirm/confirmed"), padded(63)).expect("a 64-byte count");
        assert_eq!(super::confirmed(&root), Ok(7));
        std::fs::write(root.join("confirm/confirmed"), padded(64) + "junk")
            .expect("a count past 64 bytes");
        assert!(super::confirmed(&root).is_err(), "a count past 64 bytes");
        std::fs::remove_file(root.join("confirm/confirmed")).expect("the count");
        std::os::unix::fs::symlink(&sentinel, root.join("confirm/confirmed")).expect("a link");
        assert!(super::confirmed(&root).is_err(), "a linked count");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
