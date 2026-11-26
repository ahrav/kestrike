//! Builds on disk: `builds/<build>/` holds one fetched archive, the
//! `campaign` binary of the same commit and the commit record that names
//! both. A build reaches its final path only through [`fetch`], which
//! checks every member of the download in a staging directory, runs the
//! archive's capabilities with the downloaded binary, syncs the tree and
//! then renames it into place, so a failed check publishes nothing at the
//! final path. A build already in place is admitted by the digests of its
//! build record and its binary; the sweep's own archive verification
//! checks its other members before each use.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::capture::{self, Halt};
use crate::file;
use crate::store::{Bucket, Head, LONG};

/// The largest `campaign` binary a build holds.
pub const BINARY_BOUND: u64 = 4 << 30;
/// The largest `archive.tar` a fetch downloads and the publisher stores:
/// the largest body of one put.
pub const ARCHIVE_BOUND: u64 = crate::store::PUT_BOUND;
const ENTRIES_MAX: usize = 100_000;
const DEPTH_MAX: usize = 16;
const PROBE_WAIT: Duration = Duration::from_secs(600);

/// A commit record: the build `commit` produced and the SHA-256 of its
/// `campaign` binary.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    pub format: u32,
    /// The commit id, 40 or 64 lowercase hexadecimal digits.
    pub commit: String,
    /// The SHA-256 of the archive's `build` record.
    pub build: String,
    /// The SHA-256 of the `campaign` binary.
    pub campaign: String,
}

/// Whether `text` is a commit id: 40 or 64 lowercase hexadecimal digits.
pub fn is_commit(text: &str) -> bool {
    file::is_hex(text, 40) || file::is_hex(text, 64)
}

impl Commit {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let commit: Self =
            serde_json::from_slice(bytes).map_err(|error| format!("a commit record: {error}"))?;
        commit.validate()?;
        Ok(commit)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.format != 1 {
            return Err(format!("commit record format {} is not 1", self.format));
        }
        if !is_commit(&self.commit) {
            return Err(format!("{:?} is no commit id", self.commit));
        }
        if !file::is_sha256(&self.build) || !file::is_sha256(&self.campaign) {
            return Err("a commit record's build or campaign is no SHA-256".into());
        }
        Ok(())
    }
}

pub fn builds(state: &Path) -> PathBuf {
    state.join("builds")
}

pub fn dir(state: &Path, build: &str) -> PathBuf {
    builds(state).join(build)
}

pub fn archive(state: &Path, build: &str) -> PathBuf {
    dir(state, build).join("archive")
}

pub fn campaign(state: &Path, build: &str) -> PathBuf {
    dir(state, build).join("campaign")
}

pub fn record(state: &Path, build: &str) -> PathBuf {
    dir(state, build).join("record.json")
}

pub fn key(build: &str, name: &str) -> String {
    format!("builds/{build}/{name}")
}

/// The digest of a file, keyed by the metadata a change to its bytes
/// changes: device, inode, length, and modification and status-change
/// times. A status change cannot be set by its owner, so a rewrite of a
/// binary is hashed again.
pub(crate) type Stamp = (u64, u64, u64, i64, i64, i64, i64);

static DIGESTS: Mutex<BTreeMap<PathBuf, (Stamp, String)>> = Mutex::new(BTreeMap::new());

pub(crate) fn stamp(meta: &fs::Metadata) -> Stamp {
    (
        meta.dev(),
        meta.ino(),
        meta.len(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec(),
    )
}

/// The SHA-256 of the regular file at `path`, at most `bound` bytes long.
/// A file whose metadata is unchanged since its last digest is not read
/// again.
fn digest(path: &Path, bound: u64) -> Result<String, String> {
    let shown = || path.display().to_string();
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!("{} is missing", shown()));
        }
        Err(error) => return Err(format!("{}: {error}", shown())),
    };
    if !meta.file_type().is_file() {
        return Err(format!("{} is not a regular file", shown()));
    }
    if meta.len() > bound {
        return Err(format!("{} holds more than {bound} bytes", shown()));
    }
    let stamp = stamp(&meta);
    let cached = DIGESTS
        .lock()
        .ok()
        .and_then(|digests| digests.get(path).cloned());
    if let Some((seen, digest)) = cached
        && seen == stamp
    {
        return Ok(digest);
    }
    let digest = file::sha256_file(path)
        .map_err(|error| format!("{}: {error}", shown()))?
        .ok_or_else(|| format!("{} is missing", shown()))?;
    let after = fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", shown()))?;
    if self::stamp(&after) == stamp
        && let Ok(mut digests) = DIGESTS.lock()
    {
        digests.insert(path.to_owned(), (stamp, digest.clone()));
    }
    Ok(digest)
}

fn check(dir: &Path, build: &str, campaign: &str) -> Result<(), String> {
    if digest(&dir.join("archive/build"), 1 << 20)? != build {
        return Err(format!(
            "the archive in {} is not build {build}",
            dir.display()
        ));
    }
    if digest(&dir.join("campaign"), BINARY_BOUND)? != campaign {
        return Err(format!(
            "the campaign binary in {} differs from its recorded SHA-256 {campaign}",
            dir.display()
        ));
    }
    Ok(())
}

/// Checks that `builds/<build>` holds build `build` and the binary whose
/// SHA-256 is `campaign`.
pub fn verify(state: &Path, build: &str, campaign: &str) -> Result<(), String> {
    check(&dir(state, build), build, campaign)
}

/// Checks `builds/<build>` against its own commit record and returns the
/// record. A root names only its build, so this is the check before a
/// root's binary runs.
pub fn verify_recorded(state: &Path, build: &str) -> Result<Commit, String> {
    let path = record(state, build);
    let bytes = file::read(&path, 1 << 20)
        .map_err(|error| format!("{}: {error}", path.display()))?
        .ok_or_else(|| {
            format!(
                "build {build} is not on disk: {} is missing",
                path.display()
            )
        })?;
    let commit = Commit::parse(&bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    if commit.build != build {
        return Err(format!(
            "{} names build {}, not {build}",
            path.display(),
            commit.build
        ));
    }
    verify(state, build, &commit.campaign)?;
    Ok(commit)
}

fn tar(args: &[&str], halt: Halt) -> Result<(), String> {
    let mut command = Command::new("tar");
    command.args(args);
    let output = capture::run("tar", &mut command, LONG, 1 << 20, halt)?;
    if output.success() {
        Ok(())
    } else {
        Err(format!(
            "tar {} exited {}: {}",
            args.join(" "),
            output.code,
            output.reason()
        ))
    }
}

/// Writes the tree `parent/name` to the uncompressed GNU-format tar
/// `output`.
pub fn pack(parent: &Path, name: &str, output: &Path, halt: Halt) -> Result<(), String> {
    tar(
        &[
            "--format=gnu",
            "-cf",
            &output.to_string_lossy(),
            "-C",
            &parent.to_string_lossy(),
            name,
        ],
        halt,
    )
}

/// Unpacks the tar `input` into `into`, giving every member to this user.
pub fn unpack(input: &Path, into: &Path, halt: Halt) -> Result<(), String> {
    tar(
        &[
            "--no-same-owner",
            "-xf",
            &input.to_string_lossy(),
            "-C",
            &into.to_string_lossy(),
        ],
        halt,
    )
}

/// Refuses an unpacked tree unless `into` holds exactly one directory,
/// `archive`, whose entries are directories and regular files only, within
/// the entry and depth bounds.
fn confine(into: &Path) -> Result<(), String> {
    let top: Vec<_> = fs::read_dir(into)
        .and_then(|entries| entries.collect::<Result<Vec<_>, _>>())
        .map_err(|error| format!("{}: {error}", into.display()))?;
    let only_archive = top.len() == 1
        && top[0].file_name() == "archive"
        && top[0].file_type().is_ok_and(|kind| kind.is_dir());
    if !only_archive {
        return Err("the archive tar holds more than the directory archive".into());
    }
    let mut pending = vec![(into.join("archive"), 0)];
    let mut entries = 0;
    while let Some((dir, depth)) = pending.pop() {
        for entry in fs::read_dir(&dir).map_err(|error| format!("{}: {error}", dir.display()))? {
            let entry = entry.map_err(|error| format!("{}: {error}", dir.display()))?;
            entries += 1;
            if entries > ENTRIES_MAX {
                return Err(format!("the archive holds more than {ENTRIES_MAX} entries"));
            }
            let kind = entry
                .file_type()
                .map_err(|error| format!("{}: {error}", entry.path().display()))?;
            if kind.is_dir() {
                if depth + 1 > DEPTH_MAX {
                    return Err(format!("the archive nests deeper than {DEPTH_MAX}"));
                }
                pending.push((entry.path(), depth + 1));
            } else if !kind.is_file() {
                return Err(format!(
                    "the archive member {} is not a directory or a regular file",
                    entry.path().display()
                ));
            }
        }
    }
    Ok(())
}

fn probe(staging: &Path, halt: Halt) -> Result<(), String> {
    let artifacts = staging.join("probe");
    file::private_dir(&artifacts).map_err(|error| format!("{}: {error}", artifacts.display()))?;
    let mut command = Command::new(staging.join("campaign"));
    command.args([
        "sim".as_ref(),
        "capabilities".as_ref(),
        "--archive".as_ref(),
        staging.join("archive").as_os_str(),
        "--artifacts".as_ref(),
        artifacts.as_os_str(),
    ]);
    let output = capture::run(
        "campaign sim capabilities",
        &mut command,
        PROBE_WAIT,
        16 << 20,
        halt,
    );
    let _ = file::remove_entry(&artifacts);
    let output = output?;
    if output.success() {
        Ok(())
    } else {
        Err(format!(
            "campaign sim capabilities refused the archive, exit {}: {}",
            output.code,
            output.reason()
        ))
    }
}

fn need(bucket: &Bucket, state: &Path, build: &str, reserve: u64) -> Result<(Head, Head), String> {
    let head = |name: &str, bound: u64| -> Result<Head, String> {
        let key = key(build, name);
        let head = bucket
            .head(&key)
            .map_err(|error| format!("{key}: {error}"))?;
        if head.length > bound {
            return Err(format!("{key} holds {} bytes, past {bound}", head.length));
        }
        Ok(head)
    };
    let archive = head("archive.tar", ARCHIVE_BOUND)?;
    let binary = head("campaign", BINARY_BOUND)?;
    room(
        state,
        build,
        peak_bytes(archive.length, binary.length),
        0,
        reserve,
    )?;
    Ok((archive, binary))
}

/// Estimates a fetch's peak bytes: the tar, the binary, and the unpacked
/// members counted at the tar's length.
fn peak_bytes(archive: u64, binary: u64) -> u64 {
    archive.saturating_mul(2).saturating_add(binary)
}

fn room(state: &Path, build: &str, bytes: u64, inodes: u64, reserve: u64) -> Result<(), String> {
    let builds = builds(state);
    let (free, free_inodes) =
        file::free_space(&builds).map_err(|error| format!("{}: {error}", builds.display()))?;
    if free.saturating_sub(reserve) < bytes || free_inodes < inodes.saturating_add(64) {
        return Err(format!(
            "build {build} needs {bytes} bytes and {inodes} inodes, and {free} bytes and \
             {free_inodes} inodes are free under {}, with a reserve of {reserve} bytes",
            builds.display()
        ));
    }
    Ok(())
}

const BLOCK: u64 = 4096;
const NAME_MAX: u64 = 4096;
const DIR_BYTES_MAX: usize = 8 << 20;

/// Parses a tar header's numeric field: octal digits after any leading
/// spaces, followed only by NULs and spaces. Any other field is `None`.
fn octal(field: &[u8]) -> Option<u64> {
    let start = field.iter().position(|byte| *byte != b' ')?;
    let field = &field[start..];
    let end = field
        .iter()
        .position(|byte| !(b'0'..=b'7').contains(byte))
        .unwrap_or(field.len());
    let (digits, rest) = field.split_at(end);
    if digits.is_empty() || !rest.iter().all(|byte| matches!(byte, 0 | b' ')) {
        return None;
    }
    digits.iter().try_fold(0u64, |value, digit| {
        value.checked_mul(8)?.checked_add(u64::from(digit - b'0'))
    })
}

/// Whether the checksum field equals the sum of the header's bytes, with
/// the field's own eight bytes counted as spaces.
fn summed(header: &[u8; 512]) -> bool {
    let sum: u64 = header
        .iter()
        .enumerate()
        .map(|(at, byte)| {
            if (148..156).contains(&at) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum();
    octal(&header[148..156]) == Some(sum)
}

/// Returns the header's member name: the name field, preceded by the
/// prefix field and a `/` when the magic is `ustar\0` and the prefix is
/// set.
fn short_name(header: &[u8; 512]) -> Vec<u8> {
    let text = |field: &[u8]| {
        let end = field.iter().position(|byte| *byte == 0);
        field[..end.unwrap_or(field.len())].to_vec()
    };
    let name = text(&header[..100]);
    if &header[257..263] != b"ustar\0" || header[345] == 0 {
        return name;
    }
    let mut full = text(&header[345..500]);
    full.push(b'/');
    full.extend_from_slice(&name);
    full
}

/// Reads the headers of `tarball` and returns `(entries, bytes)`.
///
/// An entry is a regular-file header or a distinct directory: one a
/// header names, or one on the path to a member.
fn survey(tarball: &Path) -> Result<(u64, u64), String> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let shown = |error: std::io::Error| format!("{}: {error}", tarball.display());
    let mut file = fs::File::open(tarball).map_err(shown)?;
    let mut header = [0u8; 512];
    let mut dirs: HashSet<Vec<u8>> = HashSet::new();
    let mut dir_bytes = 0usize;
    let mut files = 0u64;
    let mut bytes = 0u64;
    let mut long: Option<Vec<u8>> = None;
    let mut first = true;
    loop {
        if let Err(error) = file.read_exact(&mut header) {
            return Err(if first {
                "archive.tar is no uncompressed ustar archive".into()
            } else {
                shown(error)
            });
        }
        if header.iter().all(|byte| *byte == 0) {
            return Ok((dirs.len() as u64 + files, bytes));
        }
        if first && &header[257..263] != b"ustar\0" && &header[257..265] != b"ustar  \0" {
            return Err("archive.tar is no uncompressed ustar archive".into());
        }
        first = false;
        if !summed(&header) {
            return Err("archive.tar holds a header whose checksum differs from its bytes".into());
        }
        let size = octal(&header[124..136])
            .ok_or_else(|| "archive.tar holds a member size that is no octal number".to_owned())?;
        let kind = header[156];
        let directory = match kind {
            b'L' => {
                if size > NAME_MAX {
                    return Err(format!(
                        "archive.tar holds a member name past {NAME_MAX} bytes"
                    ));
                }
                let mut name = vec![0u8; size.next_multiple_of(512) as usize];
                file.read_exact(&mut name).map_err(shown)?;
                let end = name
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(name.len());
                if end as u64 > size {
                    return Err(
                        "archive.tar holds a long member name that runs past its declared size"
                            .into(),
                    );
                }
                name.truncate(end);
                long = Some(name);
                continue;
            }
            b'0' | 0 => false,
            b'5' => true,
            other => {
                return Err(format!(
                    "the archive holds a member of tar type {:?}, which is not a directory or a \
                     regular file",
                    char::from(other)
                ));
            }
        };
        let name = long.take().unwrap_or_else(|| short_name(&header));
        if directory && size != 0 {
            return Err("the archive holds a directory that holds data".into());
        }
        if !directory && name.ends_with(b"/") {
            return Err("the archive holds a regular file whose name ends in '/'".into());
        }
        let mut parts: Vec<&[u8]> = name
            .split(|byte| *byte == b'/')
            .filter(|part| !part.is_empty() && *part != b".")
            .collect();
        if !directory {
            parts.pop();
            files += 1;
            bytes = bytes.saturating_add(size.div_ceil(BLOCK).saturating_add(1) * BLOCK);
        }
        let mut path = Vec::new();
        for part in parts {
            path.extend_from_slice(part);
            path.push(b'/');
            if !dirs.contains(&path) {
                dir_bytes += path.len();
                if dir_bytes > DIR_BYTES_MAX {
                    return Err(format!(
                        "the archive's directory names hold more than {DIR_BYTES_MAX} bytes"
                    ));
                }
                dirs.insert(path.clone());
                bytes = bytes.saturating_add(BLOCK);
            }
        }
        if dirs.len() as u64 + files > ENTRIES_MAX as u64 {
            return Err(format!("the archive holds more than {ENTRIES_MAX} entries"));
        }
        let skip = i64::try_from(size.next_multiple_of(512))
            .map_err(|_| "archive.tar holds a member past any length".to_owned())?;
        file.seek(SeekFrom::Current(skip)).map_err(shown)?;
    }
}

/// Brings build `commit.build` to `builds/<build>` unless it is there.
///
/// The download goes to `builds/.fetch-<build>`. The download starts only
/// when free space less `reserve` holds the tar twice and the binary, an
/// estimate of the peak. Before unpacking, a survey of the tar's headers
/// counts its block-rounded member sizes and inodes, and a second check
/// needs room for them. The staged tree must hold only the directory
/// `archive` of directories and regular files, its build record and binary
/// must have the commit record's digests, and the binary's
/// `sim capabilities` must accept the archive. The tree is then synced and
/// renamed into place, replacing a directory that failed its check. A
/// directory whose archive build record and binary still match the commit
/// record gets only its `record.json` rewritten, with no download.
///
/// # Errors
///
/// Any failed step. A failure before the replacement leaves a directory
/// already at the final path as it was. The replacement discards that
/// directory before the rename, so a failed rename leaves no build there,
/// and a failed sync after the rename discards the new tree; either way the
/// next fetch starts again. The removal of the staging directory or the
/// new tree is tried, and a failed removal is named in the error.
pub fn fetch(bucket: &Bucket, state: &Path, commit: &Commit, reserve: u64) -> Result<(), String> {
    let build = &commit.build;
    let final_path = dir(state, build);
    if installed(state, commit) {
        return Ok(());
    }
    // A tree whose archive build record and binary match the commit record
    // needs only its own record; replacing that file alone keeps the
    // archive and binary that a running sweep or confirm uses.
    if check(&final_path, build, &commit.campaign).is_ok() {
        let bytes = serde_json::to_vec_pretty(commit).map_err(|error| error.to_string())?;
        let path = record(state, build);
        return file::replace(&path, &bytes)
            .map_err(|error| format!("{}: {error}", path.display()));
    }
    let (archive_head, binary_head) = need(bucket, state, build, reserve)?;
    let staging = builds(state).join(format!(".fetch-{build}"));
    file::remove_entry(&staging).map_err(|error| format!("{}: {error}", staging.display()))?;
    file::private_dir(&staging).map_err(|error| format!("{}: {error}", staging.display()))?;
    let mut renamed = false;
    let mut staged = || -> Result<(), String> {
        let tarball = staging.join("archive.tar");
        bucket
            .get(&key(build, "archive.tar"), &archive_head, &tarball, LONG)
            .map_err(|error| format!("{}: {error}", key(build, "archive.tar")))?;
        bucket
            .get(
                &key(build, "campaign"),
                &binary_head,
                &staging.join("campaign"),
                LONG,
            )
            .map_err(|error| format!("{}: {error}", key(build, "campaign")))?;
        let (entries, bytes) = survey(&tarball)?;
        room(state, build, bytes, entries, reserve)?;
        let unpacked = staging.join("unpacked");
        file::private_dir(&unpacked).map_err(|error| error.to_string())?;
        unpack(&tarball, &unpacked, bucket.halt)?;
        fs::remove_file(&tarball).map_err(|error| error.to_string())?;
        confine(&unpacked)?;
        fs::rename(unpacked.join("archive"), staging.join("archive"))
            .map_err(|error| error.to_string())?;
        fs::remove_dir(&unpacked).map_err(|error| error.to_string())?;
        check(&staging, build, &commit.campaign)?;
        fs::set_permissions(staging.join("campaign"), fs::Permissions::from_mode(0o755))
            .map_err(|error| error.to_string())?;
        probe(&staging, bucket.halt)?;
        let record = serde_json::to_vec_pretty(commit).map_err(|error| error.to_string())?;
        file::replace(&staging.join("record.json"), &record).map_err(|error| error.to_string())?;
        file::sync_tree(&staging).map_err(|error| format!("{}: {error}", staging.display()))?;
        file::discard(&final_path).map_err(|error| format!("{}: {error}", final_path.display()))?;
        fs::rename(&staging, &final_path).map_err(|error| error.to_string())?;
        renamed = true;
        fs::File::open(builds(state))
            .and_then(|dir| dir.sync_all())
            .map_err(|error| error.to_string())
    };
    staged().map_err(|error| {
        let (left, removed) = if renamed {
            (&final_path, file::discard(&final_path))
        } else {
            (&staging, file::remove_entry(&staging))
        };
        match removed {
            Ok(()) => error,
            Err(cleanup) => format!("{error}; removing {}: {cleanup}", left.display()),
        }
    })
}

pub fn installed(state: &Path, commit: &Commit) -> bool {
    verify_recorded(state, &commit.build).is_ok_and(|recorded| recorded.campaign == commit.campaign)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::capture::Halt;

    #[test]
    fn a_commit_record_names_a_commit_a_build_and_a_binary() {
        let digest = crate::file::sha256(b"x");
        let good = format!(
            r#"{{"format":1,"commit":"{}","build":"{digest}","campaign":"{digest}"}}"#,
            "a".repeat(40)
        );
        assert!(super::Commit::parse(good.as_bytes()).is_ok());
        for bad in [
            good.replace(r#""format":1"#, r#""format":2"#),
            good.replace(&"a".repeat(40), "main"),
            good.replace(&"a".repeat(40), &"A".repeat(40)),
            good.replace(&format!(r#""build":"{digest}""#), r#""build":"x""#),
            good.replace(&format!(r#""campaign":"{digest}""#), r#""campaign":"../x""#),
        ] {
            assert!(super::Commit::parse(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_fetch_needs_room_for_the_tar_its_unpacked_copy_and_the_binary() {
        assert_eq!(super::peak_bytes(4 << 30, 1 << 30), 9 << 30);
        assert_eq!(super::peak_bytes(u64::MAX, 1), u64::MAX);
    }

    use crate::file::scratch;

    // The real `tar` round-trips the archive layout the publisher packs and
    // the fetch unpacks, modes included.
    #[test]
    fn real_tar_round_trips_an_archive_and_confine_takes_it() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch("tar");
        let source = dir.join("source");
        fs::create_dir_all(source.join("archive/lib")).expect("the tree");
        fs::write(source.join("archive/build"), "record").expect("the record");
        fs::write(source.join("archive/worker"), "worker").expect("the worker");
        fs::write(source.join("archive/lib/libc.so.6"), "lib").expect("a library");
        let long = format!("archive/lib/{}", "n".repeat(120));
        fs::write(source.join(&long), "long").expect("a member with a long name");
        fs::set_permissions(
            source.join("archive/worker"),
            fs::Permissions::from_mode(0o500),
        )
        .expect("the mode");
        let tarball = dir.join("archive.tar");
        super::pack(&source, "archive", &tarball, Halt::OnStop).expect("it packs");
        let into = dir.join("into");
        fs::create_dir(&into).expect("the target");
        let (entries, _) = super::survey(&tarball).expect("the survey takes a packed archive");
        super::unpack(&tarball, &into, Halt::OnStop).expect("it unpacks");
        super::confine(&into).expect("a plain archive is taken");
        assert_eq!(entries, entries_under(&into));
        assert_eq!(fs::read(into.join(&long)).expect("the long name"), b"long");
        assert_eq!(
            fs::read(into.join("archive/lib/libc.so.6")).expect("the library"),
            b"lib"
        );
        let mode = fs::metadata(into.join("archive/worker"))
            .expect("the worker")
            .permissions()
            .mode();
        assert_eq!(mode & 0o700, 0o500);
        fs::set_permissions(
            into.join("archive/worker"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("the mode");
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn confine_refuses_links_special_files_and_extra_members() {
        let dir = scratch("confine");
        let tree = |name: &str| {
            let into = dir.join(name);
            fs::create_dir_all(into.join("archive")).expect("the tree");
            fs::write(into.join("archive/build"), "record").expect("the record");
            into
        };
        let link = tree("link");
        std::os::unix::fs::symlink("/etc/passwd", link.join("archive/worker")).expect("a link");
        assert!(super::confine(&link).is_err(), "a symlink member");
        let fifo = tree("fifo");
        let name = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(
            fifo.join("archive/build2").as_os_str(),
        ))
        .expect("a path");
        // SAFETY: `name` is a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(super::confine(&fifo).is_err(), "a FIFO member");
        let extra = tree("extra");
        fs::write(extra.join("campaign"), "a second binary").expect("an extra member");
        assert!(super::confine(&extra).is_err(), "a member beside archive");
        assert!(super::confine(&tree("plain")).is_ok());
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    fn seal(mut header: [u8; 512]) -> [u8; 512] {
        header[148..156].fill(b' ');
        let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        header
    }

    fn header(name: &str, size: u64, kind: u8) -> [u8; 512] {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000755\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[156] = kind;
        header[257..265].copy_from_slice(b"ustar\x0000");
        seal(header)
    }

    fn padded(data: &[u8]) -> Vec<u8> {
        let mut data = data.to_vec();
        data.resize(data.len().next_multiple_of(512), 0);
        data
    }

    fn tarball(dir: &std::path::Path, name: &str, parts: &[&[u8]]) -> std::path::PathBuf {
        let mut bytes = parts.concat();
        bytes.resize(bytes.len() + 1024, 0);
        let path = dir.join(format!("{name}.tar"));
        fs::write(&path, bytes).expect("the tar");
        path
    }

    fn entries_under(dir: &std::path::Path) -> u64 {
        fs::read_dir(dir)
            .expect("a directory")
            .map(|entry| {
                let entry = entry.expect("an entry");
                let below = if entry.file_type().expect("its type").is_dir() {
                    entries_under(&entry.path())
                } else {
                    0
                };
                1 + below
            })
            .sum()
    }

    // The survey must budget inodes for implicit parent directories in
    // name-field, ustar-prefix, and GNU long-name paths.
    #[test]
    fn the_survey_counts_an_inode_for_each_entry_tar_creates() {
        let dir = scratch("survey");
        let top = header("archive/", 0, b'5');
        let orphans: Vec<u8> = (0..20)
            .flat_map(|n| header(&format!("archive/u{n}/a/b/c/file"), 0, b'0'))
            .collect();
        let long = format!(
            "archive/{}/file\0",
            ["a-directory-with-a-long-name"; 6].join("/")
        );
        assert!(long.len() > 100, "the name needs a long-name member");
        let mut prefixed = header("file", 0, b'0');
        prefixed[345..361].copy_from_slice(b"archive/p1/p2/p3");
        let mut gnu = header("archive/g1/file", 0, b'0');
        gnu[257..265].copy_from_slice(b"ustar  \0");
        gnu[345..361].copy_from_slice(b"archive/p1/p2/p3");
        let rows = [
            ("orphans", tarball(&dir, "orphans", &[&top, &orphans])),
            (
                "long",
                tarball(
                    &dir,
                    "long",
                    &[
                        &top,
                        &header("././@LongLink", long.len() as u64, b'L'),
                        &padded(long.as_bytes()),
                        &header("cut", 0, b'0'),
                    ],
                ),
            ),
            (
                "prefixed",
                tarball(&dir, "prefixed", &[&top, &seal(prefixed)]),
            ),
            ("gnu", tarball(&dir, "gnu", &[&top, &seal(gnu)])),
        ];
        let short: Vec<String> = rows
            .iter()
            .filter_map(|(name, tarball)| {
                let (inodes, _) =
                    super::survey(tarball).unwrap_or_else(|error| panic!("{name}: {error}"));
                let into = dir.join(format!("into-{name}"));
                fs::create_dir(&into).expect("the target");
                super::unpack(tarball, &into, Halt::OnStop).expect("it unpacks");
                let created = entries_under(&into);
                (created > inodes).then(|| {
                    format!("{name}: tar created {created} entries, the survey counted {inodes}")
                })
            })
            .collect();
        assert!(short.is_empty(), "{short:#?}");
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn the_survey_refuses_a_header_tar_reads_another_way() {
        let dir = scratch("survey-refused");
        let top = header("archive/", 0, b'5');
        let hidden: Vec<u8> = (0..20)
            .flat_map(|n| header(&format!("archive/h{n}"), 0, b'0'))
            .collect();
        let covered = hidden.len() as u64;
        let record = b"10 size=0\n";
        let mut unsummed = header("archive/big", covered, b'0');
        unsummed[148..156].copy_from_slice(b"0000000\0");
        // A gzip header with an extra field can hold `ustar` at offset 257
        // followed by other bytes; GNU tar takes such a file as compressed.
        let mut magic = header("archive/", 0, b'5');
        magic[257..265].copy_from_slice(b"ustarX00");
        let mut signed = header("archive/signed", 0, b'0');
        signed[124..136].copy_from_slice(b"+0000000001\0");
        let wide = super::NAME_MAX as usize;
        let named: Vec<u8> = (0..=super::DIR_BYTES_MAX / wide)
            .flat_map(|n| {
                let name = format!("archive/{n:08}/{}/\0", "d".repeat(wide - 19));
                assert_eq!(name.len(), wide);
                [
                    header("././@LongLink", wide as u64, b'L').to_vec(),
                    name.into_bytes(),
                    header("cut", 0, b'5').to_vec(),
                ]
                .concat()
            })
            .collect();
        let rows = [
            (
                "pax",
                tarball(
                    &dir,
                    "pax",
                    &[
                        &top,
                        &header("PaxHeaders/big", record.len() as u64, b'x'),
                        &padded(record),
                        &header("archive/big", covered, b'0'),
                        &hidden,
                    ],
                ),
                "tar type 'x'",
            ),
            (
                "data",
                tarball(
                    &dir,
                    "data",
                    &[&top, &header("archive/d/", covered, b'5'), &hidden],
                ),
                "a directory that holds data",
            ),
            (
                "slash",
                tarball(
                    &dir,
                    "slash",
                    &[&top, &header("archive/s/", covered, b'0'), &hidden],
                ),
                "ends in '/'",
            ),
            (
                "sum",
                tarball(&dir, "sum", &[&top, &unsummed, &hidden]),
                "checksum differs",
            ),
            (
                "signed",
                tarball(
                    &dir,
                    "signed",
                    &[&top, &seal(signed), &padded(b"x"), &hidden],
                ),
                "no octal number",
            ),
            (
                "long",
                tarball(
                    &dir,
                    "long",
                    &[&top, &header("././@LongLink", super::NAME_MAX + 1, b'L')],
                ),
                "name past",
            ),
            (
                "names",
                tarball(&dir, "names", &[&top, &named]),
                "names hold",
            ),
            (
                "magic",
                tarball(&dir, "magic", &[&seal(magic), &hidden]),
                "no uncompressed ustar archive",
            ),
            (
                "continued",
                tarball(
                    &dir,
                    "continued",
                    &[
                        &top,
                        &header("././@LongLink", 8, b'L'),
                        &padded(b"archive/continued\0"),
                        &header("cut", 0, b'0'),
                    ],
                ),
                "runs past its declared size",
            ),
            (
                "padded-slash",
                tarball(
                    &dir,
                    "padded-slash",
                    &[
                        &top,
                        &header("././@LongLink", 9, b'L'),
                        &padded(b"archive/f/\0"),
                        &header("cut", covered, b'0'),
                        &hidden,
                    ],
                ),
                "runs past its declared size",
            ),
        ];
        let wrong: Vec<String> = rows
            .iter()
            .filter_map(|(name, tarball, text)| match super::survey(tarball) {
                Err(error) if error.contains(text) => None,
                other => Some(format!("{name}: {other:?}")),
            })
            .collect();
        assert!(wrong.is_empty(), "{wrong:#?}");
        fs::remove_dir_all(&dir).expect("cleanup");
    }
}
