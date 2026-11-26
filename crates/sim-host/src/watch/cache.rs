//! The watch's cache of root reads, one file per root under the state
//! directory's `cache/`.
//!
//! An entry holds the objects a `roots/` listing showed for one root,
//! with their lengths and ETags, and the [`Raw`] read that agreed with
//! that listing. A root is folded from its entry only when the cycle's
//! listing shows the same objects with the same lengths and ETags, every
//! one of them with an ETag. An entry is one file replaced by a staged
//! write and a rename. Its first line is the SHA-256 of everything after
//! it, the header line and the body, and a lookup returns the entry only
//! when that digest matches, so a lookup sees a whole entry or none.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sha2::Digest as _;

use crate::file;
use crate::report::{Bytes, Object, Objects, Raw, Reading};
use crate::snapshot::{LIST_BOUND, OUTPUT_BOUND};

/// The entry format. It changes with the entry's layout and with any
/// change to what [`crate::report::read_root`] produces for the same
/// listed objects, so an entry written under other read rules is a miss.
const FORMAT: u64 = 5;
/// The longest header line a lookup reads.
const HEADER_BOUND: u64 = 16 << 20;
/// The largest entry file a lookup reads: the digest line, the header and
/// the bounds of a root's three objects.
const ENTRY_BOUND: u64 = 65 + HEADER_BOUND + 1 + 2 * OUTPUT_BOUND + LIST_BOUND;

pub struct Cache {
    dir: PathBuf,
}

fn part(object: &Bytes) -> Value {
    match object {
        Object::Read(bytes) => json!({"read": bytes.len()}),
        Object::Absent => json!({"absent": true}),
        Object::Unreadable(reason) => json!({"unreadable": reason}),
    }
}

/// The next line of `reader` without its newline, when the line ends in
/// one within `bound` bytes.
fn line(reader: &mut impl BufRead, bound: u64) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(bound + 1).read_until(b'\n', &mut bytes).ok()?;
    (bytes.pop() == Some(b'\n')).then_some(bytes)
}

/// The object `part` describes, read from `reader` and added to `hasher`.
/// A read length past `bound` is a miss before any byte is read.
fn unpart(
    part: &Value,
    reader: &mut impl Read,
    hasher: &mut sha2::Sha256,
    bound: u64,
) -> Option<Bytes> {
    if let Some(length) = part["read"].as_u64() {
        if length > bound {
            return None;
        }
        let mut bytes = Vec::with_capacity(usize::try_from(length).ok()?);
        reader.take(length).read_to_end(&mut bytes).ok()?;
        if bytes.len() as u64 != length {
            return None;
        }
        hasher.update(&bytes);
        Some(Object::Read(bytes))
    } else if part["absent"] == true {
        Some(Object::Absent)
    } else {
        part["unreadable"]
            .as_str()
            .map(|reason| Object::Unreadable(reason.to_owned()))
    }
}

/// Whether a listing names every object with an ETag, the condition for
/// an entry to stand for it.
fn cacheable(listed: &Objects) -> bool {
    listed.values().all(|(_, etag)| etag.is_some())
}

impl Cache {
    pub fn new(state: &Path) -> Self {
        Self {
            dir: state.join("cache"),
        }
    }

    fn path(&self, campaign: &str) -> PathBuf {
        self.dir.join(file::sha256(campaign.as_bytes()))
    }

    /// The read the entry of `campaign` holds, when the entry reads whole
    /// and was stored for exactly `listed`. A `cache/` that is a symlink
    /// or no directory, and an entry that is a symlink, are misses. The
    /// header is compared with `listed` before the body is read, and each
    /// object is read into its own buffer, refused past its read bound or
    /// the entry's length.
    pub fn get(&self, campaign: &str, listed: &Objects) -> Option<Raw> {
        if !cacheable(listed) || !std::fs::symlink_metadata(&self.dir).ok()?.is_dir() {
            return None;
        }
        let entry = file::open_plain(&self.path(campaign)).ok()??;
        let length = entry.metadata().ok()?.len();
        if length > ENTRY_BOUND {
            return None;
        }
        let mut reader = BufReader::new(entry.take(ENTRY_BOUND));
        let digest = line(&mut reader, 64)?;
        let header_line = line(&mut reader, HEADER_BOUND)?;
        let header: Value = serde_json::from_slice(&header_line).ok()?;
        if header["format"] != FORMAT
            || header["campaign"] != campaign
            || header["listed"] != json!(listed)
        {
            return None;
        }
        let [status, suspects, findings] = header["parts"].as_array()?.as_slice() else {
            return None;
        };
        let mut hasher = sha2::Sha256::new();
        hasher.update(&header_line);
        hasher.update(b"\n");
        let bound = |object: u64| object.min(length);
        let status = unpart(status, &mut reader, &mut hasher, bound(OUTPUT_BOUND))?;
        let payload = match (suspects, findings) {
            (Value::Null, Value::Null) => None,
            (suspects, findings) => Some((
                unpart(suspects, &mut reader, &mut hasher, bound(LIST_BOUND))?,
                unpart(findings, &mut reader, &mut hasher, bound(OUTPUT_BOUND))?,
            )),
        };
        if reader.read(&mut [0]).ok()? != 0 {
            return None;
        }
        let computed: [u8; 32] = hasher.finalize().into();
        (file::hex(&computed).as_bytes() == digest).then_some(Raw { status, payload })
    }

    /// Stores the read of `reading` as the entry of `campaign` for
    /// `listed`, when the read may stand for its root, every call of it
    /// agreed with the listing, and every listed object carries an ETag.
    /// Otherwise, `put` skips the entry. When the cache's filesystem has
    /// fewer free bytes than the entry's size plus `reserve`, `put` removes
    /// the existing entry of `campaign` and returns an error; a failed
    /// removal returns its own error. `put` requires the caller to pass a
    /// root whose lookup under `listed` returned a miss.
    pub fn put(
        &self,
        campaign: &str,
        listed: &Objects,
        reading: &Reading,
        reserve: u64,
    ) -> Result<(), String> {
        if !reading.cacheable || !reading.agreed || !cacheable(listed) {
            return Ok(());
        }
        file::private_dir(&self.dir).map_err(|error| format!("{}: {error}", self.dir.display()))?;
        let raw = &reading.raw;
        let objects: Vec<&Bytes> = match &raw.payload {
            Some((suspects, findings)) => vec![&raw.status, suspects, findings],
            None => vec![&raw.status],
        };
        let mut parts: Vec<Value> = objects.iter().map(|object| part(object)).collect();
        parts.resize(3, Value::Null);
        let header = json!({
            "format": FORMAT, "campaign": campaign, "listed": listed, "parts": parts,
        });
        let mut header = header.to_string().into_bytes();
        header.push(b'\n');
        let bodies: Vec<&[u8]> = objects
            .iter()
            .filter_map(|object| match object {
                Object::Read(bytes) => Some(bytes.as_slice()),
                _ => None,
            })
            .collect();
        let mut hasher = sha2::Sha256::new();
        hasher.update(&header);
        for body in &bodies {
            hasher.update(body);
        }
        let digest: [u8; 32] = hasher.finalize().into();
        let size =
            65 + header.len() as u64 + bodies.iter().map(|body| body.len() as u64).sum::<u64>();
        let free = file::free_bytes(&self.dir)
            .map_err(|error| format!("{}: {error}", self.dir.display()))?;
        let path = self.path(campaign);
        if free < size.saturating_add(reserve) {
            file::remove_file(&path).map_err(|error| format!("{}: {error}", path.display()))?;
            return Err(format!(
                "{}: {free} free bytes hold no {size}-byte entry beside the {reserve}-byte reserve",
                self.dir.display()
            ));
        }
        file::replace_with(&path, |entry| {
            entry.write_all(file::hex(&digest).as_bytes())?;
            entry.write_all(b"\n")?;
            entry.write_all(&header)?;
            bodies.iter().try_for_each(|body| entry.write_all(body))
        })
        .map_err(|error| format!("{}: {error}", path.display()))
    }

    /// Removes every file under `cache/` except the entries of `kept`.
    pub fn retain<'a>(&self, kept: impl IntoIterator<Item = &'a str>) -> Result<(), String> {
        let kept: BTreeSet<String> = kept
            .into_iter()
            .map(|campaign| file::sha256(campaign.as_bytes()))
            .collect();
        self.remove_unless(|name| kept.contains(name))
    }

    /// Removes every entry when fewer than `reserve` bytes are free on the
    /// filesystem that holds `state`, so entries an earlier cycle stored
    /// give their space back to the cycle's downloads and staged puts.
    /// Returns whether it removed them.
    pub fn reclaim(&self, state: &Path, reserve: u64) -> Result<bool, String> {
        let free =
            file::free_bytes(state).map_err(|error| format!("{}: {error}", state.display()))?;
        if free >= reserve {
            return Ok(false);
        }
        self.remove_unless(|_| false)?;
        Ok(true)
    }

    /// Removes the staged files an interrupted entry write left under
    /// `cache/`, whose names start with a dot, and keeps every entry.
    pub fn sweep(&self) -> Result<(), String> {
        self.remove_unless(|name| !name.starts_with('.'))
    }

    /// Removes each file and symlink under `cache/` whose name `keep`
    /// refuses, without following a symlink. A directory under `cache/` is
    /// left in place and named in the error. A `cache/` that is a symlink
    /// or no directory is refused, and an absent one holds nothing.
    fn remove_unless(&self, keep: impl Fn(&str) -> bool) -> Result<(), String> {
        let failed = |error: std::io::Error| format!("{}: {error}", self.dir.display());
        match std::fs::symlink_metadata(&self.dir) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => return Err(format!("{} is not a directory", self.dir.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(failed(error)),
        }
        let mut left = Vec::new();
        for entry in std::fs::read_dir(&self.dir).map_err(failed)? {
            let entry = entry.map_err(failed)?;
            if entry.file_name().to_str().is_some_and(&keep) {
                continue;
            }
            if entry.file_type().map_err(failed)?.is_dir() {
                left.push(entry.path().display().to_string());
                continue;
            }
            match std::fs::remove_file(entry.path()) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    return Err(format!("{}: {error}", entry.path().display()));
                }
                _ => {}
            }
        }
        if left.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "{} holds directories that are no entries: {}",
                self.dir.display(),
                left.join(", ")
            ))
        }
    }
}

#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;
