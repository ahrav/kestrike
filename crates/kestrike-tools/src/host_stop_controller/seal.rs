//! After the run window ends and collection finishes, `seal` binds the collected files,
//! `coverage.json` and each standing mark in one mark, `injection/collected.json`, which names each
//! file by its relative path and the SHA-256 digest of the bytes `seal` read.
//!
//! `seal` opens each file relative to its directory's descriptor and rejects a symbolic link at the
//! final path component. It syncs each file it reads, then `records/`, `injection/` and the
//! evidence directory, before the mark. It looks up a standing mark and links its own by the
//! pathname `DIR/injection`, and trusts the operator to keep that directory under that name until
//! `seal` returns.
//!
//! A seal run again after a refused sync opens new descriptors. Their sync can report success for
//! pages whose writeback failed under the earlier descriptors, so the bytes a second seal names can
//! differ from the bytes on storage.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::File;
use std::os::fd::AsFd;
use std::path::Path;

use super::checks::{check_roles, other_package, read_halt, refused};
use super::context::Stream;
use super::controller::{Controller, window};
use super::fault::{Fault, Halt};
use super::run::{TOOL, lock_sentence};
use crate::fixtures::close;
use crate::gameday::{FleetBounds, admit, entries, load_evidence, open_dir, package_of, parsed};
use crate::host_stop::{Files, Number, Seam, encoded, lock};
use crate::json::{Object, Value};
use crate::plants::files::strerror;
use crate::python::{hexdigest, repr_float};
use crate::text::Text;

/// The directories `seal` opens and lists, by relative path, in that order.
const DIRECTORIES: [&str; 3] = ["", "records", "injection"];

const SEAL: &str = "injection/collected.json";

/// The bytes `seal` read by relative path, and the package's list bounds.
type Collected = (BTreeMap<Text, Vec<u8>>, FleetBounds);

impl<S: Seam, F: Files> Controller<'_, '_, S, F> {
    /// `seal` returns 0 when it writes `injection/collected.json`, and 1 when the write fails; for
    /// a mark it linked, it prints the mark's SHA-256 too. `seal` publishes the mark bytes the
    /// judge's loader admitted.
    ///
    /// After taking the lock, `seal` arms the signal record, ends a hold an earlier command left on
    /// it and reads it. It reads the record again before each file read and once more at the end of
    /// its armed span. A signal reported by the final read takes precedence over a refusal. It then
    /// disarms the record and writes the mark. If a record read reports a signal, `seal` returns
    /// [`Halt::Interrupted`] before writing `injection/collected.json`.
    ///
    /// # Errors
    ///
    /// `seal` returns the first refusal in check order, [`Halt::Interrupted`] for a signal it
    /// reads, and [`Halt::Fault`] for a failed close of a file or a directory it read or a failed
    /// write the mark does not word.
    pub fn seal(&mut self, evidence: &OsStr) -> Result<u8, Halt> {
        if evidence.is_empty() {
            return Err(refused("no evidence directory is named"));
        }
        let now = self.wall();
        let (root, injection) = self.evidence_dirs(evidence, "no run to seal")?;
        let _held = lock(self.cx.files, &injection)
            .map_err(|error| Halt::refused(lock_sentence(&injection, &error)))?;
        self.cx.record.arm();
        let sealing = self.sealing(evidence, &root, &injection, now);
        let sealing = self.raised(sealing);
        self.cx.record.disarm();
        let (data, count) = sealing?;
        self.injection = Some(injection);
        self.write_seal(&data, count, now)
    }

    /// `sealing` returns the mark bytes and the number of files the mark names after the judge's
    /// loader accepts the collected files together with the mark.
    fn sealing(
        &mut self,
        evidence: &OsStr,
        root: &Path,
        injection: &Path,
        now: f64,
    ) -> Result<(Vec<u8>, usize), Halt> {
        self.cx.record.release()?;
        if self.stands_in(injection, "collected.json")? {
            return Err(written_once());
        }
        let (files, bounds) = self.collect(evidence, root, now)?;
        let sealed: BTreeSet<&Text> = files.keys().filter(|rel| **rel != "package.json").collect();
        let mut digests = Object::new();
        for rel in &sealed {
            digests.insert(
                (*rel).clone(),
                Value::String(Text::from(hexdigest(&files[*rel]))),
            );
        }
        let count = sealed.len();
        let mut mark = Object::new();
        mark.insert("time", Value::Float(now));
        mark.insert("files", Value::Object(digests));
        let seal = Text::from(SEAL);
        let data = encoded(&Value::Object(mark), &seal, self.cx.mark_bound())?;
        let mut judged = files;
        judged.insert(seal.clone(), data);
        load_evidence(&judged, &bounds)?;
        let data = judged
            .remove(&seal)
            .expect("the seal's bytes stand among the judged");
        Ok((data, count))
    }

    /// `collect` indexes the bytes of `package.json`, `injection/roles.json` and each other listed
    /// file by relative path, and syncs all of them before syncing their directories.
    fn collect(&mut self, evidence: &OsStr, root: &Path, now: f64) -> Result<Collected, Halt> {
        let shown = |rel: &str| {
            if rel.is_empty() {
                Text::from_os(evidence)
            } else {
                Text::from(rel)
            }
        };
        let mut dirs: Vec<File> = Vec::new();
        for rel in DIRECTORIES {
            let opened = if rel.is_empty() {
                open_dir(root, None, &shown(rel))
            } else {
                open_dir(Path::new(rel), Some(dirs[slot("")].as_fd()), &shown(rel))
            };
            dirs.push(File::from(opened.map_err(read_halt)?));
        }
        let mut files = BTreeMap::new();
        let package = self.read_in(&dirs, "package.json")?;
        let approved = self.operator.approval().package_sha256();
        if *approved != hexdigest(&package).as_str() {
            return Err(other_package());
        }
        let bounds = self.bounds()?;
        let (p, _) = package_of(&package, &bounds)?;
        files.insert(Text::from("package.json"), package);
        let Some(Value::String(kind)) = p.get("kind") else {
            unreachable!("the package check admitted a text kind")
        };
        if *kind != "staging" {
            let mut sentence = Text::from("package.json is of kind ");
            sentence.push_text(kind);
            sentence.push_str(
                ": seal serves the controller's staging runs, and a simulation export seals its own \
                 files",
            );
            return Err(Halt::refused(sentence));
        }
        let end = window(&p, "run").1;
        if end > Number::from(now) {
            return Err(Halt::refused(Text::from(format!(
                "the run window ends at {end}, after the seal's time {}, so its collections may \
                 still grow",
                repr_float(now)
            ))));
        }
        let mut stand = BTreeSet::new();
        for (at, rel) in DIRECTORIES.iter().enumerate() {
            let prefix = if rel.is_empty() {
                Text::new()
            } else {
                Text::from(format!("{rel}/"))
            };
            for (found, is_dir) in entries(dirs[at].as_fd(), &prefix)? {
                if !is_dir {
                    stand.insert(found);
                }
            }
        }
        if stand.contains(&Text::from(SEAL)) {
            return Err(written_once());
        }
        if !stand.contains(&Text::from("package.json")) {
            return Err(refused("package.json is missing"));
        }
        let mut admitted = stand.clone();
        admitted.insert(Text::from(SEAL));
        admit(&p, &admitted)?;
        let roles = self.read_in(&dirs, "injection/roles.json")?;
        check_roles(
            &parsed(&roles, &Text::from("injection/roles.json"))?,
            approved,
        )?;
        files.insert(Text::from("injection/roles.json"), roles);
        for rel in stand {
            if let Entry::Vacant(vacant) = files.entry(rel) {
                let name = vacant
                    .key()
                    .to_str()
                    .expect("a listed name of the layout is UTF-8");
                let data = self.read_in(&dirs, name)?;
                vacant.insert(data);
            }
        }
        for rel in ["records", "injection", ""] {
            self.cx
                .files
                .fsync_directory(&dirs[slot(rel)])
                .map_err(|error| {
                    let mut sentence = shown(rel);
                    sentence.push_str(" cannot be synced: ");
                    sentence.push_str(&strerror(&error));
                    Halt::refused(sentence)
                })?;
        }
        while let Some(dir) = dirs.pop() {
            close(dir).map_err(|error| Halt::Fault(Fault::os(&error)))?;
        }
        Ok((files, bounds))
    }

    /// The file `rel` of the layout, read and synced through the descriptor of its directory once
    /// the record is read.
    fn read_in(&mut self, dirs: &[File], rel: &str) -> Result<Vec<u8>, Halt> {
        self.cx.record.read()?;
        let (at, name) = match rel.rsplit_once('/') {
            Some((at, name)) => (at, name),
            None => ("", rel),
        };
        let what = Text::from(rel);
        self.cx
            .files
            .read_synced(Path::new(name), &dirs[slot(at)], &what, self.cx.file_limit)
            .map_err(read_halt)
    }

    /// On success, `write_seal` reports the file count `count`, the seal time `now`, and the SHA-256
    /// digest of `data`. If `injection/collected.json` already exists, `write_seal` returns
    /// `Err(written_once())`. For other write failures, `write_seal` propagates errors from
    /// `failed_write` and otherwise returns `Ok(1)`.
    fn write_seal(&mut self, data: &[u8], count: usize, now: f64) -> Result<u8, Halt> {
        let digest = hexdigest(data);
        match self.publish_mark("collected", data) {
            Ok(()) => {}
            Err(Halt::Fault(Fault::Os {
                code: Some(libc::EEXIST),
                ..
            })) => return Err(written_once()),
            Err(failed) => {
                if self.failed_write("collected.json", failed)? {
                    let linked = format!(
                        "{TOOL}the mark this seal linked: injection/collected.json sha256 {digest}"
                    );
                    self.cx.say(Stream::Out, &Text::from(linked));
                }
                return Ok(1);
            }
        }
        let mut line = Text::from(TOOL);
        line.push_str(&format!(
            "sealed {count} files at {}; injection/collected.json sha256 {digest}",
            repr_float(now)
        ));
        self.cx.say(Stream::Out, &line);
        Ok(0)
    }
}

/// The index in [`DIRECTORIES`] of the directory at the relative path `rel`.
fn slot(rel: &str) -> usize {
    DIRECTORIES
        .iter()
        .position(|dir| *dir == rel)
        .expect("a listed file stands in a directory of the layout")
}

fn written_once() -> Halt {
    refused("injection/collected.json exists: the seal is written once")
}
