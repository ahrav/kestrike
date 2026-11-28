//! After the run window ends and collection finishes, `seal` binds the collected files,
//! `coverage.json` and each standing mark in one mark, `injection/collected.json`, which names each
//! file by its relative path and the SHA-256 digest of the bytes `seal` read.
//!
//! `seal` opens each file relative to its directory's descriptor and rejects a symbolic link at the
//! final path component. It syncs each file it reads, then `records/`, `injection/` and the
//! evidence directory, before the mark. It looks up a standing mark and links its own by the
//! pathname `DIR/injection`, and trusts the operator to keep that directory under that name until
//! `seal` returns.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::context::{Stream, beside, pure};
use super::controller::Controller;
use super::fault::{Fault, Halt};
use super::restore::{directory, errno_text, names_package, refused};
use super::run::{TOOL, lock_sentence, probe_refusal, shown_path};
use crate::gameday::{
    FleetBounds, Names, ReadError, admit, entries, load_evidence, open_dir, package_of, parsed,
};
use crate::host_stop::{Files, Number, Seam, encoded, lock, probe};
use crate::json::{Object, Value};
use crate::plants::files::strerror;
use crate::python::{hexdigest, repr, repr_float};
use crate::text::Text;

/// The directories `seal` opens and lists, by relative path, in that order.
const DIRECTORIES: [&str; 3] = ["", "records", "injection"];

const SEAL: &str = "injection/collected.json";

impl<S: Seam, F: Files> Controller<'_, '_, S, F> {
    /// `seal` returns 0 when it writes `injection/collected.json`, and 1 when the write fails; for
    /// a mark it linked, it prints the mark's SHA-256 too.
    ///
    /// After taking the lock, `seal` arms the signal record and reads it. It reads the record again
    /// before each file read. Before writing the mark it reads the record once more and disarms it.
    /// If a record read reports a signal, `seal` returns [`Halt::Interrupted`] before writing
    /// `injection/collected.json`.
    ///
    /// # Errors
    ///
    /// `seal` returns the first refusal in check order, and [`Halt::Interrupted`] for a signal it
    /// reads.
    pub fn seal(&mut self, evidence: &OsStr) -> Result<u8, Halt> {
        if evidence.is_empty() {
            return Err(refused("no evidence directory is named"));
        }
        let now = self.wall();
        let root = pure(evidence.as_bytes());
        let injection = beside(&root, "injection");
        if !directory(&root) {
            let mut sentence = Text::from_os(evidence);
            sentence.push_str(" is no directory");
            return Err(Halt::refused(sentence));
        }
        if !directory(&injection) {
            let mut sentence = shown_path(&injection);
            sentence.push_str(" is no directory: no run to seal");
            return Err(Halt::refused(sentence));
        }
        probe(self.cx.files, &injection).map_err(|error| probe_refusal(&injection, &error))?;
        let _held = lock(self.cx.files, &injection)
            .map_err(|error| Halt::refused(lock_sentence(&injection, &error)))?;
        self.cx.record.arm();
        self.cx.record.read()?;
        if self.stands_in(&injection, "collected.json")? {
            return Err(written_once());
        }
        let (files, mut names, bounds) = self.collect(evidence, &root, now)?;
        let sealed: BTreeSet<Text> = files
            .keys()
            .filter(|rel| **rel != "package.json")
            .cloned()
            .collect();
        let mut digests = Object::new();
        for rel in &sealed {
            digests.insert(rel.clone(), Value::String(Text::from(hexdigest(&files[rel]))));
        }
        let mut mark = Object::new();
        mark.insert("time", Value::Float(now));
        mark.insert("files", Value::Object(digests));
        let count = sealed.len();
        names.insert("sealed", sealed);
        let mark = Value::Object(mark);
        let data = encoded(&mark, &Text::from(SEAL), self.cx.mark_limit)?;
        let digest = hexdigest(&data);
        let mut judged = files;
        judged.insert(Text::from(SEAL), data);
        load_evidence(&judged, &bounds)?;
        self.injection = Some(injection);
        self.cx.record.read()?;
        self.cx.record.disarm();
        self.sealing(&mark, &names, count, now, &digest)
    }

    /// The bytes of `package.json`, `injection/roles.json` and each other file the listing holds,
    /// by relative path, with the names the package gives, every file synced and then its
    /// directories.
    fn collect(
        &mut self,
        evidence: &OsStr,
        root: &Path,
        now: f64,
    ) -> Result<(BTreeMap<Text, Vec<u8>>, Names, FleetBounds), Halt> {
        let mut dirs: Vec<File> = Vec::new();
        for rel in DIRECTORIES {
            let opened = if rel.is_empty() {
                open_dir(root, None, &Text::from_os(evidence))
            } else {
                open_dir(Path::new(rel), Some(dirs[0].as_fd()), &Text::from(rel))
            };
            dirs.push(File::from(opened.map_err(read_halt)?));
        }
        let mut files = BTreeMap::new();
        let package = self.read_in(&dirs, "package.json")?;
        let approved = self.operator.approval().package_sha256();
        if *approved != hexdigest(&package).as_str() {
            return Err(refused(
                "package.json holds other bytes than the approval's package",
            ));
        }
        let bounds = self.bounds()?;
        let (p, names) = package_of(&package, &bounds)?;
        files.insert(Text::from("package.json"), package);
        let kind = p.get("kind").expect("the package check admitted its kind");
        if *kind != Value::String(Text::from("staging")) {
            let Value::String(kind) = kind else {
                unreachable!("the package check admitted a text kind")
            };
            let mut sentence = Text::from("package.json is of kind ");
            sentence.push_text(kind);
            sentence.push_str(
                ": seal serves the controller's staging runs, and a simulation export seals its own \
                 files",
            );
            return Err(Halt::refused(sentence));
        }
        let end = run_end(&p);
        if !(Number::of(end).expect("a numeric end") <= Number::from(now)) {
            return Err(Halt::refused(Text::from(format!(
                "the run window ends at {}, after the seal's time {}, so its collections may \
                 still grow",
                repr(end),
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
        if !names_package(&parsed(&roles, &Text::from("injection/roles.json"))?, approved) {
            return Err(refused(
                "injection/roles.json names another package than the approval's",
            ));
        }
        files.insert(Text::from("injection/roles.json"), roles);
        for rel in stand {
            if !files.contains_key(&rel) {
                let shown = rel.to_str().expect("a listed name of the layout is UTF-8");
                let data = self.read_in(&dirs, shown)?;
                files.insert(rel, data);
            }
        }
        for at in [1, 2, 0] {
            self.cx.files.fsync_directory(&dirs[at]).map_err(|error| {
                let mut sentence = if at == 0 {
                    Text::from_os(evidence)
                } else {
                    Text::from(DIRECTORIES[at])
                };
                sentence.push_str(" cannot be synced: ");
                sentence.push_str(&strerror(&error));
                Halt::refused(sentence)
            })?;
        }
        Ok((files, names, bounds))
    }

    /// The file `rel` of the layout, read and synced through the descriptor of its directory once
    /// the record is read.
    fn read_in(&mut self, dirs: &[File], rel: &str) -> Result<Vec<u8>, Halt> {
        self.cx.record.read()?;
        let (at, name) = match rel.rsplit_once('/') {
            Some((at, name)) => (at, name),
            None => ("", rel),
        };
        let index = DIRECTORIES
            .iter()
            .position(|dir| *dir == at)
            .expect("a listed file stands in a directory of the layout");
        let what = Text::from(rel);
        self.cx
            .files
            .read_synced(Path::new(name), &dirs[index], &what, self.cx.file_limit)
            .map_err(read_halt)
    }

    /// The package's list bounds, read from the tree's top.
    pub(super) fn bounds(&self) -> Result<FleetBounds, Halt> {
        FleetBounds::new(self.cx.top, self.cx.file_limit)
            .ok_or_else(|| refused("the tree's top has a path no file can have"))
    }

    /// Writes the seal's `mark` under `names` and prints its `count` files, its time `now` and its
    /// `digest`. A link that finds an entry at the name is refused; a write that fails before the
    /// link exits 1, and so does one that fails after it, which prints the digest too.
    fn sealing(
        &mut self,
        mark: &Value,
        names: &Names,
        count: usize,
        now: f64,
        digest: &str,
    ) -> Result<u8, Halt> {
        let mut line = Text::from(TOOL);
        match self.mark_under("collected", mark, names) {
            Ok(()) => {}
            Err(Halt::Fault(Fault::Os {
                code: Some(libc::EEXIST),
                ..
            })) => return Err(written_once()),
            Err(Halt::Fault(Fault::Unwritten(sentence))) => {
                line.push_text(&sentence);
                self.cx.say(Stream::Err, &line);
                let linked = format!(
                    "{TOOL}the mark this seal linked: injection/collected.json sha256 {digest}"
                );
                self.cx.say(Stream::Out, &Text::from(linked));
                return Ok(1);
            }
            Err(Halt::Fault(Fault::Os { code, text })) => {
                line.push_str("collected.json is unwritten: ");
                line.push_str(&errno_text(code, &text));
                self.cx.say(Stream::Err, &line);
                return Ok(1);
            }
            Err(Halt::Fault(Fault::Refusal(sentence))) => return Err(Halt::refused(sentence)),
            Err(other) => return Err(other),
        }
        line.push_str(&format!(
            "sealed {count} files at {}; injection/collected.json sha256 {digest}",
            repr_float(now)
        ));
        self.cx.say(Stream::Out, &line);
        Ok(0)
    }
}

fn written_once() -> Halt {
    refused("injection/collected.json exists: the seal is written once")
}

/// The halt of a read or an open that failed: its refusal, or a failed close as a system error
/// with the system's text.
fn read_halt(error: ReadError) -> Halt {
    match error {
        ReadError::Refused(refusal) => refusal.into(),
        ReadError::Closed(text) => Halt::Fault(Fault::Os { code: None, text }),
        ReadError::Nul => unreachable!("a listed name and a pathname argument hold no NUL byte"),
    }
}

/// The end of package `p`'s run window, which the package check admitted.
pub(super) fn run_end(p: &Object) -> &Value {
    match p.get("run") {
        Some(Value::Object(run)) => run.get("end").expect("the package check admitted the end"),
        _ => unreachable!("the package check admitted the run window"),
    }
}
