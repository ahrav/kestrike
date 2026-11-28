//! The loader checks an evidence directory's listing against the layout, validates each file, and
//! checks the seal and the order of the records and marks.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::os::fd::AsFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use super::constants::{COLLECTED, MARKS, OBSERVATION_FILES};
use super::layout::{LAYOUT, RECORD};
use super::listing::{entries, open_dir};
use super::order::check_order;
use super::package::{FleetBounds, check_package, shards};
use super::parse::parsed;
use super::read::{ReadError, read_file};
use super::refusal::{Refusal, need, said};
use super::schema::{Names, Schema, checked_list, checked_member, checked_object, conform};
use super::seal::check_seal;
use crate::json::{Object, Value};
use crate::python::hexdigest;
use crate::text::Text;

/// `Evidence` holds the validated contents of an evidence directory.
#[derive(Debug)]
pub struct Evidence {
    package: Object,
    package_sha256: String,
    files: BTreeMap<Text, Value>,
    seal_sha256: String,
    anchors: BTreeMap<Text, Option<usize>>,
}

impl Evidence {
    pub fn package(&self) -> &Object {
        &self.package
    }

    pub fn into_package(self) -> Object {
        self.package
    }

    pub fn package_sha256(&self) -> &str {
        &self.package_sha256
    }

    /// The lookup returns the parsed value for `rel` when the layout file is present, and `None`
    /// otherwise.
    pub fn file(&self, rel: &str) -> Option<&Value> {
        self.files.get(&Text::from(rel))
    }

    pub fn seal_sha256(&self) -> &str {
        &self.seal_sha256
    }

    /// Each shard's anchor indexes a line in its record file; `None` means no line is the anchor.
    pub fn anchors(&self) -> &BTreeMap<Text, Option<usize>> {
        &self.anchors
    }
}

/// # Errors
///
/// Each refusal of [`parsed`]; `package.json is no object`; each refusal of [`check_package`].
pub fn package_of(data: &[u8], bounds: &FleetBounds) -> Result<(Object, Names), Refusal> {
    match parsed(data, &Text::from("package.json"))? {
        Value::Object(p) => {
            let names = check_package(&p, bounds)?;
            Ok((p, names))
        }
        _ => Err(Refusal::new(said!("package.json is no object"))),
    }
}

fn absent(p: &Object) -> BTreeSet<Text> {
    let outside = checked_object(checked_member(p, "outside"));
    OBSERVATION_FILES
        .iter()
        .filter(|(observation, _)| outside.get(observation).is_some())
        .map(|(_, file)| Text::from(*file))
        .collect()
}

/// # Panics
///
/// `collected` panics if `p` lacks `outside`.
pub fn collected(p: &Object) -> BTreeSet<Text> {
    let absent = absent(p);
    shards(p)
        .map(|shard| said!("records/", shard, ".jsonl"))
        .chain([Text::from("records/receipts.jsonl")])
        .chain(COLLECTED.iter().map(|rel| Text::from(*rel)))
        .filter(|rel| !absent.contains(rel))
        .collect()
}

/// `layout_of` returns a relative path, schema, and optional flag for each shard record file, in the
/// package's order, and then each [`LAYOUT`] entry.
pub fn layout_of(p: &Object) -> Vec<(Text, &'static Schema, bool)> {
    shards(p)
        .map(|shard| (said!("records/", shard, ".jsonl"), &RECORD, false))
        .chain(
            LAYOUT
                .iter()
                .map(|(rel, schema, optional)| (Text::from(*rel), schema, *optional)),
        )
        .collect()
}

/// # Errors
///
/// `admit` treats `package.json` as the manifest and checks the remaining paths in `rels` in sorted
/// order. The first failing path yields `<rel> is no file of the layout`, or
/// `<rel> stands, but the package names its observation outside its world`. Then the first required
/// file in layout order whose path is in neither `rels` nor `absent(p)` yields `<rel> is missing`.
pub fn admit(p: &Object, rels: &BTreeSet<Text>) -> Result<(), Refusal> {
    let (layout, absent) = (layout_of(p), absent(p));
    for rel in rels.iter().filter(|rel| **rel != "package.json") {
        need(layout.iter().any(|(file, _, _)| file == rel), || {
            said!(rel, " is no file of the layout")
        })?;
        need(!absent.contains(rel), || {
            said!(
                rel,
                " stands, but the package names its observation outside its world"
            )
        })?;
    }
    for (rel, _, optional) in &layout {
        need(
            *optional || rels.contains(rel) || absent.contains(rel),
            || said!(rel, " is missing"),
        )?;
    }
    Ok(())
}

/// `files` maps package-relative paths to file bytes.
///
/// # Errors
///
/// A missing manifest yields `package.json is missing`. Otherwise, `load_evidence` propagates the
/// first refusal from [`package_of`], then [`admit`], then [`parsed`] and [`conform`] over the
/// present files in layout order, then `check_seal`, then `check_order`.
pub fn load_evidence(
    files: &BTreeMap<Text, Vec<u8>>,
    bounds: &FleetBounds,
) -> Result<Evidence, Refusal> {
    let package = files.get(&Text::from("package.json"));
    let package = package.ok_or_else(|| Refusal::new(said!("package.json is missing")))?;
    let (p, mut names) = package_of(package, bounds)?;
    admit(&p, &files.keys().cloned().collect())?;
    let observed = collected(&p);
    names.insert("observed", observed.clone());
    let marks = MARKS.iter().map(|mark| Text::from(*mark));
    let sealed = observed
        .iter()
        .cloned()
        .chain([Text::from("coverage.json")])
        .chain(marks)
        .collect();
    names.insert("sealed", sealed);
    let mut values = BTreeMap::new();
    for (rel, schema, _) in layout_of(&p) {
        let Some(data) = files.get(&rel) else {
            continue;
        };
        let value = parsed(data, &rel)?;
        if rel.as_bytes().ends_with(b".jsonl") {
            for (at, row) in checked_list(&value).iter().enumerate() {
                let what = said!(rel, " line ", (at + 1).to_string());
                conform(row, schema, &what, &names)?;
            }
        } else {
            conform(&value, schema, &rel, &names)?;
        }
        values.insert(rel, value);
    }
    check_seal(&p, &values, files, &observed)?;
    let seal = files
        .get(&Text::from("injection/collected.json"))
        .expect("the layout requires the seal");
    let anchors = check_order(&p, &values)?;
    Ok(Evidence {
        package_sha256: hexdigest(package),
        seal_sha256: hexdigest(seal),
        package: p,
        files: values,
        anchors,
    })
}

fn spelled(root: &Path) -> PathBuf {
    let bytes = root.as_os_str().as_bytes();
    let lead: &[u8] = if bytes.starts_with(b"//") && !bytes.starts_with(b"///") {
        b"//"
    } else if bytes.starts_with(b"/") {
        b"/"
    } else {
        b""
    };
    let parts: Vec<&[u8]> = bytes
        .split(|byte| *byte == b'/')
        .filter(|part| !part.is_empty() && *part != b".")
        .collect();
    let mut spelling = lead.to_vec();
    spelling.extend(parts.join(&b'/'));
    if spelling.is_empty() {
        spelling.push(b'.');
    }
    PathBuf::from(OsString::from_vec(spelling))
}

/// `read_evidence` lists the evidence directory at `root` and each of its layout directories, reads
/// `package.json` first, uses its package to admit the listed paths, then reads the remaining files
/// in relative-path order, each at most `limit` bytes, and passes all files, including
/// `package.json`, to [`load_evidence`]. `read_evidence` resolves each file name relative to the open
/// descriptor for the directory that listed it.
///
/// # Errors
///
/// An empty `root` yields `no evidence directory is named`. The first refusal ends processing:
/// [`open_dir`] and [`entries`], `package.json is missing`, [`read_file`] for `package.json`, then
/// [`package_of`], [`admit`], [`read_file`] for the remaining files in relative-path order, and
/// [`load_evidence`]. A failed close of a file read is the [`ReadError::Closed`] that [`read_file`]
/// returns, passed on for the caller to word; a failed close of a directory's descriptor goes
/// unreported.
///
/// A `root` with a NUL byte yields [`ReadError::Nul`].
pub fn read_evidence(root: &Path, limit: u64, bounds: &FleetBounds) -> Result<Evidence, ReadError> {
    if root.as_os_str().is_empty() {
        return Err(Refusal::new(said!("no evidence directory is named")).into());
    }
    let mut dirs = vec![open_dir(
        &spelled(root),
        None,
        &Text::from_os(root.as_os_str()),
    )?];
    let mut place: BTreeMap<Text, (usize, Text)> = BTreeMap::new();
    for (rel, is_dir) in entries(dirs[0].as_fd(), &Text::new())? {
        if !is_dir {
            place.insert(rel.clone(), (0, rel));
            continue;
        }
        let name = rel.to_os().expect("a layout directory's name is ASCII");
        let dir = open_dir(Path::new(&name), Some(dirs[0].as_fd()), &rel)?;
        for sub in entries(dir.as_fd(), &said!(rel, "/"))?.into_keys() {
            let (_, name) = sub.rpartition(b'/');
            place.insert(sub, (dirs.len(), name));
        }
        dirs.push(dir);
    }
    let manifest = Text::from("package.json");
    let listed: BTreeSet<Text> = place.keys().cloned().collect();
    need(listed.contains(&manifest), || {
        said!("package.json is missing")
    })?;
    let package = read_file(
        Path::new("package.json"),
        Some(dirs[0].as_fd()),
        &manifest,
        limit,
        false,
    )?;
    admit(&package_of(&package, bounds)?.0, &listed)?;
    let mut files = BTreeMap::new();
    for (rel, (dir, name)) in place {
        if rel != manifest {
            let name = name
                .to_os()
                .expect("a listed name encodes as it was listed");
            let data = read_file(
                Path::new(&name),
                Some(dirs[dir].as_fd()),
                &rel,
                limit,
                false,
            )?;
            files.insert(rel, data);
        }
    }
    drop(dirs);
    files.insert(manifest, package);
    Ok(load_evidence(&files, bounds)?)
}

#[cfg(test)]
#[path = "evidence_tests.rs"]
mod tests;
