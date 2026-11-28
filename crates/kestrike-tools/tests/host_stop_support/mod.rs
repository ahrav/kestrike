//! What the host stop controller's cases share: the tree's fixtures, a scratch directory per case,
//! JSON values changed at a path, and the refusals of a run's first step as one table in
//! [`step_one`].

#![cfg(target_os = "linux")]

pub(crate) mod step_one;

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use kestrike_tools::gameday::{FILE_LIMIT, FleetBounds, decode};
use kestrike_tools::json::{Object, Text, Value, text};

/// The run's start on the wall clock, the first reading of the cases' clock.
pub(crate) const START: f64 = 104.0;
/// The package's target instance.
pub(crate) const TARGET: &str = "i-h1";
/// The mark of a prerequisite the catalog leaves unmet.
pub(crate) const BLOCKS: &str = "TBD - BLOCKS EXECUTION";

/// The checkout's top level.
pub(crate) fn tree() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the checkout's top resolves")
}

/// The committed fixtures of the controller.
pub(crate) fn fixtures() -> PathBuf {
    tree().join("scripts/host-stop-fixtures")
}

/// The held fixture's package bytes, which the fixture operator file approves.
pub(crate) fn package() -> Vec<u8> {
    fs::read(tree().join("scripts/gameday-fixtures/held/package.json")).expect("the package reads")
}

pub(crate) fn bounds() -> FleetBounds {
    FleetBounds::new(&tree(), FILE_LIMIT).expect("the tree's path holds no NUL")
}

/// `value` decodes strict JSON text.
pub(crate) fn value(json: &str) -> Value {
    decode(json, &Text::from("a case's value")).unwrap_or_else(|error| panic!("{json}: {error}"))
}

pub(crate) fn object(value: Value) -> Object {
    match value {
        Value::Object(object) => object,
        other => panic!("{other:?} is an object"),
    }
}

/// The committed game-day catalog with each GD-2 prerequisite read as met.
pub(crate) fn met() -> Value {
    let path = tree().join("verification/readiness/gamedays.json");
    let mut catalog = value(&fs::read_to_string(path).expect("the catalog reads"));
    for prerequisite in gd2_mut(&mut catalog)
        .get_mut("prerequisites")
        .map(items_mut)
        .expect("GD-2 lists its prerequisites")
    {
        if let Value::String(text) = prerequisite {
            let met = text.to_string().replace(&format!(": {BLOCKS}"), "");
            *text = Text::from(met);
        }
    }
    catalog
}

/// GD-2's entry of `catalog`.
pub(crate) fn gd2_mut(catalog: &mut Value) -> &mut Object {
    let Value::Object(catalog) = catalog else {
        panic!("the catalog is an object")
    };
    items_mut(
        catalog
            .get_mut("entries")
            .expect("the catalog lists entries"),
    )
    .iter_mut()
    .find_map(|entry| match entry {
        Value::Object(entry) if entry.get("id") == Some(&Value::String(Text::from("GD-2"))) => {
            Some(entry)
        }
        _ => None,
    })
    .expect("the catalog holds GD-2")
}

pub(crate) fn items_mut(value: &mut Value) -> &mut Vec<Value> {
    match value {
        Value::Array(items) => items,
        other => panic!("{other:?} is a list"),
    }
}

/// One byte more than the committed catalog and the fixture operator file each hold, the file size
/// limit under which the package of the first step's table is read past its limit and those two are
/// read within it.
pub(crate) fn past_limit() -> u64 {
    let size = |path: PathBuf| fs::metadata(path).expect("the file stands").len();
    let catalog = size(tree().join("verification/readiness/gamedays.json"));
    let compact = u64::try_from(json(&operator()).len()).expect("a length fits");
    catalog
        .max(size(fixtures().join("operator.json")))
        .max(compact)
        + 1
}

/// The fixture operator file's value.
pub(crate) fn operator() -> Value {
    value(&fs::read_to_string(fixtures().join("operator.json")).expect("the operator file reads"))
}

/// The member of `value` at `path`, each step a key of an object.
pub(crate) fn at_mut<'a>(value: &'a mut Value, path: &[&str]) -> &'a mut Value {
    path.iter().fold(value, |value, key| match value {
        Value::Object(object) => object
            .get_mut(key)
            .unwrap_or_else(|| panic!("{key} exists")),
        other => panic!("{other:?} is an object"),
    })
}

/// Sets the member at `path` to `new`, adding it when its object lacks it.
pub(crate) fn set(value: &mut Value, path: &[&str], new: Value) {
    let (last, parents) = path.split_last().expect("a path has a key");
    match at_mut(value, parents) {
        Value::Object(object) => object.insert(*last, new),
        other => panic!("{other:?} is an object"),
    }
}

/// Removes the member at `path`.
pub(crate) fn remove(value: &mut Value, path: &[&str]) -> Value {
    let (last, parents) = path.split_last().expect("a path has a key");
    match at_mut(value, parents) {
        Value::Object(object) => object.remove(last).expect("the member exists"),
        other => panic!("{other:?} is an object"),
    }
}

/// The JSON text of `value`, members in their order.
pub(crate) fn json(value: &Value) -> String {
    text(value)
}

/// A string of the code points `codes`, which may hold a lone surrogate.
pub(crate) fn string(codes: &str, surrogate: Option<u32>) -> Value {
    let codes = codes.chars().map(u32::from).chain(surrogate);
    Value::String(Text::from_code_points(codes).expect("each code point is a text's"))
}

/// A directory the case process made with mode 0700, removed on drop.
pub(crate) struct Scratch(pub(crate) PathBuf);

impl Scratch {
    pub(crate) fn new(label: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let parent = std::env::temp_dir()
            .canonicalize()
            .expect("the temporary directory resolves");
        loop {
            let at = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(
                "kestrike-tools-host-stop-checks-{label}-{}-{at}",
                std::process::id()
            ));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("{}: {error}", path.display()),
            }
        }
    }

    /// A copy of the committed snapshot directory, named `snapshot`.
    pub(crate) fn snapshot(&self) -> PathBuf {
        let snapshot = self.0.join("snapshot");
        fs::create_dir(&snapshot).expect("the snapshot directory is made");
        for name in ["hosts.jsonl", "shards.jsonl"] {
            fs::copy(fixtures().join("snapshot").join(name), snapshot.join(name))
                .expect("the snapshot is copied");
        }
        snapshot
    }

    /// Writes `data` as the file `name` and returns its path.
    pub(crate) fn write(&self, name: &str, data: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, data).expect("the file is written");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Rewrites the lines of the snapshot file `path` with `change` applied to their values.
pub(crate) fn rewrite(path: &Path, change: impl FnOnce(&mut Vec<Value>)) {
    let text = fs::read_to_string(path).expect("the snapshot file reads");
    let mut rows: Vec<Value> = text.lines().map(value).collect();
    change(&mut rows);
    let lines: String = rows.iter().map(|row| format!("{}\n", json(row))).collect();
    fs::write(path, lines).expect("the snapshot file is written");
}

/// The value of `work`, run on a thread of its own, or a panic naming `what` when it has not returned
/// within five seconds. A blocked thread stays blocked until the case process ends.
pub(crate) fn bounded<T: Send + 'static>(
    what: &str,
    work: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = send.send(work());
    });
    match receive.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok(value) => value,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("{what} returned within 5 s"),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => panic!("{what} panicked"),
    }
}
