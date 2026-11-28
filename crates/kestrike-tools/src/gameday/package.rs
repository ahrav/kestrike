//! The package's check: its list bounds, read from the two Rust files that declare them, its schema, its
//! windows and its kind; and the names its other files are read against.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::constants::{FLEET_BOUNDS, MAX_INTERVALS, OBSERVATION_FILES, WRITTEN_CLAUSES};
use super::exact::exact;
use super::layout::PACKAGE_SCHEMA;
use super::read::{ReadError, read_file};
use super::refusal::{Refusal, need, said};
use super::schema::{
    Names, Scalar, Schema, checked_list, checked_member, checked_object, checked_text, conform,
    sorted,
};
use crate::classes::compiled;
use crate::decimal::Decimal;
use crate::json::{Object, Value};
use crate::text::Text;

/// `FleetBounds` reads the package's list bounds from the tree at `top`: `hosts` takes `MAX_HOSTS` of
/// `crates/kestrike/src/failover/zone_loop/directory.rs`, and `shards` and `witness` both take `MAX_SLOTS`
/// of `crates/kestrike/src/failover/standbys.rs`. It reads each declaration at its first use and holds each
/// value read for the life of the value, so one command reads each declaration once and the two lists of
/// `MAX_SLOTS` share one read. A refused read is not held: the next use reads the file again.
#[derive(Debug)]
pub struct FleetBounds {
    top: PathBuf,
    limit: u64,
    read: RefCell<BTreeMap<(&'static str, &'static str), u64>>,
}

impl FleetBounds {
    /// `new` holds `top` and the file size limit `limit` for the reads of later uses and reads nothing
    /// itself; it returns `None` when `top` holds a NUL byte, which no system call takes.
    pub fn new(top: &Path, limit: u64) -> Option<Self> {
        (!top.as_os_str().as_bytes().contains(&0)).then(|| Self {
            top: top.to_path_buf(),
            limit,
            read: RefCell::new(BTreeMap::new()),
        })
    }

    /// `fleet_bound` is the longest package list `field` may hold, one of `hosts`, `shards` and
    /// `witness`.
    ///
    /// # Errors
    ///
    /// Each refusal of the read of the declaring file, as [`declared_bound`](Self::declared_bound)
    /// states.
    ///
    /// # Panics
    ///
    /// When `field` is none of the three lists.
    fn fleet_bound(&self, field: &str) -> Result<u64, Refusal> {
        let (_, rel, name) = FLEET_BOUNDS
            .iter()
            .find(|(list, _, _)| *list == field)
            .unwrap_or_else(|| panic!("{field} is a list of FLEET_BOUNDS"));
        self.declared_bound(rel, name)
    }

    /// `declared_bound` is the value of the one line `pub const <name>: usize = <digits>;` of the Rust
    /// file `rel`, with each CRLF read as LF as rustc reads it.
    ///
    /// # Errors
    ///
    /// Each refusal of [`read_file`] naming `rel`; `<rel> is not UTF-8: <reason>`;
    /// ``<rel> declares <name> <n> times as `pub const <name>: usize = N;`, not once``; and
    /// `<rel> declares <name> as a value past a 64-bit usize` for more than 20 digits or a value of at
    /// least 2^64.
    fn declared_bound(&self, rel: &'static str, name: &'static str) -> Result<u64, Refusal> {
        if let Some(&bound) = self.read.borrow().get(&(rel, name)) {
            return Ok(bound);
        }
        let what = Text::from(rel);
        let data =
            read_file(&self.top.join(rel), None, &what, self.limit, false).map_err(|error| {
                match error {
                    ReadError::Refused(refusal) => refusal,
                    ReadError::Closed(reason) => {
                        Refusal::new(said!(rel, " cannot be read: ", reason))
                    }
                    ReadError::Nul => {
                        unreachable!("the top and the relative path hold no NUL byte")
                    }
                }
            })?;
        let text = std::str::from_utf8(&data)
            .map_err(|error| Refusal::new(said!(rel, " is not UTF-8: ", error.to_string())))?
            .replace("\r\n", "\n");
        let pattern = compiled(&format!(
            r"(?m)^pub const {}: usize = ([0-9]+);$",
            regex::escape(name)
        ));
        let found: Vec<&str> = pattern
            .captures_iter(&text)
            .map(|found| {
                found
                    .get(1)
                    .expect("the pattern captures the digits")
                    .as_str()
            })
            .collect();
        need(found.len() == 1, || {
            said!(
                rel,
                " declares ",
                name,
                " ",
                found.len().to_string(),
                " times as `pub const ",
                name,
                ": usize = N;`, not once",
            )
        })?;
        let bound = Some(found[0])
            .filter(|digits| digits.len() <= 20)
            .and_then(|digits| digits.parse::<u64>().ok())
            .ok_or_else(|| {
                Refusal::new(said!(
                    rel,
                    " declares ",
                    name,
                    " as a value past a 64-bit usize"
                ))
            })?;
        self.read.borrow_mut().insert((rel, name), bound);
        Ok(bound)
    }
}

/// A list of names.
const NAMES: Schema = Schema::List(&Schema::scalar(Scalar::Name));

/// `check_package` refuses a package object off its schema or its windows and returns the package's names
/// of the kinds `host`, `shard`, `observation`, `budget` and `key`. The files of the layout read these
/// names, and `coverage.json` and `injection/collected.json` also read the kinds [`LAYOUT`](super::LAYOUT)
/// states, which the caller adds. A list longer than its bound is refused before any of its entries is
/// checked.
///
/// # Errors
///
/// The first refusal in this order: a list past its bound, or the read of the bound; `hosts` or `shards`
/// no list of names, empty or repeating a name; the package off the package's schema; a `note` that is no
/// name; a repeated witness key; windows out of order; a run window that is no whole number of
/// intervals from 1 to 1,000,000; a simulation with a clock error; a staging package that names
/// an observation outside its world.
pub fn check_package(p: &Object, bounds: &FleetBounds) -> Result<Names, Refusal> {
    let null = Value::Null;
    let field = |key: &str| p.get(key).unwrap_or(&null);
    check_bounds(&field, bounds)?;
    let mut names = host_and_shard_names(&field)?;
    names.insert(
        "observation",
        OBSERVATION_FILES
            .iter()
            .map(|(observation, _)| Text::from(*observation))
            .collect(),
    );
    names.insert(
        "budget",
        WRITTEN_CLAUSES
            .iter()
            .filter_map(|(_, budget)| budget.map(Text::from))
            .collect(),
    );
    let mut bare = p.clone();
    bare.remove("note");
    conform(
        &Value::Object(bare),
        &PACKAGE_SCHEMA,
        &Text::from("package.json"),
        &names,
    )?;
    let note = Value::String(Text::from("-"));
    conform(
        p.get("note").unwrap_or(&note),
        &Schema::scalar(Scalar::Name),
        &Text::from("package.json note"),
        &names,
    )?;
    let witness = checked_list(field("witness"));
    let keys: BTreeSet<Text> = witness
        .iter()
        .map(|entry| checked_text(checked_object(entry).get("key").unwrap_or(&null)))
        .cloned()
        .collect();
    need(keys.len() == witness.len(), || {
        said!("package.json repeats a witness key")
    })?;
    names.insert("key", keys);
    check_windows(&field)?;
    let staging = *field("kind") == Value::String(Text::from("staging"));
    need(
        staging || number(field("clock_error_seconds")).is_zero(),
        || said!("a simulation package names a clock error other than 0"),
    )?;
    let outside = checked_object(field("outside"));
    let simulation = *field("kind") == Value::String(Text::from("simulation"));
    need(simulation || outside.is_empty(), || {
        said!(
            "a staging package names ",
            sorted(outside.iter().map(|(key, _)| key.clone())),
            " as outside its world",
        )
    })?;
    Ok(names)
}

/// Refuses each of the package's lists that is longer than its bound, in the order of [`FLEET_BOUNDS`],
/// reading a bound only for a field that is a list.
fn check_bounds<'a>(
    field: &impl Fn(&str) -> &'a Value,
    bounds: &FleetBounds,
) -> Result<(), Refusal> {
    for (list, rel, name) in FLEET_BOUNDS {
        if let Value::Array(items) = field(list) {
            let bound = bounds.fleet_bound(list)?;
            let count = u64::try_from(items.len()).expect("a length fits a u64");
            need(count <= bound, || {
                said!(
                    "package.json ",
                    list,
                    " holds ",
                    items.len().to_string(),
                    " entries, more than the ",
                    bound.to_string(),
                    " that ",
                    name,
                    " of ",
                    rel,
                    " declares",
                )
            })?;
        }
    }
    Ok(())
}

/// The names of `host` and `shard`, once `hosts` and `shards` are each a list of distinct names.
fn host_and_shard_names<'a>(field: &impl Fn(&str) -> &'a Value) -> Result<Names, Refusal> {
    let mut names = Names::new();
    for (list, kind) in [("hosts", "host"), ("shards", "shard")] {
        let what = said!("package.json ", list);
        conform(field(list), &NAMES, &what, &Names::new())?;
        let items = checked_list(field(list));
        let distinct: BTreeSet<Text> = items.iter().map(checked_text).cloned().collect();
        need(!items.is_empty() && distinct.len() == items.len(), || {
            said!("package.json ", list, " is empty or repeats a name")
        })?;
        names.insert(kind, distinct);
    }
    Ok(names)
}

/// Refuses windows out of order, and a run window that is no whole number of intervals from 1 to
/// [`MAX_INTERVALS`].
fn check_windows<'a>(field: &impl Fn(&str) -> &'a Value) -> Result<(), Refusal> {
    let at = |window: &str, end: &str| {
        number(
            checked_object(field(window))
                .get(end)
                .unwrap_or(&Value::Null),
        )
    };
    let (base_start, base_end) = (at("baseline", "start"), at("baseline", "end"));
    let (run_start, run_end) = (at("run", "start"), at("run", "end"));
    need(
        base_start < base_end
            && base_end <= run_end
            && run_start <= base_end
            && run_start < run_end,
        || {
            said!(
                "the windows are empty, or the baseline window ends after the run window or before it starts"
            )
        },
    )?;
    let whole = (&run_end - &run_start)
        .whole_quotient(&number(field("interval")), MAX_INTERVALS)
        .is_some();
    need(whole, || {
        said!(
            "the run window is not a whole number of origin intervals, from 1 to ",
            MAX_INTERVALS.to_string(),
        )
    })
}

/// The exact value of a number the schema checked.
pub(super) fn number(value: &Value) -> Decimal {
    exact(value).expect("the schema made the value a finite number")
}

/// The shard names of a package that passed [`check_package`], in the package's order.
pub(super) fn shards(p: &Object) -> impl Iterator<Item = &Text> {
    checked_list(checked_member(p, "shards"))
        .iter()
        .map(checked_text)
}

#[cfg(test)]
#[path = "package_tests.rs"]
mod tests;
