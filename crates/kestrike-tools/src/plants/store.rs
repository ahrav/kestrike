//! The plant store `verification/plants/` of the checkout: every plant directory it holds, loaded and
//! checked, and the store compared with the head commit.
//!
//! The store's parent and the store are both tested for a link before either is refused. A store entry
//! that is a directory, or a link to one, is a plant, selected or not; any other entry is
//! passed over. Entries are taken in the order of their names' bytes. The store and its parent are real
//! directories, since the run writes its score there. A path of `git status` anywhere under the store,
//! in a plant directory too, whose file name, leading dots removed, starts with `score.json` is passed
//! over; the score and its staging files carry such names.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use super::git;
use super::record::{Plant, load_plant};
use super::stop::Stop;
use crate::environ::Environ;
use crate::ownership::{PathError, is_dir, is_link};
use crate::text::Text;

/// The store's path under the checkout's top.
pub const STORE: &str = "verification/plants";
/// The score's file name in the store.
pub const SCORE: &str = "score.json";

/// `rejected` is the refusal whose reason is `pieces` in order.
fn rejected(pieces: &[Text]) -> Stop {
    Stop::rejected(Text::join("", pieces))
}

fn shown(path: &Path) -> Text {
    Text::from_os(path.as_os_str())
}

/// `places` returns the store's plant directories in byte order of their names.
fn places(directory: &Path) -> Result<Vec<PathBuf>, Stop> {
    let unreadable = |error: PathError| {
        rejected(&[
            Text::from("the plant store cannot be read: "),
            Text::from(error.to_string()),
        ])
    };
    if !is_dir(directory).map_err(unreadable)? {
        return Err(rejected(&[
            shown(directory),
            Text::from(" is no directory"),
        ]));
    }
    let listing = |error| unreadable(PathError::new(directory, error));
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory).map_err(listing)? {
        entries.push(entry.map_err(listing)?.path());
    }
    entries.sort_by(|one, other| one.file_name().cmp(&other.file_name()));
    let mut places = Vec::new();
    for entry in entries {
        if is_dir(&entry).map_err(unreadable)? {
            places.push(entry);
        }
    }
    Ok(places)
}

/// `file_name` is the last name of `path` as Python's `PurePath.name` gives it: empty and `.` names
/// drop, and a path with no other name has the empty name.
fn file_name(path: &str) -> &str {
    path.split('/')
        .rfind(|name| !name.is_empty() && *name != ".")
        .unwrap_or("")
}

/// `changed` lists each path `git status` reports under the store, ignored files included, that is no
/// score.
fn changed(env: &Environ, top: &Path) -> Result<Vec<Text>, Stop> {
    let status = [
        "status",
        "--porcelain",
        "--untracked-files=all",
        "--ignored",
        "--",
        STORE,
    ]
    .map(OsStr::new);
    let done = git::text(env, top, &status)
        .and_then(git::Done::<String>::checked)
        .map_err(Stop::git)?;
    let lines = Text::from(done.stdout).splitlines();
    let mut changed = Vec::new();
    for line in &lines {
        let line = line.to_str().expect("Git's text output holds no surrogate");
        let path: String = line.chars().skip(3).collect();
        if !file_name(&path).trim_start_matches('.').starts_with(SCORE) {
            changed.push(Text::from(path));
        }
    }
    Ok(changed)
}

/// `absent` lists, in code point order, each plant directory `head` holds that the store lacks.
fn absent(env: &Environ, top: &Path, head: &str, places: &[PathBuf]) -> Result<Vec<Text>, Stop> {
    let held = format!("{STORE}/");
    let listing = ["ls-tree", "-z", "-d", "--name-only", head, "--", &held].map(OsStr::new);
    let done = git::text(env, top, &listing).map_err(Stop::git)?;
    if done.code != 0 {
        return Err(rejected(&[Text::from(format!(
            "the plant store of HEAD cannot be listed: `git ls-tree` exited {}",
            done.code
        ))]));
    }
    let present: Vec<Text> = places
        .iter()
        .map(|place| {
            let mut path = Text::from(held.as_str());
            path.push_text(&Text::from_os(place.file_name().unwrap_or_default()));
            path
        })
        .collect();
    let mut absent: Vec<Text> = done
        .stdout
        .split('\0')
        .filter(|name| !name.is_empty())
        .map(Text::from)
        .filter(|name| !present.contains(name))
        .collect();
    absent.sort();
    Ok(absent)
}

/// `load_plants` loads every plant of the store under `top`, checks the store against `head`, and
/// returns the plants `chosen` names, or all of them when it names none, in store order.
///
/// # Errors
///
/// The first check that fails refuses the run with its reason: a link at the store or its parent, a
/// store that is no directory or cannot be read, a plant [`load_plant`] refuses, an empty store, an
/// unknown chosen name, a store path `git status` reports, a store `HEAD` cannot list, and a plant
/// directory of `HEAD` the store lacks. A Git call that cannot run or prints no UTF-8 text, a `git status`
/// that exits nonzero and a link test that cannot read its path are failures.
pub(super) fn load_plants(
    env: &Environ,
    top: &Path,
    head: &str,
    chosen: &[Text],
) -> Result<Vec<Plant>, Stop> {
    let directory = top.join(STORE);
    let parent = directory
        .parent()
        .expect("the store has a parent")
        .to_path_buf();
    let mut linked = Vec::with_capacity(2);
    for path in [parent, directory.clone()] {
        let tested = is_link(&path).map_err(|error| {
            Stop::failed(format!(
                "the plant store cannot be tested for a link: {error}"
            ))
        });
        if tested? {
            linked.push(path);
        }
    }
    if let Some(first) = linked.first() {
        return Err(rejected(&[
            shown(first),
            Text::from(" is a link; the plant store must be a directory of the checkout"),
        ]));
    }
    let places = places(&directory)?;
    let mut plants = Vec::with_capacity(places.len());
    for place in &places {
        plants.push(load_plant(env, top, head, place)?);
    }
    if plants.is_empty() {
        return Err(rejected(&[
            shown(&directory),
            Text::from(" holds no plant"),
        ]));
    }
    let unknown: Vec<Text> = chosen
        .iter()
        .filter(|name| !plants.iter().any(|plant| plant.id() == *name))
        .cloned()
        .collect();
    if !unknown.is_empty() {
        return Err(rejected(&[
            Text::from("no plant named "),
            Text::join(", ", &unknown),
        ]));
    }
    let differ = |paths: &[Text]| {
        rejected(&[
            Text::from("the plant store differs from HEAD at "),
            Text::join(", ", paths),
            Text::from("; commit the plants first"),
        ])
    };
    let changed = changed(env, top)?;
    if !changed.is_empty() {
        return Err(differ(&changed));
    }
    let absent = absent(env, top, head, &places)?;
    if !absent.is_empty() {
        return Err(differ(&absent));
    }
    plants.retain(|plant| chosen.is_empty() || chosen.contains(plant.id()));
    Ok(plants)
}
