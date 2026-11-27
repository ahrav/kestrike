//! One plant of the store: its record `plant.json`, checked field by field, and its patch `plant.patch`,
//! whose paths Git reads without applying it. Each file is read once, at most [`RECORD_BOUND`] bytes, and
//! must equal the regular file of mode 100644 that the head commit holds at its path.

use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::files::{is_file, is_link, strerror};
use super::git::{self, Done};
use super::stop::Stop;
use super::store::{SCORE, STORE};
use super::values::{argument, cause, count, keys, printable, profile_name, strings, text};
use crate::environ::Environ;
use crate::json::{self, Integer, Object, Value};
use crate::text::{Text, is_space, strip_str};

/// The most bytes `plant.json` or `plant.patch` holds.
pub const RECORD_BOUND: usize = 1 << 20;
/// The fields of a record, each once.
pub const FIELDS: [&str; 8] = [
    "id",
    "row",
    "fix",
    "files",
    "restores",
    "proof",
    "expected",
    "miss_cause",
];
/// The longest plant id whose proof logs, `plant-<id>.out` and `plant-<id>.err`, fit a file name of 255
/// bytes, counted in code points.
const ID_BOUND: usize = 255 - "plant-".len() - ".out".len();
/// The `git apply --summary` lines that do more than change a file's contents.
const ODD: [&str; 4] = ["rename ", "copy ", "mode change ", "delete mode "];

/// A plant whose record holds the eight [`FIELDS`] with the values their rules take, in the record's
/// order, and whose patch bytes equal the head commit's.
#[derive(Clone, Debug, PartialEq)]
pub struct Plant {
    record: Object,
    patch: Vec<u8>,
}

fn field<'a>(record: &'a Object, name: &str) -> &'a Value {
    record
        .get(name)
        .unwrap_or_else(|| panic!("a checked record holds {name}"))
}

fn string<'a>(record: &'a Object, name: &str) -> &'a Text {
    match field(record, name) {
        Value::String(text) => text,
        _ => panic!("a checked record's {name} is text"),
    }
}

fn list<'a>(record: &'a Object, name: &str) -> Vec<&'a Text> {
    match field(record, name) {
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::String(text) => text,
                _ => panic!("a checked record's {name} holds text"),
            })
            .collect(),
        _ => panic!("a checked record's {name} is a list"),
    }
}

impl Plant {
    /// The plant's name: its directory's name and its record's `id`.
    pub fn id(&self) -> &Text {
        string(&self.record, "id")
    }

    pub fn row(&self) -> &Integer {
        match field(&self.record, "row") {
            Value::Integer(row) => row,
            _ => panic!("a checked record's row is an integer"),
        }
    }

    /// The fix: `pull_request`, a positive integer, and `commit`, text, in the record's order.
    pub fn fix(&self) -> &Object {
        match field(&self.record, "fix") {
            Value::Object(fix) => fix,
            _ => panic!("a checked record's fix is an object"),
        }
    }

    pub fn files(&self) -> Vec<&Text> {
        list(&self.record, "files")
    }

    pub fn restores(&self) -> &Text {
        string(&self.record, "restores")
    }

    /// The proof's test id: UTF-8 text without NUL.
    pub fn proof(&self) -> &Text {
        string(&self.record, "proof")
    }

    pub fn expected(&self) -> Vec<&Text> {
        list(&self.record, "expected")
    }

    /// The miss cause, `None` for `null`: an object of `cause` and `evidence` in the record's order.
    pub fn miss_cause(&self) -> Option<&Object> {
        match field(&self.record, "miss_cause") {
            Value::Null => None,
            Value::Object(cause) => Some(cause),
            _ => panic!("a checked record's miss_cause is null or an object"),
        }
    }

    /// The record as `plant.json` holds it, members in its order.
    pub fn record(&self) -> &Object {
        &self.record
    }

    pub fn patch(&self) -> &[u8] {
        &self.patch
    }
}

fn rejected(name: &Text, rule: impl Into<Text>) -> Stop {
    let mut reason = name.clone();
    reason.push_str(": ");
    reason.push_text(&rule.into());
    Stop::rejected(reason)
}

/// `bounded` reads `path` up to one byte past [`RECORD_BOUND`] and returns `None` when it holds more.
fn bounded(name: &Text, path: &Path) -> Result<Option<Vec<u8>>, Stop> {
    let unreadable = |error: std::io::Error| {
        let mut reason = Text::from_os(path.file_name().unwrap_or_default());
        reason.push_str(" is unreadable: ");
        reason.push_str(&strerror(&error));
        rejected(name, reason)
    };
    let mut data = Vec::new();
    File::open(path)
        .and_then(|file| file.take(RECORD_BOUND as u64 + 1).read_to_end(&mut data))
        .map_err(unreadable)?;
    Ok((data.len() <= RECORD_BOUND).then_some(data))
}

/// `files_and_record` reads both files and the record, or refuses the pair as the first failing check
/// states.
fn files_and_record(
    name: &Text,
    record: &Path,
    patch: &Path,
) -> Result<(Vec<u8>, Vec<u8>, Value), Stop> {
    let unreadable = |error: &dyn std::fmt::Display| {
        rejected(name, format!("plant.json is unreadable: {error}"))
    };
    for path in [record, patch] {
        let regular = is_file(path).map_err(|error| unreadable(&error))?
            && !is_link(path).map_err(|error| unreadable(&error))?;
        if !regular {
            return Err(rejected(
                name,
                "plant.json and plant.patch are both required, as regular files",
            ));
        }
    }
    let (data, patch_bytes) = (bounded(name, record)?, bounded(name, patch)?);
    let (Some(data), Some(patch_bytes)) = (data, patch_bytes) else {
        return Err(rejected(
            name,
            format!("plant.json or plant.patch holds more than {RECORD_BOUND} bytes"),
        ));
    };
    let document = std::str::from_utf8(&data).map_err(|error| unreadable(&error))?;
    let value = json::parse_unique(document).map_err(|error| unreadable(&error))?;
    Ok((data, patch_bytes, value))
}

/// The ten field rules in the order they are judged, each with the sentence its refusal states.
fn rules(name: &Text, record: &Object) -> [(bool, String); 10] {
    let [fix, files, expected, miss] =
        ["fix", "files", "expected", "miss_cause"].map(|key| field(record, key));
    [
        (
            *name != SCORE,
            format!("id is another name than {SCORE}, the path of the run's score"),
        ),
        (
            name.len() <= ID_BOUND,
            format!(
                "id holds at most {ID_BOUND} bytes, so the proof's logs plant-<id>.out and \
                 plant-<id>.err are file names"
            ),
        ),
        (
            matches!(field(record, "id"), Value::String(id) if id == name)
                && printable(name)
                && *name == name.strip(),
            "id names the plant's directory in printable ASCII without edge spaces, so campaign takes \
             plant-<id>"
                .to_owned(),
        ),
        (count(field(record, "row")), "row is a positive integer".to_owned()),
        (
            matches!(fix, Value::Object(fix) if keys(fix, &["commit", "pull_request"])
                && fix.get("pull_request").is_some_and(count)
                && fix.get("commit").is_some_and(text)),
            "fix holds a positive pull_request and a commit".to_owned(),
        ),
        (
            strings(files) && matches!(files, Value::Array(items) if !items.is_empty()),
            "files is a nonempty list of paths".to_owned(),
        ),
        (
            text(field(record, "restores")) && text(field(record, "proof")),
            "restores and proof are nonempty text".to_owned(),
        ),
        (
            argument(field(record, "proof")),
            "proof holds no NUL and is UTF-8 text a process takes as an argument".to_owned(),
        ),
        (
            strings(expected)
                && matches!(expected, Value::Array(items) if items.iter().all(profile_name)),
            "expected is a list of profile names campaign can take".to_owned(),
        ),
        (
            matches!(miss, Value::Null) || cause(miss),
            "miss_cause is null or a cause with evidence".to_owned(),
        ),
    ]
}

/// `lossy_lines` decodes Git's output as UTF-8 with each invalid sequence replaced by U+FFFD and splits it
/// as Python's `str.splitlines` does.
fn lossy_lines(bytes: &[u8]) -> Vec<String> {
    Text::from(String::from_utf8_lossy(bytes).into_owned())
        .splitlines()
        .iter()
        .map(|line| {
            line.to_str()
                .expect("a decoded line holds no surrogate")
                .to_owned()
        })
        .collect()
}

/// `patch_paths` checks the patch with `git apply --numstat` and `--summary`: it must change some path,
/// exactly the record's files, and only file contents.
fn patch_paths(
    env: &Environ,
    top: &Path,
    name: &Text,
    mut files: Vec<&Text>,
    patch: &[u8],
) -> Result<(), Stop> {
    let args = |flag: &'static str| [OsStr::new("apply"), OsStr::new(flag)];
    let stats = git::bytes(env, top, &args("--numstat"), patch).map_err(Stop::git)?;
    let mut paths: Vec<Text> = lossy_lines(&stats.stdout)
        .iter()
        .filter(|line| line.matches('\t').count() >= 2)
        .map(|line| Text::from(line.splitn(3, '\t').last().expect("a split yields a part")))
        .collect();
    if stats.code != 0 || paths.is_empty() {
        let err = String::from_utf8_lossy(&stats.stderr).into_owned();
        let lines = lossy_lines(strip_str(&err).as_bytes());
        let first = lines.first().map_or("it changes no path", String::as_str);
        return Err(rejected(name, format!("plant.patch is no patch: {first}")));
    }
    paths.sort();
    files.sort();
    if !paths.iter().eq(files.iter().copied()) {
        let mut reason = Text::from("plant.patch changes ");
        reason.push_text(&Text::join(", ", &paths));
        reason.push_str(", and files names ");
        reason.push_text(&Text::join(", ", files.iter().copied()));
        return Err(rejected(name, reason));
    }
    let Done { stdout, .. } = git::bytes(env, top, &args("--summary"), patch).map_err(Stop::git)?;
    let lines = lossy_lines(&stdout);
    let odd = lines.iter().map(|line| strip_str(line)).find(|line| {
        ODD.iter().any(|prefix| line.starts_with(prefix))
            || (line.starts_with("create mode ") && !line.starts_with("create mode 100644 "))
    });
    if let Some(odd) = odd {
        return Err(rejected(
            name,
            format!("plant.patch does more than change file contents: {odd}"),
        ));
    }
    Ok(())
}

/// `split_fields` splits `line` at runs of whitespace into at most `most` fields, the last holding the
/// rest of the line from its first code point outside the whitespace, as Python's `str.split(None, most -
/// 1)` does.
fn split_fields(line: &str, most: usize) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut rest = line.trim_start_matches(|c: char| is_space(u32::from(c)));
    while !rest.is_empty() {
        if fields.len() + 1 == most {
            fields.push(rest);
            break;
        }
        let end = rest
            .find(|c: char| is_space(u32::from(c)))
            .unwrap_or(rest.len());
        fields.push(&rest[..end]);
        rest = rest[end..].trim_start_matches(|c: char| is_space(u32::from(c)));
    }
    fields
}

/// `committed` refuses `data`, read at `relative` under the top, unless `head` holds those bytes there
/// as a regular file of mode 100644.
fn committed(
    env: &Environ,
    top: &Path,
    head: &str,
    relative: &str,
    data: &[u8],
) -> Result<(), Stop> {
    let listing = [
        OsStr::new("ls-tree"),
        OsStr::new("-z"),
        OsStr::new(head),
        OsStr::new("--"),
        OsStr::new(relative),
    ];
    let listed = git::text(env, top, &listing).map_err(Stop::git)?.stdout;
    let listed: Vec<&str> = listed.trim_end_matches('\0').split('\0').collect();
    let fields = match listed.as_slice() {
        [only] if !only.is_empty() => split_fields(only, 4),
        _ => Vec::new(),
    };
    let blob = match fields.as_slice() {
        ["100644", "blob", object, _] => {
            let show = [
                OsStr::new("cat-file"),
                OsStr::new("blob"),
                OsStr::new(object),
            ];
            Some(git::bytes(env, top, &show, b"").map_err(Stop::git)?.stdout)
        }
        _ => None,
    };
    if blob.as_deref() != Some(data) {
        return Err(Stop::rejected(format!(
            "the plant store differs from HEAD at {relative}; commit the plants first"
        )));
    }
    Ok(())
}

/// `load_plant` reads and checks the plant in `directory`, a directory of the store named `name`, against
/// the head commit `head`.
///
/// # Errors
///
/// The first check that fails, in the order the module states, refuses the plant with its reason; a Git
/// call that cannot run or prints no UTF-8 text is a failure.
pub(super) fn load_plant(
    env: &Environ,
    top: &Path,
    head: &str,
    directory: &Path,
) -> Result<Plant, Stop> {
    let name = Text::from_os(directory.file_name().unwrap_or_default());
    let (record_path, patch_path) = (directory.join("plant.json"), directory.join("plant.patch"));
    let (data, patch, value) = files_and_record(&name, &record_path, &patch_path)?;
    let record = match value {
        Value::Object(record) if keys(&record, &FIELDS) => record,
        _ => {
            return Err(rejected(
                &name,
                format!("plant.json holds exactly the fields {}", FIELDS.join(", ")),
            ));
        }
    };
    for (holds, rule) in rules(&name, &record) {
        if !holds {
            return Err(rejected(&name, rule));
        }
    }
    let files = list(&record, "files");
    patch_paths(env, top, &name, files, &patch)?;
    let id = name.to_str().expect("a checked id is ASCII");
    for (file, held) in [("plant.json", &data), ("plant.patch", &patch)] {
        committed(env, top, head, &format!("{STORE}/{id}/{file}"), held)?;
    }
    Ok(Plant { record, patch })
}
