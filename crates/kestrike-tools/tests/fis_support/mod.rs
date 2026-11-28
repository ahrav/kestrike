//! What the FIS controller's cases share: the checkout's top, the checked-in FIS profiles file, an
//! operator contract every check admits, the inputs of one run changed at a path, a scratch directory
//! per case, and the rejections of a run's inputs as one table in [`rejections`].

#![cfg(target_os = "linux")]

pub(crate) mod rejections;

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use kestrike_tools::hardware_lane::manifest_path;
use kestrike_tools::json::{self, Text, Value};
use kestrike_tools::temp_dir::make_temp_dir;

/// The volume of the base contract.
pub(crate) const VOLUME: &str = "vol-0123456789abcdef0";

/// The checkout's top level.
pub(crate) fn tree() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the checkout's top resolves")
}

/// The checked-in hardware manifest.
pub(crate) fn hardware_manifest() -> PathBuf {
    manifest_path(&tree())
}

/// The decoded JSON of `text`.
pub(crate) fn value(text: &str) -> Value {
    json::parse(text).unwrap_or_else(|error| panic!("{text}: {error}"))
}

/// The checked-in FIS profiles file, decoded.
pub(crate) fn profiles() -> Value {
    let path = tree().join("scripts/fis-profiles.json");
    value(&fs::read_to_string(&path).expect("the FIS profiles file reads"))
}

/// An operator contract every check admits, with an effect timeout of `effect` seconds.
pub(crate) fn operator(effect: &str) -> Value {
    value(&format!(
        r#"{{"account": "111122223333", "region": "us-east-1", "role_arn": "arn:aws:iam::1:role/fis",
            "volumes": ["{VOLUME}"], "attachments": {{"{VOLUME}": ["i-1"]}},
            "effect_timeout_seconds": {effect}, "stop_alarms": []}}"#
    ))
}

/// The profile `name` of the checked-in FIS profiles file.
pub(crate) fn profile(name: &str) -> Value {
    member(&profiles(), &["profiles", name]).clone()
}

/// The member of `document` at `path`.
pub(crate) fn member<'a>(document: &'a Value, path: &[&str]) -> &'a Value {
    path.iter().fold(document, |at, key| match at {
        Value::Object(object) => object.get(key).unwrap_or_else(|| panic!("no member {key}")),
        other => panic!("{other:?} holds no member {key}"),
    })
}

/// One input a run reads: the decoded operator contract or FIS profiles file, or the text of an argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Input {
    Operator,
    Profiles,
    /// `--episode`.
    Episode,
    /// The chosen profiles, in order: `--profile` alone, or the names of `--profiles`.
    Names,
    /// `--kill-grace-seconds`.
    Grace,
    /// `--poll`.
    Poll,
}

/// A change of one input: at the path, the JSON text of the new value, or none to remove the member.
/// An argument's path is empty.
pub(crate) type Change = (Input, &'static [&'static str], Option<&'static str>);

/// The inputs of one run: a decoded contract and profiles file, and the arguments the checks read.
#[derive(Clone, Debug)]
pub(crate) struct Inputs {
    pub(crate) operator: Value,
    pub(crate) profiles: Value,
    pub(crate) episode: Text,
    pub(crate) names: Vec<Text>,
    pub(crate) aws_seconds: f64,
    pub(crate) grace: f64,
    pub(crate) poll: Text,
}

impl Inputs {
    /// The base contract with a 2 s effect timeout, the checked-in profiles, the episode `e1`, the
    /// profile `fis-read-latency`, 60 s calls, the default kill grace of 900 s and a 2 s poll; every
    /// check admits them.
    pub(crate) fn base() -> Self {
        Self {
            operator: operator("2"),
            profiles: profiles(),
            episode: Text::from("e1"),
            names: vec![Text::from("fis-read-latency")],
            aws_seconds: 60.0,
            grace: 900.0,
            poll: Text::from("2"),
        }
    }

    /// The base inputs with `changes` applied in order.
    pub(crate) fn changed(changes: &[Change]) -> Self {
        let mut inputs = Self::base();
        for &(input, path, new) in changes {
            match input {
                Input::Operator => place(&mut inputs.operator, path, new),
                Input::Profiles => place(&mut inputs.profiles, path, new),
                Input::Episode => inputs.episode = text(&argument(new)),
                Input::Names => match argument(new) {
                    Value::Array(names) => inputs.names = names.iter().map(text).collect(),
                    other => panic!("a list of names, not {other:?}"),
                },
                Input::Grace => inputs.grace = real(&argument(new)),
                Input::Poll => inputs.poll = text(&argument(new)),
            }
        }
        inputs
    }
}

fn argument(new: Option<&str>) -> Value {
    value(new.expect("an argument takes a value"))
}

fn text(value: &Value) -> Text {
    match value {
        Value::String(text) => text.clone(),
        other => panic!("a string, not {other:?}"),
    }
}

fn real(value: &Value) -> f64 {
    match value {
        Value::Float(real) => *real,
        other => panic!("a float, not {other:?}"),
    }
}

/// Sets the member of `document` at `path` to the JSON `new`, or removes it for none; an empty path
/// replaces the whole document.
fn place(document: &mut Value, path: &[&str], new: Option<&str>) {
    let Some((last, parents)) = path.split_last() else {
        *document = value(new.expect("a whole document takes a value"));
        return;
    };
    let mut at = document;
    for key in parents {
        at = match at {
            Value::Object(object) => object
                .get_mut(key)
                .unwrap_or_else(|| panic!("no member {key}")),
            other => panic!("{other:?} holds no member {key}"),
        };
    }
    let Value::Object(object) = at else {
        panic!("{at:?} holds no member {last}");
    };
    match new {
        Some(new) => object.insert(*last, value(new)),
        None => {
            object
                .remove(last)
                .unwrap_or_else(|| panic!("no member {last}"));
        }
    }
}

/// A directory the case made with mode 0700 under the temporary directory, removed on drop.
pub(crate) struct Scratch(pub(crate) PathBuf);

impl Scratch {
    pub(crate) fn new(label: &str) -> Self {
        let parent = std::env::temp_dir()
            .canonicalize()
            .expect("the temporary directory resolves");
        let prefix = format!("kestrike-tools-fis-{label}-");
        Self(make_temp_dir(&prefix, &parent).expect("the scratch directory is made"))
    }

    /// Creates the file `name` in the directory, which must not stand yet, with `bytes`.
    pub(crate) fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .and_then(|mut file| file.write_all(bytes))
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
