//! The marks of an episode, three files under the resolved artifacts directory that the case reads:
//! `fis-<episode>.started`, `fis-<episode>.ended` and `fis-<episode>.abandoned`; and [`event`], the
//! read of the observer log that finds a case's event.
//!
//! A mark of the fault's start or end takes three steps in order: it appends one event to the observer
//! log, records the event's ordinal in the section's `effect_window`, then writes the ordinal's digits
//! to the mark's file through [`write_file`]. A failed append changes nothing; a failed write leaves
//! the ordinal recorded. The start's mark is the one step that makes `effect_window`. The abandon mark
//! holds the text `abandoned`.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::failure::{Failure, SystemError};
use super::section::Section;
use super::whole::write_file;
use crate::hardware_host::{Clocks, Observer};
use crate::host_stop::{Files, Record};
use crate::json::{Integer, Object, Value};
use crate::paths;
use crate::python;
use crate::text::Text;

/// The role under which the controller appends to the observer log.
pub const ROLE: &str = "fis";

/// The limit of each wait for the observer log's lock, in seconds: the lane's own limit.
pub const OBSERVER_SECONDS: f64 = 5.0;

/// The kind of the event that marks the fault's start.
pub const FAULT_START: &str = "fault-start";

/// The kind of the event that marks the fault's end.
pub const FAULT_END: &str = "fault-end";

/// The controller's observer log of `episode` under the lane's `profile`: [`ROLE`] as its role and
/// [`OBSERVER_SECONDS`] as its lock's limit.
pub fn observer(directory: &OsStr, episode: &OsStr, profile: Text) -> Observer {
    Observer::new(
        directory,
        episode,
        profile,
        Text::from(ROLE),
        Duration::from_secs_f64(OBSERVER_SECONDS),
    )
}

/// The three marks of one episode.
#[derive(Clone, Debug)]
pub struct Marks {
    started: PathBuf,
    ended: PathBuf,
    abandoned: PathBuf,
}

impl Marks {
    /// The marks of `episode` under `artifacts` resolved, the mark's own name kept, so a link at a
    /// mark's name stands as a link. The episode is joined as a path, so a caller passes an episode
    /// of one file name component.
    ///
    /// # Errors
    ///
    /// The error of the resolve: an unreadable working directory for a relative path, a link that
    /// cannot be read, links nested too deep, or a link loop.
    pub fn new(artifacts: &Path, episode: &OsStr) -> Result<Self, SystemError> {
        let resolved = paths::resolve(artifacts).map_err(|error| SystemError::of(&error, &[]))?;
        let mark = |suffix: &str| {
            let mut name = b"fis-".to_vec();
            name.extend_from_slice(episode.as_bytes());
            name.extend_from_slice(suffix.as_bytes());
            let joined = paths::join(resolved.as_os_str().as_bytes(), &name);
            PathBuf::from(OsStr::from_bytes(&paths::pure_bytes(&joined)))
        };
        Ok(Self {
            started: mark(".started"),
            ended: mark(".ended"),
            abandoned: mark(".abandoned"),
        })
    }

    pub fn started(&self) -> &Path {
        &self.started
    }

    pub fn ended(&self) -> &Path {
        &self.ended
    }

    pub fn abandoned(&self) -> &Path {
        &self.abandoned
    }

    /// Marks the fault's start of `experiment`: appends a [`FAULT_START`] event with `experiment`,
    /// sets the section's `effect_window` to `{"start_ordinal": <ordinal>}` and writes the ordinal to
    /// the started mark. Returns the ordinal.
    ///
    /// # Errors
    ///
    /// The append's failure, with the section unchanged; [`Failure::Unreadable`] where the episode has
    /// no observer log, with nothing changed; the write's system error, with `effect_window` set.
    pub fn start(
        &self,
        files: &impl Files,
        observer: &Observer,
        clocks: &mut impl Clocks,
        record: &mut Record<'_>,
        section: &mut Section,
        experiment: &Text,
    ) -> Result<Value, Failure> {
        let ordinal = append(observer, clocks, record, FAULT_START, experiment)?;
        let mut window = Object::new();
        window.insert("start_ordinal", ordinal.clone());
        section
            .insert("effect_window", Value::Object(window))
            .expect("effect_window is no key the rules own");
        write_file(files, &self.started, &python::str_of(&ordinal).to_string())?;
        Ok(ordinal)
    }

    /// Marks the fault's end of `experiment`: appends a [`FAULT_END`] event with `experiment`, sets
    /// `end_ordinal` in the section's `effect_window` and writes the ordinal to the ended mark.
    /// Returns the ordinal.
    ///
    /// # Errors
    ///
    /// The append's failure, with the section unchanged; [`Failure::Unreadable`] where the episode has
    /// no observer log, with nothing changed, and where the section holds no `effect_window` object,
    /// after the event was appended; the write's system error, with `end_ordinal` set.
    pub fn end(
        &self,
        files: &impl Files,
        observer: &Observer,
        clocks: &mut impl Clocks,
        record: &mut Record<'_>,
        section: &mut Section,
        experiment: &Text,
    ) -> Result<Value, Failure> {
        let ordinal = append(observer, clocks, record, FAULT_END, experiment)?;
        let Some(Value::Object(window)) = section.get_mut("effect_window") else {
            return Err(Failure::Unreadable(Text::from(
                "the section records no effect window to end",
            )));
        };
        window.insert("end_ordinal", ordinal.clone());
        write_file(files, &self.ended, &python::str_of(&ordinal).to_string())?;
        Ok(ordinal)
    }

    /// Writes the abandon mark, which holds `abandoned`.
    ///
    /// # Errors
    ///
    /// The write's system error.
    pub fn abandon(&self, files: &impl Files) -> Result<(), SystemError> {
        write_file(files, &self.abandoned, "abandoned")
    }
}

/// Appends one event of `kind` with `experiment` and returns its `ordinal`.
fn append(
    observer: &Observer,
    clocks: &mut impl Clocks,
    record: &mut Record<'_>,
    kind: &str,
    experiment: &Text,
) -> Result<Value, Failure> {
    let mut fields = Object::new();
    fields.insert("experiment", Value::String(experiment.clone()));
    let Some(event) = observer.append(clocks, record, kind, fields)? else {
        return Err(Failure::Unreadable(Text::from(
            "the episode has no observer log, so a mark has no ordinal",
        )));
    };
    event
        .get("ordinal")
        .cloned()
        .ok_or_else(|| Failure::Unreadable(Text::from("the appended event holds no ordinal")))
}

/// The first event of one read of the log whose `name` is `name`, whose `ordinal` is past `after`, and
/// whose `profile` and `role` are the lane's. The members are compared in that order, and the read
/// ends at the first event that matches. An `ordinal` that is a boolean counts as 0 or 1, a float
/// compares by its exact value, and a NaN is past nothing.
///
/// # Errors
///
/// The read's failure, and [`Failure::Unreadable`] for an event up to the one found that is no object,
/// and for one whose name matches with no `ordinal` or with one that is no number.
pub fn event(
    observer: &Observer,
    clocks: &mut impl Clocks,
    record: &mut Record<'_>,
    name: &str,
    after: &Integer,
    profile: &Text,
    role: &Text,
) -> Result<Option<Object>, Failure> {
    for event in observer.events(clocks, record)? {
        let Value::Object(event) = event else {
            return Err(Failure::Unreadable(Text::from(format!(
                "an observer event is no object: {}",
                python::repr(&event)
            ))));
        };
        if !matches!(event.get("name"), Some(Value::String(found)) if *found == name) {
            continue;
        }
        let Some(ordinal) = event.get("ordinal") else {
            return Err(Failure::Unreadable(Text::from(
                "an observer event has no member \"ordinal\"",
            )));
        };
        if !past(ordinal, after)? {
            continue;
        }
        let ours = |key: &str, want: &Text| matches!(event.get(key), Some(Value::String(found)) if found == want);
        if ours("profile", profile) && ours("role", role) {
            return Ok(Some(event));
        }
    }
    Ok(None)
}

/// Whether `ordinal` is greater than `after` by value.
fn past(ordinal: &Value, after: &Integer) -> Result<bool, Failure> {
    match ordinal {
        Value::Integer(ordinal) => Ok(ordinal > after),
        Value::Bool(flag) => Ok(Integer::from(u64::from(*flag)) > *after),
        Value::Float(value) if value.is_nan() => Ok(false),
        Value::Float(value) if value.is_infinite() => Ok(*value > 0.0),
        Value::Float(value) => {
            let whole =
                python::int(ordinal).map_err(|reason| Failure::Unreadable(Text::from(reason)))?;
            Ok(match whole.cmp(after) {
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Equal => *value > value.trunc(),
            })
        }
        other => Err(Failure::Unreadable(Text::from(format!(
            "an observer event's ordinal {} has no order beside an integer",
            python::repr(other)
        )))),
    }
}
