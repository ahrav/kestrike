//! The custody marker `<custody>/fis-<episode>.json`, which quarantines the host for the next sweep
//! and campaign while an episode's fault or its case is in doubt.
//!
//! The marker is one line, `json.dumps(record, sort_keys=True)` and a line feed, written whole by
//! [`write_file`]. Its record holds a null `pgid`, the boot identity or null as `boot`, the episode,
//! the lane's profile and role, the doubts joined by `; ` as `custody`, and `durable` true while the
//! fault is in doubt: the section records `fault_end_unconfirmed` truthy, or records no
//! `custody_unknown`. A durable marker holds across boots; a marker for a case in doubt alone holds
//! for this boot.
//!
//! [`Marker::write`] records the marker's path as the section's `quarantine` once the write stands.
//! [`Marker::remove`] unlinks the name, a link at it included, syncs the directory and drops
//! `quarantine`; with nothing at the name it does nothing. A failed write or removal returns the
//! system's error and leaves the section as it was.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::failure::{Failure, SystemError};
use super::section::Section;
use super::whole::{episode_file, exists, is_symlink, parent, sync, write_file};
use crate::hardware_host::boot_id;
use crate::host_stop::Files;
use crate::json::{self, Object, Value};
use crate::python::{str_of, truthy};
use crate::text::{Text, text};

/// The marker of one episode under one lane profile and role.
#[derive(Clone, Debug)]
pub struct Marker {
    path: PathBuf,
    shown: Text,
    episode: Text,
    profile: Text,
    role: Text,
    boot: PathBuf,
}

/// What the marker's text reads of the episode's progress beside its section.
#[derive(Clone, Debug, Default)]
pub struct Progress {
    /// The experiment the controller's own start acknowledged.
    pub experiment_id: Option<Text>,
    /// Whether that experiment was observed in a terminal state.
    pub terminal: bool,
    /// The `request` tag of the template's creation request, once it was sent.
    pub lost_creation: Option<Text>,
    /// Whether the template is confirmed gone.
    pub template_gone: bool,
    /// Whether a start request was sent.
    pub requested: bool,
    /// The volumes' restoration: confirmed, refused, or not polled.
    pub restoration: Option<bool>,
}

/// When a marker is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Moment {
    /// While the episode runs: the fault in doubt is named as one doubt.
    During,
    /// After the episode: each doubt of the fault is named apart.
    Final,
}

impl Marker {
    /// The marker `<custody>/fis-<episode>.json` in Python's pure form, whose writes read the boot
    /// identity at `boot`. The episode is joined as a path, so a caller passes an episode of one file
    /// name component.
    pub fn new(custody: &OsStr, episode: &OsStr, profile: Text, role: Text, boot: PathBuf) -> Self {
        let path = episode_file(custody.as_bytes(), episode, ".json");
        Self {
            shown: Text::from_os(path.as_os_str()),
            path,
            episode: Text::from_os(episode),
            profile,
            role,
            boot,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The marker's path as text, as the section records it.
    pub fn shown(&self) -> &Text {
        &self.shown
    }

    /// The marker's line for the section and the episode as they stand, with `boot` as its boot
    /// identity. `note` says when the marker is written and `request` is the creation request's tag
    /// where the caller has one to name.
    ///
    /// # Errors
    ///
    /// [`Failure::Unreadable`] where `unconfirmed_experiments` is a number, a boolean or null that is
    /// truthy, or an experiment to name is no text.
    fn text(
        &self,
        section: &Section,
        progress: &Progress,
        note: &str,
        request: Option<&Text>,
        moment: Moment,
        boot: Option<Text>,
    ) -> Result<String, Failure> {
        let in_doubt = fault_in_doubt(section);
        let doubts = doubts(section, progress, note, request, moment, in_doubt)?;
        let mut record = Object::new();
        record.insert("pgid", Value::Null);
        record.insert("boot", boot.map_or(Value::Null, Value::String));
        record.insert("episode", Value::String(self.episode.clone()));
        record.insert("profile", Value::String(self.profile.clone()));
        record.insert("role", Value::String(self.role.clone()));
        record.insert("custody", Value::String(Text::join("; ", &doubts)));
        if in_doubt {
            record.insert("durable", Value::Bool(true));
        }
        let mut line = json::line_sorted(&Value::Object(record));
        line.push('\n');
        Ok(line)
    }

    /// Writes the marker's line with the boot identity read as the write starts, then records the
    /// marker's path as the section's `quarantine`.
    ///
    /// # Errors
    ///
    /// The errors of [`Marker::text`], and the system error of [`write_file`], with the section
    /// unchanged.
    pub fn write(
        &self,
        files: &impl Files,
        section: &mut Section,
        progress: &Progress,
        note: &str,
        request: Option<&Text>,
        moment: Moment,
    ) -> Result<(), Failure> {
        let line = self.text(
            section,
            progress,
            note,
            request,
            moment,
            boot_id(&self.boot),
        )?;
        write_file(files, &self.path, &line)?;
        section
            .insert("quarantine", Value::String(self.shown.clone()))
            .expect("quarantine is no key the rules own");
        Ok(())
    }

    /// Where an entry stands at the marker's name, followed or not, unlinks it, syncs the directory and
    /// drops the section's `quarantine`. With no entry at the name, nothing changes.
    ///
    /// # Errors
    ///
    /// [`Unremoved::Check`] for a check of the name that fails other than by an absence, before any
    /// removal; [`Unremoved::Removal`] for a failed unlink, and for a failed sync after the unlink
    /// stood. The section is unchanged in each case.
    pub fn remove(&self, files: &impl Files, section: &mut Section) -> Result<(), Unremoved> {
        let present = exists(files, &self.path)
            .and_then(|exists| Ok(exists || is_symlink(files, &self.path)?));
        if !present.map_err(Unremoved::Check)? {
            return Ok(());
        }
        fs::remove_file(&self.path)
            .map_err(|error| Unremoved::Removal(SystemError::of(&error, &[&self.path])))?;
        sync(files, &parent(&self.path)).map_err(Unremoved::Removal)?;
        section
            .remove("quarantine")
            .expect("quarantine is no key the rules own");
        Ok(())
    }
}

/// Why [`Marker::remove`] left the section as it was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unremoved {
    /// The check of what stands at the name failed; nothing was removed.
    Check(SystemError),
    /// The unlink failed, or the directory's sync after it did, so the removal may not survive a
    /// crash.
    Removal(SystemError),
}

impl std::fmt::Display for Unremoved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Check(error) | Self::Removal(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for Unremoved {}

/// Whether the fault is in doubt: `fault_end_unconfirmed` truthy, or no `custody_unknown`.
fn fault_in_doubt(section: &Section) -> bool {
    section.get("fault_end_unconfirmed").is_some_and(truthy) || !section.contains("custody_unknown")
}

/// The doubts the marker names, in order.
fn doubts(
    section: &Section,
    progress: &Progress,
    note: &str,
    request: Option<&Text>,
    moment: Moment,
    in_doubt: bool,
) -> Result<Vec<Text>, Failure> {
    let named = experiments(section, progress)?;
    let start_token = shown(section, "start_token");
    let tag = request
        .filter(|request| !request.is_empty())
        .cloned()
        .map(Value::String)
        .or_else(|| {
            section
                .get("template_unconfirmed")
                .filter(|value| truthy(value))
                .cloned()
        })
        .unwrap_or_else(|| {
            progress
                .lost_creation
                .clone()
                .map_or(Value::Null, Value::String)
        });
    let tag = str_of(&tag);
    let template = ["template_id", "template_retained"]
        .iter()
        .find_map(|key| section.get(key).filter(|value| truthy(value)))
        .map_or_else(|| text!("tagged request=", &tag), str_of);
    let fault = text!(
        "the FIS fault's end is unconfirmed (",
        note,
        "): experiment ",
        &Text::join(", ", &named),
        ", template ",
        &template,
        ", start token ",
        &start_token
    );
    let mut doubts = Vec::new();
    if in_doubt && moment == Moment::Final {
        let lost = progress
            .lost_creation
            .as_ref()
            .is_some_and(|lost| !lost.is_empty());
        if section.get("template_retained").is_some_and(truthy) || (lost && !progress.template_gone)
        {
            doubts.push(text!(
                "the FIS template ",
                &template,
                " may remain and admits starts (",
                note,
                "); delete it or confirm the tag request=",
                &tag,
                " lists none"
            ));
        }
        if let Some(listed) = section
            .get("template_experiments_unconfirmed")
            .filter(|value| truthy(value))
        {
            doubts.push(text!(
                "the experiments of the deleted FIS template ",
                &template,
                " are unconfirmed (",
                note,
                "): ",
                &str_of(listed),
                "; list the experiments under the template's ID and confirm each ended with the \
                 volume restored"
            ));
        }
        let unrestored = progress.requested && progress.restoration != Some(true);
        if ["unconfirmed_experiments", "start_unconfirmed"]
            .iter()
            .any(|key| section.get(key).is_some_and(truthy))
            || section.contains("unbound_targets")
            || section.get("binding_unconfirmed").is_some_and(truthy)
            || unrestored
            || doubts.is_empty()
        {
            doubts.push(fault);
        }
    } else if in_doubt {
        doubts.push(fault);
    }
    if let Some(unknown) = section.get("custody_unknown") {
        doubts.push(text!(
            "the case's custody is unknown (",
            note,
            "): ",
            &str_of(unknown)
        ));
    }
    Ok(doubts)
}

/// The experiments the fault's doubt names: those of `unconfirmed_experiments`, the controller's own
/// first while it is not terminal and not among them, the unlisted start by its token where the
/// section records no `experiment_id` and either records `start_unconfirmed` or no other is named,
/// and the section's `experiment_id` where none is named.
fn experiments(section: &Section, progress: &Progress) -> Result<Vec<Text>, Failure> {
    let mut named = match section.get("unconfirmed_experiments") {
        Some(value) if truthy(value) => items(value)?,
        _ => Vec::new(),
    };
    if let Some(own) = progress
        .experiment_id
        .as_ref()
        .filter(|own| !own.is_empty())
    {
        let own = Value::String(own.clone());
        if !progress.terminal && !named.contains(&own) {
            named.insert(0, own);
        }
    }
    let recorded = section.get("experiment_id").filter(|value| truthy(value));
    if recorded.is_none()
        && (section.get("start_unconfirmed").is_some_and(truthy) || named.is_empty())
    {
        let token = shown(section, "start_token");
        named.push(Value::String(text!("the unlisted start tagged ", &token)));
    }
    if named.is_empty() {
        named.extend(recorded.cloned());
    }
    named
        .into_iter()
        .map(|value| match value {
            Value::String(name) => Ok(name),
            other => Err(Failure::Unreadable(Text::from(format!(
                "the experiment {} to name in the custody marker is no text",
                crate::python::repr(&other)
            )))),
        })
        .collect()
}

/// The items a list of a truthy value gives: an array's items, an object's keys and a string's code
/// points, each a text of one.
fn items(value: &Value) -> Result<Vec<Value>, Failure> {
    match value {
        Value::Array(items) => Ok(items.clone()),
        Value::Object(members) => Ok(members
            .iter()
            .map(|(key, _)| Value::String(key.clone()))
            .collect()),
        Value::String(string) => Ok(string
            .code_points()
            .filter_map(|code| Text::from_code_points([code]))
            .map(Value::String)
            .collect()),
        other => Err(Failure::Unreadable(Text::from(format!(
            "the section's unconfirmed_experiments {} holds no experiments",
            crate::python::repr(other)
        )))),
    }
}

/// The section's member `key` as Python's `str` gives it, `None` where it is absent.
fn shown(section: &Section, key: &str) -> Text {
    section.get(key).map_or_else(|| Text::from("None"), str_of)
}
