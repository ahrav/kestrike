//! The receipt's `fis` section and its verdict rules.
//!
//! A section holds a verdict of `HELD` with a `first_failure` of null until a rule records a failure;
//! from then on the verdict is `INVALID`, `INCONCLUSIVE` or `DISPROVEN` and `first_failure` holds its
//! reason. [`Section::fail`] records a failure only while none stands. [`Section::contaminate`] and
//! [`Section::disprove`] replace a standing failure in the two cases they name, each keeping the
//! replaced reason as `diagnostic`. The rules own `verdict`, `first_failure` and `diagnostic`, and
//! [`Section::set_status`] owns `status`: [`Section::insert`] and [`Section::remove`] refuse those
//! four keys, so their values keep the shapes the rules read.

use std::fmt;
use std::fs;
use std::path::Path;

use super::failure::Failure;
use crate::json::{Integer, Object, Value};
use crate::python;
use crate::text::{Text, newlines};

/// Where the kernel gives the NVMe driver's I/O timeout, which a section records as
/// `kernel_nvme_io_timeout`.
pub const NVME_IO_TIMEOUT: &str = "/sys/module/nvme_core/parameters/io_timeout";

/// The keys the rules and [`Section::set_status`] own.
const OWNED: [&str; 4] = ["verdict", "first_failure", "diagnostic", "status"];

/// A verdict that records a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Invalid,
    Inconclusive,
    Disproven,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "INVALID",
            Self::Inconclusive => "INCONCLUSIVE",
            Self::Disproven => "DISPROVEN",
        }
    }
}

/// The run status a section records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    NotStarted,
    Completed,
    Halted,
    FailedToInject,
    ControllerLost,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "NOT_STARTED",
            Self::Completed => "COMPLETED",
            Self::Halted => "HALTED",
            Self::FailedToInject => "FAILED_TO_INJECT",
            Self::ControllerLost => "CONTROLLER_LOST",
        }
    }
}

/// [`Section::insert`] or [`Section::remove`] named a key the rules own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Owned(pub &'static str);

impl fmt::Display for Owned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the section's {} is set by its rules alone", self.0)
    }
}

impl std::error::Error for Owned {}

/// What a section records before any phase: the values a manifest and an operator file give, each
/// as it stands there.
#[derive(Clone, Debug)]
pub struct Opening {
    /// The profile's name in the manifest.
    pub profile: Text,
    pub episode: Text,
    /// The profile's `action`.
    pub action: Value,
    /// The profile's `attachment`.
    pub attachment: Value,
    /// The operator file's `volumes`.
    pub targets: Value,
    /// The profile's `timeout_io_us`.
    pub test_timeout_io_us: Value,
    /// The manifest's `production_timeout_io_us`.
    pub production_timeout_io_us: Value,
    /// The text [`kernel_timeout`] read, or none.
    pub kernel_nvme_io_timeout: Option<Text>,
}

/// The receipt's `fis` section: its members in the order they were first set.
#[derive(Clone, Debug, PartialEq)]
pub struct Section {
    members: Object,
}

impl Section {
    /// The section before any phase: `profile`, `episode`, `action`, `attachment`, `targets`, a
    /// `status` of `NOT_STARTED`, a `verdict` of `HELD`, a null `first_failure`, a null `abort`, a
    /// false `release_proof` and `timeouts` with the three timeouts, the kernel's null when unread.
    pub fn new(opening: Opening) -> Self {
        let mut timeouts = Object::new();
        timeouts.insert("test_timeout_io_us", opening.test_timeout_io_us);
        timeouts.insert("production_timeout_io_us", opening.production_timeout_io_us);
        timeouts.insert(
            "kernel_nvme_io_timeout",
            opening
                .kernel_nvme_io_timeout
                .map_or(Value::Null, Value::String),
        );
        let mut members = Object::new();
        members.insert("profile", Value::String(opening.profile));
        members.insert("episode", Value::String(opening.episode));
        members.insert("action", opening.action);
        members.insert("attachment", opening.attachment);
        members.insert("targets", opening.targets);
        members.insert("status", text(Status::NotStarted.as_str()));
        members.insert("verdict", text("HELD"));
        members.insert("first_failure", Value::Null);
        members.insert("abort", Value::Null);
        members.insert("release_proof", Value::Bool(false));
        members.insert("timeouts", Value::Object(timeouts));
        Self { members }
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.members.get(key)
    }

    /// The member `key` for a change in place, or none for an absent key and a key the rules own.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        if OWNED.contains(&key) {
            return None;
        }
        self.members.get_mut(key)
    }

    pub fn contains(&self, key: &str) -> bool {
        self.members.get(key).is_some()
    }

    pub fn members(&self) -> &Object {
        &self.members
    }

    /// Sets the member `key`, in the place it holds when it stands.
    ///
    /// # Errors
    ///
    /// [`Owned`] for a key the rules own; the section stays as it was.
    pub fn insert(&mut self, key: &str, value: Value) -> Result<(), Owned> {
        owned(key)?;
        self.members.insert(key, value);
        Ok(())
    }

    /// Removes the member `key` and returns it, or none when it is absent.
    ///
    /// # Errors
    ///
    /// [`Owned`] for a key the rules own; the section stays as it was.
    pub fn remove(&mut self, key: &str) -> Result<Option<Value>, Owned> {
        owned(key)?;
        Ok(self.members.remove(key))
    }

    pub fn set_status(&mut self, status: Status) {
        self.members.insert("status", text(status.as_str()));
    }

    /// The receipt: `envelope` of version 1 and section `fis`, and the section as `fis`.
    pub fn receipt(&self) -> Value {
        let mut envelope = Object::new();
        envelope.insert("version", Value::Integer(Integer::from(1u64)));
        envelope.insert("section", text("fis"));
        let mut receipt = Object::new();
        receipt.insert("envelope", Value::Object(envelope));
        receipt.insert("fis", Value::Object(self.members.clone()));
        Value::Object(receipt)
    }

    /// While `first_failure` is null, records `reason` as `first_failure` with `verdict`, and `status`
    /// where one is given; a standing failure stays as it is.
    pub fn fail(&mut self, verdict: Verdict, reason: Text, status: Option<Status>) {
        if self.members.get("first_failure") != Some(&Value::Null) {
            return;
        }
        self.members.insert("first_failure", Value::String(reason));
        self.members.insert("verdict", text(verdict.as_str()));
        if let Some(status) = status {
            self.set_status(status);
        }
    }

    /// A failure another principal's experiment may have caused. A `DISPROVEN` verdict becomes
    /// `INCONCLUSIVE`: its reason moves to `diagnostic`, and `first_failure` takes the diagnostic that
    /// stood before when that was a nonempty text, else `reason`. Under any other verdict it is
    /// [`Section::fail`] with `INCONCLUSIVE` and no status.
    pub fn contaminate(&mut self, reason: Text) {
        if !self.verdict_is(Verdict::Disproven) {
            return self.fail(Verdict::Inconclusive, reason, None);
        }
        let earlier = self.members.get("diagnostic").cloned();
        let standing = self
            .members
            .get("first_failure")
            .cloned()
            .unwrap_or(Value::Null);
        self.members.insert("diagnostic", standing);
        let first = match earlier {
            Some(earlier) if python::truthy(&earlier) => earlier,
            _ => Value::String(reason),
        };
        self.members.insert("first_failure", first);
        self.members
            .insert("verdict", text(Verdict::Inconclusive.as_str()));
    }

    /// A case that failed or died after the fault started. With no failure standing, or no
    /// `effect_window` recorded, it is [`Section::fail`] with `DISPROVEN` and no status. Otherwise an
    /// `INCONCLUSIVE` failure moves to `diagnostic` and `reason` stands as a `DISPROVEN` one; an
    /// `INVALID` or `DISPROVEN` failure stays as it is.
    pub fn disprove(&mut self, reason: Text) {
        if self.members.get("first_failure") == Some(&Value::Null)
            || !self.contains("effect_window")
        {
            return self.fail(Verdict::Disproven, reason, None);
        }
        if self.verdict_is(Verdict::Inconclusive) {
            let standing = self
                .members
                .get("first_failure")
                .cloned()
                .unwrap_or(Value::Null);
            self.members.insert("diagnostic", standing);
            self.members.insert("first_failure", Value::String(reason));
            self.members
                .insert("verdict", text(Verdict::Disproven.as_str()));
        }
    }

    fn verdict_is(&self, verdict: Verdict) -> bool {
        matches!(self.members.get("verdict"), Some(Value::String(standing)) if *standing == verdict.as_str())
    }
}

/// The text at `path` stripped of Python's whitespace, read as UTF-8 with `\r\n` and `\r` read as
/// `\n`, or none when the read fails.
///
/// # Errors
///
/// [`Failure::Unreadable`] for bytes that are no UTF-8.
pub fn kernel_timeout(path: &Path) -> Result<Option<Text>, Failure> {
    let Ok(bytes) = fs::read(path) else {
        return Ok(None);
    };
    let text = String::from_utf8(bytes).map_err(|_| {
        let shown = Text::from_os(path.as_os_str()).repr();
        Failure::Unreadable(Text::from(format!("{shown} holds bytes that are no UTF-8")))
    })?;
    Ok(Some(Text::from(newlines(text)).strip()))
}

fn owned(key: &str) -> Result<(), Owned> {
    match OWNED.iter().find(|owned| **owned == key) {
        Some(owned) => Err(Owned(owned)),
        None => Ok(()),
    }
}

fn text(value: &str) -> Value {
    Value::String(Text::from(value))
}
