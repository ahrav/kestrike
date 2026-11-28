//! Evidence checks and refusals that `restore` and `seal` both make.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::context::{Stream, beside, pure};
use super::controller::Controller;
use super::fault::{Fault, Halt};
use super::run::{TOOL, lock_sentence, probe_refusal};
use crate::gameday::{FleetBounds, ReadError};
use crate::host_stop::{Files, Lock, Seam, lock, probe, stands};
use crate::json::Value;
use crate::plants::files::strerror;
use crate::text::Text;

impl<S: Seam, F: Files> Controller<'_, '_, S, F> {
    /// The evidence root and `injection/` must each be a directory under `lstat`, and `probe` must
    /// succeed for `injection/`. `missing` ends the refusal of an `injection/` that is no
    /// directory.
    pub(super) fn evidence_dirs(
        &self,
        evidence: &OsStr,
        missing: &str,
    ) -> Result<(PathBuf, PathBuf), Halt> {
        let root = pure(evidence.as_bytes());
        let injection = beside(&root, "injection");
        if !self.directory(&root) {
            let mut sentence = Text::from_os(evidence);
            sentence.push_str(" is no directory");
            return Err(Halt::refused(sentence));
        }
        if !self.directory(&injection) {
            let mut sentence = Text::from_os(injection.as_os_str());
            sentence.push_str(" is no directory: ");
            sentence.push_str(missing);
            return Err(Halt::refused(sentence));
        }
        probe(self.cx.files, &injection).map_err(|error| probe_refusal(&injection, &error))?;
        Ok((root, injection))
    }

    fn directory(&self, path: &Path) -> bool {
        self.cx
            .files
            .lstat(path)
            .is_ok_and(|found| found.file_type().is_dir())
    }

    /// A missing mark yields `Ok(false)`; a lookup that fails otherwise is refused.
    pub(super) fn stands_in(&self, injection: &Path, name: &str) -> Result<bool, Halt> {
        stands(self.cx.files, &beside(injection, name)).map_err(|error| {
            Halt::refused(Text::from(format!(
                "injection/{name} cannot be looked up: {}",
                strerror(&error)
            )))
        })
    }

    /// The lock of `injection/` that `restore` and `seal` hold, on the directory the name gives. A
    /// run that holds the lock can remove its new `injection/` and free the lock between this
    /// command's open of that directory and its `flock`, which then succeeds on the removed
    /// directory; the lookup behind the lock refuses that. Once the lock is held on the directory
    /// at the name, no command removes it: a run removes `injection/` only under its lock.
    ///
    /// # Errors
    ///
    /// A refusal for a lock that cannot be opened or is taken, for a name that gives another
    /// directory than the one locked, and for a lookup of the name that fails, a name with no
    /// entry included.
    pub(super) fn locked(&self, injection: &Path) -> Result<Lock, Halt> {
        let files = self.cx.files;
        let held = lock(files, injection)
            .map_err(|error| Halt::refused(lock_sentence(injection, &error)))?;
        let mut sentence = Text::from_os(injection.as_os_str());
        match held.stands_at(files, injection) {
            Ok(true) => return Ok(held),
            Ok(false) => sentence.push_str(
                " is another directory than the one locked: the one this command opened was \
                 removed while it took the lock",
            ),
            Err(error) => sentence.push_str(&format!(
                " cannot be looked up behind its lock, so the directory locked may be another: {}",
                strerror(&error)
            )),
        }
        Err(Halt::refused(sentence))
    }

    /// Arms the record, runs `span`, passes its end through [`Controller::raised`] and disarms the
    /// record on every return. A panic in `span` unwinds with the record armed.
    pub(super) fn armed<T>(
        &mut self,
        span: impl FnOnce(&mut Self) -> Result<T, Halt>,
    ) -> Result<T, Halt> {
        self.cx.record.arm();
        let ended = span(self);
        let ended = self.raised(ended);
        self.cx.record.disarm();
        ended
    }

    pub(super) fn bounds(&self) -> Result<FleetBounds, Halt> {
        FleetBounds::new(self.cx.top, self.cx.file_limit)
            .ok_or_else(|| refused("the tree's top has a path no file can have"))
    }

    /// Prints the failed write of `file` on stderr. `Ok(true)` means the write linked the mark
    /// before it failed, so the mark is removed with the removal synced, removed with the removal
    /// unsynced, or standing whole, as the printed sentence says; `Ok(false)` means it failed
    /// through the link and left the name as it found it.
    pub(super) fn failed_write(&mut self, file: &str, failed: Halt) -> Result<bool, Halt> {
        let mut line = Text::from(TOOL);
        let linked = match failed {
            Halt::Fault(Fault::Unwritten(sentence)) => {
                line.push_text(&sentence);
                true
            }
            Halt::Fault(Fault::Os { code, text }) => {
                line.push_str(&format!("{file} is unwritten: {}", errno_text(code, &text)));
                false
            }
            Halt::Fault(Fault::Refusal(sentence)) => return Err(Halt::refused(sentence)),
            other => return Err(other),
        };
        self.cx.say(Stream::Err, &line);
        Ok(linked)
    }
}

pub(super) fn refused(sentence: &str) -> Halt {
    Halt::refused(Text::from(sentence))
}

/// Refuses a `roles.json` that names another package than the approval's `digest`.
pub(super) fn check_roles(roles: &Value, digest: &Text) -> Result<(), Halt> {
    let named = matches!(roles, Value::Object(roles)
        if matches!(roles.get("package_sha256"), Some(Value::String(named)) if named == digest));
    if named {
        return Ok(());
    }
    Err(refused(
        "injection/roles.json names another package than the approval's",
    ))
}

pub(super) fn other_package() -> Halt {
    refused("package.json holds other bytes than the approval's package")
}

pub(super) fn errno_text(code: Option<i32>, text: &str) -> String {
    match code {
        Some(code) => format!("[Errno {code}] {text}"),
        None => text.to_owned(),
    }
}

/// Read and open failures become refusals; a close failure becomes a system error with the
/// system's text.
pub(super) fn read_halt(error: ReadError) -> Halt {
    match error {
        ReadError::Refused(refusal) => refusal.into(),
        ReadError::Closed(text) => Halt::Fault(Fault::Os { code: None, text }),
        ReadError::Nul => unreachable!("a listed name and a pathname argument hold no NUL byte"),
    }
}
