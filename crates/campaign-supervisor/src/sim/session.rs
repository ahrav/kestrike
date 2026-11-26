//! Session credit requires the worker's output to agree with the verified session files.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{self, BufReader, Read};
use std::path::Path;

use super::class::{Stop, incomplete, rejected};
use super::command::{Command, REASON, Ran, input_read_error, new_output, text};
use super::evidence::{Frozen, evidence_read_error};
use super::input::Values;
use crate::exit::Sim;
use crate::protocol::{Session, SessionEnd, SessionEnding, SessionReplay, Terminal, WindowLine};
use crate::record::{BOUND, Digest, Hashing, SessionEvidence};
use crate::store::{Store, canonical_host, open_evidence, open_host, read_host};

const INDEX_BYTES: u64 = BOUND / 4;
const END_BYTES: u64 = BOUND / 64;
const DIAGNOSTIC_BYTES: usize = REASON;
// Index lines occupy at least 256 bytes; each JSON digest occupies 67 bytes.
const MAX_WINDOWS: u64 = INDEX_BYTES / 256;
const PATH_BYTES: u64 = 4096;
// Control-character escaping uses at most seven JSON bytes per raw byte.
// Lossy source paths use nine JSON bytes per byte; output and archive paths use two.
// Index newline escaping reserves four JSON bytes per retained window.
// Session commands leave the separate branch/explore Artifact.output field absent.
// The remaining fields reserve 8 KiB, three paths and three bounded diagnostics.
const ENVELOPE_MAX: u64 = 2 * INDEX_BYTES
    + 4 * MAX_WINDOWS
    + 2 * 67 * MAX_WINDOWS
    + 2 * 7 * END_BYTES
    + 3 * 7 * DIAGNOSTIC_BYTES as u64
    + 9 * PATH_BYTES
    + 2 * PATH_BYTES
    + 2 * PATH_BYTES
    + 8 * 1024;
const _: () = assert!(ENVELOPE_MAX < BOUND);

enum Metadata {
    Manifest,
    Index,
    End,
}

struct Checked {
    evidence: SessionEvidence,
    end: Result<SessionEnd, Stop>,
    files: Vec<Frozen>,
}
struct Verifier {
    evidence: SessionEvidence,
    files: Vec<Frozen>,
    budget: (u64, u64),
    confined: bool,
}

impl Command {
    /// Retains output after its barriers succeed. A phase stop keeps its class
    /// ahead of a non-poisoning barrier failure; an ordinary exit propagates the barrier.
    fn checked_output(&mut self, checked: &Checked, ran: Result<Ran, Stop>) -> Result<Ran, Stop> {
        let durable = checked.durable(&self.store);
        if durable.is_ok() {
            self.session = Some(checked.evidence.clone());
        }
        let ran = after_barrier(ran, &durable)?;
        durable?;
        Ok(ran)
    }

    pub(super) fn session(
        &mut self,
        archive: &Path,
        manifest: &Path,
        output: Option<&Path>,
    ) -> Result<Stop, Stop> {
        let target = new_output(
            &self.store,
            output.unwrap_or(&self.path("session")),
            "session",
            Some(&self.path("session")),
        )?;
        let mut archive = self.load(archive)?;
        let bytes = read(manifest, BOUND)?;
        let source = utf8(&bytes).map_err(rejected)?;
        let budget = budget(source).map_err(rejected)?;
        self.admit(&mut archive, source, &bytes, "manifest")?;
        let kept = self.path("manifest");
        let ran = self.phase(
            &mut archive,
            "session",
            &[
                OsStr::new("--session"),
                kept.as_os_str(),
                OsStr::new("--output"),
                target.as_os_str(),
            ],
        );
        if refused_before_output(&ran) {
            return Err(rejected("the worker refused the session"));
        }
        // Successful output barriers retain verified windows after a phase stop.
        let checked = check(&target, source, budget, true);
        let ran = self.checked_output(&checked, ran)?;
        if ran.code == 2 {
            return Err(incomplete("the refused session printed a result"));
        }
        let end = checked.valid().map_err(|stop| incomplete(stop.1))?;
        if let SessionEnding::Panicked(panic) = &end.end {
            return Err(incomplete(if ran.code == 3 && ran.stdout.is_empty() {
                format!("the session panicked: {panic}")
            } else {
                "the panicked session disagrees with its stdout or exit".to_owned()
            }));
        }
        let printed = Session::parse(&ran.stdout)
            .map_err(|error| incomplete(format!("the session output: {error}")))?;
        if printed.windows != checked.evidence.verified_windows
            || printed.chain != checked.evidence.chain
            || SessionEnding::Ended(printed.end) != end.end
        {
            return Err(incomplete(
                "the session output disagrees with its verified files",
            ));
        }
        let class = session_class(end, ran.code);
        mark(
            self.session.as_mut().expect("the output was checked"),
            class.0,
        );
        Ok(class)
    }

    pub(super) fn replay_session(
        &mut self,
        archive: &Path,
        source: &Path,
        output: Option<&Path>,
    ) -> Result<Stop, Stop> {
        let target = new_output(
            &self.store,
            output.unwrap_or(&self.path("replay-session")),
            "session replay",
            Some(&self.path("replay-session")),
        )?;
        let mut archive = self.load(archive)?;
        let source = canonical_host(source)
            .map_err(|error| input_read_error(&error.into(), "the source session"))?;
        let source = source.as_path();
        let bytes = read(&source.join("manifest"), BOUND)?;
        let manifest = utf8(&bytes).map_err(rejected)?;
        let budget = budget(manifest).map_err(rejected)?;
        let original = check(source, manifest, budget, false);
        let stored = self.session_original.insert(original.evidence.clone());
        let source_class = end_class(&original.valid()?.end);
        mark(stored, source_class);
        if source.to_str().is_none() {
            return Err(rejected("the source session path must be UTF-8"));
        }
        self.frozen.extend(original.files);
        self.admit(&mut archive, manifest, &bytes, "session")?;
        let ran = self.phase(
            &mut archive,
            "replay-session",
            &[
                OsStr::new("--replay-session"),
                source.as_os_str(),
                OsStr::new("--output"),
                target.as_os_str(),
            ],
        );
        if refused_before_output(&ran) {
            return Err(rejected("the worker refused the session replay"));
        }
        // Successful output barriers retain verified windows after a phase stop.
        let observed = check(&target, manifest, budget, true);
        let ran = self.checked_output(&observed, ran)?;
        if ran.code == 2 {
            return Err(incomplete("the refused session replay printed a result"));
        }
        let original_end = original.end.as_ref().expect("the source end verified");
        let observed_end = observed.valid().map_err(|stop| incomplete(stop.1))?;
        let equal = original.evidence.index == observed.evidence.index
            && original_end.reproduces(observed_end);
        if let SessionEnding::Panicked(panic) = &observed_end.end {
            return Err(incomplete(if ran.code == 3 && ran.stdout.is_empty() {
                format!("the session replay panicked: {panic}; reproduced={equal}")
            } else {
                "the panicked session replay disagrees with its stdout or exit".to_owned()
            }));
        }
        let verdict = SessionReplay::parse(&ran.stdout)
            .map_err(|error| incomplete(format!("the session replay output: {error}")))?;
        let observed_class = end_class(&observed_end.end);
        let class = match verdict {
            SessionReplay::Reproduced { windows, chain }
                if ran.code == 0
                    && equal
                    && windows == observed.evidence.verified_windows
                    && chain == observed.evidence.chain =>
            {
                observed_class
            }
            SessionReplay::Diverged(_) if ran.code == 1 && !equal => Sim::Complete,
            _ => {
                return Err(incomplete(
                    "the session replay verdict disagrees with its verified files or exit",
                ));
            }
        };
        if matches!(original_end.end, SessionEnding::Panicked(_)) {
            return Err(incomplete(
                "the panicked source session remains incomplete after replay",
            ));
        }
        let evidence = self.session.as_mut().expect("the output was checked");
        mark(evidence, observed_class);
        evidence.counts &= equal;
        Ok(Stop(
            class,
            if equal {
                "the session reproduced"
            } else {
                "the session diverged"
            }
            .to_owned(),
        ))
    }
}

fn refused_before_output(ran: &Result<Ran, Stop>) -> bool {
    ran.as_ref()
        .is_ok_and(|ran| ran.code == 2 && ran.stdout.is_empty())
}

fn after_barrier(ran: Result<Ran, Stop>, durable: &Result<(), Stop>) -> Result<Ran, Stop> {
    ran.map_err(|Stop(class, reason)| match durable {
        Err(stop) => Stop(class, format!("{reason}; {}", stop.1)),
        Ok(()) => Stop(class, reason),
    })
}

fn read(path: &Path, bound: u64) -> Result<Vec<u8>, Stop> {
    read_host(path, bound)
        .map_err(|error| input_read_error(&error, &format!("{} cannot be read", path.display())))?
        .ok_or_else(|| rejected(format!("{} is missing", path.display())))
}
fn utf8(bytes: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(bytes).map_err(|error| error.to_string())
}
fn assignments(manifest: &str) -> Result<BTreeMap<&str, &str>, String> {
    let mut values = BTreeMap::new();
    for line in manifest.lines() {
        let (key, value) = line
            .split_once(" = ")
            .ok_or("a manifest line is malformed")?;
        // `cpu` records diagnostic CPU features; the comparison covers canonical assignments.
        if key == "cpu" {
            continue;
        }
        if values.insert(key, value).is_some() {
            return Err(format!("the manifest repeats {key}"));
        }
    }
    Ok(values)
}
fn budget(manifest: &str) -> Result<(u64, u64), String> {
    Values::parse(manifest, "session")?.session_budget()
}
fn session_class(end: &SessionEnd, exit: i32) -> Stop {
    let class = end_class(&end.end);
    let agreed = match class {
        Sim::Counts => 0,
        Sim::Complete => 1,
        _ => 3,
    };
    if exit != agreed {
        incomplete("the worker exit disagrees with the session end")
    } else {
        Stop(
            class,
            format!(
                "session: {}, {} windows, chain {}; {}",
                class.name(),
                end.windows,
                end.chain,
                match &end.end {
                    SessionEnding::Ended(end) => format!(
                        "stop={}, terminal={}, turns={}",
                        end.stop, end.terminal, end.turns
                    ),
                    SessionEnding::Panicked(panic) => format!("panicked: {panic}"),
                }
            ),
        )
    }
}

impl Checked {
    fn durable(&self, store: &Store) -> Result<(), Stop> {
        for frozen in &self.files {
            let (opened, parent) = open_evidence(frozen.path())
                .map_err(|error| evidence_read_error(frozen.path(), error))?;
            store.sync_evidence(&parent, &opened).map_err(|error| {
                incomplete(format!("the session cannot be made durable: {error}"))
            })?;
            frozen.check()?;
        }
        Ok(())
    }
    fn valid(&self) -> Result<&SessionEnd, Stop> {
        self.end
            .as_ref()
            .map_err(|stop| Stop(stop.0, stop.1.clone()))
    }
}
impl Verifier {
    fn opened(&self, path: &Path) -> Result<crate::store::Opened, Stop> {
        if self.confined {
            open_evidence(path)
                .map(|(opened, _)| opened)
                .map_err(|error| evidence_read_error(path, error))
        } else {
            open_host(path).map_err(|error| match error {
                crate::store::Unreadable::Io(error) if error.kind() == io::ErrorKind::NotFound => {
                    rejected(format!("{} is missing", path.display()))
                }
                error => input_read_error(&error, &format!("{} cannot be read", path.display())),
            })
        }
    }
    fn freeze(&mut self, path: &Path, digest: Digest, bound: u64) -> Result<(), Stop> {
        let frozen = if self.confined {
            Frozen::worker_file(path.to_owned(), digest, bound)
        } else {
            Frozen::raw_file(path.to_owned(), digest, bound)
        }?;
        self.files.push(frozen);
        Ok(())
    }
    fn file(&mut self, path: &Path, kind: Metadata) -> Result<Vec<u8>, Stop> {
        let bound = match kind {
            Metadata::Manifest => BOUND,
            Metadata::Index => INDEX_BYTES,
            Metadata::End => END_BYTES,
        };
        let remaining = self.budget.1.saturating_sub(self.evidence.bytes);
        let cap = bound.min(remaining);
        let mut bytes = Vec::new();
        self.opened(path)?
            .take(cap.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| {
                input_read_error(&error.into(), &format!("{} cannot be read", path.display()))
            })?;
        if bytes.len() as u64 > cap {
            return Err(if remaining < bound {
                rejected("the session exceeds its manifest byte budget")
            } else if matches!(kind, Metadata::End) {
                // The end retention bound preserves the verified prefix as incomplete.
                incomplete(format!("the session end exceeds {END_BYTES} bytes"))
            } else {
                input_read_error(
                    &crate::store::Unreadable::Oversize,
                    &format!("{} cannot be read", path.display()),
                )
            });
        }
        self.evidence.bytes = self
            .evidence
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| rejected("session byte overflow"))?;
        self.freeze(path, Digest::of(&bytes), bound)?;
        Ok(bytes)
    }
    fn chunk(&mut self, path: &Path) -> Result<Digest, Stop> {
        let opened = self.opened(path)?;
        let left = self.budget.1.saturating_sub(self.evidence.bytes);
        let mut source = Hashing::new(BufReader::new(opened.take(left.saturating_add(1))));
        let mut bytes = 0u64;
        let mut records = 0u64;
        loop {
            let mut header = [0; 5];
            let n = source.read(&mut header[..1]).map_err(chunk_io)?;
            if n == 0 {
                break;
            }
            source.read_exact(&mut header[1..]).map_err(chunk_io)?;
            if !(1..=4).contains(&header[0]) {
                return Err(rejected("a session record has an unknown tag"));
            }
            let len = u64::from(u32::from_le_bytes(
                header[1..].try_into().expect("four bytes"),
            ));
            bytes = bytes
                .checked_add(5 + len)
                .ok_or_else(|| rejected("session byte overflow"))?;
            records += 1;
            if bytes > left || records > self.budget.0.saturating_sub(self.evidence.records) {
                return Err(rejected("the session exceeds its manifest budget"));
            }
            let read = io::copy(&mut (&mut source).take(len), &mut io::sink()).map_err(chunk_io)?;
            if read != len {
                return Err(rejected("a session record is torn"));
            }
        }
        let digest = source.finish();
        self.evidence.bytes += bytes;
        self.evidence.records += records;
        self.freeze(path, digest, left)?;
        Ok(digest)
    }
    fn verify(&mut self, dir: &Path, expected: &str) -> Result<SessionEnd, Stop> {
        let manifest = self.file(&dir.join("manifest"), Metadata::Manifest)?;
        if assignments(utf8(&manifest).map_err(rejected)?).map_err(rejected)?
            != assignments(expected).map_err(rejected)?
        {
            return Err(rejected(
                "the session manifest differs from the frozen input",
            ));
        }
        self.evidence.chain = Digest::of(&manifest);
        let index = self.file(&dir.join("index"), Metadata::Index)?;
        let index = utf8(&index).map_err(rejected)?;
        let mut failed = false;
        for line in index.split_inclusive('\n') {
            if !line.ends_with('\n') || line.contains('\r') {
                return Err(rejected("the session index is torn"));
            }
            let window = WindowLine::parse(&line[..line.len() - 1])
                .map_err(|error| rejected(error.to_string()))?;
            failed |= !window.passed;
            if u64::from(window.index) != self.evidence.verified_windows {
                return Err(rejected("the session index is out of order"));
            }
            let digest = self.chunk(
                &dir.join("windows")
                    .join(format!("{:06}.chunk", window.index)),
            )?;
            if digest != window.digest {
                return Err(rejected("a window chunk differs from its index digest"));
            }
            let chain = link(self.evidence.chain, window.index, digest);
            if chain != window.chain {
                return Err(rejected("a window is out of its chain"));
            }
            self.evidence.chain = chain;
            self.evidence.digests.push(digest);
            self.evidence.verified_windows += 1;
            self.evidence.index = text(&format!("{}{line}", self.evidence.index.as_str()));
        }
        let end = self.file(&dir.join("end"), Metadata::End)?;
        let end_text = utf8(&end).map_err(rejected)?;
        let parsed = SessionEnd::parse(end_text).map_err(|error| rejected(error.to_string()))?;
        if failed && matches!(&parsed.end, SessionEnding::Ended(end) if end.counts) {
            return Err(rejected("a counting end follows a failed window"));
        }
        if parsed.windows != self.evidence.verified_windows || parsed.chain != self.evidence.chain {
            return Err(rejected("the end names another window count or chain"));
        }
        let tail = self.chunk(&dir.join("windows/tail.chunk"))?;
        if parsed.tail != tail {
            return Err(rejected("the tail differs from the end digest"));
        }
        self.evidence.end = Some(text(end_text));
        self.evidence.tail = Some(tail);
        Ok(parsed)
    }
}
fn chunk_io(error: io::Error) -> Stop {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        rejected("a session record is torn")
    } else {
        input_read_error(&error.into(), "the session chunk cannot be read")
    }
}

fn check(dir: &Path, manifest: &str, budget: (u64, u64), confined: bool) -> Checked {
    let mut verifier = Verifier {
        evidence: SessionEvidence {
            bytes: 0,
            chain: Digest::of(manifest.as_bytes()),
            complete: false,
            counts: false,
            digests: Vec::new(),
            end: None,
            index: text(""),
            output: text(&dir.to_string_lossy()),
            records: 0,
            tail: None,
            verification_error: None,
            verified_windows: 0,
        },
        files: Vec::new(),
        budget,
        confined,
    };
    let end = verifier.verify(dir, manifest);
    if let Err(stop) = &end {
        let reason = &stop.1[..stop.1.floor_char_boundary(DIAGNOSTIC_BYTES)];
        verifier.evidence.verification_error = Some(text(reason));
    }
    Checked {
        evidence: verifier.evidence,
        end,
        files: verifier.files,
    }
}

fn end_class(ending: &SessionEnding) -> Sim {
    let SessionEnding::Ended(end) = ending else {
        return Sim::Incomplete;
    };
    if end.counts && end.turns > 0 {
        Sim::Counts
    } else if !end.counts && matches!(end.terminal, Terminal::Complete { .. }) {
        Sim::Complete
    } else {
        Sim::Incomplete
    }
}

fn link(previous: Digest, index: u32, digest: Digest) -> Digest {
    let mut bytes = [0; 68];
    bytes[..32].copy_from_slice(previous.bytes());
    bytes[32..36].copy_from_slice(&index.to_le_bytes());
    bytes[36..].copy_from_slice(digest.bytes());
    Digest::of(&bytes)
}

fn mark(evidence: &mut SessionEvidence, class: Sim) {
    evidence.complete = matches!(class, Sim::Counts | Sim::Complete);
    evidence.counts = class == Sim::Counts;
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
