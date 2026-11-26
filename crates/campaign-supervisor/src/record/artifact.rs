//! The artifact record: what one simulation command ran and the
//! class it ended in. The command writes it last into its artifact
//! directory. It names each phase's stored output, frozen inputs and bundle
//! by digest. Session output and replay sources carry their own paths.
//!
//! FORMAT 1 omits absent `archive_path`, `comparison`, `output`, `session` and
//! `session_original` fields. Earlier artifacts retain their canonical bytes.
//! Summaries omit absent `cause`, `first_failure`, `identity` and
//! `unsuccessful`. Other options
//! encode absence as `null`. Canonical verification holds explicit `null` for
//! each field whose absent value is omitted.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{Digest, Text};

/// One launcher command's evidence and class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    /// The archive's identity, the SHA-256 of its build record; `None`
    /// when the archive did not load.
    pub archive: Option<Digest>,
    /// The canonical path of the archive identified by `archive`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_path: Option<Text>,
    /// The SHA-256 of the bundle the command left durable: the run's own
    /// bundle, the staged copy of an inspected one, or the partial bundle a
    /// run that stopped early had written so far. `None` when no bundle file
    /// exists or staging failed.
    pub bundle: Option<Digest>,
    /// The name of the command's [`Sim`](crate::exit::Sim) class.
    pub class: Text,
    /// `run`, `inspect`, `capabilities`, `replay`, `reduce`, `branch`, `explore`,
    /// `session` or `replay-session`.
    pub command: Text,
    /// Replay and reduction set the comparison during bundle admission.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparison: Option<Comparison>,
    /// The SHA-256 of the frozen manifest the worker read; `None` before
    /// it was frozen.
    pub manifest: Option<Digest>,
    /// Branch and exploration's admitted directory for child evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<Text>,
    /// Why the command ended in its class.
    pub reason: Text,
    /// The run id, the artifact directory's name.
    pub run_id: Text,
    /// The output's verified window prefix and first verification error after its
    /// file and directory barriers succeed, including after a phase stop.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionEvidence>,
    /// The source's verified window prefix and first verification error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_original: Option<SessionEvidence>,
    /// The inspected summary, before profile and first-failure checks.
    /// Replay and reduction prefer the comparison's original summary when present.
    pub summary: Option<Summarized>,
    /// Each worker phase by its name, matching its stored output files.
    pub workers: BTreeMap<Text, Worker>,
}

/// The summary facts a class derives from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summarized {
    /// The worker's reason for the bundle's credit verdict; present for non-counting bundles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<Text>,
    pub counts: bool,
    /// The decision count; `None` when the bundle records none.
    pub decisions: Option<u64>,
    /// The bundle's semantic digest.
    pub digest: Digest,
    /// The first violation record, with its semantic index and clock.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_failure: Option<Event>,
    /// The full versioned failure identity printed by the worker.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Text>,
    /// The recovery ledger's verdict word, such as `credited`, for a
    /// recovery bundle.
    pub ledger: Option<Text>,
    /// The terminal as the worker printed it.
    pub terminal: Text,
    /// The rule of the first unsuccessful check, as the worker printed it:
    /// at most 41 bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsuccessful: Option<Text>,
}

/// Evidence derived from one raw semantic record. Indexes start at zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    /// Node and operation are null. `record` retains the raw evidence.
    pub node: Option<u64>,
    pub operation: Option<Text>,
    /// The whole raw record in lowercase hexadecimal.
    pub record: Text,
    pub semantic_record: u64,
    pub virtual_us: Option<u64>,
}

/// The first differing semantic records, or null at a result-only difference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Difference {
    pub committed: Option<Event>,
    pub replayed: Option<Event>,
}

/// A triage verdict and the evidence compared to reach it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Comparison {
    /// The raw digest of the candidate named by `output`.
    pub candidate: Option<Digest>,
    pub divergence: Option<Difference>,
    pub failure_identity: Option<Text>,
    pub failure_kind: Option<Text>,
    pub observed: Option<Summarized>,
    pub original: Option<Summarized>,
    /// The candidate bundle’s absolute path, admitted as printable ASCII.
    pub output: Option<Text>,
    /// `reproduced`, `reduced`, `diverged`, `unreproduced`, `unreducible`, `incomplete`,
    /// `rejected`, `interrupted` or `watchdog`.
    pub status: Text,
}

/// One worker phase: how it ended, and the digests of the standard output
/// and error the launcher captured, which it stores as `NAME.stdout` and
/// `NAME.stderr`. When another entry already holds one of those names, the
/// phase ends the command as incomplete: the directory's entry for that
/// name is absent or holds other bytes, and the digest here stays that of
/// the captured stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Worker {
    /// How the launcher saw the phase end: `exited`, `signaled`,
    /// `watchdog`, `interrupted`, `oversized`, `escaped` or `failed`.
    pub ended: Text,
    /// The exit code, for a worker that exited.
    pub exit: Option<u64>,
    /// The signal number that killed the worker, for one that died of a
    /// signal.
    pub signal: Option<u64>,
    pub stderr: Digest,
    pub stdout: Digest,
}

/// Verified window facts and the state of the session that contains them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionEvidence {
    /// Bytes from fully read metadata and fully framed chunks within the budget.
    /// A fully framed chunk contributes even when its digest check fails.
    pub bytes: u64,
    /// The chain after the last verified window, or the manifest digest at zero windows.
    pub chain: Digest,
    /// The verified end is complete. Output also requires an agreeing command verdict.
    pub complete: bool,
    /// True for a source whose verified end passes with positive turns.
    /// Output also requires stdout and exit agreement, and replay equality.
    pub counts: bool,
    /// Raw chunk digests in verified index order.
    pub digests: Vec<Digest>,
    /// The escaped rendering of the stored end after end and tail verification.
    pub end: Option<Text>,
    /// Verified index lines with control characters escaped.
    pub index: Text,
    /// The escaped rendering of the output path, or source path in `session_original`.
    pub output: Text,
    /// Callback records from fully framed chunks, including a chunk whose digest fails.
    /// A read or framing failure contributes zero records from that chunk.
    pub records: u64,
    /// The raw tail digest after end and tail verification.
    pub tail: Option<Digest>,
    /// The bounded escaped rendering of the first refusal while verifying session files.
    pub verification_error: Option<Text>,
    pub verified_windows: u64,
}

impl Artifact {
    /// The summary that classifies this artifact. A replay's `summary` repeats
    /// the comparison's original, so a replay with a comparison reports only
    /// its observed side; every other command reports `summary`.
    pub(crate) fn outcome_summary(&self) -> Option<&Summarized> {
        match (&self.comparison, self.command.as_str()) {
            (Some(comparison), "replay") => comparison.observed.as_ref(),
            _ => self.summary.as_ref(),
        }
    }
    /// The bundle file name of a `command` evidence directory: `bundle` for
    /// a run and `input` for every other command.
    pub(crate) fn bundle_name(command: &str) -> &'static str {
        if command == "run" { "bundle" } else { "input" }
    }

    /// The report measures inspection stdout and reads capability listings
    /// from these retained streams after bulk reclamation.
    pub(crate) const REPORTED_STREAMS: [&'static str; 2] =
        ["inspect.stdout", "capabilities.stdout"];
    /// Evidence records retained after reclaiming bulk.
    pub(crate) const RECLAIMED_RECORDS: [&'static str; 2] = ["artifact", "manifest"];

    /// The bulk files of this artifact's evidence directory: its declared
    /// bundle and worker streams selected for deletion. `REPORTED_STREAMS`
    /// stay available to report readers. Invalid stream names return `None`.
    pub(crate) fn bulk(&self) -> Option<Vec<crate::store::Name>> {
        let mut bulk = Vec::new();
        if self.bundle.is_some() {
            bulk.push(crate::store::Name::new(Self::bundle_name(
                self.command.as_str(),
            ))?);
        }
        for (phase, stream, _) in self.streams() {
            let entry = Self::stream_name(phase, stream)?;
            if !Self::REPORTED_STREAMS.contains(&entry.as_str()) {
                bulk.push(entry);
            }
        }
        Some(bulk)
    }

    /// The evidence file name of `phase`'s `stream`, `<phase>.<stream>`;
    /// `None` when it breaks the store's name rules.
    pub(crate) fn stream_name(phase: &Text, stream: &str) -> Option<crate::store::Name> {
        crate::store::Name::new(&format!("{}.{stream}", phase.as_str()))
    }

    pub(crate) fn streams(&self) -> impl Iterator<Item = (&Text, &'static str, Digest)> {
        self.workers.iter().flat_map(|(phase, worker)| {
            [
                (phase, "stdout", worker.stdout),
                (phase, "stderr", worker.stderr),
            ]
        })
    }
}
