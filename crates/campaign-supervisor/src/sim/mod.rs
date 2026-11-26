//! The simulation commands: archived worker execution under the launch
//! contract, and the typed artifact record of what it ran and the class
//! it earned.
//!
//! Each command creates its artifact directory, `RUN_ID` under the
//! artifacts directory, as a new [store](crate::store); a directory that
//! exists, or whose absolute path is no UTF-8 text, refuses the command. The run id is `--run-id`,
//! or else `local-SECONDS-PID`, the time and the launcher's process ID.
//! The run and inspect directories hold the frozen `manifest` the worker reads, the
//! worker's `bundle` for `run` or the staged `input` copy for `inspect`,
//! each worker phase's bounded `NAME.stdout` and `NAME.stderr`, and the
//! [`Artifact`](crate::record::Artifact) record `artifact`, written last,
//! whose class matches the command's exit when the record write succeeds.
//! A record write that fails or finds an existing `artifact` entry exits 4,
//! and a record such a write leaves can name a class the exit does not, so a
//! reader credits a record only beside an exit that agrees with it. The
//! directory is a store root of its
//! own, so it also holds the store's `.state` marker and `.staging`
//! directory; a reader that walks a tree of artifact directories opens each
//! as its own store or view.
//!
//! `run` runs the capability listing, then the run form, then the inspect
//! form over the bundle. The manifest and the archive are
//! checked before any phase: a manifest or bundle whose pins name another
//! build than the archive exits 2 with no worker started, and so does an
//! inspected bundle that lacks any archive pin or a record maximum, or holds more records than its
//! manifest's maximum. A manifest of another schema version than the
//! listing names, or names no version, exits 2 after the capability listing alone. The watchdog is
//! `--watchdog`, else the manifest's `watchdog` seconds, else an hour, for
//! each phase; branch and explore triple the inherited wait for their fork phase.
//!
//! Run and inspect derive their class from the inspected bundle's summary and an agreeing
//! worker exit: exit 0 needs the summary to count, which the parser
//! allows only beside a passing terminal and, for a recovery profile, a
//! credited ledger; more than zero decisions; a summary naming the
//! profile the frozen manifest runs; and `run`'s worker
//! exit must agree, 0 for a counting bundle, 1 for another complete one
//! and 3 for an incomplete one, with a run form summary equal to the
//! inspected one. A complete result that does not count exits 1. A
//! disagreement, a refused or torn output, an output past its bound, a
//! worker that died of a signal or panicked, a frozen input that changed
//! during the command, a host fault such as `EIO` reading an input, or a
//! failed write exits 4.
//!
//! A pending SIGINT or SIGTERM makes the class
//! [`Sim::Interrupted`](crate::exit::Sim::Interrupted), exit 5, unless the
//! watchdog already ended a phase. A phase past its watchdog has the class
//! [`Sim::Watchdog`](crate::exit::Sim::Watchdog), exit 6.

//!
//! `sim capabilities --archive DIR` records and prints the verified worker’s
//! full text listing in the CLI JSON `capabilities` field. `capabilities.stdout`
//! retains the listing, and the artifact names its digest. Success exits 0.
//! Its watchdog defaults to 60 seconds, with `--watchdog` as the override.
//! `sim replay BUNDLE --archive DIR` stages the raw bundle and compares a fresh
//! replay’s full bundle summary and semantic records with the original’s.
//! `sim replay --from-run DIR` reads DIR’s verified `artifact`, frozen manifest
//! and bundle. The artifact’s `archive_path` resolves the original archive;
//! its recorded archive and input digests must agree before a worker starts.
//! `sim reduce BUNDLE --archive DIR --output DIR` uses the worker’s bounded
//! reducer and independently checks its candidate in a fresh worker process.
//! A complete violation keeps its full identity. A panic keeps its location
//! and payload and reproduces the candidate bundle in a fresh manifest run.
//! Replay and reduction output paths admit printable ASCII (0x20..=0x7e).
//! `comparison.output` names the candidate bundle’s absolute path and
//! `comparison.candidate` records its raw digest.
//! The reduction output directory must be new. Worker output remains evidence
//! at that path, and `comparison.status` states whether the candidate qualifies.
//!
//! During admission, `comparison` records the original summary. Fresh inspection
//! supplies `observed`. Reduction records its failure kind and identity.
//! `replay --from-run` takes a panic identity from the original run’s verified
//! `run.stdout`, or from a replay or reduction artifact’s recorded panic comparison.
//! It reruns the frozen manifest in a fresh process. Manual replay of a truncated
//! bundle exits 4.
//! Panic reduction records the panic identity and the candidate’s raw digest.
//! The status is: `reproduced`, `reduced`, `diverged`,
//! `unreproduced`, `unreducible`, `incomplete`, `rejected`, `interrupted` or `watchdog`.
//! A passing rerun of a violation is `unreproduced`. Different semantic records
//! or failure identities are `diverged`. Torn or incomplete evidence gives 4.
//! A reproduced bundle replay takes the inspected summary’s credit class:
//! 0 for a counting bundle and 1 for another complete bundle. A reproduced panic
//! rerun earns 1. A violation reduction first replays the
//! original as `baseline`; a panic reduction first reruns the frozen manifest as
//! `panic-original`. An unreproduced, diverged or incomplete first step ends the
//! command before the reducer runs. A passing original whose baseline reproduces
//! ends `unreducible` with exit 1. Reproduced failures and accepted reductions earn 1. The capabilities command’s exit 0
//! attests a parsed listing and a worker exit 0.
//!
//! Structured divergence retains the first differing semantic record on each
//! available side, with
//! zero-based indexes and the last TURN or CLOCK time at or before that record. Node and
//! operation facts remain null. Summary `first_failure` retains the first raw
//! violation record. Each phase checks frozen input digests and identities
//! before execution and after process teardown. Archive verification also runs
//! after teardown for every phase end; interruption and watchdog keep their
//! exit classes while failed checks yield incomplete evidence on an ordinary exit.
//!
//! Branch and exploration use the archived worker's bounded output. Their parsed
//! child set, terminal reports and verdict must agree with its exit. A branch
//! accepts exactly the requested suffix and sibling pairs, with 1..=16 suffixes
//! and 1..=4 siblings. Siblings default to one. Each suffix's siblings agree on
//! digest and terminal for credit. Exploration limits agree with the manifest,
//! and each credited node is either a leaf or the parent of a printed child.
//! Both forms require a nonempty printable-ASCII milestone. Output defaults to
//! `branch` or `explore` under the artifact directory. `output` records that path.
//! All four new forms accept the shared artifact, run-id, watchdog and output options.
//! Inside an artifact directory, output is admitted only at the command default.
//! Other entries there are refused with exit 2 before workers. Reduce takes an
//! external output directory.
//! A default
//! forking watchdog is three times the manifest watchdog, or three hours when it
//! names none, capped at u32::MAX seconds.
//!
//! Session output lives at `--output DIR` or the artifact directory's `session`.
//! Replay-session defaults to its `replay-session` directory. Output paths admit
//! printable ASCII. Replay-session canonicalizes and escapes its source path. The launcher verifies the canonical manifest assignments,
//! ordered index lines, variable-length chunk records, raw digests, chain, end
//! and tail within the manifest's callback-record and total file-byte budgets.
//! Index text admits 256 KiB; a source index over that cap is refused with exit 2.
//! End text admits 16 KiB. An end over that cap with at least 16 KiB of
//! remaining file-byte budget yields incomplete evidence with a published
//! verified-prefix record.
//! A verified source whose canonical path is not UTF-8 keeps its
//! `session_original` evidence and exits 2 before any worker starts, because
//! the archived worker reads its arguments as UTF-8 text.
//! After successful output barriers, `session` retains the verified prefix's
//! count, digests and chain after teardown, including a stopped worker.
//! A barrier failure leaves output session evidence absent and names the failure
//! in the reason. A non-poisoning barrier failure preserves the phase stop class.
//! Retained windows follow index order. A worker index-sync
//! failure restores the prior index length before latching incomplete state.
//! If rollback also fails, the informational visible prefix has unknown durability
//! and the command remains incomplete. Output files use
//! confined opens; replay sources use host path resolution. A stop leaves
//! `complete=false` and `counts=false`. A counting end reaches its goal and all
//! window verdicts pass.
//! Ordinary completion also requires the stdout end and chain to agree with the
//! verified files and the worker exit. Replay checks every source file before and
//! after the worker, and compares every index and end fact except `apply_ms`.
//! A reproduced replay takes the verified end's class: 0 for a passing end with
//! a positive turn count, 1 for a complete end with `counts=false`, and 4 for
//! every other end. A verified divergence with worker exit 1 gives exit 1;
//! observed `complete` follows its end and observed `counts` is false.
//! A panicked source with a verified footer and tail runs through the same archived
//! replay phase and remains incomplete with exit 4.

mod class;
pub(crate) use class::{INCOMPLETE, agrees};
mod command;
mod evidence;
mod forked;
pub(crate) use forked::branch_probe_charge;
pub(crate) mod input;
pub(crate) use launch::OUTPUT;
mod launch;
mod session;
mod triage;

#[cfg(test)]
mod class_tests;
#[cfg(test)]
mod evidence_tests;
#[cfg(test)]
mod input_tests;

pub use self::command::{Ended, Input, Options, sim};
pub use self::input::seconds;
pub(crate) use self::input::{Stager, Values, worker_manifest};

pub(crate) use self::command::REASON;
