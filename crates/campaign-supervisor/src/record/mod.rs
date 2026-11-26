//! Typed records: the canonical envelope codec, the read rule that yields
//! a verified record or a held code, and the identity derivations.
//!
//! Every record file the store holds is one [`Kind`] of record in one
//! envelope. The envelope's bytes are canonical compact JSON: struct fields
//! in byte order of their names, ordered maps, `null` for an absent option
//! or no key for an option its type omits when `None`, no floats, exact
//! integers up to `u64::MAX`, and printable ASCII text.
//! Over that domain the encoding is byte-identical to a sorted-key, compact
//! JSON encoding with ASCII escapes, so the identities derived from it keep
//! their values: a job id, its root seed, the branch suffix roots and the
//! manifest digest.
//!
//! [`Store::read_record`](crate::store::Store::read_record) and
//! [`View::read_record`](crate::store::View::read_record) are the only
//! sources of a [`Verified`] record. A file that fails any step of the read
//! rule is [`Held`] with the code of that step, and no verified value of it
//! exists.

mod admission;
mod artifact;
mod attempt;
mod build;
mod calibration;
mod capacity;
mod codec;
mod configuration;
mod corpus;
mod digest;
mod finding;
mod hardware;
mod identity;
mod job;
mod kind;
mod lifecycle;
mod probe;
mod settlement;

mod stored;
mod target;
mod text;
mod triage;
mod value;

#[cfg(test)]
mod codec_tests;
#[cfg(test)]
mod identity_tests;
#[cfg(test)]
mod stored_tests;

pub use self::admission::{Admission, AdmissionError, Purpose};
pub use self::artifact::{
    Artifact, Comparison, Difference, Event, SessionEvidence, Summarized, Worker,
};
pub use self::attempt::{Attempt, Binding, BoundEvidence, Class, Finished, Kernel};
pub use self::build::{Build, Loader, Native, Provenance};
pub use self::calibration::{
    Calibration, CalibrationContract, CalibrationEvidence, CalibrationPlan, CalibrationReplay,
    CalibrationVerdict, ResourceBounds,
};
pub use self::capacity::{Capacity, CapacityError};
pub use self::codec::{FORMAT, Held};
pub(crate) use self::configuration::{
    COMPLETION_RECORD_BYTES, Charge, probe_charge, resource_charge, retention_charge,
};
pub use self::configuration::{Configuration, ConfigurationError};
pub use self::corpus::{CorpusAsset, CorpusProbe, CorpusRetirement, CorpusVersion};
pub use self::digest::{Digest, Hashing};
pub use self::finding::{Captured, ChildEvidence, Decision, Disposition, Finding, FindingKind};
pub use self::hardware::{
    Hardware, HardwareClass, HardwareDisposition, HardwareKind, HardwarePhase,
};
pub use self::identity::{JobId, suffix_root};
pub use self::job::{Experiment, Job, ManifestError, Pins};
pub use self::kind::{Kind, Record};
pub use self::lifecycle::{Intent, Started};
pub use self::probe::{ProbeFinished, ProbeOutcome, Reservation};
pub use self::settlement::{JobResult, Pin, Reclaimed};

pub use self::stored::{BOUND, Verified};
pub use self::target::{ForkForm, Target};
pub use self::text::Text;
pub use self::triage::{
    RegressionCandidate, ReplayDependencies, ReplayStatus, StepKind, StepState, TriageResult,
    TriageStep,
};
