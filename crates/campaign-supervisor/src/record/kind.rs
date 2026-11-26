//! The record kinds and the sealed trait every record type implements.
//! One list generates [`Kind`], [`Kind::ALL`], [`Kind::name`] and the
//! [`Record`] impl of each kind's record type, so `ALL` holds every kind
//! and each record type has exactly one kind. The round-trip and
//! read-fault tests match exhaustively on each kind in `ALL`, so a kind
//! joins the store only together with its fixtures.

use serde::Serialize;
use serde::de::DeserializeOwned;

macro_rules! kinds {
    ($($(#[$doc:meta])* $kind:ident => $name:literal, $record:ty;)+) => {
        /// One kind of record file. An envelope names its kind, so a
        /// record read as another kind is held.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Kind {
            $($(#[$doc])* $kind,)+
        }

        impl Kind {
            pub const ALL: &[Self] = &[$(Self::$kind),+];

            /// The fixed encoded-byte bound for this kind.
            pub const fn bound(self) -> u64 {
                match self {
                    Self::Finding => 5 * super::BOUND,
                    _ => super::BOUND,
                }
            }

            /// The kind's name in an envelope.
            pub fn name(self) -> &'static str {
                match self {
                    $(Self::$kind => $name,)+
                }
            }
        }

        $(
            impl sealed::Sealed for $record {}

            impl Record for $record {
                const KIND: Kind = Kind::$kind;
            }
        )+
    };
}

kinds! {
    Hardware => "hardware", super::Hardware;
    HardwareDisposition => "hardware-disposition", super::HardwareDisposition;
    /// A job: one frozen experiment with its identity, seed and manifest
    /// digest.
    Job => "job", super::Job;
    /// A build record: an archived worker build's file digests and
    /// provenance.
    Build => "build", super::Build;
    /// An artifact record: one launcher command's evidence and class.
    Artifact => "artifact", super::Artifact;
    Admission => "admission", super::Admission;
    Configuration => "configuration", super::Configuration;
    Capacity => "capacity", super::Capacity;
    Calibration => "calibration", super::Calibration;
    CalibrationPlan => "calibration-plan", super::CalibrationPlan;
    CalibrationReplay => "calibration-replay", super::CalibrationReplay;
    ResourceBounds => "resource-bounds", super::ResourceBounds;
    Intent => "intent", super::Intent;
    Started => "started", super::Started;
    Attempt => "attempt", super::Attempt;
    Finished => "finished", super::Finished;
    Bound => "bound", super::BoundEvidence;
    /// The retained first-failure result of a job.
    Pin => "pin", super::Pin;
    /// The selected outcome published for a job.
    JobResult => "job_result", super::JobResult;
    /// The bulk names a settled attempt's reclaim deletes.
    Reclaimed => "reclaimed", super::Reclaimed;
    Reservation => "reservation", super::Reservation;
    ProbeFinished => "probe_finished", super::ProbeFinished;
    CorpusProbe => "corpus-probe", super::CorpusProbe;
    CorpusAsset => "corpus-asset", super::CorpusAsset;
    CorpusVersion => "corpus-version", super::CorpusVersion;
    CorpusRetirement => "corpus-retirement", super::CorpusRetirement;
    Captured => "captured", super::Captured;
    Finding => "finding", super::Finding;
    Disposition => "disposition", super::Disposition;
    TriageStep => "triage-step", super::TriageStep;
    TriageResult => "triage-result", super::TriageResult;
    ReplayDependencies => "replay-dependencies", super::ReplayDependencies;
    RegressionCandidate => "regression-candidate", super::RegressionCandidate;

}

mod sealed {
    pub trait Sealed {}
}

/// A record type the store encodes and verifies. The trait is sealed: the
/// kind list in this module implements it for each kind's record type, so
/// every record type is one the kind registry and its fixtures cover.
///
/// A record type declares its fields in byte order of their names, holds
/// no floats, encodes an absent option as `null`, or as an absent key when
/// it declares `skip_serializing_if = "Option::is_none"`, keeps maps
/// ordered, and
/// takes text only as [`Text`](super::Text). Its fields are unsigned
/// integers up to `u64`, booleans, options, ordered sequences, ordered maps keyed by `Text`,
/// `Text`, [`Digest`](super::Digest), record structs and
/// `#[serde(transparent)]` newtypes of these. Textual enums serialize as
/// printable strings. The struct serde decodes, the record
/// itself or the struct its `#[serde(try_from)]` names, and every struct
/// in it carry `#[serde(deny_unknown_fields)]`, so an undeclared field is
/// [`Held::UnknownField`](super::Held::UnknownField). Its derived encoding
/// is then its canonical form.
///
/// ```
/// use campaign_supervisor::record::{Job, Kind, Record};
/// assert_eq!(<Job as Record>::KIND, Kind::Job);
/// ```
///
/// ```compile_fail,E0277
/// // A type outside this crate cannot become a record type.
/// #[derive(serde::Serialize, serde::Deserialize)]
/// struct Forged;
/// impl campaign_supervisor::record::Record for Forged {
///     const KIND: campaign_supervisor::record::Kind = campaign_supervisor::record::Kind::Job;
/// }
/// ```
///
/// ```compile_fail,E0603
/// // The module holding the sealing trait is private.
/// struct Forged;
/// impl campaign_supervisor::record::kind::sealed::Sealed for Forged {}
/// ```
///
/// ```compile_fail,E0433
/// // The record module exports no sealing trait.
/// struct Forged;
/// impl campaign_supervisor::record::sealed::Sealed for Forged {}
/// ```
pub trait Record: sealed::Sealed + Serialize + DeserializeOwned {
    const KIND: Kind;
    const BOUND: u64 = Self::KIND.bound();

    fn encoded_len(&self) -> usize
    where
        Self: Sized,
    {
        super::codec::encode(self).len()
    }
}
