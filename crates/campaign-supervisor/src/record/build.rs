//! The build record: the provenance and the file digests of one archived
//! worker build. An archive publishes it last, so a build record exists
//! only beside every file it names, and the SHA-256 of its stored bytes is
//! the archive's identity, the `build` pin of every manifest run under it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{Digest, Text};

/// One archived build: the digests of its files and how it was built.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Build {
    /// The archived executable's digest.
    pub executable: Digest,
    /// Each archived shared library's file name, the name the program
    /// interpreter resolves, with its digest.
    pub libraries: BTreeMap<Text, Digest>,
    /// The program interpreter the executable names; `None` for a static
    /// executable, which has neither interpreter nor libraries.
    pub loader: Option<Loader>,
    /// The digest of the lockfile the build resolved its dependencies
    /// from, whose exact bytes the archive holds.
    pub lock: Digest,
    /// The machine the build ran on, as `uname` names it, such as
    /// `x86_64`.
    pub machine: Text,
    pub provenance: Provenance,
}

/// The host's program interpreter, which the archive pins by digest and
/// leaves in place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Loader {
    /// Its absolute path, as the executable names it.
    pub path: Text,
    pub sha256: Digest,
}

/// How the archived executable was built.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// `cargo -V`.
    pub cargo: Text,
    /// The build command's arguments after the Cargo program, joined by
    /// spaces.
    pub command: Text,
    /// Whether a tracked file of the checkout differed from its revision.
    pub dirty: bool,
    /// The listed build-affecting environment variables the build ran
    /// with, each value converted lossily to UTF-8 and escaped as Rust's
    /// `str::escape_default` escapes it.
    pub environment: BTreeMap<Text, Text>,
    pub native: Native,
    /// The checkout's revision: 40 or 64 lowercase hexadecimal digits.
    pub revision: Text,
    /// The target bound to Cargo: an explicit triple, or the compiler host
    /// when the target is absent or set to `host-tuple`.
    pub target: Text,
    /// `rustc -V`, the manifest's `toolchain` pin.
    pub toolchain: Text,
    /// How many untracked files the checkout held.
    pub untracked: u64,
}

/// The native SPDK build the executable links, as its build script
/// selected it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Native {
    /// The selected install record's file name.
    pub install_record: Text,
    pub install_record_sha256: Digest,
    /// The digest of the link plan the build script wrote.
    pub link_plan_sha256: Digest,
    /// The Cargo package identity of the build script's package.
    pub package: Text,
}
