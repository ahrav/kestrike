//! The identity derivations. A job's identity is the SHA-256 of its frozen
//! experiment's canonical encoding, and every seed derives from that
//! identity alone, so admitting the same frozen inputs again gives the same
//! job and the same seeds.

use std::fmt;

use serde::Serialize;

use super::Digest;

/// A job identity: the SHA-256 of its experiment's canonical encoding.
/// [`Experiment::id`](super::Experiment::id) is its only constructor.
///
/// ```
/// use campaign_supervisor::record::{Digest, JobId};
/// fn digest(id: JobId) -> Digest {
///     id.digest()
/// }
/// ```
///
/// ```compile_fail,E0423
/// use campaign_supervisor::record::{Digest, JobId};
/// let id = JobId(Digest::of(b"forged"));
/// ```
///
/// ```compile_fail,E0277
/// use campaign_supervisor::record::{Digest, JobId};
/// let id: JobId = Digest::of(b"forged").into();
/// ```
///
/// ```compile_fail,E0277
/// use campaign_supervisor::record::JobId;
/// let id: JobId = serde_json::from_str("\"00\"").unwrap();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct JobId(Digest);

impl JobId {
    /// The identity of the experiment whose canonical encoding is
    /// `encoding`.
    pub(super) fn of(encoding: &[u8]) -> Self {
        Self(Digest::of(encoding))
    }

    pub fn digest(&self) -> Digest {
        self.0
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The domain prefix of a branch suffix's root.
const SUFFIX_DOMAIN: &[u8] = b"image-cache suffix v1";

/// The root seed of the job `id`: the little-endian `u64` of the first 8
/// bytes of SHA-256(`"seed\0"` + `id` in hex). The `seed\0` prefix keeps
/// the seed's hash input apart from the identity's, and a zero draw becomes
/// 1 because a manifest's root is at least 1.
pub(super) fn seed(id: &JobId) -> u64 {
    let mut input = b"seed\0".to_vec();
    input.extend_from_slice(id.to_string().as_bytes());
    root(&Digest::of(&input))
}

/// The root seed a seed hash draws: its [`draw`], with 0 mapped to 1.
pub(super) fn root(hash: &Digest) -> u64 {
    draw(hash).max(1)
}

/// The root of suffix `suffix` of a branch from a bundle of root `root`:
/// the little-endian `u64` of the first 8 bytes of SHA-256 of the bytes
/// `kestrike suffix v1`, `root` as 8 little-endian bytes and `suffix`
/// as 4. A zero draw is returned as 0. The worker derives the same roots
/// when it runs the branch.
pub fn suffix_root(root: u64, suffix: u32) -> u64 {
    let mut input = SUFFIX_DOMAIN.to_vec();
    input.extend_from_slice(&root.to_le_bytes());
    input.extend_from_slice(&suffix.to_le_bytes());
    draw(&Digest::of(&input))
}

/// The little-endian `u64` of the digest's first 8 bytes.
fn draw(digest: &Digest) -> u64 {
    let (first, _) = digest
        .bytes()
        .split_first_chunk::<8>()
        .expect("a digest holds 32 bytes");
    u64::from_le_bytes(*first)
}
