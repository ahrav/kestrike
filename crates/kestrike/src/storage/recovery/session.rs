//! The session every record of a tenure carries: `s = g·2^32 + a`, with the volume generation `g` from the shard
//! record and the activated epoch `a = 2n + 2` from the attempt's own acknowledged compare-and-swap of the attempt
//! counter `E` from `n` to `n + 1`.
//!
//! - NO-REISSUE: [`Session::activate`] is the one constructor, and it consumes the store client's [`Bumped`]
//!   witness, which only an acknowledged `E` bump or takeover produces, so each acknowledged bump yields one session. A
//!   `Session` is neither `Clone` nor `Copy`, so it moves into one serving authority. The shard record's `E` rises
//!   with every committed bump or takeover and `g` with every flip, which resets `E` to zero, so no two acknowledged bumps share
//!   `(g, n)` and no two tenures of a shard share a session (`NoEpochReuse`). No input comes from the medium, so a
//!   stale write that lowers a root slot changes no later session.
//! - The candidate epoch `2n + 1` of an attempt is odd and never activated; every activated epoch is even.
//! - `g = 2^32 - 1`, or an attempt whose activated epoch passes [`ActivatedEpoch::MAX`], refuses with a
//!   [`SessionRefusal`]; the caller then retires the volume. The store client refuses a bump from
//!   `E = ATTEMPTS_MAX` before any witness exists.

use crate::failover::records::Host;
use crate::failover::retire::Target;
use crate::net::ownership::{ActivatedEpoch, Shard, ShardGeneration, session_of};
use crate::storage::store::Bumped;

/// A tenure's session `g·2^32 + a`. Its one constructor consumes an acknowledged `E` bump, so no medium value or
/// raw integer makes one.
///
/// The witness of an acknowledged bump builds one:
///
/// ```
/// use kestrike::storage::store::Bumped;
/// use kestrike::storage::{Session, SessionRefusal};
///
/// fn session_of(bumped: Bumped) -> Result<Session, SessionRefusal> {
///     Session::activate(bumped)
/// }
/// ```
///
/// A raw integer, a struct literal or a root's generation read from the medium does not:
///
/// ```compile_fail,E0277
/// let _ = kestrike::storage::Session::from(5u64);
/// ```
///
/// ```compile_fail,E0451
/// use kestrike::net::ownership::{ActivatedEpoch, Shard, ShardGeneration};
/// let _ = kestrike::storage::Session {
///     generation: ShardGeneration::new(1).unwrap(),
///     epoch: ActivatedEpoch::new(2).unwrap(),
///     shard: Shard::new(7).unwrap(),
/// };
/// ```
///
/// ```compile_fail,E0308
/// let root_generation: u64 = 7;
/// let _ = kestrike::storage::Session::activate(root_generation);
/// ```
///
/// A session moves into one consumer; it has no clone and no second use:
///
/// ```compile_fail,E0599
/// fn twice(session: kestrike::storage::Session) {
///     let _ = session.clone();
/// }
/// ```
///
/// ```compile_fail,E0382
/// fn twice(session: kestrike::storage::Session) {
///     let first = session;
///     let second = session;
/// }
/// ```
///
/// The witness of one bump activates one session; it has no clone and no second activation:
///
/// ```compile_fail,E0599
/// fn twice(bumped: kestrike::storage::store::Bumped) {
///     let _ = bumped.clone();
/// }
/// ```
///
/// ```compile_fail,E0382
/// use kestrike::storage::Session;
/// fn twice(bumped: kestrike::storage::store::Bumped) {
///     let _ = Session::activate(bumped);
///     let _ = Session::activate(bumped);
/// }
/// ```
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Session {
    generation: ShardGeneration,
    epoch: ActivatedEpoch,
    shard: Shard,
    owner: Host,
}

/// Why [`Session::activate`] refuses an acknowledged bump: the session it would encode falls outside its fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRefusal {
    /// `g` is `2^32 - 1`.
    GenerationExhausted,
    /// The attempt's activated epoch `2n + 2` exceeds [`ActivatedEpoch::MAX`].
    AttemptsExhausted,
}

impl Session {
    /// The session of the attempt whose `E` bump `bumped` acknowledged.
    ///
    /// # Errors
    ///
    /// [`SessionRefusal::GenerationExhausted`] before [`SessionRefusal::AttemptsExhausted`].
    pub fn activate(bumped: Bumped) -> Result<Self, SessionRefusal> {
        let generation = bumped.generation();
        if generation.get() == u64::from(u32::MAX) {
            return Err(SessionRefusal::GenerationExhausted);
        }
        let epoch = activated(bumped.attempt()).ok_or(SessionRefusal::AttemptsExhausted)?;
        Ok(Self {
            generation,
            epoch,
            shard: bumped.shard(),
            owner: bumped.owner(),
        })
    }

    /// Whether `value` is the `g·2^32 + a` of a session [`Session::activate`] returns: a generation that is nonzero
    /// and below `2^32 - 1`, the generation `activate` refuses, and an epoch an attempt activated. A fence a tenure
    /// wrote on a record or a coverage page is such a value.
    pub fn is_activated(value: u64) -> bool {
        let generation = value >> 32;
        let exhausted = generation == u64::from(u32::MAX);
        generation != 0
            && !exhausted
            && ActivatedEpoch::new(value as u32).is_some_and(ActivatedEpoch::is_activated)
    }

    /// `g·2^32 + a`, the value every root and record header of the tenure carries.
    pub fn get(&self) -> u64 {
        session_of(self.generation.get() as u32, self.epoch.get())
    }

    pub fn generation(&self) -> ShardGeneration {
        self.generation
    }

    /// The shard record's `(g, owner, E)` after the acknowledged bump, with `E = n + 1 = a / 2`.
    pub fn target(&self) -> Target {
        Target {
            generation: self.generation,
            owner: self.owner,
            attempts: self.epoch.get() / 2,
        }
    }

    pub fn epoch(&self) -> ActivatedEpoch {
        self.epoch
    }

    /// The shard whose `E` bump activated the session; sessions of two shards may share `g·2^32 + a`.
    pub fn shard(&self) -> Shard {
        self.shard
    }
}

/// The activated epoch `2n + 2` of attempt `n`, or `None` past [`ActivatedEpoch::MAX`].
fn activated(n: u32) -> Option<ActivatedEpoch> {
    n.checked_mul(2)?
        .checked_add(2)
        .and_then(ActivatedEpoch::new)
}

/// The candidate epoch `2n + 1` of attempt `n`.
#[cfg(any(test, kani))]
pub(super) fn candidate(n: u32) -> Option<u32> {
    n.checked_mul(2)?.checked_add(1)
}

#[cfg(kani)]
mod verification {
    use super::{activated, candidate, session_of};

    /// Over two symbolic generations below `2^32 - 1` and two symbolic attempts: the encoding of their activated
    /// sessions is equal exactly when both fields are, every activated epoch is even and above every candidate of
    /// the same attempt, every candidate is odd, and an attempt whose `2n + 2` passes `ActivatedEpoch::MAX` refuses.
    #[kani::proof]
    fn session_encoding_injective_and_parity() {
        let (g1, g2): (u32, u32) = (kani::any(), kani::any());
        let (n1, n2): (u32, u32) = (kani::any(), kani::any());
        kani::assume(g1 < u32::MAX && g2 < u32::MAX);
        kani::cover!(activated(n1).is_some() && activated(n2).is_some() && g1 == g2 && n1 != n2);
        kani::cover!(activated(n1).is_none());
        match (activated(n1), activated(n2)) {
            (Some(a1), Some(a2)) => {
                let same = session_of(g1, a1.get()) == session_of(g2, a2.get());
                assert_eq!(same, g1 == g2 && n1 == n2);
                assert!(a1.get() % 2 == 0 && a1.get() >= 2);
                let c = candidate(n1).expect("a candidate exists below every activated epoch");
                assert!(c % 2 == 1 && c + 1 == a1.get());
            }
            (None, _) => assert!(
                u64::from(n1) * 2 + 2 > u64::from(crate::net::ownership::ActivatedEpoch::MAX)
            ),
            (_, None) => assert!(
                u64::from(n2) * 2 + 2 > u64::from(crate::net::ownership::ActivatedEpoch::MAX)
            ),
        }
    }
}
