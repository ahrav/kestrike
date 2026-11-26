//! A planned request asks an owner host to transfer one shard to its named standby (`Transfer`) or to restart on the
//! same host (`Restart`).
//!
//! Layout, schema 1, big-endian at fixed offsets, [`REQUEST_LEN`] bytes: the schema `u16` at 0, the kind `u8` at 2
//! (1 `Transfer`, 2 `Restart`), the operation identity at 3, 16 bytes; the sequence `u64` at 19, the shard `u32` at
//! 27, the generation `g` `u64` at 31, the attempt counter `E` `u32` at 39, the owner host `u64` at 43, the target
//! host `u64` at 51 (zero for `Restart`), the deadline in microseconds from receipt on the owner's suspend-aware clock
//! `u32` at 59, and the 32-byte tag at 63.
//!
//! Invariants:
//!
//! - REQUEST-AUTHENTICATED: the tag is HMAC-SHA256 under the owner host's [`RequestKey`] over a 16-byte domain label,
//!   the addressed host and every byte before the tag. A [`RequestKey`] holds the two SHA-256 states HMAC reaches
//!   after its key pad blocks, so a tag costs three compressions: through `net::sha_one::compress` on a
//!   little-endian aarch64 CPU with the `sha2` and `sha3` features, and through `sha2::block_api::compress256` on
//!   every other CPU and under Miri. Both leave the same states, so the tag is the same on every CPU. [`decode`]
//!   checks the exact length, then the tag in constant time, and reads the fields only after the tag verifies. Only
//!   [`decode`] returns an [`AuthenticatedRequest`], and [`Ledger::admit`] classes only an
//!   [`AuthenticatedRequest`].
//! - AVAILABILITY-ONLY: a valid tag is availability evidence alone. A request asks the one tenure it binds
//!   ([`Ledger::admit`]) to stop in order, and the shard record's compare-and-swap decides every ownership change.
//! - ONE-TENURE: a request binds the `(shard, g, E)` of one activated session. A [`Ledger`] holds the shard and
//!   target of the session it was built from, and admission requires the owner, shard, generation and attempt
//!   counter to match the tenure, so each tenure of a host admits only the requests addressed to it.
//! - ONE-OPERATION: a tenure runs one operation at a time, accepted at a sequence above every sequence it saw bound
//!   to it. A request naming the tenure's latest operation, running or ended, is a repeat, which the caller answers
//!   with that operation's status. Admission rejects any other request at or below the sequence high-water mark, so
//!   each drain starts from one fresh request. [`Sequence::of`] orders sequences by `started_s` first and `counter`
//!   second. Cross-restart ordering requires the new issuer start to have a greater `started_s`.
//! - ONE-ENCODING: [`decode`] accepts exactly the encodings [`encode`] writes, and [`encode`] seals each request for
//!   the owner it names.

use std::num::NonZeroU32;

use sha2::block_api::compress256;
use subtle::ConstantTimeEq;

use crate::failover::assignment::hmac;
use crate::failover::records::Host;
use crate::failover::report::{ExitOperation, field_at, put, u32_at, u64_at};
use crate::failover::retire::Target;
use crate::failover::serving::State;
use crate::net::ownership::{Shard, ShardGeneration};
use crate::net::{Keyed, digest_bytes, keyed, outer_block, padded};
use crate::storage::Session;

/// The layout schema this codec writes and accepts.
pub const SCHEMA: u16 = 1;
pub const REQUEST_LEN: usize = TAG_AT + TAG_LEN;
pub const OPERATIONS_MAX: usize = 64;

const TAG_LEN: usize = 32;
const DOMAIN: &[u8; 16] = b"ebs-planned-req1";
const KEY_DOMAIN: &[u8; 16] = b"ebs-plan-key--01";

const KIND_AT: usize = 2;
const OPERATION_AT: usize = 3;
const SEQUENCE_AT: usize = 19;
const SHARD_AT: usize = 27;
const GENERATION_AT: usize = 31;
const ATTEMPTS_AT: usize = 39;
const OWNER_AT: usize = 43;
const TARGET_AT: usize = 51;
const DEADLINE_AT: usize = 59;
const TAG_AT: usize = 63;

const _: () = assert!(DEADLINE_AT + 4 == TAG_AT);
const _: () = assert!(REQUEST_LEN == 95);

/// The SHA-256 block length, which is also the length of each HMAC key pad.
const BLOCK: usize = 64;
/// The bytes a tag authenticates: the domain label, the addressed host and every byte before the tag.
const SEALED_LEN: usize = DOMAIN.len() + 8 + TAG_AT;

// The authenticated bytes fill one block and leave the second room for the padding byte and the 8-byte length.
const _: () = assert!(SEALED_LEN >= BLOCK && SEALED_LEN + 9 <= 2 * BLOCK);

/// An owner host uses this key to authenticate planned requests addressed to that host. It holds the SHA-256 states
/// after HMAC's inner and outer key pad blocks (RFC 2104), each as secret as the key bytes. It has no `Debug`, so no
/// format string prints it.
#[derive(Clone, Copy)]
pub struct RequestKey(Keyed);

impl RequestKey {
    /// The request key of `host_key`, in an HMAC domain of its own.
    pub fn derive(host_key: &[u8; 32]) -> Self {
        Self(keyed(&hmac(host_key, &[KEY_DOMAIN])))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A transfer of the shard to `target`, which the shard record must still name standby.
    Transfer { target: Host },
    /// A cooperative same-host restart.
    Restart,
}

/// A request's sequence: the issuing process's start time in seconds since the Unix epoch in the high 32 bits and
/// a counter of that process in the low 32 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sequence(pub u64);

impl Sequence {
    /// The sequence of request `counter` of the issuer incarnation that started at `started_s`. Every sequence of
    /// an incarnation lies above every sequence of an earlier one exactly when its `started_s` is greater, and the
    /// sequences of one incarnation rise with `counter`; the issuer supplies both values.
    pub fn of(started_s: u32, counter: u32) -> Self {
        Self(u64::from(started_s) << 32 | u64::from(counter))
    }
}

/// The fields [`encode`] seals; [`decode`] returns them inside an [`AuthenticatedRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannedRequest {
    pub kind: Kind,
    pub operation: ExitOperation,
    pub sequence: Sequence,
    pub shard: Shard,
    pub generation: ShardGeneration,
    /// The shard record's attempt counter `E` of the tenure the request binds.
    pub attempts: u32,
    /// The host the request is sealed for and the owner of the tenure it binds.
    pub owner: Host,
    /// The time from receipt, on the owner's suspend-aware clock, within which the exit reaches its withdrawal or
    /// resumes.
    pub deadline_us: NonZeroU32,
}

/// A request whose tag verified under the key the caller supplied to [`decode`] for the addressed host, and whose
/// owner is that host. Only [`decode`] returns one.
///
/// ```compile_fail,E0423
/// # use kestrike::failover::planned::{AuthenticatedRequest, PlannedRequest};
/// fn forge(request: PlannedRequest) -> AuthenticatedRequest {
///     AuthenticatedRequest(request)
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedRequest(PlannedRequest);

impl AuthenticatedRequest {
    pub fn request(&self) -> &PlannedRequest {
        &self.0
    }
}

/// The first check that refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    /// [`decode`] requires exactly [`REQUEST_LEN`] bytes.
    Length,
    /// [`decode`] requires the tag to verify under the key for the addressed host.
    Tag,
    /// [`decode`] requires the schema field to equal [`SCHEMA`].
    Schema,
    /// [`decode`] requires kind 1 with a nonzero target or kind 2 with a zero target.
    Kind,
    Field,
    /// [`decode`] requires the request's owner to equal `addressed`.
    Addressee,
}

/// HMAC-SHA256 under `key` over the domain label, `addressed` and `body`, in three compressions: the inner hash
/// continues from the key's inner pad state over two blocks, and the outer hash continues from the outer pad state
/// over the inner digest's one block.
fn tag(key: &RequestKey, addressed: Host, body: &[u8; TAG_AT]) -> [u8; TAG_LEN] {
    let sealed = sealed_blocks(addressed, body);
    #[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
    if crate::net::sha_one::detected() {
        // SAFETY: `sha_one::detected` reported every CPU feature `sha_one::with_features` gives `chained_one`.
        return unsafe { chained_one(key, &sealed) };
    }
    chained(key, &sealed, compress256)
}

/// The bytes a tag authenticates, ended as the inner hash's message: the domain label, `addressed` and `body`, then
/// the padding of a message that began with the inner pad block.
fn sealed_blocks(addressed: Host, body: &[u8; TAG_AT]) -> [[u8; BLOCK]; 2] {
    // The second block starts as SHA-256's padding (FIPS 180-4, section 5.1.1) of the key pad block and the
    // authenticated bytes: the byte 0x80 after the last authenticated byte and the message's bit length in the last
    // eight bytes.
    let mut sealed = [[0; BLOCK], padded(SEALED_LEN - BLOCK, SEALED_LEN)];
    let bytes = sealed.as_flattened_mut();
    put(bytes, 0, DOMAIN);
    put(bytes, DOMAIN.len(), &addressed.get().to_be_bytes());
    put(bytes, DOMAIN.len() + 8, body);
    sealed
}

/// The two hashes of [`tag`] over the padded blocks `sealed`, each compression through `compress`.
#[inline(always)]
fn chained(
    key: &RequestKey,
    sealed: &[[u8; BLOCK]; 2],
    compress: impl Fn(&mut [u32; 8], &[[u8; BLOCK]]),
) -> [u8; TAG_LEN] {
    let mut inner = key.0.inner;
    compress(&mut inner, sealed);
    let mut outer = key.0.outer;
    compress(&mut outer, &[outer_block(&inner)]);
    digest_bytes(&outer)
}

#[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
crate::net::sha_one::with_features! {
    /// [`chained`] as one chain of compressions in the aarch64 `sha2` instructions.
    fn chained_one(key: &RequestKey, sealed: &[[u8; BLOCK]; 2]) -> [u8; TAG_LEN] {
        chained(key, sealed, |state, blocks| crate::net::sha_one::compress(state, blocks))
    }
}

/// The encoding of `request`, sealed under `key` for its owner host.
pub fn encode(request: &PlannedRequest, key: &RequestKey) -> [u8; REQUEST_LEN] {
    let mut out = [0; REQUEST_LEN];
    let (kind, target) = match request.kind {
        Kind::Transfer { target } => (1, target.get()),
        Kind::Restart => (2, 0),
    };
    put(&mut out, 0, &SCHEMA.to_be_bytes());
    out[KIND_AT] = kind;
    put(&mut out, OPERATION_AT, &request.operation.bytes());
    put(&mut out, SEQUENCE_AT, &request.sequence.0.to_be_bytes());
    put(&mut out, SHARD_AT, &request.shard.get().to_be_bytes());
    put(
        &mut out,
        GENERATION_AT,
        &request.generation.get().to_be_bytes(),
    );
    put(&mut out, ATTEMPTS_AT, &request.attempts.to_be_bytes());
    put(&mut out, OWNER_AT, &request.owner.get().to_be_bytes());
    put(&mut out, TARGET_AT, &target.to_be_bytes());
    put(
        &mut out,
        DEADLINE_AT,
        &request.deadline_us.get().to_be_bytes(),
    );
    let (body, _) = out.split_first_chunk().expect("a request holds a body");
    let sealed = tag(key, request.owner, body);
    put(&mut out, TAG_AT, &sealed);
    out
}

/// Decodes and authenticates one request addressed to `addressed` under that host's `key`.
///
/// # Errors
///
/// The first failing check in this order: `Length`, `Tag`, then `Schema`, `Kind` and `Field` over the fields.
/// `Addressee` indicates that the request's owner differs from `addressed`.
pub fn decode(
    bytes: &[u8],
    addressed: Host,
    key: &RequestKey,
) -> Result<AuthenticatedRequest, RequestError> {
    let Some((body, received)) = split(bytes) else {
        return Err(RequestError::Length);
    };
    #[cfg(test)]
    if tests::planted(tests::Plant::FieldsFirst) {
        fields(body)?;
    }
    let expected = words(&tag(key, addressed, body));
    if !bool::from(expected[..].ct_eq(&words(received)[..])) {
        return Err(RequestError::Tag);
    }
    let request = fields(body)?;
    if request.owner != addressed {
        return Err(RequestError::Addressee);
    }
    Ok(AuthenticatedRequest(request))
}

/// The body and the tag of a request of exactly [`REQUEST_LEN`] bytes.
fn split(bytes: &[u8]) -> Option<(&[u8; TAG_AT], &[u8; TAG_LEN])> {
    let (body, tag) = bytes.split_first_chunk()?;
    Some((body, tag.try_into().ok()?))
}

/// The four words of a tag. [`decode`] compares two tags word by word, each word in constant time.
fn words(tag: &[u8; TAG_LEN]) -> [u64; 4] {
    let (words, _) = tag.as_chunks();
    std::array::from_fn(|at| u64::from_ne_bytes(words[at]))
}

fn fields(body: &[u8]) -> Result<PlannedRequest, RequestError> {
    if u16::from_be_bytes([body[0], body[1]]) != SCHEMA {
        return Err(RequestError::Schema);
    }
    let kind = match (body[KIND_AT], Host::new(u64_at(body, TARGET_AT))) {
        (1, Some(target)) => Kind::Transfer { target },
        (2, None) => Kind::Restart,
        _ => return Err(RequestError::Kind),
    };
    Ok(PlannedRequest {
        kind,
        operation: ExitOperation::new(field_at(body, OPERATION_AT)).ok_or(RequestError::Field)?,
        sequence: Sequence(u64_at(body, SEQUENCE_AT)),
        shard: Shard::new(u32_at(body, SHARD_AT)).ok_or(RequestError::Field)?,
        generation: ShardGeneration::new(u64_at(body, GENERATION_AT)).ok_or(RequestError::Field)?,
        attempts: u32_at(body, ATTEMPTS_AT),
        owner: Host::new(u64_at(body, OWNER_AT)).ok_or(RequestError::Field)?,
        deadline_us: NonZeroU32::new(u32_at(body, DEADLINE_AT)).ok_or(RequestError::Field)?,
    })
}

/// How one owner tenure classes an authenticated request.
#[must_use = "an accepted request is the tenure's running operation, and a repeat is answered with its status"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// The request becomes the tenure's running operation; the caller starts its drain.
    Accept,
    /// The request names the tenure's latest operation, running or ended; the caller answers with that operation's
    /// status.
    Repeat,
    /// The request binds an earlier tenure of this owner: a lower generation, or a lower `E` at the tenure's
    /// generation. The tenure refuses it silently.
    Stale,
    /// The request names another owner, another shard or a later tenure.
    NotOwner,
    Busy,
    NotServing,
    /// The sequence lies at or below the highest sequence the tenure saw bound to it.
    LowSequence,
    Consumed,
    Full,
}

/// `Ledger` records one owner tenure's accepted operations, oldest first.
#[cfg_attr(test, derive(Clone))]
#[derive(Debug, PartialEq, Eq)]
pub struct Ledger {
    shard: Shard,
    own: Target,
    accepted: Vec<ExitOperation>,
    running: bool,
    rolling: bool,
    seen: Option<Sequence>,
}

impl Ledger {
    /// The empty ledger of the tenure `session` activated.
    pub fn new(session: &Session) -> Self {
        Self {
            shard: session.shard(),
            own: session.target(),
            accepted: Vec::with_capacity(OPERATIONS_MAX),
            running: false,
            rolling: false,
            seen: None,
        }
    }

    /// Classifies `request` under the tenure's serving state `state`, which the caller reads from the serving
    /// machine of the same session. The first matching class, in this order:
    ///
    /// 1. `NotOwner` or `Stale` when the owner, shard, generation or attempt counter differs from the tenure's,
    ///    with the ledger unchanged.
    /// 2. `Repeat` when the request names the latest accepted operation, whatever its sequence and the serving
    ///    state.
    /// 3. `Consumed` when the request names an earlier accepted operation, whatever its sequence and the serving
    ///    state.
    /// 4. `LowSequence` when the sequence lies at or below the high-water mark, with the ledger unchanged.
    /// 5. `NotServing` when `state` is `PreBoundary`, `Recovering`, `Withdrawn` or `Closed`.
    /// 6. `Busy` while a requested operation or a roll runs.
    /// 7. `Full` when the tenure holds [`OPERATIONS_MAX`] accepted operations.
    /// 8. `Accept`, which makes the request the running operation.
    ///
    /// ```compile_fail,E0308
    /// # use kestrike::failover::planned::{Ledger, PlannedRequest};
    /// # use kestrike::failover::serving::State;
    /// fn admit_raw(ledger: &mut Ledger, request: &PlannedRequest) {
    ///     let _ = ledger.admit(request, State::Serving);
    /// }
    /// ```
    ///
    /// A bound request whose sequence exceeds the high-water mark raises the mark to it, a repeat included.
    pub fn admit(&mut self, request: &AuthenticatedRequest, state: State) -> Binding {
        let request = request.request();
        let named = (request.generation, request.attempts);
        let tenure = (self.own.generation, self.own.attempts);
        #[cfg(test)]
        let tenure = match tests::planted(tests::Plant::AttemptsIgnored) {
            true => (self.own.generation, request.attempts),
            false => tenure,
        };
        if request.owner != self.own.owner || request.shard != self.shard || named > tenure {
            return Binding::NotOwner;
        }
        if named < tenure {
            return Binding::Stale;
        }
        let fresh = self.seen.is_none_or(|seen| request.sequence > seen);
        if fresh {
            self.seen = Some(request.sequence);
        }
        if self.accepted.last() == Some(&request.operation) {
            return Binding::Repeat;
        }
        if self.accepted.contains(&request.operation) {
            return Binding::Consumed;
        }
        if !fresh {
            return Binding::LowSequence;
        }
        if state != State::Serving {
            return Binding::NotServing;
        }
        if self.running || self.rolling {
            return Binding::Busy;
        }
        if self.accepted.len() == OPERATIONS_MAX {
            return Binding::Full;
        }
        self.accepted.push(request.operation);
        self.running = true;
        Binding::Accept
    }

    pub fn running(&self) -> Option<ExitOperation> {
        self.accepted.last().copied().filter(|_| self.running)
    }

    pub fn start_roll(&mut self) -> bool {
        let start = !self.running && !self.rolling;
        self.rolling |= start;
        start
    }

    pub fn roll_resumed(&mut self) {
        self.rolling = false;
    }

    /// Ends `operation` when it is the running operation and resumed in place before its withdrawal, and preserves
    /// the ledger for any other operation. The ledger keeps the ended operation, so a request naming it stays a
    /// repeat, and keeps its sequence high-water mark, so a later request must exceed that mark to be accepted.
    pub fn resumed(&mut self, operation: ExitOperation) {
        if self.running() == Some(operation) {
            self.running = false;
        }
    }
}

#[cfg(test)]
#[path = "request_tests.rs"]
mod tests;
