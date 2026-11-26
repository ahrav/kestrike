//! The owner's PUT core bounds concurrent uploads by a global PUT cap and a per-peer PUT cap.
//!
//! - Coverage: with a fencing installed, a BEGIN starts an attempt only while [`Fencing::admits`] its key and version, and a ready FILL reaches the index insert only when the same check passes again just before it.
//! - Conservation: `live` and each peer's count equal the live PUT records in the request table, active and draining, because `release` lowers them only when `requests.release` frees the record.
//! - GET backlog: the request table counts active and draining GETs. The backlog check rejects a BEGIN with `RequestPressure` when the total reaches [`PutConfig::get_backlog`] and `2 * peers` times the issuing peer's count of them reaches `get_backlog` too. Rejection precedes allocation of a request slot, lane, or fill record. Existing PUTs continue, and a peer whose own count falls short passes this check whatever GETs the other peers hold.
//! - Reserves: [`OwnerConfig`](super::owner::OwnerConfig) bounds `puts` by `request_slots - get_reserve` and `peer_puts` by `peer_requests - peer_get_reserve`. These caps include draining PUTs to preserve GET headroom; each retired request slot reduces that headroom by one.
//! - Write commands: each peer's share is the volume's write share divided among the peers, rounded down. A turn lends: a PUT takes any write command the volume admits (WRITE-ROOM), so a peer's uploads use the commands other peers leave idle. A turn in which a PUT with a write to submit or an object to prime, of a peer holding fewer commands than its share, finds no command it may take, because the volume admits none or the turn's budget is spent, is followed by a turn that lends nothing, in which a PUT takes a command only while its peer holds fewer than its share. A PUT whose every unit is submitted waits for its terminals and asks for no command. So from the turn after such a peer first finds none, and while a PUT of a peer below its share ends each turn with a write to submit and no command for it, every command goes to a peer below its share. Such a peer waits for at most the terminals of the commands held beyond the other peers' shares and for the budget that earlier admissions of peers below their shares take.
//! - Order: each PUT slot retains its rank from admission until record release. Ranks increase in BEGIN admission order. Each progress pass reads only waiting PUTs' ranks and visits those PUTs in rank order. Among PUTs admitted by the write-command rule, earlier admissions receive write commands, the turn's copy and command-byte budgets, and free runs first, so a later admission copies a held fragment from what the earlier admissions' held fragments leave of those budgets. PREPARE reserves and primes a one-extent PUT or starts placement of a larger PUT. A DATA resend incurs its comparison cost at receipt, before the turn's progress pass.
//! - Wire bindings: a PUT ERROR that tells the client its upload ended names the record's table handle, so the PUT's wire binding frees once that ERROR enters the sent prefix: the ERROR the end queues, and, while the ended record still holds the binding, the replay of its retained terminal or the `UnknownOutcome` that answers a frame after the row expired. An ended PUT whose writes are still outstanding then drains unbound, keeping its table slot, lane, peer share and write custody until `release`. A PUT whose client was sent no such ERROR keeps its binding until release. A PUT RESULT names no record: the call that queues it releases the record and its binding, before the reply can be sent.
//! - Run waiters: `report.run_waiters` equals the placing PUTs whose builder waits for a free run and stays at most `config.run_waiters`. A placement that begins to wait raises it once, or ends its PUT in the same turn when the count is at the cap; a waiter's retry that clears the wait and `end` on an admitted waiting placement each lower it once.

use subtle::ConstantTimeEq;

use crate::index::ShardIndex;
use crate::storage::CacheVersion;
use crate::storage::page_coverage::Fencing;
use crate::storage::{
    BeginError, Crc32c, Decision, Disk, EngineBudget, EngineBudgetExceeded, FillAttempt,
    FillFailure, FillPublishError, FillReserveError, Ineligible, PlacingFill, Platform,
    ReceiveError, Volume, WorkBudget, WorkKind, WritableFill,
};

use super::auth::{KeyRing, TAG_LEN};
use super::datagram::{HEADER_LEN, MAX_DATAGRAM, PeerId};
use super::frame::{
    Direction, Header, Kind, MAX_WINDOW, MacInput, Status, encode_with_body_crc, mac_input_for,
    raw_body_crc,
};
use super::namespace::{Cached, Operation, Refusal, Route};
use super::packet::PacketLease;
use super::permit::PutPermits;
use super::requests::{RequestId, RequestTable};
use super::serve::{Manifest, PutReply, ServeCore};
use super::served::{Outcome, Request, Requests};
use super::session::Admitted;
use super::sha_lanes::LANES;

const NANOS: u64 = 1_000_000_000;

/// The owner returns [`OwnerError::GetReserve`](super::owner::OwnerError::GetReserve) when `puts` exceeds `request_slots - get_reserve` or `peer_puts` exceeds `peer_requests - peer_get_reserve`, so the PUT caps keep both GET reserves free of PUT records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PutConfig {
    /// Active and draining PUTs count toward `puts` until their request-table records are released. Live PUTs across all peers obey the limits documented by [`OwnerError::Puts`](super::owner::OwnerError::Puts) and [`OwnerError::FillCapacity`](super::owner::OwnerError::FillCapacity). The fill-capacity check is pooled across shards, while each BEGIN takes its fill record from its key's shard, so a BEGIN within `puts` can still refuse `FillSlotsFull`; [`IndexConfig::fills`](crate::index::IndexConfig::fills) states the per-shard sizing rule. With watermarks and `puts > 0`, start also requires `low_units` at least [`structural_floor`](crate::storage::ValidatedConfig::structural_floor)`(puts)`.
    pub puts: u32,
    /// Active and draining PUTs of one peer count toward `peer_puts` until their records are released; `fits` requires peers times this at most `puts`.
    pub peer_puts: u32,
    /// `run_waiters` caps concurrent PUTs waiting for a free run, across every peer. Startup returns [`OwnerError::RunWaiters`](super::owner::OwnerError::RunWaiters) when `puts` is positive and `run_waiters` lies outside `1..=puts`. [`PutReport::run_wait_refused`] counts PUTs refused at the cap. Each waiter retains a request slot and the fill record its BEGIN drew from its key's shard, so BEGINs routed to a shard whose records waiters hold refuse `FillSlotsFull`; the deployer sizes `run_waiters` with [`IndexConfig::fills`](crate::index::IndexConfig::fills) in view. Startup checks `run_waiters` against `puts` alone. Waiters can hold `min(run_waiters, fills)` records of one shard, leaving that shard `fills.saturating_sub(run_waiters)` records for other attempts; at `run_waiters >= fills` they can hold every record of one shard.
    pub run_waiters: u32,
    /// After both PUT caps pass, the owner refuses BEGIN with `RequestPressure` if both the total active or draining GET count and `2 * peers * k` are at least `get_backlog`. Here, `peers` counts all peers in the table, and `k` counts active or draining GETs for the requesting peer. [`PutReport::refused_get_backlog`] counts these refusals, which precede request-slot, lane, and fill-record allocation. Otherwise, BEGIN proceeds to request-table admission. Set `get_backlog` above the estimated mean backlog at normal load: admitted GET rate times mean time per admitted GET spent active or draining. A value above the request-slot count disables backlog refusals. Startup returns [`OwnerError::Puts`](super::owner::OwnerError::Puts) when `puts > 0` and `get_backlog == 0`.
    pub get_backlog: u32,
    pub commands: usize,
    pub command_bytes: usize,
    pub window: u32,
    pub copy_bytes: usize,
    pub publish_tries: usize,
    pub publish_work: usize,
}

impl PutConfig {
    pub(super) fn fits(
        &self,
        (peers, slots): (u16, u32),
        (data_cap, write_cap, segment_len): (u32, u64, usize),
    ) -> bool {
        u64::from(peers) * u64::from(self.peer_puts) <= u64::from(self.puts)
            && self.puts <= slots
            && u64::from(self.puts) * u64::from(self.window) <= u64::from(data_cap)
            && self.publish_tries > 0
            && self.publish_work > 0
            && (self.puts == 0
                || self.commands > 0
                    && self.get_backlog > 0
                    && write_cap >= u64::from(peers)
                    && self.command_bytes >= segment_len
                    && self.copy_bytes >= 2 * MAX_DATAGRAM
                    && (1..=MAX_WINDOW).contains(&self.window))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Shape {
    metadata_len: u32,
    body_len: u32,
    ttl_ms: u32,
}

impl Shape {
    fn of(header: &Header) -> Self {
        Self {
            metadata_len: header.metadata_len,
            body_len: header.body_len,
            ttl_ms: header.remaining_ms,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
    key: [u8; 32],
    serial: u64,
    shape: Option<Shape>,
    /// The cache version PUT BEGIN names.
    version: CacheVersion,
}

impl Fingerprint {
    fn matches(&self, header: &Header) -> bool {
        let serial = header.allocation == self.serial;
        header.key == self.key
            && match header.kind {
                Kind::PutPrepare => {
                    serial && self.shape.is_none_or(|shape| shape == Shape::of(header))
                }
                Kind::PutCancel => header.allocation == 0 || serial,
                Kind::PutBegin => begin_version(header) == self.version,
                _ => true,
            }
    }

    fn manifest(&self) -> Manifest {
        let (metadata_len, body_len) = self
            .shape
            .map_or((0, 0), |shape| (shape.metadata_len, shape.body_len));
        Manifest {
            allocation: self.serial,
            metadata_len,
            body_len,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Terminal {
    Published(Manifest),
    Failed(Status),
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct PutRow {
    fingerprint: Fingerprint,
    terminal: Terminal,
}

enum Stage<'s, 'a, P: Platform> {
    Authority(FillAttempt<'s, P>),
    /// An object of several extents whose placement continues on progress turns, each funded with the reservation work.
    Placing(PlacingFill<'s, P>),
    Priming(WritableFill<'s, 'a, P>),
    Ready(WritableFill<'s, 'a, P>),
    /// An ended upload whose writes are still outstanding, with the failure
    /// its fill records for followers when the drain ends it.
    Draining(WritableFill<'s, 'a, P>, Option<FillFailure>),
}

/// A record's stage lent to a write receive. `Receiving` drops the stage and its fill on unwinding; [`PutCore::receive`] forgets the guard on return to preserve the stage.
struct Receiving<'p, 's, 'a, P: Platform>(&'p mut Option<Stage<'s, 'a, P>>);

impl<P: Platform> Drop for Receiving<'_, '_, '_, P> {
    fn drop(&mut self) {
        *self.0 = None;
    }
}

pub struct Put<'s, 'a, P: Platform> {
    peer: PeerId,
    epoch: u64,
    request: u64,
    fingerprint: Fingerprint,
    deadline_us: u64,
    /// When the BEGIN was admitted, and when READY was sent; zero before.
    begun_us: u64,
    ready_us: u64,
    /// The core's turn number at the PREPARE. A PUT whose PREPARE placement starts a run wait retries the placement
    /// from the next turn on.
    prepared_turn: u64,
    expires_s: u32,
    lane: u16,
    base: u32,
    consumed: u32,
    held: u32,
    offset: usize,
    granted: u32,
    window: u32,
    /// Write commands the fill had in flight at the last observation, counted in the peer's share.
    commands: u32,
    /// The commands the fill had in flight at the latest read a progress visit made of it on entry, when that read found every fragment consumed and every unit submitted; zero otherwise. While it is nonzero and `commands` equals it, no command of the fill ended since that read, so the write set's counts are as that read found them, and the fill fails only when its token stops admitting fills.
    quiet: u32,
    /// Whether the fill holds a segment whose submit a receive that returned `Ok` found refused, for the turn's
    /// budget or by the volume, and every receive since was refused before it took a byte, so the segment still
    /// waits staged for the next receive. A receive that returns `Ok` with no refused submit submitted it and
    /// clears this.
    staged: bool,
    stage: Option<Stage<'s, 'a, P>>,
}

impl<P: Platform> Put<'_, '_, P> {
    fn draining(&self) -> bool {
        matches!(self.stage, Some(Stage::Draining(..)))
    }

    fn takes(&self, session: Admitted, header: &Header) -> bool {
        let manifest = self.fingerprint.manifest();
        self.epoch == session.epoch
            && header.key == self.fingerprint.key
            && header.allocation == self.fingerprint.serial
            && matches!(self.stage, Some(Stage::Ready(_)))
            && header.total == manifest.total()
            && header.metadata_len == manifest.metadata_len
            && header.body_len == manifest.body_len
            && header.index < self.granted
    }

    /// Queues the reply of `kind`; `table` names this record when the reply is the PUT ERROR that ends it, so the sent reply frees the record's wire binding.
    #[inline(always)]
    fn reply(
        &self,
        serve: &mut ServeCore,
        table: Option<RequestId>,
        kind: Kind,
        status: Option<Status>,
        mask: u64,
    ) {
        let (manifest, grant, index) = match kind {
            Kind::PutReady => (self.fingerprint.manifest(), self.granted, 0),
            Kind::PutAck => (self.fingerprint.manifest(), self.granted, self.base),
            Kind::PutResult => (self.fingerprint.manifest(), 0, 0),
            _ => (
                Manifest {
                    allocation: self.fingerprint.serial,
                    metadata_len: 0,
                    body_len: 0,
                },
                0,
                0,
            ),
        };
        let put = PutReply {
            kind,
            manifest,
            grant,
            status: status.map_or(0, |status| status as u16),
            index,
            offset: mask,
        };
        // The fill's own PUT RESULT is its first; a replay of the retained terminal queues through `replay`.
        if kind == Kind::PutResult {
            let key = self.fingerprint.key;
            serve.queue_put_result(self.peer, self.epoch, self.request, key, put);
            return;
        }
        serve.queue_put(
            table,
            self.peer,
            self.epoch,
            self.request,
            self.fingerprint.key,
            put,
        );
    }

    fn ending(&self, status: Status) -> Status {
        if self.stage.is_some() {
            status
        } else {
            Status::UnknownOutcome
        }
    }
}

fn refuse(serve: &mut ServeCore, session: Admitted, header: &Header, status: Status) {
    answer(serve, None, session, header, status);
}

/// Queues a PUT ERROR of `status` answering `header`; `table` names the ended record the wire identity still binds, whose binding the sent reply frees.
fn answer(
    serve: &mut ServeCore,
    table: Option<RequestId>,
    session: Admitted,
    header: &Header,
    status: Status,
) {
    let put = PutReply {
        kind: Kind::PutError,
        manifest: Manifest {
            allocation: 0,
            metadata_len: 0,
            body_len: 0,
        },
        grant: 0,
        status: status as u16,
        index: 0,
        offset: 0,
    };
    serve.queue_put(
        table,
        session.peer,
        session.epoch,
        header.request,
        header.key,
        put,
    );
}

/// Queues the retained terminal `row` answering `header`; `table` names the ended record the wire identity still binds, whose binding a sent PUT ERROR frees.
fn replay(
    serve: &mut ServeCore,
    table: Option<RequestId>,
    session: Admitted,
    header: &Header,
    row: &PutRow,
) {
    let (kind, manifest, status) = match row.terminal {
        Terminal::Published(manifest) => (Kind::PutResult, manifest, 0),
        Terminal::Failed(status) => (
            Kind::PutError,
            Manifest {
                allocation: row.fingerprint.serial,
                metadata_len: 0,
                body_len: 0,
            },
            status as u16,
        ),
    };
    let put = PutReply {
        kind,
        manifest,
        grant: 0,
        status,
        index: 0,
        offset: 0,
    };
    serve.queue_put(
        table.filter(|_| kind == Kind::PutError),
        session.peer,
        session.epoch,
        header.request,
        header.key,
        put,
    );
}

struct Lane<'m> {
    ring: Box<[Option<PacketLease<'m>>]>,
    /// The lane records each fragment's sequence and verified tag on ring entry and retains them for comparison with resends of consumed indices while it holds the attempt.
    sequences: Box<[u64]>,
    tags: Box<[[u8; TAG_LEN]]>,
}

impl Lane<'_> {
    fn evidence(&self, index: usize) -> Evidence {
        Evidence {
            sequence: self.sequences[index],
            tag: self.tags[index],
        }
    }
}

/// The send sequence and verified tag of the DATA frame that delivered a fragment. Every other authenticated field of a PUT DATA header follows from the attempt, its session and the fragment index, so the frame's authenticated header can be rebuilt from a resend's header and this sequence.
#[derive(Clone, Copy)]
struct Evidence {
    sequence: u64,
    tag: [u8; TAG_LEN],
}

/// `Resend` pairs an authenticated PUT DATA frame for a consumed fragment with evidence from the frame that delivered the fragment.
struct Resend<'b> {
    peer: PeerId,
    header: &'b Header,
    body: &'b [u8],
    crc: u32,
    evidence: Evidence,
}

/// `Retag` recomputes resend tags using the original frames' sequences for comparison with retained evidence.
pub(super) struct Retag<'r> {
    pub(super) ring: &'r KeyRing,
    pub(super) endpoint: u32,
    pub(super) crc: Crc32c,
}

impl Retag<'_> {
    /// `compare` checks resend bodies against retained evidence by restoring each original sequence and comparing tags in constant time. Equal tags for unequal bodies require a collision of HMAC-SHA256 truncated to 128 bits. Each result contains the original sequence and tag equality; an entry is `None` when the resend is absent or header encoding, MAC input construction, or tagging fails.
    fn compare<const N: usize>(&self, resends: [Option<Resend<'_>>; N]) -> [Option<Verdict>; N] {
        const { assert!(N <= LANES) };
        let encoded: [Option<[u8; HEADER_LEN]>; N] = std::array::from_fn(|at| {
            let resend = resends[at].as_ref()?;
            let original = Header {
                sequence: resend.evidence.sequence,
                ..*resend.header
            };
            let mut out = [0; HEADER_LEN];
            encode_with_body_crc(
                self.crc,
                &original,
                [resend.body, &[]],
                resend.crc,
                &mut out,
            )
            .ok()?;
            Some(out)
        });
        let inputs: [Option<(PeerId, MacInput<'_>, Evidence)>; N] = std::array::from_fn(|at| {
            let resend = resends[at].as_ref()?;
            let input = mac_input_for(
                encoded[at].as_ref()?,
                [resend.body, &[]],
                self.endpoint,
                Direction::ClientToOwner,
            )?;
            Some((resend.peer, input, resend.evidence))
        });
        let Some(&first) = inputs.iter().flatten().next() else {
            return [None; N];
        };
        let (mut picked, mut slots, mut count) = ([first; N], [0; N], 0);
        for (at, input) in inputs.iter().enumerate() {
            if let Some(input) = input {
                (picked[count], slots[count]) = (*input, at);
                count += 1;
            }
        }
        let group = |k: usize| (picked[k].0, &picked[k].1);
        let tags = match count {
            4 => self
                .ring
                .tag_group(std::array::from_fn::<_, 4, _>(group))
                .map(pad),
            3 => self
                .ring
                .tag_group(std::array::from_fn::<_, 3, _>(group))
                .map(pad),
            2 => self
                .ring
                .tag_group(std::array::from_fn::<_, 2, _>(group))
                .map(pad),
            _ => self
                .ring
                .tag_group(std::array::from_fn::<_, 1, _>(group))
                .map(pad),
        };
        #[cfg(test)]
        RETAG_GROUPS.with(|groups| {
            let mut seen = groups.get();
            seen[count] += 1;
            groups.set(seen);
        });
        let mut verdicts = [None; N];
        let Some(tags) = tags else {
            return verdicts;
        };
        for (k, &at) in slots[..count].iter().enumerate() {
            let evidence = picked[k].2;
            verdicts[at] = Some(Verdict {
                sequence: evidence.sequence,
                equal: bool::from(tags[k].ct_eq(&evidence.tag)),
            });
        }
        verdicts
    }
}

fn pad<const K: usize>(tags: [[u8; TAG_LEN]; K]) -> [[u8; TAG_LEN]; LANES] {
    let mut out = [[0; TAG_LEN]; LANES];
    out[..K].copy_from_slice(&tags);
    out
}

#[cfg(test)]
thread_local! {
    pub(super) static RETAG_GROUPS: std::cell::Cell<[usize; LANES + 1]> = const { std::cell::Cell::new([0; LANES + 1]) };
}

pub(super) type DataFrame<'f> = (Admitted, &'f Header, &'f [u8], u32);

#[derive(Clone, Copy)]
pub(super) struct Verdict {
    sequence: u64,
    equal: bool,
}

impl Verdict {
    fn for_sequence(self, stored: u64) -> Option<bool> {
        (self.sequence == stored).then_some(self.equal)
    }
}

fn debit_comparison(copy: &mut WorkBudget, header: &Header) -> bool {
    copy.debit_command(WorkKind::Comparison, 0, header.datagram_len as usize)
        .is_ok()
}

/// PutReport accumulates refusals and failures by stage over the PUT core's lifetime; `run_waiters` counts admitted PUTs waiting for a run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PutReport {
    /// BEGINs that acquired fill authority.
    pub begun: u64,
    /// BEGINs refused because the live PUTs, the peer's share or the lanes were spent or the live GETs reached the backlog; each such refusal also counts once in `refused_global_cap`, `refused_peer_share`, `refused_get_backlog` or `refused_lane_guard`.
    pub refused_live: u64,
    /// BEGINs refused because live PUTs reached `puts`, a check that precedes the peer's, so a BEGIN with both caps spent counts here.
    pub refused_global_cap: u64,
    /// BEGINs refused because the peer's live PUTs reached `peer_puts`; the counter includes BEGINs with `peer_puts == 0` that pass the global cap check.
    pub refused_peer_share: u64,
    /// Counts BEGINs rejected by the GET backlog check. The check precedes the lane check. Rejection requires at least [`PutConfig::get_backlog`] live GETs in the request table and `2 * peers` times the requesting peer's live GETs reaching `get_backlog`.
    pub refused_get_backlog: u64,
    /// BEGINs refused because no lane was free while both caps had room and the GET backlog check passed.
    pub refused_lane_guard: u64,
    /// BEGINs that the request namespace refuses with a [`NamespaceRefusal`](super::NamespaceRefusal).
    pub refused_namespace: u64,
    /// BEGINs refused because the storage's fill records were spent.
    pub refused_fill_slots: u64,
    /// `run_wait_refused` counts PUTs ended with `StoragePressure` when a builder begins waiting for a free run while [`PutConfig::run_waiters`] PUTs already wait. Each refusal also increments `failed_other` and ends its placement in the same turn. `reserve_refused` and its four parts exclude these refusals.
    pub run_wait_refused: u64,
    /// Placing PUTs whose builder waits for a free run, at most [`PutConfig::run_waiters`]. The count rises once when a placement begins to wait and falls once when a retry clears the wait or the waiting PUT ends.
    pub run_waiters: u32,
    /// BEGINs refused because another attempt holds the key.
    pub refused_in_progress: u64,
    /// BEGINs refused for any other reason.
    pub refused_other: u64,
    /// `reserve_refused` counts reservation refusals for any status at PREPARE, on placement turns, and when a placement waiting for a free run reaches its deadline. Each storage-pressure refusal also increments exactly one of `reserve_refused_slots`, `reserve_refused_payload`, `reserve_refused_clean_reserve`, or `reserve_refused_retired`. Refusals at the run-waiter cap count in [`run_wait_refused`](Self::run_wait_refused) instead.
    pub reserve_refused: u64,
    /// Reservations refused with [`FillReserveError::ObjectSlotsFull`] because no object slot was free; a BEGIN short of a fill record counts in `refused_fill_slots` instead.
    pub reserve_refused_slots: u64,
    /// Reservations refused with [`FillReserveError::PayloadFull`] count here when the layout's unit or extent requirements exceed every free run's capacity, or the sequence arena's blocks are exhausted. Refusals at the run-waiter cap count in [`run_wait_refused`](Self::run_wait_refused).
    pub reserve_refused_payload: u64,
    /// Reservations refused with [`FillReserveError::CleanReserve`] because the charge plus the clean reserve and the escrow of promised units exceeded the free units.
    pub reserve_refused_clean_reserve: u64,
    /// Reservations refused with [`FillReserveError::RetiredPressure`] because the retired charge had reached the retired allowance.
    pub reserve_refused_retired: u64,
    /// PUT reservations return [`FillReserveError::Bootstrapping`] while the volume's readiness is below `Live`.
    pub reserve_refused_bootstrapping: u64,
    pub published: u64,
    /// Receives the volume refused with a terminal error, on any stage's path; each such PUT also ends through `fail` and counts once more below.
    pub failed_receive: u64,
    pub failed_publish: u64,
    /// PUTs that ended with a failure status, by status: `TimedOut` or `UnknownOutcome`, `Cancelled`, and every other status.
    pub failed_timed_out: u64,
    pub cancelled: u64,
    pub failed_other: u64,
    /// Write commands the fills submitted through the core's turn budgets.
    pub write_commands: u64,
    /// Consume passes that stopped with received data held because no write command was available.
    pub command_waits: u64,
    /// Receives the volume refused for a full table, an empty pool or a spent budget, which the next progress turn retries.
    pub receive_waits: u64,
    /// Placement calls, at PREPARE or on a progress turn, that left the PUT placing for the next turn: extents still unplaced, a placement completed with the shard hold still to take, a budget short of one placement at the PREPARE, or a busy pool gate. A call that found no free run counts in `run_waits`, or in `run_wait_refused` when refused at the run-waiter cap.
    pub place_waits: u64,
    /// `run_waits` counts one wait per waiting PUT per turn: the placement call, at PREPARE or on a progress turn, that finds no free run for the next extent and leaves the PUT placing, and each later progress pass that again finds no free run. A pass whose retry meets a busy pool gate counts in `place_waits` instead. The waiting PUT retains its request slot and fill record, and its [`Builder`](crate::storage::Builder) its object slot, sequence block, placed extents and the units still promised, between passes. A pass retries the waiter's placement, or counts the wait from the pool's run bound alone while that bound proves no free run for the marked waiters' least wait units, until a retry places an extent or the PUT ends. Placements refused at the run-waiter cap count in `run_wait_refused`.
    pub run_waits: u64,
    /// The most PUTs live at once.
    pub live_peak: u32,
    /// Microseconds from the admitted BEGIN to the PREPARE taken, summed over the PUTs whose PREPARE arrived; from the admitted BEGIN to the READY sent, summed over the PUTs that reached READY; and from READY to the publication, summed over the published PUTs.
    pub begin_to_prepare_us: u64,
    pub begin_to_ready_us: u64,
    pub ready_to_published_us: u64,
}

pub(super) struct PutCore<'m> {
    config: PutConfig,
    report: PutReport,
    linger_us: u64,
    max_wait_us: u64,
    tries: usize,
    work: usize,
    write_cap: u64,
    live: u32,
    peers: Box<[u32]>,
    /// Write commands each peer's PUTs have in flight, by the last observation of each.
    commands: Box<[u32]>,
    /// For each peer, the volume's count of ended write commands when each of the peer's uploads was last observed together; zero from the start, when the peer has none. An upload's count rises only through [`receive`](Self::receive), which observes it at once, and falls only when that count of ended commands rises, so while the volume's count equals the peer's entry the peer's count in `commands` is what the peer holds.
    observed: Box<[u64]>,
    /// Whether this turn lends: a PUT takes write commands beyond its peer's share.
    lending: bool,
    /// Whether a PUT of a peer below its share found no write command it may take this turn; the next turn then lends nothing.
    short: bool,
    lanes: Box<[Lane<'m>]>,
    free: Vec<u16>,
    /// `occupied` holds one bit per table slot, set exactly while that slot holds a PUT record.
    occupied: Box<[u64]>,
    /// `waiting` holds one bit per table slot, set while that slot's PUT has progress-turn work: it is placing or priming, holds a primed empty object, holds received data or in-flight writes, has received every fragment, or is draining.
    waiting: Box<[u64]>,
    /// `holding` holds one bit per lane, set by each [`receive`](Self::receive) that leaves the lane's PUT counting a write command in flight, and cleared by the peer observation that finds the count at zero or by the PUT's release. A count rises only through `receive`, so a PUT that counts a command is marked here, and a PUT not marked counts none and holds none: only the marked PUTs can count more than they hold.
    holding: Box<[u64]>,
    /// The peer and table slot of the PUT that holds each lane, written when the PUT takes the lane; read only for a lane marked in `holding`.
    holders: Box<[(PeerId, u16)]>,
    /// `marked_waiters` holds one bit per table slot. Each marked slot holds a live placing PUT whose builder waits and whose slot is set in `waiting`. A mark is set when a waiter's retry returns `PayloadFull`, after that retry's `place_steps` preflight passed on the fixed `work` budget. While [`Storage::proves_no_run`](crate::storage::Storage::proves_no_run) holds for `wait_floor`, the progress pass counts each marked PUT's run wait from that proof alone.
    marked_waiters: Box<[u64]>,
    /// `wait_floor` is a lower bound on the marked PUTs' wait units and equals their minimum while `floor_stale` is false. A lower floor makes `proves_no_run` harder to satisfy. When `proves_no_run(wait_floor)` is false, each marked PUT retries using its own wait units.
    wait_floor: u64,
    /// `floor_stale` records removal of a mark at `wait_floor`. The next progress pass with work recomputes `wait_floor` by scanning remaining marks once, batching recomputation across waiter removals.
    floor_stale: bool,
    pending: u32,
    /// The admission rank of each slot's PUT, [`NONE`] for a slot without one.
    rank: Box<[u32]>,
    /// The slot whose PUT holds each rank, [`NONE`] for a vacant rank.
    ranked: Box<[u32]>,
    /// One bit per rank, set while a PUT holds the rank.
    ranked_live: Box<[u64]>,
    /// One bit per rank, set while the rank's slot is set in `waiting`.
    ranked_waiting: Box<[u64]>,
    next_rank: u32,
    turn: WorkBudget,
    /// The number of turns begun, so a PUT tells the turn of its PREPARE apart from later turns at the same `now_us`.
    turn_number: u64,
    copy: WorkBudget,
    deadlines: Deadlines,
    released: bool,
    /// `run_waiter` records whether a placement registered as a run waiter under the cap since the last take. The owner consumes this flag before maintenance and ends the maintenance rest on a waiter's first registration, so the next headroom read follows within the stage rotation.
    run_waiter: bool,
    /// The fills that departed since the last take: published, failed or abandoned.
    departed: Departed,
    lost: bool,
    /// One bit per table slot, set while the slot's PUT owes an ACK this turn: a DATA frame taken or matched against a consumed fragment, a consume pass that moved, or a duplicate PREPARE of a ready PUT whose base is above zero. The turn's end sends one ACK per marked PUT with its final receipt base, mask and grant.
    acks: Box<[u64]>,
    acks_pending: u32,
    /// Validated fragments in validation order.
    #[cfg(test)]
    validated: Vec<Validation>,
    #[cfg(test)]
    validated_overflow: bool,
}

/// The slot of a vacant rank.
const NONE: u32 = u32::MAX;

/// Ranks in the admission order: one for each table slot and each PUT.
fn ranks(config: &PutConfig, slots: u32) -> usize {
    slots as usize + config.puts as usize
}

#[cfg(test)]
const VALIDATED_ROOM: usize = 1 << 12;

/// One fragment the PUT core validated and retained.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Validation {
    pub(crate) key: [u8; 32],
    /// The fill's serial.
    pub(crate) serial: u64,
    pub(crate) index: u32,
    /// The fill's receipt base once this fragment was retained.
    pub(crate) base: u32,
}

/// Tests use this snapshot for conservation checks.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Occupancy {
    pub(super) live: u32,
    pub(super) peers: Vec<u32>,
    pub(super) free_lanes: usize,
    pub(super) records: Vec<u32>,
}

/// The live PUTs placing with a fill that waits for a free run, counted from the request table's stages.
#[cfg(test)]
pub(super) fn waiting_placements<C, P: Platform>(requests: &Requests<C, Put<'_, '_, P>>) -> u32 {
    let table = requests.table();
    let mut waiting = 0;
    for slot in 0..table.high_water() {
        if let Some(id) = table.live_id(slot)
            && let Some(Request::Put(put)) = table.get(id)
            && let Some(Stage::Placing(placing)) = &put.stage
            && placing.waiting()
        {
            waiting += 1;
        }
    }
    waiting
}

pub(super) struct PutLimits {
    pub(super) linger_us: u64,
    pub(super) max_wait_us: u64,
    pub(super) tries: usize,
    pub(super) work: usize,
    pub(super) fragments: u32,
    pub(super) write_cap: u64,
}

impl<'m> PutCore<'m> {
    /// The returned byte count covers the allocations in [`new`](Self::new): each lane's record, receive ring, sequence and tag per fragment, and free-list entry; each peer's PUT and write-command counts and its observation mark; each lane's holder and its bit in `holding`; the `occupied`, `waiting`, `marked_waiters` and `acks` slot bitmaps; each slot's rank; each rank's slot and its live and waiting bits; and the deadline heap.
    pub(super) fn charge(
        config: &PutConfig,
        (peers, slots): (u16, u32),
        fragments: u32,
    ) -> Option<usize> {
        let lane = (config.window as usize)
            .checked_mul(size_of::<Option<PacketLease<'m>>>())?
            .checked_add((fragments as usize).checked_mul(size_of::<u64>() + TAG_LEN)?)?
            .checked_add(size_of::<Lane<'m>>() + size_of::<u16>())?;
        let words = (slots as usize).div_ceil(u64::BITS as usize);
        let ranks = ranks(config, slots);
        (config.puts as usize)
            .checked_mul(lane)?
            .checked_add(usize::from(peers) * (2 * size_of::<u32>() + size_of::<u64>()))?
            .checked_add((config.puts as usize).checked_mul(size_of::<(PeerId, u16)>())?)?
            .checked_add((config.puts as usize).div_ceil(u64::BITS as usize) * size_of::<u64>())?
            .checked_add(4 * words * size_of::<u64>())?
            .checked_add((slots as usize).checked_mul(size_of::<u32>())?)?
            .checked_add(ranks.checked_mul(size_of::<u32>())?)?
            .checked_add(2 * ranks.div_ceil(u64::BITS as usize) * size_of::<u64>())?
            .checked_add(Deadlines::bytes(config.puts, slots))
    }

    pub(super) fn new<C, F>(
        config: PutConfig,
        limits: &PutLimits,
        requests: &Requests<C, F>,
        budget: &mut EngineBudget,
    ) -> Result<Self, EngineBudgetExceeded> {
        let (peers, slots) = (requests.table().peers(), requests.table().slots());
        let words = (slots as usize).div_ceil(u64::BITS as usize);
        let ranks = ranks(&config, slots);
        let rank_words = ranks.div_ceil(u64::BITS as usize);
        budget.charge(
            Self::charge(&config, (peers, slots), limits.fragments).unwrap_or(usize::MAX),
        )?;
        let lanes = (0..config.puts)
            .map(|_| Lane {
                ring: (0..config.window).map(|_| None).collect(),
                sequences: vec![0; limits.fragments as usize].into_boxed_slice(),
                tags: vec![[0; TAG_LEN]; limits.fragments as usize].into_boxed_slice(),
            })
            .collect();
        Ok(Self {
            config,
            linger_us: limits.linger_us,
            max_wait_us: limits.max_wait_us,
            tries: limits.tries,
            work: limits.work,
            write_cap: limits.write_cap,
            live: 0,
            peers: vec![0; usize::from(peers)].into_boxed_slice(),
            commands: vec![0; usize::from(peers)].into_boxed_slice(),
            observed: vec![0; usize::from(peers)].into_boxed_slice(),
            lanes,
            free: (0..config.puts).rev().map(|lane| lane as u16).collect(),
            occupied: vec![0; words].into_boxed_slice(),
            waiting: vec![0; words].into_boxed_slice(),
            holding: vec![0; (config.puts as usize).div_ceil(u64::BITS as usize)]
                .into_boxed_slice(),
            holders: vec![(PeerId(0), 0); config.puts as usize].into_boxed_slice(),
            marked_waiters: vec![0; words].into_boxed_slice(),
            wait_floor: u64::MAX,
            floor_stale: false,
            pending: 0,
            rank: vec![NONE; slots as usize].into_boxed_slice(),
            ranked: vec![NONE; ranks].into_boxed_slice(),
            ranked_live: vec![0; rank_words].into_boxed_slice(),
            ranked_waiting: vec![0; rank_words].into_boxed_slice(),
            next_rank: 0,
            turn: WorkBudget::new(0),
            turn_number: 0,
            copy: WorkBudget::new(0),
            lending: true,
            short: false,
            deadlines: Deadlines::new(config.puts, slots),
            released: false,
            run_waiter: false,
            departed: Departed::default(),
            lost: false,
            acks: vec![0; words].into_boxed_slice(),
            acks_pending: 0,
            #[cfg(test)]
            validated: Vec::new(),
            #[cfg(test)]
            validated_overflow: false,
            report: PutReport::default(),
        })
    }

    /// Notes that the PUT in `slot` owes an ACK at the turn's end.
    fn owe_ack(&mut self, slot: u16) {
        let (word, bit) = (usize::from(slot) / 64, u64::from(slot) % 64);
        if self.acks[word] & (1 << bit) == 0 {
            self.acks[word] |= 1 << bit;
            self.acks_pending += 1;
        }
    }

    /// Sends one ACK to every PUT that received or consumed fragments this turn and is still ready, with its receipt base, mask and grant as they stand now; a PUT that ended this turn sent its own terminal reply.
    pub(super) fn flush_acks<C, P: Platform>(
        &mut self,
        requests: &mut Requests<C, Put<'_, '_, P>>,
        serve: &mut ServeCore,
    ) {
        if self.acks_pending == 0 {
            return;
        }
        let mut from = 0;
        while let Some(slot) = next_set(&self.acks, from) {
            from = slot + 1;
            self.acks[slot as usize / 64] &= !(1 << (slot % 64));
            if let Some((table, put)) = requests.live_put(slot)
                && matches!(put.stage, Some(Stage::Ready(_)))
            {
                self.acknowledge(requests, serve, table);
            }
        }
        self.acks_pending = 0;
    }

    pub(super) fn report(&self) -> PutReport {
        self.report
    }

    /// Whether this turn lends: a PUT takes any write command the volume admits, where a turn that lends nothing gives a PUT a command only while its peer holds fewer than its share.
    #[cfg(test)]
    pub(super) fn lends(&self) -> bool {
        self.lending
    }

    /// The table slots that hold PUT records, oldest admission first.
    #[cfg(test)]
    pub(super) fn admission_order(&self) -> Vec<u32> {
        let mut order = Vec::new();
        let mut from = 0;
        while let Some(rank) = next_set(&self.ranked_live, from) {
            from = rank + 1;
            order.push(self.ranked[rank as usize]);
        }
        order
    }

    /// Checks that the held ranks name exactly the slots whose `occupied` bit is set, each once and below `next_rank`, that each held rank's slot holds that rank, and that a rank's waiting bit is set exactly when its slot's `waiting` bit is.
    #[cfg(test)]
    pub(super) fn check_admission_order(&self) -> Result<(), String> {
        let bit = |words: &[u64], at: usize| words[at / 64] & (1 << (at % 64)) != 0;
        let count =
            |words: &[u64]| -> usize { words.iter().map(|word| word.count_ones() as usize).sum() };
        let mut held = 0;
        for (at, &slot) in self.ranked.iter().enumerate() {
            let live = bit(&self.ranked_live, at);
            if live != (slot != NONE) {
                return Err(format!("rank {at} names slot {slot} with live bit {live}"));
            }
            if slot == NONE {
                if bit(&self.ranked_waiting, at) {
                    return Err(format!("vacant rank {at} has its waiting bit set"));
                }
                continue;
            }
            held += 1;
            if at >= self.next_rank as usize {
                return Err(format!(
                    "rank {at} is at or past the next rank {}",
                    self.next_rank
                ));
            }
            if !bit(&self.occupied, slot as usize) {
                return Err(format!("rank {at} names slot {slot}, which holds no PUT"));
            }
            if self.rank[slot as usize] as usize != at {
                return Err(format!(
                    "rank {at} names slot {slot}, whose rank is {}",
                    self.rank[slot as usize]
                ));
            }
            if bit(&self.ranked_waiting, at) != self.waiting(slot as u16) {
                return Err(format!("rank {at} and slot {slot} disagree on waiting"));
            }
        }
        let occupied = count(&self.occupied);
        if held != occupied {
            return Err(format!("{held} held ranks over {occupied} occupied slots"));
        }
        let (waiting, ranked) = (count(&self.waiting), count(&self.ranked_waiting));
        if waiting != ranked {
            return Err(format!(
                "{waiting} waiting slots over {ranked} waiting ranks"
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn occupancy<C, F>(&self, requests: &Requests<C, F>) -> Occupancy {
        let table = requests.table();
        let mut records = vec![0; usize::from(table.peers())];
        for slot in 0..table.high_water() {
            if let Some(id) = table.live_id(slot)
                && let Some(Request::Put(_)) = table.get(id)
                && let Some(peer) = table.peer(id)
            {
                records[usize::from(peer.0)] += 1;
            }
        }
        Occupancy {
            live: self.live,
            peers: self.peers.to_vec(),
            free_lanes: self.free.len(),
            records,
        }
    }

    /// `(held, ring entries)` of each live PUT in its ready stage, for a test to compare: the two are equal while `held` counts exactly the fragments the lane ring holds.
    #[cfg(test)]
    pub(super) fn ready_lanes<C, P: Platform>(
        &self,
        requests: &Requests<C, Put<'_, '_, P>>,
    ) -> Vec<(u32, usize)> {
        let table = requests.table();
        (0..table.high_water())
            .filter_map(|slot| {
                let Some(Request::Put(put)) = table.get(table.live_id(slot)?) else {
                    return None;
                };
                let ring = &self.lanes[usize::from(put.lane)].ring;
                matches!(put.stage, Some(Stage::Ready(_))).then(|| {
                    (
                        put.held,
                        ring.iter().filter(|entry| entry.is_some()).count(),
                    )
                })
            })
            .collect()
    }

    /// Starts recording validated fragments and clears the incomplete mark earlier validations set; a repeated call keeps the recorded history.
    #[cfg(test)]
    pub(super) fn track_validated(&mut self) {
        if self.validated.capacity() == 0 {
            self.validated.reserve_exact(VALIDATED_ROOM);
            self.validated_overflow = false;
        }
    }

    /// A validation beyond recording capacity marks the history incomplete.
    #[cfg(test)]
    fn record_validated(&mut self, validation: Validation) {
        if self.validated.len() < self.validated.capacity() {
            self.validated.push(validation);
        } else {
            self.validated_overflow = true;
        }
    }

    /// Returns validations in validation order and whether any validation exceeded recording capacity.
    #[cfg(test)]
    pub(super) fn validated(&self) -> (&[Validation], bool) {
        (&self.validated, self.validated_overflow)
    }

    /// Bytes the turn's copies and resend comparisons charged against the per-turn copy budget so far.
    #[cfg(test)]
    pub(super) fn turn_copy_bytes(&self) -> usize {
        self.copy.bytes_used()
    }

    pub(super) fn begin_turn(&mut self) {
        self.turn_number += 1;
        self.lending = !std::mem::take(&mut self.short);
        self.turn = WorkBudget::with_io(0, self.config.commands, self.config.command_bytes);
        self.copy = WorkBudget::with_io(0, usize::MAX, self.config.copy_bytes);
    }

    pub(super) fn take_released(&mut self) -> bool {
        std::mem::take(&mut self.released)
    }

    pub(super) fn take_run_waiter(&mut self) -> bool {
        std::mem::take(&mut self.run_waiter)
    }

    /// Whether a live PUT holds `fill`, a shard and a serial: its departure, by publication, failure or abandonment, reaches [`take_departed`](Self::take_departed).
    pub(super) fn produces<C, P: Platform>(
        &self,
        requests: &Requests<C, Put<'_, '_, P>>,
        fill: (ShardIndex, u64),
    ) -> bool {
        let mut from = 0;
        while let Some(slot) = next_set(&self.occupied, from) {
            from = slot + 1;
            if let Some(id) = requests.table().live_id(slot)
                && let Some(Request::Put(put)) = requests.table().get(id)
                && let Some(Stage::Priming(held) | Stage::Ready(held) | Stage::Draining(held, _)) =
                    &put.stage
                && (held.shard(), held.serial()) == fill
            {
                return true;
            }
        }
        false
    }

    /// The fills that departed since the last call, if any did, so their followers can observe their terminals.
    pub(super) fn take_departed(&mut self) -> Option<Departed> {
        self.departed.fills[0]?;
        Some(std::mem::take(&mut self.departed))
    }

    pub(super) fn take_lost(&mut self) -> bool {
        std::mem::take(&mut self.lost)
    }

    fn flip(&mut self, slot: u16) {
        let slot = usize::from(slot);
        self.occupied[slot / 64] ^= 1 << (slot % 64);
    }

    fn rank_admission(&mut self, slot: u16) {
        if self.next_rank as usize == self.ranked.len() {
            self.renumber();
        }
        let rank = self.next_rank;
        self.next_rank += 1;
        self.rank[usize::from(slot)] = rank;
        self.ranked[rank as usize] = u32::from(slot);
        let rank = rank as usize;
        self.ranked_live[rank / 64] |= 1 << (rank % 64);
    }

    /// Moves the held ranks down to `0..held` in their order, with their slots and waiting bits. Each held rank moves to a rank at or below its own, so the scan from `old + 1` reads every later held rank once.
    fn renumber(&mut self) {
        #[cfg(test)]
        RENUMBERINGS.with(|total| total.set(total.get() + 1));
        let (mut next, mut from) = (0, 0);
        while let Some(old) = next_set(&self.ranked_live, from) {
            from = old + 1;
            if old != next {
                let (old, new) = (old as usize, next as usize);
                let slot = std::mem::replace(&mut self.ranked[old], NONE);
                self.ranked[new] = slot;
                self.rank[slot as usize] = next;
                self.ranked_live[old / 64] &= !(1 << (old % 64));
                self.ranked_live[new / 64] |= 1 << (new % 64);
                if self.ranked_waiting[old / 64] & (1 << (old % 64)) != 0 {
                    self.ranked_waiting[old / 64] &= !(1 << (old % 64));
                    self.ranked_waiting[new / 64] |= 1 << (new % 64);
                }
            }
            next += 1;
        }
        self.next_rank = next;
    }

    fn release_rank(&mut self, slot: u16) {
        let rank = std::mem::replace(&mut self.rank[usize::from(slot)], NONE) as usize;
        self.ranked[rank] = NONE;
        self.ranked_live[rank / 64] &= !(1 << (rank % 64));
        self.ranked_waiting[rank / 64] &= !(1 << (rank % 64));
    }

    fn waiting(&self, slot: u16) -> bool {
        let slot = usize::from(slot);
        self.waiting[slot / 64] & (1 << (slot % 64)) != 0
    }

    fn wait(&mut self, slot: u16) {
        if !self.waiting(slot) {
            let rank = self.rank[usize::from(slot)] as usize;
            self.ranked_waiting[rank / 64] |= 1 << (rank % 64);
            let slot = usize::from(slot);
            self.waiting[slot / 64] |= 1 << (slot % 64);
            self.pending += 1;
        }
    }

    fn settle(&mut self, slot: u16) {
        if self.waiting(slot) {
            let rank = self.rank[usize::from(slot)] as usize;
            self.ranked_waiting[rank / 64] &= !(1 << (rank % 64));
            let slot = usize::from(slot);
            self.waiting[slot / 64] &= !(1 << (slot % 64));
            self.pending -= 1;
        }
    }

    fn is_marked(&self, slot: u32) -> bool {
        let slot = slot as usize;
        self.marked_waiters[slot / 64] & (1 << (slot % 64)) != 0
    }

    fn mark_waiter(&mut self, slot: u16, units: u64) {
        let slot = usize::from(slot);
        self.marked_waiters[slot / 64] |= 1 << (slot % 64);
        self.wait_floor = self.wait_floor.min(units);
    }

    /// Clears the mark of `slot`, whose placement waited for `units`. Removing a marked waiter whose `units` is at or below `wait_floor` sets `floor_stale`. An unmarked slot is left unchanged.
    fn unmark_waiter(&mut self, slot: u16, units: u64) {
        if !self.is_marked(u32::from(slot)) {
            return;
        }
        let slot = usize::from(slot);
        self.marked_waiters[slot / 64] &= !(1 << (slot % 64));
        self.floor_stale |= units <= self.wait_floor;
    }

    /// Recomputes a stale `wait_floor` as the least wait units of the marked PUTs, reading each marked record once.
    fn refresh_wait_floor<C, P: Platform>(&mut self, requests: &mut Requests<C, Put<'_, '_, P>>) {
        if !std::mem::take(&mut self.floor_stale) {
            return;
        }
        self.wait_floor = u64::MAX;
        let mut from = 0;
        while let Some(marked) = next_set(&self.marked_waiters, from) {
            from = marked + 1;
            #[cfg(test)]
            FLOOR_READS.with(|total| total.set(total.get() + 1));
            let marked_units = requests
                .live_put(marked)
                .and_then(|(_, put)| match &put.stage {
                    Some(Stage::Placing(placing)) => Some(placing.wait_units()),
                    _ => None,
                });
            debug_assert!(
                marked_units.is_some(),
                "marked slot {marked} holds no placement"
            );
            self.wait_floor = self.wait_floor.min(marked_units.unwrap_or(u64::MAX));
        }
    }

    /// Returns an error unless every occupied slot holds a PUT, every PUT that counts a write command in flight has its lane marked in `holding`, and every marked lane's holder names a live PUT of that peer on that lane. The peer observation reads only marked lanes, so an unmarked PUT that counts a command would keep a count above what it holds, and a mark left on a released lane would observe whatever PUT took its table slot.
    #[cfg(test)]
    pub(super) fn check_holding<C, P: Platform>(
        &self,
        requests: &Requests<C, Put<'_, '_, P>>,
    ) -> Result<(), String> {
        let table = requests.table();
        let put_in = |slot: u32| match table.live_id(slot).and_then(|id| table.get(id)) {
            Some(Request::Put(put)) => Some(put),
            _ => None,
        };
        let mut from = 0;
        while let Some(slot) = next_set(&self.occupied, from) {
            from = slot + 1;
            let put = put_in(slot).ok_or_else(|| format!("occupied slot {slot} holds no PUT"))?;
            let marked = self.holding[usize::from(put.lane) / 64] & (1 << (put.lane % 64)) != 0;
            if put.commands > 0 && !marked {
                return Err(format!(
                    "slot {slot} counts {} commands on unmarked lane {}",
                    put.commands, put.lane
                ));
            }
        }
        let mut from = 0;
        while let Some(lane) = next_set(&self.holding, from) {
            from = lane + 1;
            let (peer, slot) = self.holders[lane as usize];
            if !put_in(u32::from(slot))
                .is_some_and(|put| put.peer == peer && u32::from(put.lane) == lane)
            {
                return Err(format!(
                    "marked lane {lane} names slot {slot}, which holds no PUT of its peer on the lane"
                ));
            }
        }
        Ok(())
    }

    /// Returns an error unless every marked slot holds a waiting placement set in `waiting`, `wait_floor` is at most the marks' least wait units and equals it while `floor_stale` is false, and the marks number at most `report.run_waiters`.
    #[cfg(test)]
    pub(super) fn check_marked_waiters<C, P: Platform>(
        &self,
        requests: &Requests<C, Put<'_, '_, P>>,
    ) -> Result<(), String> {
        let (mut floor, mut marks, mut from) = (u64::MAX, 0, 0);
        while let Some(slot) = next_set(&self.marked_waiters, from) {
            from = slot + 1;
            marks += 1;
            if !self.waiting(slot as u16) {
                return Err(format!("marked slot {slot} has no progress-turn work"));
            }
            let placing = requests
                .table()
                .live_id(slot)
                .and_then(|id| requests.table().get(id))
                .and_then(|request| match request {
                    Request::Put(put) => match &put.stage {
                        Some(Stage::Placing(placing)) if placing.waiting() => Some(placing),
                        _ => None,
                    },
                    Request::Get(_) => None,
                })
                .ok_or(format!("marked slot {slot} holds no waiting placement"))?;
            floor = floor.min(placing.wait_units());
        }
        if self.wait_floor > floor || (!self.floor_stale && self.wait_floor != floor) {
            return Err(format!(
                "wait floor {} (stale: {}) over marks of least {floor}",
                self.wait_floor, self.floor_stale
            ));
        }
        if marks > self.report.run_waiters {
            return Err(format!(
                "{marks} marks over {} waiters",
                self.report.run_waiters
            ));
        }
        Ok(())
    }

    #[expect(clippy::too_many_arguments)]
    pub(super) fn take<'s, 'a, C, P: Platform, D: Disk>(
        &mut self,
        requests: &mut Requests<C, Put<'s, 'a, P>>,
        serve: &mut ServeCore,
        volume: &mut Volume<'s, 'a, P, D>,
        permits: &PutPermits,
        open: Result<(), Status>,
        coverage: Option<&Fencing>,
        session: Admitted,
        header: &Header,
        now_us: u64,
    ) {
        let id = RequestId::from_wire(header.request);
        if u32::from(id.slot()) >= session.caps.slots {
            return refuse(serve, session, header, Status::InvalidRequest);
        }
        match requests.route(session.peer, id, Operation::Put) {
            Route::Outside => refuse(serve, session, header, Status::InvalidRequest),
            Route::WrongOperation => {}
            Route::Same {
                active: Some(table),
                ..
            } if requests.put_mut(table).is_some_and(|put| !put.draining()) => {
                self.live_frame(requests, serve, volume, table, session, header, now_us);
            }
            // `active`, when set, is an ended PUT still draining under its
            // binding, whose terminal was dropped or is not yet sent. The
            // replayed PUT ERROR or the `UnknownOutcome` this frame draws
            // names that record and frees the binding once sent; a
            // `ConflictingRequest` answer keeps the binding.
            Route::Same { active, cached } => {
                match cached.and_then(|row| row.current(session.epoch, now_us)) {
                    Some(Outcome::Put(row)) if row.fingerprint.matches(header) => {
                        replay(serve, active, session, header, &row);
                    }
                    Some(_) => refuse(serve, session, header, Status::ConflictingRequest),
                    None => answer(serve, active, session, header, Status::UnknownOutcome),
                }
            }
            Route::Fresh if header.kind == Kind::PutBegin => {
                match self.begin(
                    requests, volume, permits, open, coverage, session, header, now_us,
                ) {
                    Ok(table) => {
                        self.report.begun += 1;
                        self.report.live_peak = self.report.live_peak.max(self.live);
                        if let Some(put) = requests.put_mut(table) {
                            put.reply(serve, None, Kind::PutAuthority, None, 0);
                        }
                    }
                    Err(refusal) => {
                        self.settle_begin(requests, session, header, now_us, refusal.status());
                        let counter = match refusal {
                            BeginRefusal::Live(cause) => {
                                self.report.refused_live += 1;
                                match cause {
                                    LiveCause::GlobalCap => &mut self.report.refused_global_cap,
                                    LiveCause::PeerShare => &mut self.report.refused_peer_share,
                                    LiveCause::GetBacklog => &mut self.report.refused_get_backlog,
                                    LiveCause::LaneGuard => &mut self.report.refused_lane_guard,
                                }
                            }
                            BeginRefusal::Namespace(_) => &mut self.report.refused_namespace,
                            BeginRefusal::Fill(BeginError::FillSlotsFull) => {
                                &mut self.report.refused_fill_slots
                            }
                            BeginRefusal::Fill(BeginError::InProgress) => {
                                &mut self.report.refused_in_progress
                            }
                            BeginRefusal::Fill(_) | BeginRefusal::Admission(_) => {
                                &mut self.report.refused_other
                            }
                        };
                        *counter += 1;
                        refuse(serve, session, header, refusal.status());
                    }
                }
            }
            Route::Fresh => {
                // The rowless slot answers the identity's late BEGIN
                // `UnknownOutcome` whatever cache version that BEGIN names.
                // On a slot a request still binds, that BEGIN is refused
                // while the binding lasts and answered `UnknownOutcome`
                // once it frees.
                requests.settle(session.peer, id, None);
                refuse(serve, session, header, Status::UnknownOutcome);
            }
            Route::Older => refuse(serve, session, header, Status::UnknownOutcome),
        }
    }

    /// Caches `status` for the refused BEGIN's fresh request identity so
    /// retransmissions replay the refusal. On a wire slot a request still
    /// binds, the namespace keeps the refused generation alone: a
    /// retransmission is refused again while the binding lasts and answered
    /// `UnknownOutcome` once it frees.
    fn settle_begin<C, P: Platform>(
        &self,
        requests: &mut Requests<C, Put<'_, '_, P>>,
        session: Admitted,
        header: &Header,
        now_us: u64,
        status: Status,
    ) {
        let cached = Cached {
            epoch: session.epoch,
            expires_us: now_us
                .saturating_add(self.wait_us(header))
                .saturating_add(self.linger_us),
            outcome: Outcome::Put(PutRow {
                fingerprint: Fingerprint {
                    key: header.key,
                    serial: 0,
                    shape: None,
                    version: begin_version(header),
                },
                terminal: Terminal::Failed(status),
            }),
        };
        requests.settle(
            session.peer,
            RequestId::from_wire(header.request),
            Some(cached),
        );
    }

    #[expect(clippy::too_many_arguments)]
    fn begin<'s, 'a, C, P: Platform, D: Disk>(
        &mut self,
        requests: &mut Requests<C, Put<'s, 'a, P>>,
        volume: &Volume<'s, 'a, P, D>,
        permits: &PutPermits,
        open: Result<(), Status>,
        coverage: Option<&Fencing>,
        session: Admitted,
        header: &Header,
        now_us: u64,
    ) -> Result<RequestId, BeginRefusal> {
        open.map_err(BeginRefusal::Admission)?;
        permits
            .check(session.peer)
            .map_err(BeginRefusal::Admission)?;
        let peer = usize::from(session.peer.0);
        if self.live >= self.config.puts {
            return Err(BeginRefusal::Live(LiveCause::GlobalCap));
        }
        if self
            .peers
            .get(peer)
            .is_none_or(|&held| held >= self.config.peer_puts)
        {
            return Err(BeginRefusal::Live(LiveCause::PeerShare));
        }
        if self.get_backlogged(requests.table(), session.peer) {
            return Err(BeginRefusal::Live(LiveCause::GetBacklog));
        }
        let id = RequestId::from_wire(header.request);
        requests
            .admissible(session.peer, id)
            .map_err(BeginRefusal::Namespace)?;
        let lane = *self
            .free
            .last()
            .ok_or(BeginRefusal::Live(LiveCause::LaneGuard))?;
        let version = begin_version(header);
        if coverage.is_some_and(|fencing| !fencing.admits(&header.key, version)) {
            return Err(BeginRefusal::Admission(Status::Contended));
        }
        let attempt = volume
            .storage()
            .begin_fill(
                &header.key,
                version,
                self.tries,
                &mut WorkBudget::new(self.work),
            )
            .map_err(BeginRefusal::Fill)?;
        let deadline_us = now_us.saturating_add(self.wait_us(header));
        let put = Put {
            peer: session.peer,
            epoch: session.epoch,
            request: header.request,
            fingerprint: Fingerprint {
                key: header.key,
                serial: attempt.serial(),
                shape: None,
                version,
            },
            deadline_us,
            begun_us: now_us,
            ready_us: 0,
            prepared_turn: 0,
            expires_s: 0,
            lane,
            base: 0,
            consumed: 0,
            held: 0,
            offset: 0,
            granted: 0,
            window: 0,
            commands: 0,
            quiet: 0,
            staged: false,
            stage: Some(Stage::Authority(attempt)),
        };
        let table = requests
            .admit(session.peer, id, || Request::Put(put))
            .map_err(BeginRefusal::Namespace)?;
        self.free.pop();
        self.holders[usize::from(lane)] = (session.peer, table.slot());
        self.flip(table.slot());
        self.rank_admission(table.slot());
        self.deadlines.push(table.slot(), deadline_us);
        self.live += 1;
        self.peers[peer] += 1;
        Ok(table)
    }

    /// A BEGIN from `peer` hits the backlog limit when live GETs total at least [`PutConfig::get_backlog`] and `2 * peers` times `peer`'s live GETs reaches it too, so `peer` holds at least half its equal share of that limit. Live GETs include active and draining requests and exclude the PUTs counted by `self.live` globally and `self.peers` per peer.
    fn get_backlogged<T>(&self, table: &RequestTable<T>, peer: PeerId) -> bool {
        let backlog = self.config.get_backlog;
        if table.census().live() - self.live < backlog {
            return false;
        }
        let share = table.peer_census(peer);
        let own = share.active + share.draining - self.peers[usize::from(peer.0)];
        u64::from(own) * 2 * self.peers.len() as u64 >= u64::from(backlog)
    }

    fn wait_us(&self, header: &Header) -> u64 {
        (u64::from(header.remaining_ms) * 1000).min(self.max_wait_us)
    }

    #[expect(clippy::too_many_arguments)]
    #[inline(always)]
    fn live_frame<'s, 'a, C, P: Platform, D: Disk>(
        &mut self,
        requests: &mut Requests<C, Put<'s, 'a, P>>,
        serve: &mut ServeCore,
        volume: &mut Volume<'s, 'a, P, D>,
        table: RequestId,
        session: Admitted,
        header: &Header,
        now_us: u64,
    ) {
        let wait_us = self.wait_us(header);
        let Some(put) = requests.put_mut(table) else {
            return;
        };
        if put.epoch != session.epoch {
            return refuse(serve, session, header, Status::SessionMismatch);
        }
        if !put.fingerprint.matches(header) {
            return refuse(serve, session, header, Status::ConflictingRequest);
        }
        // A reservation, write receive or publication that unwound left `stage` at `None`; the next matching BEGIN, PREPARE or CANCEL ends the PUT with `UnknownOutcome`.
        if put.stage.is_none() {
            return self.fail(requests, serve, table, Status::UnknownOutcome, now_us);
        }
        match header.kind {
            Kind::PutBegin => {
                put.deadline_us = put.deadline_us.min(now_us.saturating_add(wait_us));
                self.deadlines.lower(table.slot(), put.deadline_us);
                put.reply(serve, None, Kind::PutAuthority, None, 0);
            }
            Kind::PutPrepare if put.fingerprint.shape.is_none() => {
                self.prepare(requests, serve, volume, table, session, header, now_us);
            }
            Kind::PutPrepare => {
                if let Some(Stage::Ready(_)) = put.stage {
                    if put.base == 0 {
                        put.reply(serve, None, Kind::PutReady, None, 0);
                    } else {
                        self.owe_ack(table.slot());
                    }
                }
            }
            Kind::PutCancel => {
                let cancel = Status::from_wire(header.status).unwrap_or(Status::Cancelled);
                let status = put.ending(cancel);
                self.refuse_with(requests, serve, table, status, None, now_us);
            }
            _ => {}
        }
    }

    #[expect(clippy::too_many_arguments)]
    #[inline(always)]
    fn prepare<'s, 'a, C, P: Platform, D: Disk>(
        &mut self,
        requests: &mut Requests<C, Put<'s, 'a, P>>,
        serve: &mut ServeCore,
        volume: &mut Volume<'s, 'a, P, D>,
        table: RequestId,
        session: Admitted,
        header: &Header,
        now_us: u64,
    ) {
        let (tries, work, window) = (self.tries, self.work, self.config.window);
        let Some(put) = requests.put_mut(table) else {
            return;
        };
        let shape = Shape::of(header);
        put.fingerprint.shape = Some(shape);
        self.report.begin_to_prepare_us += now_us.saturating_sub(put.begun_us);
        put.prepared_turn = self.turn_number;
        match reserve(put, volume, shape, (tries, work)) {
            Ok(()) => {
                put.window = window.min(session.caps.window);
                put.granted = put.fingerprint.manifest().count().min(put.window);
                self.wait(table.slot());
                match &put.stage {
                    Some(Stage::Placing(placing)) if placing.waiting() => {
                        self.start_run_wait(requests, serve, table, now_us);
                    }
                    Some(Stage::Placing(_)) => self.report.place_waits += 1,
                    _ => self.prime(requests, serve, volume, table, now_us),
                }
            }
            Err(refusal) => {
                let status = self.reserve_status(refusal);
                self.fail(requests, serve, table, status, now_us);
            }
        }
    }

    /// One turn of a PUT of several extents, funded with the reservation work: a placement complete at the turn's start takes the shard hold and primes the fill; otherwise the turn places what the work funds, and a partial placement, a placement completed this turn or a busy gate waits for the next turn. A placement that finds no free run for the next extent waits until a run forms or the deadline when it already waited or the waiter count is below the cap; otherwise it ends its PUT in this turn. Another refusal ends the PUT.
    fn place<'s, 'a, C, P: Platform, D: Disk>(
        &mut self,
        requests: &mut Requests<C, Put<'s, 'a, P>>,
        serve: &mut ServeCore,
        volume: &mut Volume<'s, 'a, P, D>,
        table: RequestId,
        now_us: u64,
    ) {
        let (tries, work, turn) = (self.tries, self.work, self.turn_number);
        let Some(put) = requests.put_mut(table) else {
            return;
        };
        let Some(Stage::Placing(placing)) = &mut put.stage else {
            return;
        };
        if placing.waiting() && put.prepared_turn == turn {
            return;
        }
        let mut budget = WorkBudget::new(work);
        let refusal = if placing.is_complete() {
            let Some(Stage::Placing(placing)) = put.stage.take() else {
                return;
            };
            match placing.reserve_storage(tries, &mut budget) {
                Ok(fill) => {
                    put.stage = Some(Stage::Priming(fill));
                    self.prime(requests, serve, volume, table, now_us);
                    return;
                }
                Err(error) => error,
            }
        } else {
            let (waited, units) = (placing.waiting(), placing.wait_units());
            let placed = placing.retry(&mut budget);
            let stopped = waited && !placing.waiting();
            if stopped {
                self.report.run_waiters -= 1;
                self.unmark_waiter(table.slot(), units);
            }
            match placed {
                Ok(_) | Err(FillReserveError::Contended) => {
                    self.report.place_waits += 1;
                    return;
                }
                Err(FillReserveError::PayloadFull) if waited => {
                    self.report.run_waits += 1;
                    self.mark_waiter(table.slot(), units);
                    return;
                }
                Err(FillReserveError::PayloadFull) => {
                    return self.start_run_wait(requests, serve, table, now_us);
                }
                Err(error) => error,
            }
        };
        let status = self.reserve_status(ReserveRefusal::Fill(refusal));
        self.fail(requests, serve, table, status, now_us);
    }

    /// Takes a placement that has just begun waiting for a free run, at PREPARE or on a progress turn. Below the run-waiter cap the PUT becomes a waiter: the waiter count and `run_waits` each rise once, and `run_waiter` records the registration for the owner's maintenance wake. At the cap the placement ends through [`PlacingFill::end`], which refunds its unplaced charge and clears its waiting flag, and the PUT ends with `StoragePressure` in the same turn, incrementing `run_wait_refused` and `failed_other`.
    fn start_run_wait<C, P: Platform>(
        &mut self,
        requests: &mut Requests<C, Put<'_, '_, P>>,
        serve: &mut ServeCore,
        table: RequestId,
        now_us: u64,
    ) {
        if self.report.run_waiters < self.config.run_waiters {
            self.report.run_waiters += 1;
            self.report.run_waits += 1;
            self.run_waiter = true;
            return;
        }
        // Taking the refused PUT's stage before `fail` ensures that `end` decrements the run-waiter count only for admitted waiters.
        if let Some(put) = requests.put_mut(table)
            && let Some(Stage::Placing(placing)) = put.stage.take()
        {
            placing.end();
        }
        self.report.run_wait_refused += 1;
        self.fail(requests, serve, table, Status::StoragePressure, now_us);
    }

    fn prime<'s, 'a, C, P: Platform, D: Disk>(
        &mut self,
        requests: &mut Requests<C, Put<'s, 'a, P>>,
        serve: &mut ServeCore,
        volume: &mut Volume<'s, 'a, P, D>,
        table: RequestId,
        now_us: u64,
    ) {
        let Some(put) = requests.put_mut(table) else {
            return;
        };
        let Some(Stage::Priming(_)) = &put.stage else {
            return;
        };
        let peer = put.peer;
        let (put, commands) = match self.commands_counted(peer, volume) {
            Some(commands) => (put, commands),
            None => {
                let commands = self.commands_observed(requests, volume, peer);
                let Some(put) = requests.put_mut(table) else {
                    return;
                };
                (put, commands)
            }
        };
        if commands == 0 {
            self.wait_for_command(requests, volume, peer);
            return;
        }
        match self.receive(put, volume, commands, (&[], None)) {
            Ok((_, refused)) => {
                if let Some(Stage::Priming(fill)) = put.stage.take() {
                    put.stage = Some(Stage::Ready(fill));
                }
                if put.consumed < put.fingerprint.manifest().count() && put.commands == 0 {
                    self.settle(table.slot());
                }
                put.ready_us = now_us;
                self.report.begin_to_ready_us += now_us.saturating_sub(put.begun_us);
                put.reply(serve, None, Kind::PutReady, None, 0);
                if refused {
                    let peer = put.peer;
                    self.wait_for_command(requests, volume, peer);
                }
            }
            Err(
                error @ (ReceiveError::Budget(_)
                | ReceiveError::PoolExhausted
                | ReceiveError::TableFull),
            ) => {
                let peer = put.peer;
                self.receive_wait(requests, volume, peer, &error);
            }
            Err(error) => {
                let status = self.receive_status(error);
                self.fail(requests, serve, table, status, now_us);
            }
        }
    }

    /// `compare_resends` compares each frame that resends a fragment its attempt already consumed with that fragment's evidence, re-tagging the group's resends in one [`Retag::compare`] pass. Consumed-fragment resends pay the comparison debit before re-tagging, including when re-tagging fails and produces `None`.
    pub(super) fn compare_resends<C, P: Platform, const N: usize>(
        &mut self,
        requests: &Requests<C, Put<'_, '_, P>>,
        retag: &Retag<'_>,
        frames: [Option<DataFrame<'_>>; N],
    ) -> [Option<Verdict>; N] {
        let resends = frames.map(|frame| {
            let (session, header, body, crc) = frame?;
            let evidence = self.resend_evidence(requests, session, header)?;
            Some(Resend {
                peer: session.peer,
                header,
                body,
                crc,
                evidence,
            })
        });
        retag.compare(resends)
    }

    fn resend_evidence<C, P: Platform>(
        &mut self,
        requests: &Requests<C, Put<'_, '_, P>>,
        session: Admitted,
        header: &Header,
    ) -> Option<Evidence> {
        let id = RequestId::from_wire(header.request);
        let Route::Same {
            active: Some(table),
            ..
        } = requests.lookup(session.peer, id, Operation::Put)
        else {
            return None;
        };
        let Some(Request::Put(put)) = requests.table().get(table) else {
            return None;
        };
        if !put.takes(session, header)
            || header.index >= put.consumed
            || !debit_comparison(&mut self.copy, header)
        {
            return None;
        }
        Some(self.lanes[usize::from(put.lane)].evidence(header.index as usize))
    }

    /// Consumed-index resends use comparison results from [`compare_resends`](Self::compare_resends); `data` drops the frame when `verdict` lacks a result for the stored sequence. For ring-held resends, `data` charges the comparison budget before comparing payload bytes. A differing resend ends the attempt with `Status::ConflictingData`.
    pub(super) fn data<C, P: Platform>(
        &mut self,
        requests: &mut Requests<C, Put<'_, '_, P>>,
        serve: &mut ServeCore,
        (session, header): (Admitted, &Header),
        mut lease: PacketLease<'m>,
        verdict: Option<Verdict>,
        now_us: u64,
    ) -> bool {
        let id = RequestId::from_wire(header.request);
        let Route::Same {
            active: Some(table),
            ..
        } = requests.route(session.peer, id, Operation::Put)
        else {
            return false;
        };
        let window = self.config.window;
        let Some(put) = requests.put_mut(table) else {
            return false;
        };
        if !put.takes(session, header) {
            return false;
        }
        let lane = &mut self.lanes[usize::from(put.lane)];
        let at = (header.index % window) as usize;
        let conflict = if header.index < put.consumed {
            let stored = lane.sequences[header.index as usize];
            let Some(equal) = verdict.and_then(|verdict| verdict.for_sequence(stored)) else {
                return false;
            };
            !equal
        } else if let Some(held) = &lane.ring[at] {
            if !debit_comparison(&mut self.copy, header) {
                return false;
            }
            held.bytes()[HEADER_LEN..] != lease.bytes()[HEADER_LEN..]
        } else {
            if lease.retain_as_data().is_err() {
                return false;
            }
            lane.ring[at] = Some(lease);
            lane.sequences[header.index as usize] = header.sequence;
            lane.tags[header.index as usize] = header.tag;
            put.held += 1;
            while put.base < put.granted && lane.ring[(put.base % window) as usize].is_some() {
                put.base += 1;
            }
            #[cfg(test)]
            self.record_validated(Validation {
                key: put.fingerprint.key,
                serial: put.fingerprint.serial,
                index: header.index,
                base: put.base,
            });
            self.wait(table.slot());
            false
        };
        if conflict {
            self.fail(requests, serve, table, Status::ConflictingData, now_us);
        } else {
            self.owe_ack(table.slot());
        }
        true
    }

    fn acknowledge<C, P: Platform>(
        &mut self,
        requests: &mut Requests<C, Put<'_, '_, P>>,
        serve: &mut ServeCore,
        table: RequestId,
    ) {
        let window = self.config.window;
        let Some(put) = requests.put_mut(table) else {
            return;
        };
        let ring = &self.lanes[usize::from(put.lane)].ring;
        let count = put.fingerprint.manifest().count();
        debug_assert_eq!(
            put.held as usize,
            ring.iter().filter(|entry| entry.is_some()).count()
        );
        let grant = (put.base + put.window.saturating_sub(put.held))
            .min(count)
            .max(put.granted);
        put.granted = grant;
        let mut mask = 0u64;
        // Every entry in `consumed..base` is held, so only a count above that range leaves a bit to set.
        if put.held > put.base - put.consumed {
            let mut at = ((put.base + 1) % window) as usize;
            for bit in 0..grant.saturating_sub(put.base + 1).min(64) {
                if ring[at].is_some() {
                    mask |= 1 << bit;
                }
                at = if at + 1 == ring.len() { 0 } else { at + 1 };
            }
        }
        put.reply(serve, None, Kind::PutAck, None, mask);
    }

    fn fail<C, P: Platform>(
        &mut self,
        requests: &mut Requests<C, Put<'_, '_, P>>,
        serve: &mut ServeCore,
        table: RequestId,
        status: Status,
        now_us: u64,
    ) {
        self.refuse_with(requests, serve, table, status, fill_failure(status), now_us);
    }

    fn refuse_with<C, P: Platform>(
        &mut self,
        requests: &mut Requests<C, Put<'_, '_, P>>,
        serve: &mut ServeCore,
        table: RequestId,
        status: Status,
        cause: Option<FillFailure>,
        now_us: u64,
    ) {
        if let Some(put) = requests.put_mut(table) {
            put.reply(serve, Some(table), Kind::PutError, Some(status), 0);
        }
        match status {
            Status::TimedOut | Status::UnknownOutcome => self.report.failed_timed_out += 1,
            Status::Cancelled => self.report.cancelled += 1,
            _ => self.report.failed_other += 1,
        }
        self.end(
            requests,
            table,
            Some(Terminal::Failed(status)),
            cause,
            now_us,
        );
    }

    #[inline(always)]
    fn end<C, P: Platform>(
        &mut self,
        requests: &mut Requests<C, Put<'_, '_, P>>,
        table: RequestId,
        terminal: Option<Terminal>,
        cause: Option<FillFailure>,
        now_us: u64,
    ) {
        let Some(put) = requests.put_mut(table) else {
            return;
        };
        let (peer, slot) = (put.peer, RequestId::from_wire(put.request).slot());
        if let Some(terminal) = terminal {
            let cached = Cached {
                epoch: put.epoch,
                expires_us: put.deadline_us.max(now_us).saturating_add(self.linger_us),
                outcome: Outcome::Put(PutRow {
                    fingerprint: put.fingerprint,
                    terminal,
                }),
            };
            requests.retain(peer, slot, table, cached);
        }
        let Some(put) = requests.put_mut(table) else {
            return;
        };
        let ring = &mut self.lanes[usize::from(put.lane)].ring;
        let (front, back) = ring.split_at_mut((put.consumed % self.config.window) as usize);
        back.iter_mut()
            .chain(front)
            .take((put.granted - put.consumed) as usize)
            .for_each(|entry| *entry = None);
        debug_assert!(ring.iter().all(Option::is_none));
        put.held = 0;
        match put.stage.take() {
            Some(Stage::Authority(attempt)) => attempt.abort(),
            Some(Stage::Placing(placing)) => {
                self.report.run_waiters -= u32::from(placing.waiting());
                let units = placing.wait_units();
                placing.end();
                self.unmark_waiter(table.slot(), units);
            }
            Some(Stage::Priming(fill) | Stage::Ready(fill)) => {
                put.stage = Some(Stage::Draining(fill, cause));
                requests.begin_drain(table);
                self.wait(table.slot());
                return;
            }
            Some(Stage::Draining(fill, failure)) => {
                put.stage = Some(Stage::Draining(fill, failure));
                requests.begin_drain(table);
                self.wait(table.slot());
                return;
            }
            None => {}
        }
        self.release(requests, table);
    }

    #[inline(always)]
    fn release<C, P: Platform>(
        &mut self,
        requests: &mut Requests<C, Put<'_, '_, P>>,
        table: RequestId,
    ) {
        let Some(put) = requests.put_mut(table) else {
            return;
        };
        let (peer, slot, lane) = (put.peer, RequestId::from_wire(put.request).slot(), put.lane);
        self.commands[usize::from(peer.0)] -= put.commands;
        if requests.release(table, peer, slot) {
            self.holding[usize::from(lane) / 64] &= !(1 << (lane % 64));
            self.free.push(lane);
            self.flip(table.slot());
            self.settle(table.slot());
            self.release_rank(table.slot());
            self.deadlines.remove(table.slot());
            self.live -= 1;
            self.peers[usize::from(peer.0)] -= 1;
            self.released = true;
        }
    }

    pub(super) fn tick<C, P: Platform>(
        &mut self,
        requests: &mut Requests<C, Put<'_, '_, P>>,
        serve: &mut ServeCore,
        now_us: u64,
    ) {
        while let Some(slot) = self.deadlines.pop_due(now_us) {
            let Some((table, put)) = requests.live_put(u32::from(slot)) else {
                continue;
            };
            if put.draining() {
                continue;
            }
            let status = match &put.stage {
                Some(Stage::Placing(placing)) if placing.waiting() => {
                    self.reserve_status(ReserveRefusal::Fill(FillReserveError::PayloadFull))
                }
                _ => put.ending(Status::TimedOut),
            };
            self.fail(requests, serve, table, status, now_us);
        }
    }

    pub(super) fn progress<'s, 'a, C, P: Platform, D: Disk>(
        &mut self,
        requests: &mut Requests<C, Put<'s, 'a, P>>,
        serve: &mut ServeCore,
        volume: &mut Volume<'s, 'a, P, D>,
        coverage: Option<&Fencing>,
        now_us: u64,
    ) {
        if self.pending == 0 {
            return;
        }
        self.refresh_wait_floor(requests);
        let storage = volume.storage();
        let all_marked = (self.marked_waiters.iter())
            .zip(self.waiting.iter())
            .all(|(marked, waiting)| marked == waiting);
        if all_marked && storage.proves_no_run(self.wait_floor) {
            #[cfg(test)]
            {
                let pending = self.pending as usize;
                PROGRESS_VISITS.with(|total| total.set(total.get() + pending));
                PROVEN_RUN_WAITS.with(|total| total.set(total.get() + pending));
            }
            self.report.run_waits += u64::from(self.pending);
            return;
        }
        // Whether the serving token admits fills at the owner's latest deadline sample, read once for the pass when a fully submitted upload asks.
        let mut admitted = None;
        let ranked = self.next_rank;
        let held = (ranked as usize).div_ceil(u64::BITS as usize);
        let mut from = 0;
        while let Some(rank) = next_set(&self.ranked_waiting[..held], from) {
            from = rank + 1;
            let slot = self.ranked[rank as usize];
            #[cfg(test)]
            PROGRESS_VISITS.with(|total| total.set(total.get() + 1));
            debug_assert!(
                self.waiting(slot as u16),
                "rank {rank} names a waiting slot"
            );
            if self.is_marked(slot) && storage.proves_no_run(self.wait_floor) {
                #[cfg(test)]
                PROVEN_RUN_WAITS.with(|total| total.set(total.get() + 1));
                self.report.run_waits += 1;
                continue;
            }
            let Some((table, put)) = requests.live_put(slot) else {
                continue;
            };
            self.observe(put, volume);
            match &put.stage {
                Some(Stage::Placing(_)) => self.place(requests, serve, volume, table, now_us),
                Some(Stage::Priming(_)) => self.prime(requests, serve, volume, table, now_us),
                Some(Stage::Ready(fill)) if put.consumed == put.fingerprint.manifest().count() => {
                    // A fill whose every unit is submitted changes only when one of its commands ends, or fails when its token stops admitting fills. Every live upload's write set carries the serving token, because a token change retires every upload before this pass, so the token's admission answers for each of them.
                    if put.quiet != 0
                        && put.quiet == put.commands
                        && *admitted.get_or_insert_with(|| {
                            volume
                                .admit_authority_at_sample(
                                    crate::failover::serving::Operation::Fill,
                                    volume.serving_token(),
                                )
                                .is_ok()
                        })
                    {
                        continue;
                    }
                    #[cfg(test)]
                    FILL_READS.with(|total| total.set(total.get() + 1));
                    let progress = fill.progress(volume);
                    put.quiet = 0;
                    if progress.failed {
                        self.fail(requests, serve, table, Status::DeviceError, now_us);
                    } else if progress.is_ready() {
                        self.publish(requests, serve, volume, table, coverage, now_us);
                    } else if progress.submitted_units < progress.len_units {
                        // A staged segment waits for its submit.
                        self.consume(requests, serve, volume, table, now_us);
                    } else {
                        put.quiet = progress.outstanding_commands;
                    }
                }
                Some(Stage::Ready(_)) => {
                    self.consume(requests, serve, volume, table, now_us);
                    self.idle(requests, table);
                }
                Some(Stage::Draining(..)) if put.commands == 0 => {
                    if let Some(Stage::Draining(fill, failure)) = put.stage.take() {
                        self.departed.push((fill.shard(), fill.serial()));
                        match failure {
                            Some(failure) => fill.fail(failure),
                            None => fill.abort(),
                        }
                        self.release(requests, table);
                    }
                }
                _ => {}
            }
        }
        debug_assert_eq!(self.next_rank, ranked, "a progress pass admits no PUT");
        #[cfg(test)]
        debug_assert!(self.check_admission_order().is_ok());
        #[cfg(test)]
        debug_assert_eq!(self.check_holding(requests), Ok(()));
    }

    /// Settles a primed upload that now waits only on its peer: nothing held, no segment staged by a refused submit, no writes in flight, and fragments still to come.
    fn idle<C, P: Platform>(
        &mut self,
        requests: &mut Requests<C, Put<'_, '_, P>>,
        table: RequestId,
    ) {
        let Some(put) = requests.put_mut(table) else {
            return;
        };
        if matches!(put.stage, Some(Stage::Ready(_)))
            && !put.staged
            && put.held == 0
            && put.commands == 0
            && put.consumed < put.fingerprint.manifest().count()
        {
            self.settle(table.slot());
        }
    }

    fn observe<P: Platform, D: Disk>(
        &mut self,
        put: &mut Put<'_, '_, P>,
        volume: &Volume<'_, '_, P, D>,
    ) {
        let Some(Stage::Priming(fill) | Stage::Ready(fill) | Stage::Draining(fill, _)) = &put.stage
        else {
            return;
        };
        let now = fill.outstanding_commands(volume);
        let peer = &mut self.commands[usize::from(put.peer.0)];
        *peer = *peer - put.commands + now;
        put.commands = now;
    }

    /// Write commands a PUT of `peer` may submit now: the commands the volume admits, within the turn's budget and, in a turn that lends nothing, within what remains of the peer's share.
    fn commands<P: Platform, D: Disk>(&self, peer: PeerId, volume: &Volume<'_, '_, P, D>) -> usize {
        let free = self.free_commands(volume);
        let within = if self.lending {
            free
        } else {
            free.min(self.below_share(peer))
        };
        within.min(self.turn.operations_remaining() as u64) as usize
    }

    /// Write commands a PUT of `peer` may submit now, as [`commands`](Self::commands) counts them, or `None` in a turn that lends nothing when the volume admits a command and the turn's budget pays one but the peer's count shows its share spent. The count is the sum of the peer's uploads' counts as last observed, and the progress pass observes one upload at a time in rank order, so an upload whose command ended may not be observed yet in this turn: the caller then asks [`commands_observed`](Self::commands_observed), which makes the peer's count what it holds before the share caps the take.
    #[inline]
    fn commands_counted<P: Platform, D: Disk>(
        &self,
        peer: PeerId,
        volume: &Volume<'_, '_, P, D>,
    ) -> Option<usize> {
        let open = self
            .free_commands(volume)
            .min(self.turn.operations_remaining() as u64);
        if self.lending {
            return Some(open as usize);
        }
        let within = open.min(self.below_share(peer));
        (within > 0 || open == 0).then_some(within as usize)
    }

    /// [`commands`](Self::commands) for `peer` once [`observe_peer`](Self::observe_peer) made the peer's count what it holds.
    #[inline(never)]
    fn commands_observed<C, P: Platform, D: Disk>(
        &mut self,
        requests: &mut Requests<C, Put<'_, '_, P>>,
        volume: &Volume<'_, '_, P, D>,
        peer: PeerId,
    ) -> usize {
        self.observe_peer(requests, volume, peer);
        self.commands(peer, volume)
    }

    /// Makes `peer`'s count what the peer holds. The volume's count of ended write commands tells whether any upload's count can have fallen since the peer's uploads were last observed together: while it stands the count is already exact, and the call reads that word and the peer's entry.
    #[inline]
    fn observe_peer<C, P: Platform, D: Disk>(
        &mut self,
        requests: &mut Requests<C, Put<'_, '_, P>>,
        volume: &Volume<'_, '_, P, D>,
        peer: PeerId,
    ) {
        let ended = volume.write_ends();
        if self.observed[usize::from(peer.0)] != ended {
            self.observe_marked(requests, volume, peer, ended);
        }
    }

    /// Observes each upload of `peer` marked in `holding`, clears the mark of each that counts no command, and records `ended`, the volume's count of ended write commands, as the peer's observation mark.
    #[inline(never)]
    fn observe_marked<C, P: Platform, D: Disk>(
        &mut self,
        requests: &mut Requests<C, Put<'_, '_, P>>,
        volume: &Volume<'_, '_, P, D>,
        peer: PeerId,
        ended: u64,
    ) {
        let mut from = 0;
        while let Some(lane) = next_set(&self.holding, from) {
            from = lane + 1;
            let (holder, slot) = self.holders[lane as usize];
            if holder == peer
                && let Some((_, put)) = requests.live_put(u32::from(slot))
            {
                self.observe(put, volume);
                if put.commands == 0 {
                    self.holding[lane as usize / 64] &= !(1 << (lane % 64));
                }
            }
        }
        self.observed[usize::from(peer.0)] = ended;
    }

    /// Write commands the volume admits now: the write share and each metadata slot no metadata command claims, less the commands the writes hold (WRITE-ROOM).
    fn free_commands<P: Platform, D: Disk>(&self, volume: &Volume<'_, '_, P, D>) -> u64 {
        u64::from(volume.write_room())
    }

    /// Commands `peer` may still take within its share.
    fn below_share(&self, peer: PeerId) -> u64 {
        let share = self.write_cap / self.peers.len().max(1) as u64;
        share.saturating_sub(u64::from(self.commands[usize::from(peer.0)]))
    }

    /// Notes a PUT of `peer` that has a write to submit, or an object to prime, and finds no command it may take: the volume admits none, the turn's budget is spent, or the turn lends nothing and the peer holds its share. A peer below its share makes the next turn lend nothing.
    ///
    /// The peer's count is the sum of its uploads' counts as last observed. A count rises only through [`receive`](Self::receive), which observes at once, and falls only where the volume's count of ended write commands rises, so it is never below what the peer holds. When it shows the peer at its share, an upload whose command ended may not be observed yet in this turn, so [`observe_peer`](Self::observe_peer) makes the count what the peer holds before the share is judged.
    fn wait_for_command<C, P: Platform, D: Disk>(
        &mut self,
        requests: &mut Requests<C, Put<'_, '_, P>>,
        volume: &Volume<'_, '_, P, D>,
        peer: PeerId,
    ) {
        if self.below_share(peer) == 0 {
            self.observe_peer(requests, volume, peer);
        }
        self.short |= self.below_share(peer) > 0;
    }

    /// Counts a receive the volume refused for a full table, an empty pool or a spent budget. A [`ReceiveError::Budget`] refusal leaves a write that finds no command it may take because the turn's budget is spent, so a peer below its share makes the next turn lend nothing.
    fn receive_wait<C, P: Platform, D: Disk>(
        &mut self,
        requests: &mut Requests<C, Put<'_, '_, P>>,
        volume: &Volume<'_, '_, P, D>,
        peer: PeerId,
        error: &ReceiveError,
    ) {
        self.report.receive_waits += 1;
        if matches!(error, ReceiveError::Budget(_)) {
            self.wait_for_command(requests, volume, peer);
        }
    }

    fn funded<T>(&mut self, commands: usize, run: impl FnOnce(&mut WorkBudget) -> T) -> T {
        let mut call = WorkBudget::with_io(0, commands, self.turn.bytes_remaining());
        let result = run(&mut call);
        self.report.write_commands += call.operations_used() as u64;
        self.turn = WorkBudget::with_io(
            0,
            self.turn.operations_remaining() - call.operations_used(),
            self.turn.bytes_remaining() - call.bytes_used(),
        );
        result
    }

    /// If `fill.receive` unwinds, [`Receiving`] clears `put.stage` and drops its fill.
    ///
    /// `checksum` is the crc32c of `bytes` when the caller holds one that was verified against them; the fill then derives the record's chunk checksums from it.
    ///
    /// Returns the bytes taken and whether the fill accepted them but its volume refused a segment's submit on the turn's budget; the caller then notes the PUT with [`wait_for_command`](Self::wait_for_command) once `put` is no longer borrowed.
    ///
    /// # Panics
    ///
    /// When `put` is in neither its priming nor its ready stage; [`prime`](Self::prime) and [`consume`](Self::consume), the only callers, matched it in one.
    fn receive<'s, 'a, P: Platform, D: Disk>(
        &mut self,
        put: &mut Put<'s, 'a, P>,
        volume: &mut Volume<'s, 'a, P, D>,
        commands: usize,
        (bytes, checksum): (&[u8], Option<u32>),
    ) -> Result<(usize, bool), ReceiveError> {
        let lent = Receiving(&mut put.stage);
        let Some(Stage::Priming(fill) | Stage::Ready(fill)) = &mut *lent.0 else {
            unreachable!("prime and consume receive only into a priming or ready fill");
        };
        let result = self.funded(commands, |call| match checksum {
            Some(checksum) => fill.receive_verified(volume, bytes, checksum, call),
            None => fill.receive(volume, bytes, call),
        });
        let refused = result.is_ok() && fill.budget_refused();
        put.staged = (result.is_ok() && fill.submit_refused())
            || (put.staged
                && matches!(
                    result,
                    Err(ReceiveError::Budget(_)
                        | ReceiveError::PoolExhausted
                        | ReceiveError::TableFull)
                ));
        std::mem::forget(lent);
        self.observe(put, volume);
        if put.commands != 0 {
            self.holding[usize::from(put.lane) / 64] |= 1 << (put.lane % 64);
        }
        result.map(|taken| (taken, refused))
    }

    fn consume<'s, 'a, C, P: Platform, D: Disk>(
        &mut self,
        requests: &mut Requests<C, Put<'s, 'a, P>>,
        serve: &mut ServeCore,
        volume: &mut Volume<'s, 'a, P, D>,
        table: RequestId,
        now_us: u64,
    ) {
        let window = self.config.window;
        let mut moved = false;
        loop {
            let Some(put) = requests.put_mut(table) else {
                return;
            };
            let Some(Stage::Ready(_)) = &put.stage else {
                return;
            };
            let peer = put.peer;
            let (put, commands) = match self.commands_counted(peer, volume) {
                Some(commands) => (put, commands),
                None => {
                    let commands = self.commands_observed(requests, volume, peer);
                    let Some(put) = requests.put_mut(table) else {
                        return;
                    };
                    (put, commands)
                }
            };
            let Some(Stage::Ready(fill)) = &put.stage else {
                return;
            };
            if commands == 0 {
                // The PUT has a write to submit when the next fragment in order is received (`consumed` below the receipt base), when a refused submit left a segment staged, or when it consumed every fragment and a staged segment still waits. The progress pass calls with every fragment consumed only for a staged segment, so the fill is read only after this pass consumed the last fragment.
                let held = put.consumed < put.base;
                if held {
                    self.report.command_waits += 1;
                }
                let staged = || {
                    let staged = fill.progress(volume);
                    !staged.failed && staged.submitted_units < staged.len_units
                };
                if held
                    || put.staged
                    || (put.consumed == put.fingerprint.manifest().count() && (!moved || staged()))
                {
                    let peer = put.peer;
                    self.wait_for_command(requests, volume, peer);
                }
                break;
            }
            let at = (put.consumed % window) as usize;
            let lane = usize::from(put.lane);
            let held = if put.consumed < put.base {
                self.lanes[lane].ring[at].take()
            } else {
                None
            };
            let Some(held) = held else {
                // A segment a refused submit left staged is retried before the next fragment arrives, so the PUT does not wait on its client for a write it holds.
                let staged = fill.progress(volume);
                if (put.staged || put.consumed == put.fingerprint.manifest().count())
                    && !staged.failed
                    && staged.submitted_units < staged.len_units
                {
                    match self.receive(put, volume, commands, (&[], None)) {
                        Ok((_, refused)) => {
                            if refused {
                                let peer = put.peer;
                                self.wait_for_command(requests, volume, peer);
                            }
                        }
                        Err(
                            error @ (ReceiveError::Budget(_)
                            | ReceiveError::PoolExhausted
                            | ReceiveError::TableFull),
                        ) => {
                            let peer = put.peer;
                            self.receive_wait(requests, volume, peer, &error);
                        }
                        Err(error) => {
                            let status = self.receive_status(error);
                            return self.fail(requests, serve, table, status, now_us);
                        }
                    }
                }
                break;
            };
            let payload = &held.bytes()[HEADER_LEN..];
            let room = self.copy.bytes_remaining().min(payload.len() - put.offset);
            let result = if room == 0 {
                Ok((0, false))
            } else {
                let rest = &payload[put.offset..put.offset + room];
                // The ring holds only frames whose body passed its crc check, and a lease holds its buffer alone from that check to this copy, so the header's field is the checksum of the payload as it stands; it covers the whole payload, so it serves only a fragment the copy budget takes whole.
                let checksum = (room == payload.len()).then(|| raw_body_crc(held.bytes()));
                self.receive(put, volume, commands, (rest, checksum))
            };
            match result {
                Ok((taken, refused)) if put.offset + taken == payload.len() => {
                    let copied = self.copy.debit_command(WorkKind::Update, 0, taken);
                    debug_assert!(copied.is_ok());
                    put.held -= 1;
                    put.consumed += 1;
                    put.offset = 0;
                    moved = true;
                    if refused {
                        let peer = put.peer;
                        self.wait_for_command(requests, volume, peer);
                    }
                }
                Ok((taken, refused)) => {
                    let copied = self.copy.debit_command(WorkKind::Update, 0, taken);
                    debug_assert!(copied.is_ok());
                    put.offset += taken;
                    self.lanes[lane].ring[at] = Some(held);
                    if refused {
                        let peer = put.peer;
                        self.wait_for_command(requests, volume, peer);
                    }
                    break;
                }
                Err(
                    error @ (ReceiveError::Budget(_)
                    | ReceiveError::PoolExhausted
                    | ReceiveError::TableFull),
                ) => {
                    let peer = put.peer;
                    self.receive_wait(requests, volume, peer, &error);
                    self.lanes[lane].ring[at] = Some(held);
                    break;
                }
                Err(error) => {
                    self.lanes[lane].ring[at] = Some(held);
                    let status = self.receive_status(error);
                    return self.fail(requests, serve, table, status, now_us);
                }
            }
        }
        if moved {
            self.owe_ack(table.slot());
        }
    }

    fn receive_status(&mut self, error: ReceiveError) -> Status {
        self.report.failed_receive += 1;
        self.lost |= matches!(error, ReceiveError::Lost | ReceiveError::ForeignVolume);
        receive_status(error)
    }

    /// Tallies the refusal in `reserve_refused` and in its pressure or bootstrap part, if any, and returns its status; the caller ends the PUT with that status in the same turn. This method is the only writer of the six counters.
    pub(super) fn reserve_status(&mut self, refusal: ReserveRefusal) -> Status {
        self.report.reserve_refused += 1;
        match refusal {
            ReserveRefusal::Fill(FillReserveError::ObjectSlotsFull) => {
                self.report.reserve_refused_slots += 1;
            }
            ReserveRefusal::Fill(FillReserveError::PayloadFull) => {
                self.report.reserve_refused_payload += 1;
            }
            ReserveRefusal::Fill(FillReserveError::CleanReserve) => {
                self.report.reserve_refused_clean_reserve += 1;
            }
            ReserveRefusal::Fill(FillReserveError::RetiredPressure) => {
                self.report.reserve_refused_retired += 1;
            }
            ReserveRefusal::Fill(FillReserveError::Bootstrapping) => {
                self.report.reserve_refused_bootstrapping += 1;
            }
            ReserveRefusal::Before(_)
            | ReserveRefusal::Fill(
                FillReserveError::TornDown
                | FillReserveError::Layout(_)
                | FillReserveError::Closed
                | FillReserveError::Withdrawn
                | FillReserveError::BudgetExhausted
                | FillReserveError::Contended
                | FillReserveError::Superseded
                | FillReserveError::Corrupt
                | FillReserveError::IndexFull
                | FillReserveError::LeaseLimit,
            ) => {}
        }
        refusal.status()
    }

    fn publish<'s, 'a, C, P: Platform, D: Disk>(
        &mut self,
        requests: &mut Requests<C, Put<'s, 'a, P>>,
        serve: &mut ServeCore,
        volume: &mut Volume<'s, 'a, P, D>,
        table: RequestId,
        coverage: Option<&Fencing>,
        now_us: u64,
    ) {
        let (tries, work) = (self.config.publish_tries, self.config.publish_work);
        let Some(put) = requests.put_mut(table) else {
            return;
        };
        let Some(Stage::Ready(fill)) = put.stage.take() else {
            return;
        };
        self.settle(table.slot());
        let expires_at = u64::from(put.expires_s) * NANOS;
        self.departed.push((fill.shard(), fill.serial()));
        // The FILL's outcome is decided here: the owner thread alone changes the coverage, so none changes between this recheck and the index insert below.
        #[cfg(test)]
        let coverage = coverage.filter(|_| !SKIP_INSERT_RECHECK.with(std::cell::Cell::get));
        if coverage
            .is_some_and(|fencing| !fencing.admits(&put.fingerprint.key, put.fingerprint.version))
        {
            fill.abort();
            self.report.failed_publish += 1;
            self.fail(requests, serve, table, Status::Contended, now_us);
            return;
        }
        let published = fill.publish(volume, expires_at, tries, &mut WorkBudget::new(work));
        match published {
            Ok(lease) => {
                drop(lease);
                self.report.published += 1;
                self.report.ready_to_published_us += now_us.saturating_sub(put.ready_us);
                put.reply(serve, None, Kind::PutResult, None, 0);
                let terminal = Terminal::Published(put.fingerprint.manifest());
                self.end(requests, table, Some(terminal), None, now_us);
            }
            Err(error) => {
                self.report.failed_publish += 1;
                self.lost |= error == FillPublishError::Lost;
                self.fail(requests, serve, table, publish_status(error), now_us);
            }
        }
    }

    pub(super) fn stop_fills<C, P: Platform>(
        &mut self,
        requests: &mut Requests<C, Put<'_, '_, P>>,
        serve: &mut ServeCore,
        status: Status,
        now_us: u64,
    ) {
        let mut from = 0;
        while let Some(slot) = next_set(&self.occupied, from) {
            from = slot + 1;
            if let Some((table, put)) = requests.live_put(slot)
                && !put.draining()
            {
                let status = put.ending(status);
                self.fail(requests, serve, table, status, now_us);
            }
        }
    }

    /// Each ended fill records `cause` for its followers: `Closed` from the
    /// owner's close, none from a session's end.
    pub(super) fn retire_peer<C, P: Platform>(
        &mut self,
        requests: &mut Requests<C, Put<'_, '_, P>>,
        peer: PeerId,
        cause: Option<FillFailure>,
    ) {
        let mut from = 0;
        while let Some(slot) = next_set(&self.occupied, from) {
            from = slot + 1;
            if let Some((table, put)) = requests.live_put(slot)
                && put.peer == peer
                && !put.draining()
            {
                self.end(requests, table, None, cause, 0);
            }
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Every PUT the progress scan examined on this thread, so a test can bound a turn's work.
    static PROGRESS_VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn take_progress_visits() -> usize {
    PROGRESS_VISITS.with(|total| total.replace(0))
}

#[cfg(test)]
thread_local! {
    /// Progress visits, on this thread, that read the fill on entry because the upload had consumed every fragment before the visit.
    static FILL_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn take_fill_reads() -> usize {
    FILL_READS.with(|total| total.replace(0))
}

#[cfg(test)]
thread_local! {
    static RENUMBERINGS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn take_renumberings() -> usize {
    RENUMBERINGS.with(|total| total.replace(0))
}

#[cfg(test)]
thread_local! {
    /// Run waits on this thread that a progress pass counted from the run bound without a retry.
    static PROVEN_RUN_WAITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn take_proven_run_waits() -> usize {
    PROVEN_RUN_WAITS.with(|total| total.replace(0))
}

#[cfg(test)]
thread_local! {
    /// Planted: publication skips the coverage recheck at the index insert.
    pub(super) static SKIP_INSERT_RECHECK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
thread_local! {
    static FLOOR_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn take_floor_reads() -> usize {
    FLOOR_READS.with(|total| total.replace(0))
}

/// Fills one [`Departed`] names; a turn's further departures set its `more`, which owes every parked GET a visit.
const DEPARTURES: usize = 4;

/// Fills that departed, by shard and serial: the first `DEPARTURES`, and whether more departed.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Departed {
    pub(super) fills: [Option<(ShardIndex, u64)>; DEPARTURES],
    pub(super) more: bool,
}

impl Departed {
    /// Records `fill`'s departure; the first slot fills first, so an empty first slot means none departed.
    fn push(&mut self, fill: (ShardIndex, u64)) {
        match self.fills.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => *slot = Some(fill),
            None => self.more = true,
        }
    }
}

/// Each heap entry identifies a live PUT's table slot, and `at[heap[i].1] == i` for every `i < len`.
pub(super) struct Deadlines {
    heap: Box<[(u64, u16)]>,
    at: Box<[u16]>,
    len: usize,
}

impl Deadlines {
    fn bytes(puts: u32, slots: u32) -> usize {
        puts as usize * size_of::<(u64, u16)>() + slots as usize * size_of::<u16>()
    }

    pub(super) fn new(puts: u32, slots: u32) -> Self {
        Self {
            heap: vec![(0, 0); puts as usize].into_boxed_slice(),
            at: vec![0; slots as usize].into_boxed_slice(),
            len: 0,
        }
    }

    fn position(&self, slot: u16) -> Option<usize> {
        let at = usize::from(self.at[usize::from(slot)]);
        (at < self.len && self.heap[at].1 == slot).then_some(at)
    }

    pub(super) fn push(&mut self, slot: u16, deadline_us: u64) {
        let at = self.len;
        self.len += 1;
        self.heap[at] = (deadline_us, slot);
        self.at[usize::from(slot)] = at as u16;
        self.up(at);
    }

    pub(super) fn lower(&mut self, slot: u16, deadline_us: u64) {
        if let Some(at) = self.position(slot)
            && deadline_us < self.heap[at].0
        {
            self.heap[at].0 = deadline_us;
            self.up(at);
        }
    }

    pub(super) fn remove(&mut self, slot: u16) {
        if let Some(at) = self.position(slot) {
            self.remove_at(at);
        }
    }

    /// Each call that returns a slot removes the first entry, so with no pushes between calls, draining the heap takes at most the initial `len` successful calls and one call returning `None`.
    pub(super) fn pop_due(&mut self, now_us: u64) -> Option<u16> {
        let (deadline_us, slot) = *self.heap[..self.len].first()?;
        if deadline_us > now_us {
            return None;
        }
        self.remove_at(0);
        Some(slot)
    }

    fn remove_at(&mut self, at: usize) {
        self.len -= 1;
        if at < self.len {
            self.heap[at] = self.heap[self.len];
            self.at[usize::from(self.heap[at].1)] = at as u16;
            self.up(at);
            self.down(at);
        }
    }

    fn up(&mut self, mut at: usize) {
        while at > 0 {
            let parent = (at - 1) / 2;
            if self.heap[parent].0 <= self.heap[at].0 {
                break;
            }
            self.swap(parent, at);
            at = parent;
        }
    }

    fn down(&mut self, mut at: usize) {
        loop {
            let left = 2 * at + 1;
            if left >= self.len {
                break;
            }
            let right = left + 1;
            let child = if right < self.len && self.heap[right].0 < self.heap[left].0 {
                right
            } else {
                left
            };
            if self.heap[at].0 <= self.heap[child].0 {
                break;
            }
            self.swap(at, child);
            at = child;
        }
    }

    fn swap(&mut self, a: usize, b: usize) {
        self.heap.swap(a, b);
        self.at[usize::from(self.heap[a].1)] = a as u16;
        self.at[usize::from(self.heap[b].1)] = b as u16;
    }
}

/// The lowest bit at or above bit `from` that is set in `words`.
pub(super) fn next_set(words: &[u64], from: u32) -> Option<u32> {
    let start = from as usize / 64;
    let first = words.get(start)? & (u64::MAX << (from % 64));
    if first != 0 {
        return Some(start as u32 * 64 + first.trailing_zeros());
    }
    let (n, word) = words[start + 1..]
        .iter()
        .enumerate()
        .find(|(_, word)| **word != 0)?;
    Some((start + 1 + n) as u32 * 64 + word.trailing_zeros())
}

fn reserve<'s, 'a, P: Platform, D: Disk>(
    put: &mut Put<'s, 'a, P>,
    volume: &Volume<'s, 'a, P, D>,
    shape: Shape,
    (tries, work): (usize, usize),
) -> Result<(), ReserveRefusal> {
    let storage = volume.storage();
    let lengths = (
        Some(shape.metadata_len as usize),
        Some(shape.body_len as usize),
    );
    let before = ReserveRefusal::Before;
    let admitted = match storage.decide_admission(lengths.0, lengths.1) {
        Decision::Admit(admitted) => admitted,
        Decision::Ineligible(Ineligible::Layout(_)) => return Err(before(Status::TooLarge)),
        Decision::Ineligible(Ineligible::TornDown) => {
            return Err(before(Status::OwnerUnavailable));
        }
        Decision::Closed => return Err(before(Status::Closed)),
    };
    let ticks = storage
        .clock_ticks()
        .ok_or(before(Status::ClockUnavailable))?;
    let expires_s = ticks
        .checked_add(u64::from(shape.ttl_ms) * 1_000_000)
        .and_then(|deadline| u32::try_from(deadline / NANOS).ok())
        .filter(|&seconds| seconds < u32::MAX)
        .ok_or(before(Status::InvalidRequest))?;
    let Some(Stage::Authority(attempt)) = put.stage.take() else {
        return Err(before(Status::InvalidRequest));
    };
    let mut budget = WorkBudget::new(work);
    let stage = if admitted.extents() == 1 {
        let fill = attempt
            .reserve_storage(admitted, lengths.0, lengths.1, tries, &mut budget)
            .map_err(ReserveRefusal::Fill)?;
        Stage::Priming(fill)
    } else {
        // The placement spans progress turns, each funded with one reservation work, so an object of any admitted size is placed under the per-call bound. The PREPARE places what the promise left it; a short remainder, as the shard hold after a completed placement, waits for a turn's fresh work, and a placement that finds no free run waits until a run forms or the deadline, or ends its PUT at PREPARE when the run-waiter cap is reached.
        let mut placing = attempt
            .promise_storage(admitted, lengths.0, lengths.1, &mut budget)
            .map_err(ReserveRefusal::Fill)?;
        match placing.place(&mut budget) {
            Ok(_)
            | Err(
                FillReserveError::Contended
                | FillReserveError::BudgetExhausted
                | FillReserveError::PayloadFull,
            ) => Stage::Placing(placing),
            Err(error) => {
                placing.end();
                return Err(ReserveRefusal::Fill(error));
            }
        }
    };
    put.expires_s = expires_s;
    put.stage = Some(stage);
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum BeginRefusal {
    Live(LiveCause),
    Namespace(Refusal),
    Fill(BeginError),
    /// The owner is closed to PUTs or the peer lacks a PUT permit.
    Admission(Status),
}

#[derive(Debug, Clone, Copy)]
enum LiveCause {
    GlobalCap,
    PeerShare,
    GetBacklog,
    LaneGuard,
}

/// Why a PREPARE or a placement turn refused its reservation.
#[derive(Debug, Clone, Copy)]
pub(super) enum ReserveRefusal {
    /// The PREPARE ended before its reservation with `TooLarge`, `OwnerUnavailable`, `Closed`, `ClockUnavailable` or `InvalidRequest`.
    Before(Status),
    /// The storage refused the reservation or a placement step.
    Fill(FillReserveError),
}

impl ReserveRefusal {
    fn status(self) -> Status {
        match self {
            Self::Before(status) => status,
            Self::Fill(error) => reserve_status(error),
        }
    }
}

impl BeginRefusal {
    fn status(self) -> Status {
        match self {
            Self::Live(_) => Status::RequestPressure,
            Self::Namespace(refusal) => refusal_status(refusal),
            Self::Fill(error) => begin_status(error),
            Self::Admission(status) => status,
        }
    }
}

fn refusal_status(refusal: Refusal) -> Status {
    match refusal {
        Refusal::Outside => Status::InvalidRequest,
        Refusal::Exhausted => Status::CounterExhausted,
        Refusal::Busy | Refusal::Stale | Refusal::Pressure(_) => Status::RequestPressure,
    }
}

fn begin_status(error: BeginError) -> Status {
    match error {
        BeginError::InProgress => Status::InProgress,
        BeginError::AttemptExhausted => Status::AttemptExhausted,
        BeginError::Closed => Status::Closed,
        BeginError::FillSlotsFull => Status::StoragePressure,
        BeginError::BudgetExhausted | BeginError::Contended => Status::Contended,
        BeginError::NoIndex | BeginError::Corrupt => Status::OwnerUnavailable,
    }
}

fn reserve_status(error: FillReserveError) -> Status {
    match error {
        FillReserveError::Layout(_) => Status::TooLarge,
        FillReserveError::Closed | FillReserveError::Withdrawn => Status::Closed,
        FillReserveError::BudgetExhausted
        | FillReserveError::Contended
        | FillReserveError::Superseded
        | FillReserveError::Bootstrapping => Status::Contended,
        FillReserveError::ObjectSlotsFull
        | FillReserveError::PayloadFull
        | FillReserveError::CleanReserve
        | FillReserveError::RetiredPressure => Status::StoragePressure,
        FillReserveError::TornDown | FillReserveError::Corrupt => Status::OwnerUnavailable,
        FillReserveError::LeaseLimit => Status::LeasePressure,
        FillReserveError::IndexFull => Status::ObjectPressure,
    }
}

/// A draining fill records a `FillFailure` for its followers based on the
/// owner's chosen `status`. `Cancelled`, `Expired`, `ConflictingData` (a
/// status of PUT alone) and every status an upload reaches only before its
/// grant map to `None`, so followers report missing. The `PutCancel` path
/// passes `None` directly, since its sender picks the status.
pub(crate) fn fill_failure(status: Status) -> Option<FillFailure> {
    Some(match status {
        Status::DeviceError => FillFailure::DeviceError,
        Status::TimedOut => FillFailure::TimedOut,
        Status::Closed => FillFailure::Closed,
        Status::OwnerUnavailable => FillFailure::OwnerUnavailable,
        Status::ClockUnavailable => FillFailure::ClockUnavailable,
        Status::Contended => FillFailure::Contended,
        Status::StoragePressure => FillFailure::StoragePressure,
        Status::ObjectPressure => FillFailure::ObjectPressure,
        _ => return None,
    })
}

fn receive_status(error: ReceiveError) -> Status {
    match error {
        ReceiveError::Closed => Status::Closed,
        ReceiveError::Revoked | ReceiveError::Bootstrapping => Status::Contended,
        ReceiveError::Refused(_) => Status::DeviceError,
        ReceiveError::Budget(_) | ReceiveError::PoolExhausted | ReceiveError::TableFull => {
            Status::StoragePressure
        }
        ReceiveError::LengthExceeded | ReceiveError::Lost | ReceiveError::ForeignVolume => {
            Status::OwnerUnavailable
        }
    }
}

/// The cache version a PUT BEGIN names in its offset field.
fn begin_version(header: &Header) -> CacheVersion {
    CacheVersion(header.offset)
}

fn publish_status(error: FillPublishError) -> Status {
    match error {
        FillPublishError::Expired => Status::Expired,
        FillPublishError::ClockUnavailable => Status::ClockUnavailable,
        FillPublishError::Closed => Status::Closed,
        FillPublishError::IndexFull | FillPublishError::History => Status::ObjectPressure,
        FillPublishError::Contended
        | FillPublishError::BudgetExhausted
        | FillPublishError::Superseded => Status::Contended,
        FillPublishError::Incomplete => Status::DeviceError,
        FillPublishError::ForeignVolume | FillPublishError::Lost | FillPublishError::Corrupt => {
            Status::OwnerUnavailable
        }
    }
}
