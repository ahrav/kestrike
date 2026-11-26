//! The checks a holder runs before and during its use of a cache volume: the owner's poll, the standby's check of
//! its idle spare, and the fresh path's check before its first device command, with the owner's reclaim selection
//! after a continuing poll. Each check compares the shard record, the
//! volume record and the control plane's attachment listing with the desired state, and the owner's poll also its
//! Report, and returns a [`Verdict`].
//!
//! - ATTACH-OUTSIDE-DESIRED-STATE-RETIRES: a listing with any attachment record outside the check's admitted set
//!   retires the volume at that check, whatever the Report and the volume record show, unless the reads depose the
//!   holder. The owner's admitted set is its own record, one record of each peer the caller binds whose host the
//!   volume record shows attached, now or before a detach, and one record of each instance an attach or ended entry
//!   of another host binds (ENDED-NEVER-RETIRES); the spare and fresh checks admit the holder's one record
//!   alone. The owner's poll takes its target from its caller and retires on such a listing even without a shard
//!   read; the spare and fresh checks take their target from the shard record and are unobserved without it. The
//!   listing is the only evidence of an attachment that never registered and that the volume record's events never
//!   recorded.
//! - FreshIsEmpty, attachment scope: [`fresh`] continues only on a full observation in which the listing holds
//!   exactly the standby's own attachment and the volume record an uncompacted history of exactly its one attach
//!   event, so no attachment the
//!   listing showed at the check had written the spare.
//! - NO-OBSERVATION: a source whose read returned no value, a volume record of another volume, an unreadable
//!   Report and an empty listing contribute no evidence. Such a source neither vetoes a trigger or a deposition
//!   another source shows nor moves state by itself. A check with no trigger and an unobserved source is
//!   [`Verdict::Unobserved`], and so is a spare or fresh check without the shard record, which evaluates no other
//!   source; [`fresh`] continues only on a full clean observation. Without the owner's volume record the listing
//!   admits every bound peer, whose attach events it cannot check, and no entry's instance, and the check is
//!   unobserved at the volume stage;
//!   a foreign or duplicate listed record keeps its trigger.
//! - ROLE-BOUND: a check whose shard record names the holder in another role or under another `(g, owner, E)`, or an
//!   owner's poll without a shard record whose volume record shows the volume retired or deleted, is
//!   [`Verdict::Deposed`] and requests nothing, so a check that outlived its role never retires the volume of the
//!   role's successor. Every retirement names the role the record holds the volume in, and its `(g, owner, E)`.
//! - READ-ORDER: a caller reads the volume record before the shard record, and the owner's poll obtains its Report
//!   and listing before reading the volume and shard records. The reconciler commits the shard write
//!   that displaces a volume, the flip for the active volume or the spare drop for the spare, before it records that
//!   volume retired, and the flip's write of its spare's volume record makes a retired-state write conditioned on an
//!   earlier read of it fail. Under linearizable reads a check that sees the retired record then reads a shard
//!   record that names the volume active in no generation; a naming write racing the retirement can leave the
//!   retired volume named spare until the retirement's settling shard write clears it, and a spare check in that
//!   window requests the retirement already under way. The reconciler commits a spare's volume record, fresh with the
//!   standby's one attach event, before the shard record names that volume as spare.
//! - The poll and the spare check run at a fixed cadence that carries availability only; the fresh check is the one
//!   whose verdict decides an activation. The owner's poll also bounds the serving deferral of a standby's
//!   registration: the serving authority keeps the owner beside it for one serving window, so the owner polls with a
//!   volume-record read within that window (`Volume::owner_poll`).
//! - ENDED-PREEMPT and EndOrder: [`reclaim`] is the owner's reclaim selection over the Report and the volume record
//!   of a poll whose verdict was [`Verdict::Continue`], the record read after the Report, a precondition its caller
//!   keeps. It selects at most one key, a key some registrant of the Report carries that no holder carries and that
//!   the record ties to ended entries alone, never a key a recorded pair of a live attach carries, and the recorded
//!   pairs of ended entries whose keys no registrant of the Report carries. A Report whose count is inconclusive
//!   selects nothing. The record can show an end written after the Report sampled the registrants, so a selected
//!   pair is a candidate: its caller drops it when the Report was submitted after the caller saw the pair ended.
//! - POST-WITHDRAWAL-POLL: after the owner withdraws with no flip request, on a deposing status,
//!   `Cause::RecordedHolder`, `Cause::Unheld` or [`Verdict::Withdraw`], its caller keeps this poll's cadence with a
//!   Report and a listing read for each poll until one retires or deposes; the listing check is this poll's alone.
//!   After a withdrawal by `Cause::Planned`, `Volume::owner_poll` maps a retiring verdict to [`Verdict::Withdraw`]
//!   and passes [`Verdict::Deposed`] through (`TransferRetainsVolume`). LAPSE-UNVERIFIED: after a withdrawal by
//!   `Cause::Unverified`, which requests no flip, this poll is the judge of the lapsed pair: a Report inside its
//!   serving window that lists the pair and a volume record read after it that does not admit it, as a recorded
//!   pair or a pair under an ended attach's key, retire the volume at the caller's target, and the shard record
//!   deposes as it does for every poll. `Volume::owner_poll` counts a Report as unread when its submission falls
//!   after the reads' send sample or at least one serving window before that sample.
//!   Once the authority observed a later tenure (`Machine::superseded`), `Volume::owner_poll` is deposed and the
//!   serving authority submits no further Report. Until then, after a status the serving authority's own Report also
//!   judges the holder (STATUS-REJUDGE), after the gate's
//!   Acquire or Report status as well; after the Register's status that Report shows the own host ID under another
//!   key, which is no retirement evidence before the boundary, and this poll remains the judge. NO-OBSERVATION's
//!   exception: an owner's poll without its volume record judges a parsed Report's `ForeignHolder`, and a Report with
//!   nobody holding, each with at most one own record under the own key, as clean and withdraws.
//!
//! FRESH-IS-EMPTY rests on two premises the listing cannot establish, since it holds the attachment records the
//! control plane returns at one read and `DescribeVolumes` is eventually consistent. Every attachment that could
//! have written the spare is visible to the listing by the fresh check. No such attachment was removed before the
//! check: the access-control statement lets only the reconciler detach a cache-tagged volume, and it binds neither
//! the detach that terminating the attaching instance causes nor a principal the statement exempts. That the spare
//! the fresh path activates is unwritten needs a third premise: no attachment is made between the listing read and
//! the fresh path's Acquire, from which point the reservation refuses the writes of an unregistered attachment.

use crate::failover::attachments::{InstanceId, Mismatch, Peer, check};
use crate::failover::bounds::Bounds;
use crate::failover::evidence::{Census, NotSole, Pair, Report, find_from};
use crate::failover::flip::volume_state;
use crate::failover::identity::Key;
use crate::failover::records::{
    Host, MAX_ATTACHED, ShardRecord, VolumeId, VolumeRecord, VolumeState, attachment_seq,
};
use crate::failover::retire::{Retirement, Role, Target, Trigger};
use crate::storage::EndedPreempt;

/// A volume, the host the shard record names for it, and that host's instance. The caller supplies `instance` as
/// the verified instance identity of `host`. These checks trust the caller's binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Holder {
    pub volume: VolumeId,
    pub host: Host,
    pub instance: InstanceId,
}

impl Holder {
    /// Whether `binding` names this holder's instance and volume.
    pub(crate) fn binds(&self, binding: &crate::failover::record::Binding) -> bool {
        binding.instance == self.instance.as_str() && binding.volume == self.volume.as_str()
    }
}

/// What one check read, each part `None` when its read returned no value. A `volume` record of another volume counts
/// as unread. The caller reads `volume` before `shard` (READ-ORDER).
#[derive(Debug, Clone, Copy, Default)]
pub struct Reads<'a> {
    pub shard: Option<&'a ShardRecord>,
    pub volume: Option<&'a VolumeRecord>,
    pub listed: Option<&'a [String]>,
    /// The caller supplies the verified instance identity of each expected standby host in `peers`. `peers` must
    /// include every host whose recorded attach is live with no enrolled pair and binds no instance, the format-2
    /// case, even if the attach request failed
    /// permanently and the host's standby slot moved to another host, since the volume record keeps that attach live
    /// (SLOT-RECLAMATION in `failover::standbys`). For each live attach on a host other than `holder.host`,
    /// `owner_events`' host check passes when `peers` contains the host, `volume.pinned(host, attach)` returns a
    /// pin, or the attach's entry binds an instance.
    /// An entry's instance admits its listed instance only while `volume` holds that entry; with `volume` unread only
    /// `peers` admits a listed instance.
    pub peers: &'a [Peer],
}

/// The outcome of one check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a verdict takes effect only through the holder that acts on it"]
pub enum Verdict {
    /// Every source was read and shows the desired state: the owner keeps serving, the standby keeps its spare idle,
    /// and the fresh path proceeds.
    Continue,
    /// No evaluated source shows a trigger and at least one was not observed; a spare or fresh check without the
    /// shard record evaluates no other source. The holder keeps its current state and the fresh path waits.
    /// Detection stays stopped while such checks repeat, so a caller alarms on a run of them.
    Unobserved,
    /// The holder stops every I/O to the volume at once and requests nothing.
    Deposed,
    /// The holder stops every I/O to the volume at once, raises the alarm, and sends the request.
    Retire(Retirement),
    /// The owner's own entry is ended or gone (ENDED-GRANTS-NOTHING), with no other source deposing or retiring.
    /// RECORDED-HOLDER-HOLD: another pair holds beside recorded registrants, with at most one own record: a recorded
    /// pair, of a live attach or an ended one, or any holder under an unread volume record, and no other source
    /// deposes or retires.
    /// NO-HOLDER-HOLD: nobody holds, beside the own pair and the recorded pairs of a read volume record, or any
    /// registrants under an unread volume record, with at most one own record, and no other source deposes or retires.
    /// Under either hold, the holder suspends all volume I/O and raises the alarm, and sends a retirement request only
    /// if a later poll returns `Retire`.
    /// `Volume::owner_poll` returns `Withdraw` for retirement evidence that arrives after a planned exit withdrew the
    /// owner (`TransferRetainsVolume`), which keeps the volume for the shard's next tenure.
    Withdraw,
}

/// Which check runs.
#[derive(Debug, Clone, Copy)]
enum Check {
    Owner(Target, Pair),
    Spare,
    Fresh,
}

impl Check {
    /// The role the shard record holds the checked volume in.
    fn held(self) -> Role {
        match self {
            Self::Spare => Role::Spare,
            Self::Owner(..) | Self::Fresh => Role::Active,
        }
    }

    fn standbys<'a>(self, reads: &Reads<'a>) -> Option<&'a [Peer]> {
        match self {
            Self::Owner(..) => Some(reads.peers),
            Self::Spare | Self::Fresh => None,
        }
    }
}

/// The `attachments::check` result of the listing in `reads` against the admitted set of a check whose expected
/// standbys are `standbys`, `None` without a listing. An owner check, whose `standbys` is `Some`, also admits the
/// instances the read volume record's attach and ended entries bind for other hosts.
fn listing(
    holder: &Holder,
    reads: &Reads<'_>,
    standbys: Option<&[Peer]>,
) -> Option<Result<(), Mismatch>> {
    let volume = reads.volume.filter(|record| record.volume == holder.volume);
    let peers = (standbys.unwrap_or_default().iter())
        .filter(move |peer| {
            peer.host != holder.host
                && volume.is_none_or(|record| record.has_attach_event(peer.host))
        })
        .map(|peer| &peer.instance);
    let entries = (volume.filter(|_| standbys.is_some()).into_iter())
        .flat_map(|record| record.instances_beside(holder.host));
    (reads.listed).map(|listed| check(listed, &holder.instance, peers.chain(entries)))
}

/// The listing check [`poll`] runs over `reads`: the `attachments::check` result of the listing against the owner's
/// admitted set, `None` when `reads` holds no listing. The poll retires on a mismatch unless the reads depose the
/// holder first; this read returns the check's result whatever the poll decided.
pub fn owner_listing(holder: &Holder, reads: &Reads<'_>) -> Option<Result<(), Mismatch>> {
    listing(holder, reads, Some(reads.peers))
}

/// What one source of a check showed.
enum Seen {
    Unobserved,
    Clean,
    Retire(Retirement),
    /// The volume record ends the holder's own attach.
    Ended,
}

/// The owner's poll of the volume it serves under `target`. Its census of the Report admits as non-holding
/// registrants the recorded pairs of the volume record in `reads` and each pair that record classes
/// [`Registration::Ended`] (ENDED-NEVER-RETIRES). RECORDED-HOLDER-HOLD: a parsed Report whose
/// `ForeignHolder` refusal the volume record cannot refute, a holder the holder resolver validates as a recorded pair
/// beside recorded registrants or, under an unread volume record, any holder beside at most one own record under the
/// own key, is judged with the other sources as
/// clean and returns [`Verdict::Withdraw`] unless another source deposes or retires. An unrecorded holder retires
/// with the alarm. NO-HOLDER-HOLD: a `ReservationType` or `NotHolder` refusal of a parsed Report with nobody holding,
/// beside the own pair and the recorded pairs of the volume record in `reads`, is judged the same way; without that
/// volume record, which is no observation of the registrants, the test admits every listed pair, so a Report with
/// nobody holding and at most one own record, under the own key, holds until a poll that reads the record decides, as
/// a foreign holder does. The
/// poll judges `report` for `own` with
/// [`Report::registrants`] over the recorded pairs of the volume record in `reads`, and a refused parse with [`NotSole::unparsed`] over the same
/// pairs, then judges `reads` under the module's rules. The caller follows READ-ORDER, passes
/// [`ReportError::refusal`] for a refused Report parse and [`NotSole::Unreadable`] when the Report returns no value.
///
/// [`ReportError::refusal`]: crate::storage::ReportError::refusal
pub fn poll(
    holder: &Holder,
    target: Target,
    own: Pair,
    report: Result<&Report<'_>, NotSole>,
    reads: &Reads<'_>,
    bounds: &Bounds,
) -> Verdict {
    let volume = reads.volume.filter(|record| record.volume == holder.volume);
    let pairs = volume.map(|record| &record.pairs[..]);
    let recorded = || volume.map(VolumeRecord::recorded);
    let (judged, hold) = match report {
        Ok(report) => {
            let mut seen = 0;
            let census = report.census(own, |pair| {
                pairs.is_some_and(|pairs| {
                    find_from(pairs, &mut seen, |recorded| recorded.pair == *pair).is_some()
                }) || volume.is_some_and(|record| record.ended_registrant(report.entries, pair))
            });
            let admitted = volume.map(|record| record.admitted(report.entries));
            let judged = report.verdict(&census, own, admitted, bounds);
            let hold = match judged {
                Err(NotSole::ForeignHolder) => {
                    crate::storage::device::own_record(&census).is_ok()
                        && recorded().is_none_or(|recorded| {
                            crate::storage::held_by_recorded(report, &census, recorded, own, bounds)
                        })
                }
                Err(NotSole::ReservationType | NotSole::NotHolder) => {
                    // An unread volume record is no observation of the registrants, so the test admits every
                    // listed pair.
                    let listed = Census {
                        unknown: census.unknown && pairs.is_some(),
                        ..census
                    };
                    crate::storage::unheld_among_recorded(report, &listed, own, bounds)
                }
                _ => false,
            };
            (judged, hold)
        }
        Err(refusal) => (Err(refusal.unparsed(recorded(), bounds)), false),
    };
    let judged = if hold { Ok(()) } else { judged };
    match judge(holder, Check::Owner(target, own), judged, reads) {
        Verdict::Continue | Verdict::Unobserved if hold => Verdict::Withdraw,
        verdict => verdict,
    }
}

/// The owner's reclaim decision over one poll: the ended key to preempt, at most one, and the ended pairs to drop.
/// A selection only: it issues no device command and writes no record.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Reclaim {
    /// The smallest key a registrant of the Report carries that passes [`EndedPreempt::target`] against the volume
    /// record: no registrant under it holds, no recorded pair that pins no ended entry carries it, and the record
    /// ties every registrant under it to an ended entry, a recorded pair of an ended entry or a pair classed
    /// [`Registration::Ended`].
    pub(crate) preempt: Option<Key>,
    /// The recorded pairs of ended entries whose keys no registrant of the Report carries, in record order.
    /// Each pair is a candidate: the caller drops the pair once the ordering condition of [`reclaim`] holds.
    pub(crate) dropped: Vec<Pair>,
}

/// The owner's reclaim decision over `report` and `volume`. Precondition: `report` is the Report of a poll whose
/// verdict was [`Verdict::Continue`] and `volume` is the volume record that poll read after it; `reclaim` checks
/// neither. ENDED-PREEMPT: it names at most one key, a registered key of an ended attach that does not hold, so a
/// poll preempts one ended registration and a later poll takes the next; the smallest such key, whatever the order
/// of the Report's entries. EndOrder: it names a recorded pair of an ended entry to drop only when no registrant of
/// `report` carries its key, so a pair whose key the Report lists is preempted first and dropped on a later poll
/// whose Report shows the key absent. A preempt's successful status shows no key absent; only a later Report does.
/// The named pairs are candidates, because an entry can end after `report` samples the registrants and before the
/// caller reads `volume`, as when a Register lands and the reconciler then ends the attach. The caller drops a
/// named pair when `report` was submitted after a clock reading at which the caller saw that pair pinned to the
/// same ended entry, so the Report that shows the key absent follows the end mark.
/// It names no key a recorded pair of a live attach carries, no pair of a live attach, and nothing from a Report
/// whose count is inconclusive. The caller builds the preempt through [`EndedPreempt::resolve`] and drops the pairs
/// through [`VolumeRecord::dropped`] by an exact-version replace of `volume`; a pair it drops under a retained key
/// that its entry does not derive leaves a late Register under that key unknown ([`VolumeRecord::dropped`]).
pub(crate) fn reclaim(report: &Report<'_>, volume: &VolumeRecord, bounds: &Bounds) -> Reclaim {
    if report.holding(bounds) == crate::failover::evidence::Holding::Inconclusive {
        return Reclaim::default();
    }
    let listed = |key: Key| report.entries.iter().any(|entry| entry.pair.key == key);
    let preempt = (report.entries.iter())
        .map(|entry| entry.pair.key)
        .filter(|&key| EndedPreempt::target(report, volume, key).is_ok())
        .min();
    let dropped = (volume.ended_pairs())
        .filter(|held| !listed(held.pair.key))
        .map(|held| held.pair)
        .collect();
    Reclaim { preempt, dropped }
}

/// The standby's check of its idle spare.
pub fn spare(holder: &Holder, reads: &Reads<'_>) -> Verdict {
    judge(holder, Check::Spare, Ok(()), reads)
}

/// Fresh acquisition checks the listing, the shard record's naming, and the volume record's layout floor, state, events and modification before its first device command.
/// The path proceeds only on [`Verdict::Continue`].
/// The fresh path's caller requires `CreationSource::Provisioned` and `Lineage::None` before activation.
pub fn fresh(holder: &Holder, reads: &Reads<'_>) -> Verdict {
    judge(holder, Check::Fresh, Ok(()), reads)
}

/// A deposition first, then the first trigger in the order listing, Report, volume record. A spare or fresh check
/// takes its target from the shard record, so a check without the shard record is unobserved.
#[inline(always)]
fn judge(holder: &Holder, kind: Check, report: Result<(), NotSole>, reads: &Reads<'_>) -> Verdict {
    let target = match (kind, reads.shard) {
        (Check::Owner(target, _), _) => target,
        (_, Some(shard)) => Target::of(shard),
        (_, None) => return Verdict::Unobserved,
    };
    let volume = reads.volume.filter(|record| record.volume == holder.volume);
    let deposed = match reads.shard {
        Some(shard) => !names(kind, holder, shard),
        None => volume.is_some_and(|record| {
            matches!(record.state, VolumeState::Retired | VolumeState::Deleted)
        }),
    };
    if deposed {
        return Verdict::Deposed;
    }
    let request = |trigger: Trigger| {
        Retirement::new(holder.volume, kind.held(), target, trigger)
            .map_or(Seen::Unobserved, Seen::Retire)
    };
    let mut unobserved = false;
    let mut settle = |seen: Seen| match seen {
        Seen::Retire(retirement) => Some(Verdict::Retire(retirement)),
        Seen::Ended => Some(Verdict::Withdraw),
        Seen::Unobserved => {
            unobserved = true;
            None
        }
        Seen::Clean => None,
    };
    let listing = match listing(holder, reads, kind.standbys(reads)) {
        Some(Err(mismatch)) => request(Trigger::Attachment(mismatch)),
        Some(Ok(())) => Seen::Clean,
        None => Seen::Unobserved,
    };
    if let Some(verdict) = settle(listing) {
        return verdict;
    }
    let report = match report {
        Ok(()) => Seen::Clean,
        Err(refusal) => request(Trigger::Report(refusal)),
    };
    if let Some(verdict) = settle(report) {
        return verdict;
    }
    let standbys = kind.standbys(reads);
    let own = match kind {
        Check::Owner(_, own) => Some(own),
        Check::Spare | Check::Fresh => None,
    };
    let seen = |found: Option<Contradiction>, none: Seen| match found {
        None => none,
        Some(Contradiction::Retire(trigger)) => request(trigger),
        Some(Contradiction::Ended) => Seen::Ended,
    };
    let volume = match (volume, reads.shard) {
        (None, _) => Seen::Unobserved,
        (Some(record), Some(shard)) => seen(
            judged_volume(kind.held(), standbys, own, holder, shard, record),
            Seen::Clean,
        ),
        (Some(record), None) => seen(
            recorded(
                holder,
                record,
                standbys.filter(|_| target.attempts > 0),
                own,
            ),
            Seen::Unobserved,
        ),
    };
    if let Some(verdict) = settle(volume) {
        return verdict;
    }
    if unobserved {
        Verdict::Unobserved
    } else {
        Verdict::Continue
    }
}

#[inline(always)]
fn names(kind: Check, holder: &Holder, shard: &ShardRecord) -> bool {
    let active = || shard.active == holder.volume && shard.owner == holder.host;
    match kind {
        Check::Owner(target, _) => Target::of(shard) == target && active(),
        Check::Spare => shard
            .spare
            .is_some_and(|(volume, host)| volume == holder.volume && host == holder.host),
        Check::Fresh => shard.attempts == 0 && active(),
    }
}

/// What the volume record shows against the role a check holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Contradiction {
    /// A retirement trigger.
    Retire(Trigger),
    /// ENDED-GRANTS-NOTHING: when [`VolumeRecord::ended`] returns `true` for the holder's host, the owner withdraws and
    /// both restart and takeover refuse admission.
    Ended,
}

/// The first contradiction `volume` shows under `shard`: a state other than the one the role requires, then those
/// of [`recorded`]. `standbys` is `Some` for the owner, whose events [`owner_events`] judges at `E > 0`; at `E = 0`
/// and for `None` the holder's one attach of [`VolumeRecord::attached_once`] applies.
pub(crate) fn contradiction(
    role: Role,
    standbys: Option<&[Peer]>,
    holder: &Holder,
    shard: &ShardRecord,
    volume: &VolumeRecord,
) -> Option<Contradiction> {
    judged_volume(role, standbys, None, holder, shard, volume)
}

fn judged_volume(
    role: Role,
    standbys: Option<&[Peer]>,
    own: Option<Pair>,
    holder: &Holder,
    shard: &ShardRecord,
    volume: &VolumeRecord,
) -> Option<Contradiction> {
    let expected = match role {
        Role::Spare => VolumeState::Fresh,
        Role::Active => VolumeState::Active,
    };
    if volume_state(shard, volume) == Ok(expected) {
        recorded(holder, volume, standbys.filter(|_| shard.attempts > 0), own)
    } else {
        Some(Contradiction::Retire(Trigger::VolumeState))
    }
}

/// OWNER-EVENTS, the owner's events rule at `E > 0`: a live attach of the holder's host, at most `MAX_ATTACHED`
/// live hosts, and each other live host bound in `peers`, enrolled for its live attach or bound to an instance by
/// that attach's entry. An earlier entry of the holder's host and entries the record no longer retains leave the
/// rule unchanged.
fn owner_events(holder: &Holder, volume: &VolumeRecord, peers: &[Peer]) -> bool {
    volume.live(holder.host).is_some()
        && volume
            .live_attaches()
            .enumerate()
            .all(|(at, (attach, host))| {
                at < MAX_ATTACHED
                    && (host == holder.host
                        || peers.iter().any(|peer| peer.host == host)
                        || volume.pinned(host, attach).is_some()
                        || volume
                            .event(attach)
                            .is_some_and(|event| event.instance.is_some()))
            })
}

fn recorded(
    holder: &Holder,
    volume: &VolumeRecord,
    owner_peers: Option<&[Peer]>,
    own: Option<Pair>,
) -> Option<Contradiction> {
    let superseded = || {
        let Some((own, live)) = own.zip(volume.live(holder.host)) else {
            return false;
        };
        let pinned = volume
            .pairs
            .iter()
            .find(|recorded| recorded.pair == own && recorded.host == holder.host)
            .map(|recorded| recorded.attach);
        let earlier = pinned.or_else(|| {
            attachment_seq(own.key)
                .filter(|_| volume.recorded().all(|recorded| *recorded != own))
                .filter(|&seq| match volume.event(seq) {
                    Some(event) => event.host == holder.host,
                    None => volume.removed(seq),
                })
        });
        earlier.is_some_and(|attach| attach != live)
    };
    let attached = match owner_peers {
        Some(_) if volume.ended(holder.host) || superseded() => {
            return Some(Contradiction::Ended);
        }
        Some(peers) => owner_events(holder, volume, peers),
        None => volume.attached_once(holder.host),
    };
    let trigger = if !attached {
        Some(Trigger::Events)
    } else if volume.modification.is_some() {
        Some(Trigger::Modification)
    } else {
        volume.layout.check_floor().err().map(Trigger::Layout)
    };
    trigger.map(Contradiction::Retire)
}
