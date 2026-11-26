//! Typed reservation operations, validated owner bounds and bounded extended Report decoding.

use crate::failover::bounds::Bounds;
use crate::failover::evidence::{
    Census, Holding, NotSole, Pair, Registrant, Report, ReservationType,
};
use crate::failover::identity::{Exhid, IdentityError, Key};
use crate::failover::records::{Registration, VolumeRecord};

/// Validated owner inputs. Deadlines use the owner's clock unit; command drain requires independent evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservationLimits {
    registrants: u32,
    commands: u32,
    report_timeout: u64,
    preempt_timeout: u64,
    bytes: u32,
}

/// An invalid registrant bound, insufficient reserve, or zero deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationLimitsError {
    Registrants,
    Commands,
    Deadline,
}

impl ReservationLimits {
    /// Validates `N_reg` in `1..=65535`, `N_resv >= 2`, and positive owner-clock deadlines.
    /// Each table retains `N_resv` buffers and slots. Report storage is `64 + 64 * N_reg` bytes.
    ///
    /// # Errors
    ///
    /// Returns `Registrants`, `Commands`, or `Deadline` in that check order.
    pub fn new(
        registrants: u32,
        commands: u32,
        report_timeout: u64,
        preempt_timeout: u64,
    ) -> Result<Self, ReservationLimitsError> {
        if registrants == 0 || registrants > u32::from(u16::MAX) {
            return Err(ReservationLimitsError::Registrants);
        }
        if commands < 2 {
            return Err(ReservationLimitsError::Commands);
        }
        if report_timeout == 0 || preempt_timeout == 0 {
            return Err(ReservationLimitsError::Deadline);
        }
        let bytes = registrants
            .checked_mul(64)
            .and_then(|entries| entries.checked_add(64))
            .ok_or(ReservationLimitsError::Registrants)?;
        Ok(Self {
            registrants,
            commands,
            report_timeout,
            preempt_timeout,
            bytes,
        })
    }
    pub fn registrants(self) -> u32 {
        self.registrants
    }
    pub fn commands(self) -> u32 {
        self.commands
    }
    pub fn report_timeout(self) -> u64 {
        self.report_timeout
    }
    pub fn preempt_timeout(self) -> u64 {
        self.preempt_timeout
    }
    pub fn report_bytes(self) -> u32 {
        self.bytes
    }
    /// Whether these limits and `bounds` agree on the registrant bound `N_reg` and the Report deadline `T_report`.
    pub fn agrees_with(self, bounds: &Bounds) -> bool {
        self.registrants == bounds.registrant_max()
            && self.report_timeout == bounds.report_deadline()
    }
}

/// The reservation operations the cache issues, each over Exclusive Access (type 2) where a type applies. The type
/// restricts the cache to registration, extended reporting, acquisition, self preemption, superseded-tenure
/// preemption and ended-attach preemption. `NoPreemptOfForeignKey` admits three forms of PRKEY, each with the host's
/// own key as CRKEY: a Preempt-and-Abort names either the own key or the key of the holder a Report shows, a pair the
/// volume record records for another host, live or ended, whose tenure the issuer's own acknowledged shard-record
/// write superseded, the takeover's compare-and-swap or the bump of a restart the record names owner, directly or
/// through earlier committed tenure writes, resolved by [`LineagePreempt::resolve`]; and a Preempt with no
/// abort, from the record-named owner past its fencing boundary, names the key of an ended attach that a Report
/// shows registered and not holding, resolved by [`EndedPreempt::resolve`] (ENDED-PREEMPT). While the own pair holds,
/// no form names another holder's key. The ended form names neither the own key nor a key that a recorded pair of a
/// live attach carries; the lineage form names a recorded superseded holder, on a live attach or an ended entry.
///
/// ```compile_fail,E0559
/// use kestrike::storage::ReservationCommand;
/// let _ = ReservationCommand::Register { current: None, new: todo!() };
/// ```
///
/// ```compile_fail,E0599
/// use kestrike::storage::ReservationCommand;
/// let _ = ReservationCommand::Release { current: todo!() };
/// ```
///
/// ```compile_fail,E0599
/// use kestrike::storage::ReservationCommand;
/// let _ = ReservationCommand::Clear { current: todo!() };
/// ```
///
/// ```compile_fail,E0599
/// use kestrike::storage::ReservationCommand;
/// let _ = ReservationCommand::Unregister { current: todo!() };
/// ```
///
/// ```compile_fail,E0559
/// use kestrike::storage::ReservationCommand;
/// let _ = ReservationCommand::Acquire { current: todo!(), ignore_existing: true };
/// ```
///
/// ```compile_fail,E0559
/// use kestrike::storage::ReservationCommand;
/// let _ = ReservationCommand::PreemptAndAbort { current: todo!(), preempt: todo!() };
/// ```
///
/// ```compile_fail,E0451
/// use kestrike::storage::SelfPreempt;
/// let _ = SelfPreempt { own: todo!() };
/// ```
///
/// ```compile_fail,E0451
/// use kestrike::storage::LineagePreempt;
/// let _ = LineagePreempt { own: todo!(), preempted: todo!() };
/// ```
///
/// ```compile_fail,E0451
/// use kestrike::storage::EndedPreempt;
/// let _ = EndedPreempt { own: todo!(), ended: todo!() };
/// ```
///
/// ```
/// use kestrike::storage::{EndedPreempt, LineagePreempt, ReservationCommand, SelfPreempt};
/// fn form(command: ReservationCommand) -> u8 {
///     match command {
///         ReservationCommand::Register { new: _ } => 0,
///         ReservationCommand::Report { not_before: _ } => 1,
///         ReservationCommand::Acquire { current: _ } => 2,
///         ReservationCommand::PreemptAndAbort(own) => {
///             let _: SelfPreempt = own;
///             3
///         }
///         ReservationCommand::PreemptLineage(lineage) => {
///             let _: LineagePreempt = lineage;
///             4
///         }
///         ReservationCommand::PreemptEnded(ended) => {
///             let _: EndedPreempt = ended;
///             5
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationCommand {
    /// Register with action 0, CPTPL unchanged.
    Register { new: Key },
    /// Extended Report, eligible from submission ordinal `not_before`.
    Report { not_before: u64 },
    /// Acquire with action 0 and Exclusive Access, type 2.
    Acquire { current: Key },
    /// Preempt-and-Abort with action 2 and Exclusive Access, type 2, naming the own key as both CRKEY and PRKEY.
    PreemptAndAbort(SelfPreempt),
    /// Preempt-and-Abort with action 2 and Exclusive Access, type 2, naming the own key as CRKEY and the key of the
    /// holder the issuer's own acknowledged shard-record write superseded as PRKEY, a takeover's or a lineage
    /// restart's: the fence of that holder's registration.
    PreemptLineage(LineagePreempt),
    /// Preempt with action 1 and Exclusive Access, type 2, naming the own key as CRKEY and an ended attach's key that
    /// does not hold as PRKEY: the registrations under that key end and the holder and type stay (NVMe Base
    /// Specification 2.1, section 8.1.22.7). An ended registrant holds no access under Exclusive Access, so the
    /// command aborts nothing. A Report after its completion is the only receipt of its effect.
    PreemptEnded(EndedPreempt),
}

/// The self Preempt-and-Abort: the host's own pair preempting itself, with the own key as both
/// CRKEY and PRKEY. Only [`SelfPreempt::from_report`] builds one, from a Report that shows the own pair as the one
/// holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfPreempt {
    own: Pair,
}

impl SelfPreempt {
    /// A self preempt for `own` when `report` shows `own` as the one holder of a type-2 reservation under `bounds`
    /// and carries exactly one record with the own host ID. The checks read the Report's content only: the caller
    /// passes the parsed bytes of the certified Report #1 of the current restart and submits the value once.
    pub fn from_report(report: &Report<'_>, bounds: &Bounds, own: Pair) -> Option<Self> {
        let census = holds_alone(report, bounds, own)?;
        own_record(&census).is_ok().then_some(Self { own })
    }

    pub fn pair(self) -> Pair {
        self.own
    }
}

/// The lineage Preempt-and-Abort of the takeover and of the same-host restart's lineage arm: the own pair,
/// registered under its own key, preempting the registration of `preempted`, the key of the pair a Report showed as
/// the one holder. Only [`LineagePreempt::resolve`] and [`LineagePreempt::resolve_counted`] build one, so every such
/// preempt names a key of the admitted set the caller passes: both callers pass the pairs the volume record records
/// for the other hosts, on a live attach or an ended entry, whose tenures their own acknowledged shard-record write
/// superseded. Each resolves over a census that admits the recorded pairs and the non-holding registrants under an
/// ended attach's key. The completion guarantee covers the preempted registration's earlier commands that remain at
/// the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineagePreempt {
    own: Pair,
    preempted: Key,
}

/// Why [`LineagePreempt::resolve`] refused to name a holder, in check order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolderRefusal {
    /// The Report shows a reservation of another type, nobody holding, several holding pairs or an inconclusive
    /// count, so it resolves to no key.
    Unresolved,
    /// The own pair holds: the takeover's preempt names another host's registration only.
    Own,
    /// Resolution requires the holder's pair among the volume record's recorded pairs.
    Unrecorded,
    /// The holder's pair is recorded and outside the admitted holders: for the takeover and the restart's lineage arm,
    /// a pair recorded for the issuer's own host.
    NotAdmitted,
    /// A registrant other than the holder and the own pair is outside the census's admitted registrants, which for
    /// the takeover and the restart's lineage arm are the recorded pairs and the non-holding registrants under an
    /// ended attach's key, or the records carrying the own host ID are more than one or carry another key.
    Registrants(NotSole),
}

impl LineagePreempt {
    /// Resolves the holder `report` shows against `recorded`, the pairs the census admits, and `admitted`, the
    /// admitted holders among them: the value names the holder's key when the Report shows a type-2 reservation held
    /// by one pair other than `own`, that pair is in `admitted`, at most one record carries the own host ID, and
    /// every other registrant is `own` or a pair of `recorded`. The takeover passes the pairs of
    /// `VolumeRecord::admitted` as `recorded`: the recorded pairs and the non-holding registrants under an ended
    /// attach's key.
    ///
    /// The takeover and the restart's lineage arm build one: each passes the pairs recorded for the other hosts as
    /// `admitted`, against a volume record read after the Report, and issues the value only after its own
    /// acknowledged shard-record write and a shard read that still names its tenure (`NoPreemptOfForeignKey`). [`held_by_recorded`] is the hold sites'
    /// test over the same checks; it builds a value only to test it and issues none.
    ///
    /// # Errors
    ///
    /// The first [`HolderRefusal`] in variant order.
    pub(crate) fn resolve<'r>(
        report: &Report<'_>,
        recorded: impl IntoIterator<Item = &'r Pair> + Clone,
        admitted: impl IntoIterator<Item = &'r Pair>,
        own: Pair,
        bounds: &Bounds,
    ) -> Result<Self, HolderRefusal> {
        let census = report.census(own, |pair| {
            recorded.clone().into_iter().any(|held| held == pair)
        });
        Self::resolve_counted(report, &census, admitted, own, bounds)
    }

    /// [`LineagePreempt::resolve`] over `census`, a census of `report` the caller built: the value names the holder's
    /// key when the Report shows a type-2 reservation held by one pair other than `own` that `census` admits and
    /// `admitted` lists, at most one record carries the own host ID, and `census` holds no unknown registrant. The
    /// takeover reaches it through `resolve`, whose census admits the pairs the takeover passes as `recorded`: the
    /// recorded pairs and the non-holding registrants under an ended attach's key (`VolumeRecord::admitted`). The
    /// restart's lineage arm calls it with a census that admits the same two classes and passes the pairs recorded
    /// for the other hosts as `admitted`, so the preempted key is a recorded pair of another host.
    ///
    /// # Errors
    ///
    /// The first [`HolderRefusal`] in variant order.
    pub(crate) fn resolve_counted<'r>(
        report: &Report<'_>,
        census: &Census,
        admitted: impl IntoIterator<Item = &'r Pair>,
        own: Pair,
        bounds: &Bounds,
    ) -> Result<Self, HolderRefusal> {
        let holder = match report.holding_of(census, own, bounds) {
            Holding::One(holder) if report.rtype == ReservationType::ExclusiveAccess => holder,
            _ => return Err(HolderRefusal::Unresolved),
        };
        if holder == own {
            return Err(HolderRefusal::Own);
        }
        // The one holder is another pair, so the census holds it with the caller's admission of it.
        if !census.foreign.is_some_and(|(_, recorded)| recorded) {
            return Err(HolderRefusal::Unrecorded);
        }
        if !admitted.into_iter().any(|pair| *pair == holder) {
            return Err(HolderRefusal::NotAdmitted);
        }
        own_record(census).map_err(|error| HolderRefusal::Registrants(error.refusal()))?;
        if census.unknown {
            return Err(HolderRefusal::Registrants(NotSole::ForeignRegistrant));
        }
        Ok(Self {
            own,
            preempted: holder.key,
        })
    }

    pub fn pair(self) -> Pair {
        self.own
    }

    /// The key the preempt names as PRKEY.
    pub fn preempted(self) -> Key {
        self.preempted
    }
}

/// The owner's ended-attach Preempt: the own pair, the one holder, removing the registration of `ended`, the key of
/// an ended attach. Only [`EndedPreempt::resolve`] builds one (ENDED-PREEMPT). Its issuer is the serving owner past
/// its fencing boundary, on a poll whose verdict continues, against a Report and a volume record read after that
/// Report; the issuer condition is the caller's precondition, and the constructor reads the Report and the record
/// alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndedPreempt {
    own: Pair,
    ended: Key,
}

/// Why [`EndedPreempt::resolve`] refused to name a key, in check order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndedRefusal {
    /// The Report does not show the own pair as the sole holder of a type-2 reservation under a conclusive count:
    /// another pair holds, alone or beside it, several pairs hold, nobody holds, the Report shows no reservation or
    /// another type, or the count is inconclusive. A registrant under the target key that holds refuses here.
    NotSoleHolder,
    /// More than one record carries the own host ID, or one carries it under another key.
    OwnRecord,
    /// The target is the own key.
    Own,
    /// No registrant of the Report carries the target key.
    Unregistered,
    /// The target key belongs to an attach that is not ended: a recorded pair of the volume record that pins no
    /// ended entry carries it (the pair of a live attach, or of a format-2 attach whose host a later detach or force
    /// detach marks), whether or not the Report lists that pair, or KEY-PER-ATTACH derives it for a live attach,
    /// enrolled or not, or for a number at or past `next`.
    Live,
    /// A registrant under the target key is neither a recorded pair of an ended entry nor a pair the volume record
    /// classes [`Registration::Ended`].
    Unknown,
}

/// The census of the entries for `own` that admits every pair, when `report` shows `own` as the sole holder of a
/// type-2 reservation under `bounds`: the hold test of [`SelfPreempt::from_report`] and [`EndedPreempt::resolve`],
/// which each check the own record over the census it returns.
fn holds_alone(report: &Report<'_>, bounds: &Bounds, own: Pair) -> Option<Census> {
    let census = report.census(own, |_| true);
    (report.holding_of(&census, own, bounds) == Holding::One(own)
        && report.rtype == ReservationType::ExclusiveAccess)
        .then_some(census)
}

impl EndedPreempt {
    /// The preempt of `ended` by `own` when `report` shows `own` as the sole holder of a type-2 reservation with one
    /// own record, as [`SelfPreempt::from_report`] requires, so no other registrant holds, `ended` is another key,
    /// and `ended` passes [`EndedPreempt::target`] against `volume`, a volume record read after the Report. The value
    /// never names the holder's key, the own key or a key that a recorded pair of a live attach carries
    /// (EndedPreemptSparesLiveAttach).
    ///
    /// # Errors
    ///
    /// The first [`EndedRefusal`] in variant order.
    pub(crate) fn resolve(
        report: &Report<'_>,
        volume: &VolumeRecord,
        ended: Key,
        own: Pair,
        bounds: &Bounds,
    ) -> Result<Self, EndedRefusal> {
        let census = holds_alone(report, bounds, own).ok_or(EndedRefusal::NotSoleHolder)?;
        own_record(&census).map_err(|_| EndedRefusal::OwnRecord)?;
        if ended == own.key {
            return Err(EndedRefusal::Own);
        }
        Self::target(report, volume, ended)?;
        Ok(Self { own, ended })
    }

    /// ENDED-PREEMPT's target test, which [`EndedPreempt::resolve`] and `poll::reclaim` share: no registrant of
    /// `report` under `ended` holds, some registrant carries it, no recorded pair of `volume` that pins no ended
    /// entry carries it ([`VolumeRecord::carries_unended`]), KEY-PER-ATTACH gives it to no live attach and to no
    /// number at or past `next` ([`VolumeRecord::derives_unended`]), and `volume` ties every registrant under it to an ended
    /// entry: a recorded pair of an ended entry or a pair it classes [`Registration::Ended`]. The refusals keep
    /// variant order whatever the order of the Report's entries.
    ///
    /// # Errors
    ///
    /// `NotSoleHolder`, `Unregistered`, `Live` or `Unknown`, the first in variant order.
    pub(crate) fn target(
        report: &Report<'_>,
        volume: &VolumeRecord,
        ended: Key,
    ) -> Result<(), EndedRefusal> {
        let under = || {
            report
                .entries
                .iter()
                .filter(move |entry| entry.pair.key == ended)
        };
        if under().any(|entry| entry.holder) {
            return Err(EndedRefusal::NotSoleHolder);
        }
        if under().next().is_none() {
            return Err(EndedRefusal::Unregistered);
        }
        if volume.carries_unended(ended) || volume.derives_unended(ended) {
            return Err(EndedRefusal::Live);
        }
        // With no unended recorded pair under `ended`, a registrant the record holds pins an ended entry.
        if under().any(|entry| volume.registrant(&entry.pair) == Registration::Unknown) {
            return Err(EndedRefusal::Unknown);
        }
        Ok(())
    }

    pub fn pair(self) -> Pair {
        self.own
    }

    /// The key the preempt names as PRKEY.
    pub fn ended(self) -> Key {
        self.ended
    }
}

/// RECORDED-HOLDER-HOLD's holder test: a pair of `holders` other than `own` is the one type-2 holder, at most one
/// record carries the own host ID, under the own key, and every other registrant is `own` or admitted: the checks of
/// [`LineagePreempt::resolve`] over `census`, the census of `report` for `own` that admits the caller's registrant
/// set. The poll and the restart admit the pairs of a volume record read after the Report and pass them as `holders`.
/// The serving authority admits its last volume-record read with its deferred pairs and passes that read as
/// `holders`, and its owner's later polls judge the holder again (POST-WITHDRAWAL-POLL).
pub(crate) fn held_by_recorded<'r>(
    report: &Report<'_>,
    census: &Census,
    holders: impl IntoIterator<Item = &'r Pair>,
    own: Pair,
    bounds: &Bounds,
) -> bool {
    LineagePreempt::resolve_counted(report, census, holders, own, bounds).is_ok()
}

/// NO-HOLDER-HOLD's test: nobody holds the reservation, at most one record carries the own host ID, under the own key,
/// and every registrant is `own` or admitted by `census`, the census of `report` for `own`. The restart admits the
/// pairs of its reread volume record. The owner poll admits the pairs of its volume record, or every pair when that
/// record is unread. The serving authority admits its last volume-record read with its deferred pairs, or after the
/// fencing boundary with no recorded set no pair. A registration that ended without a preempt, a reservation never
/// acquired and an unregistering self preempt leave this state; none shows volume loss.
pub(crate) fn unheld_among_recorded(
    report: &Report<'_>,
    census: &Census,
    own: Pair,
    bounds: &Bounds,
) -> bool {
    report.holding_of(census, own, bounds) == Holding::Nobody
        && own_record(census).is_ok()
        && !census.unknown
}

/// The data transfer length of a Register, Acquire, Preempt or Preempt-and-Abort: the current and the new or
/// preempted key.
pub(crate) const KEY_DATA_BYTES: u32 = 16;

impl ReservationCommand {
    pub(crate) fn is_report(self) -> bool {
        matches!(self, Self::Report { .. })
    }
    pub(crate) fn len(self, limits: ReservationLimits) -> u32 {
        if self.is_report() {
            limits.report_bytes()
        } else {
            KEY_DATA_BYTES
        }
    }
    pub(crate) fn encode(self, bytes: &mut [u8]) {
        let (current, next) = match self {
            Self::Register { new } => (0, new.encode()),
            Self::Acquire { current } => (current.encode(), 0),
            Self::PreemptAndAbort(own) => {
                let key = own.own.key.encode();
                (key, key)
            }
            Self::PreemptLineage(lineage) => (lineage.own.key.encode(), lineage.preempted.encode()),
            Self::PreemptEnded(ended) => (ended.own.key.encode(), ended.ended.encode()),
            Self::Report { .. } => return,
        };
        bytes[..8].copy_from_slice(&current.to_le_bytes());
        bytes[8..16].copy_from_slice(&next.to_le_bytes());
    }
}

/// A bounded Report failed structural or identity validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportError {
    /// The header or declared controller entries exceed the available bytes.
    Truncated,
    /// An EXHID has a width other than 16 bytes.
    ExhidLength,
    /// A key or EXHID violates the ownership identity codec.
    Identity(IdentityError),
    /// One key appears under different EXHIDs.
    DuplicateKey,
    /// More than one record carries the own host ID: an alias attachment shares it.
    DuplicateOwnHostId { records: u32 },
    /// The record with the own host ID carries a key other than the volume's.
    OwnHostIdKey,
    /// A reservation type other than None (0) or Exclusive Access (2).
    ReservationType(u8),
    /// The header exceeds the configured registrant bound; entries establish nothing.
    Inconclusive { regctl: u32 },
    /// The caller's entry array is shorter than REGCTL.
    OutputShort,
    /// Report entries require identity validation before use as identity evidence.
    Unchecked,
}

impl ReportError {
    /// The sole-registrant refusal a withheld Report's parse refusal establishes, for the attach gate and the poll
    /// alike. The own pair's key and EXHID follow the ownership identity codec and one key names one EXHID, so an
    /// entry that violates the codec or shares its key with another entry registers a foreign pair:
    /// [`NotSole::ForeignRegistrant`]. A header count above the registrant bound, which is at least one, counts a
    /// second registrant: [`NotSole::Excess`]. A second record with the own host ID, or the own host ID under another
    /// key, is an alias of the own attachment: [`NotSole::DuplicateOwnRecord`]. A length, width or validation refusal
    /// is [`NotSole::Unreadable`].
    pub fn refusal(self) -> NotSole {
        match self {
            Self::ReservationType(_) => NotSole::ReservationType,
            Self::DuplicateOwnHostId { .. } | Self::OwnHostIdKey => NotSole::DuplicateOwnRecord,
            Self::DuplicateKey | Self::Identity(_) => NotSole::ForeignRegistrant,
            Self::Inconclusive { .. } => NotSole::Excess,
            Self::Truncated | Self::ExhidLength | Self::OutputShort | Self::Unchecked => {
                NotSole::Unreadable
            }
        }
    }
}

/// Counts the own record among a Report's header-less `entries`, a whole number of 64-byte controller rows, by
/// host ID and key. The controller ID carries no per-attachment identity, so the count never reads it. `Ok` also
/// covers a Report with no record carrying the own host ID, which is legal before Register; presence and
/// holdership are the caller's checks.
///
/// # Errors
///
/// `Truncated` when `entries` ends in a partial row, `DuplicateOwnHostId` when more than one row carries
/// `own.exhid`, and `OwnHostIdKey` when the one such row carries a key other than `own.key`.
pub fn check_own_record(entries: &[u8], own: Pair) -> Result<(), ReportError> {
    let (rows, rest) = entries.as_chunks::<64>();
    if !rest.is_empty() {
        return Err(ReportError::Truncated);
    }
    let key = own.key.encode().to_le_bytes();
    let mut own_rows = rows.iter().filter(|row| row[16..32] == own.exhid.bytes());
    let Some(first) = own_rows.next() else {
        return Ok(());
    };
    one_keyed(1 + own_rows.count() as u32, first[8..16] == key)
}

/// Own-record errors within the bounded row prefix take precedence over an excessive registrant count.
///
/// # Errors
///
/// `Truncated` when `bytes` lacks the 64-byte header or `min(count, limits.registrants())` 64-byte rows, the errors
/// of [`check_own_record`], and `Inconclusive` when the header's count exceeds `limits.registrants()`.
pub(crate) fn check_report_identity(
    bytes: &[u8],
    limits: ReservationLimits,
    own: Pair,
) -> Result<(), ReportError> {
    let header = bytes.get(..64).ok_or(ReportError::Truncated)?;
    let count = usize::from(u16::from_le_bytes([header[5], header[6]]));
    let bound = limits.registrants() as usize;
    let entries = bytes
        .get(64..64 + count.min(bound) * 64)
        .ok_or(ReportError::Truncated)?;
    check_own_record(entries, own)?;
    if count > bound {
        return Err(ReportError::Inconclusive {
            regctl: count as u32,
        });
    }
    Ok(())
}

/// The own-record count of [`check_own_record`] read from `census`, the census of parsed records for the own pair.
/// `Ok` covers a Report with no record carrying the own host ID.
///
/// # Errors
///
/// `DuplicateOwnHostId` when more than one record carries the own host ID, and `OwnHostIdKey` when the one such
/// record carries a key other than the own key.
pub(crate) fn own_record(census: &Census) -> Result<(), ReportError> {
    if census.own_host == 0 {
        return Ok(());
    }
    one_keyed(census.own_host, !census.rekeyed)
}

/// The own-record rule over `records`, at least one record carrying the own host ID: more than one is an alias of
/// the own attachment, and `keyed` says whether the one record carries the own key.
fn one_keyed(records: u32, keyed: bool) -> Result<(), ReportError> {
    if records > 1 {
        return Err(ReportError::DuplicateOwnHostId { records });
    }
    if !keyed {
        return Err(ReportError::OwnHostIdKey);
    }
    Ok(())
}

/// `report_exhid` decodes a 16-byte Report EXHID field into an [`Exhid`].
///
/// # Errors
///
/// `report_exhid` returns `ExhidLength` for lengths other than 16 bytes and `Identity(ExhidZero)` for 16 zero bytes.
pub fn report_exhid(bytes: &[u8]) -> Result<Exhid, ReportError> {
    let bytes = bytes.try_into().map_err(|_| ReportError::ExhidLength)?;
    Exhid::new(bytes).map_err(ReportError::Identity)
}

/// Decodes the CTRATT-qualified extended layout: a 64-byte header and 64-byte controller entries, into caller-preallocated entries. `submitted_at` is the caller's pre-submission clock sample, copied into the Report. A successful certified Report completion is required before these bytes can certify evidence.
/// Entries are bounded by `limits`; a refused parse grants no evidence, even if it wrote a prefix of `entries`.
/// An accepted Report lists its entries in ascending `Key` order; entries that share a key appear in unspecified
/// relative order.
pub fn parse_extended_report<'a>(
    bytes: &[u8],
    limits: ReservationLimits,
    submitted_at: u64,
    entries: &'a mut [Registrant],
) -> Result<Report<'a>, ReportError> {
    if bytes.len() < 64 {
        return Err(ReportError::Truncated);
    }
    let regctl = u32::from(u16::from_le_bytes([bytes[5], bytes[6]]));
    if regctl > limits.registrants() {
        return Err(ReportError::Inconclusive { regctl });
    }
    let count = regctl as usize;
    if bytes.len() < 64 + count * 64 {
        return Err(ReportError::Truncated);
    }
    if entries.len() < count {
        return Err(ReportError::OutputShort);
    }
    let rtype = match bytes[4] {
        0 => ReservationType::None,
        2 => ReservationType::ExclusiveAccess,
        value => return Err(ReportError::ReservationType(value)),
    };
    let entries = &mut entries[..count];
    let (devices, _) = bytes[64..64 + count * 64].as_chunks::<64>();
    // Whether every row's key is at or above the key of the row before it. Key order is the order of the encoded
    // value.
    let (mut ordered, mut last) = (true, 0);
    for (entry, device) in entries.iter_mut().zip(devices) {
        let raw = u64::from_le_bytes(device[8..16].try_into().expect("eight key bytes"));
        let key = Key::decode(raw).map_err(ReportError::Identity)?;
        ordered &= last <= raw;
        last = raw;
        let exhid: [u8; 16] = device[16..32].try_into().expect("sixteen EXHID bytes");
        if exhid == [0; 16] {
            return Err(ReportError::Identity(IdentityError::ExhidZero));
        }
        let exhid = Exhid::new(exhid).map_err(ReportError::Identity)?;
        *entry = Registrant {
            cntlid: u16::from_le_bytes([device[0], device[1]]),
            holder: device[2] & 1 != 0,
            pair: Pair { exhid, key },
        };
    }
    // Key order makes each key's entries contiguous, so a key under two EXHIDs leaves an adjacent pair with equal
    // keys and different EXHIDs. Rows that arrive out of key order are sorted into it.
    if !ordered {
        entries.sort_unstable_by_key(|entry| entry.pair.key);
    }
    if entries.windows(2).any(|pair| {
        pair[0].pair.key == pair[1].pair.key && pair[0].pair.exhid != pair[1].pair.exhid
    }) {
        return Err(ReportError::DuplicateKey);
    }
    Ok(Report {
        submitted_at,
        rtype,
        regctl,
        entries,
    })
}
