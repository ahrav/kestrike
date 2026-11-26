//! Row admissibility: `malformed_field` returns the first field that is
//! empty or inconsistent with the row's kind.
//!
//! A missing required field, a durable fact on a kind other than
//! `Persistence`, an outcome outside the kind's family, a lookup hit with an
//! empty label, a lookup hit or expiry without a whole-second clock sample,
//! live evidence on a recovery evidence kind, qualified evidence on a kind
//! other than a recovery evidence kind or a lookup, qualified evidence
//! without a profile or boundary or naming its own command as a
//! predecessor, a frozen identity on a row that is not an exclusion fact,
//! a qualified exclusion fact without a frozen identity, or ordinals out of
//! invocation, response and custody-end order each make the row malformed.
//! A hit and an expiry carry the sample that decided them; every other
//! lookup outcome may leave the clock empty. A terminal carries its real
//! result or a drop. A take or release of an incarnated resource names its
//! incarnation, a resource release names its custodian, and an isolated
//! checkpoint names the resource it retains. A terminal or write submit
//! names a command. Remote PUT facts follow [`malformed_put_field`].

use super::action::ActionKind;
use super::attempt::{Open, Receipt, Serial, malformed_put_field};
use super::clients::Acceptance;
use super::coverage::Cover;
use super::custody::{Checkpoint, Custodian};
use super::evidence::{Decision, DurableFact, Evidence};
use super::ids::{
    ClientId, ClockSample, CutId, Episode, Incarnation, KeyId, Label, OpId, Ordinal, ResourceId,
    ResourceKind, SessionId, Subject, Tenure,
};
use super::outcome::{NoInformation, Outcome, VisibilityCause};
use super::tenure::Place;
use super::verdict::Inconclusive;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Row {
    pub(crate) op: OpId,
    pub(crate) kind: ActionKind,
    pub(crate) evidence: Evidence,
    pub(crate) subject: Option<Subject>,
    pub(crate) candidate_key: Option<KeyId>,
    pub(crate) label: Option<Label>,
    pub(crate) metadata_len: Option<u32>,
    pub(crate) body_len: Option<u64>,
    pub(crate) payload: Option<Vec<u8>>,
    pub(crate) session: Option<SessionId>,
    pub(crate) incarnation: Option<Incarnation>,
    pub(crate) episode: Option<Episode>,
    pub(crate) invoked: Option<Ordinal>,
    pub(crate) responded: Option<Ordinal>,
    pub(crate) custody_end: Option<Ordinal>,
    pub(crate) outcome: Option<Outcome>,
    pub(crate) clock: Option<ClockSample>,
    pub(crate) deadline: Option<u64>,
    pub(crate) cause: Option<VisibilityCause>,
    pub(crate) report: Option<Report>,
    pub(crate) fact: Option<DurableFact>,
    pub(crate) unresolved: Option<Decision>,
    pub(crate) custodian: Option<Custodian>,
    pub(crate) checkpoint: Option<Checkpoint>,
    /// The writable extent's start and length in units.
    pub(crate) span: Option<(u64, u64)>,
    /// The key whose label visibility a resource release ends.
    pub(crate) owner: Option<KeyId>,
    /// The upload attempt's serial, once the owner's authority named it.
    pub(crate) serial: Option<Serial>,
    /// The fragment index a validated fragment or a source slot holds.
    pub(crate) fragment: Option<u32>,
    pub(crate) receipt: Option<Receipt>,
    /// The fragment count the owner admits: fragments below it may be sent.
    pub(crate) grant: Option<u32>,
    /// The facts a pending or `Unknown` attempt leaves unresolved.
    pub(crate) open: Open,
    /// The frozen identity of the binding a recovery-safe exclusion fact
    /// excludes.
    pub(crate) frozen: Option<u64>,
    /// The device-boundary evidence of a write submission or completion: each captured write command of the attempt and its delivered terminal.
    pub(crate) commands: Option<Vec<super::command::CommandEvidence>>,
    /// The tenure tag of a completed response; on a `Restart`, the tenure it
    /// activates.
    pub(crate) tenure: Option<Tenure>,
    /// Where a request's effect lands: the tenure its session was bound to
    /// when it was sent, or the client's high-water at send as a floor.
    pub(crate) target: Option<Place>,
    /// The client instance that sent the request; a row without one is the
    /// owner's.
    pub(crate) client: Option<ClientId>,
    /// The client's high-water at receipt and whether it accepted the
    /// response.
    pub(crate) acceptance: Option<Acceptance>,
    /// The client-supplied version a publication carries, monotone per key.
    pub(crate) version: Option<u64>,
    /// The versions an invalidation names; `None` names every label present
    /// at its linearization point.
    pub(crate) covers: Option<Cover>,
    /// The retained cut an activation recovers from, a restore names, or a
    /// capture belongs to.
    pub(crate) cut: Option<CutId>,
    /// A captured entry's row unit and payload unit.
    pub(crate) captured_units: Option<(u32, u32)>,
    /// The unit a damage row names; `None` names the whole volume.
    pub(crate) damaged_unit: Option<u32>,
}

impl Row {
    pub(crate) fn malformed_field(&self) -> Option<Field> {
        if let Some(&missing) = self.kind.required().iter().find(|&&f| !self.has(f)) {
            return Some(missing);
        }
        if self.fact.is_some() && !self.kind.required().contains(&Field::Fact) {
            return Some(Field::Fact);
        }
        let exclusion = self.fact == Some(DurableFact::RecoveryExclusion);
        if self.frozen.is_some() && !exclusion {
            return Some(Field::Frozen);
        }
        if exclusion && self.frozen.is_none() && matches!(self.evidence, Evidence::Qualified(_)) {
            return Some(Field::Frozen);
        }
        if self.kind.requires_recovery_evidence() && !self.evidence.is_recovery() {
            return Some(Field::Evidence);
        }
        if let Evidence::Qualified(qualified) = self.evidence
            && (!qualified.well_formed()
                || !(self.kind.requires_recovery_evidence() || self.kind == ActionKind::Lookup))
        {
            return Some(Field::Evidence);
        }
        if let Some(outcome) = self.outcome {
            let family = outcome.family();
            if family.is_some() && family != self.kind.outcome_family() {
                return Some(Field::Outcome);
            }
            if let Outcome::NoInformation(member) = outcome
                && !self.kind.admits_no_information(member)
            {
                return Some(Field::Outcome);
            }
            if matches!(
                outcome,
                Outcome::Hit
                    | Outcome::Expired
                    | Outcome::NoInformation(NoInformation::ClockUnavailable)
            ) && self.label.is_none()
            {
                return Some(Field::Label);
            }
            if outcome == Outcome::NoInformation(NoInformation::ClockUnavailable)
                && self.clock != Some(ClockSample::Unavailable)
            {
                return Some(Field::Clock);
            }
        }
        if self.decided_by_clock() && !matches!(self.clock, Some(ClockSample::Seconds(_))) {
            return Some(Field::Clock);
        }
        if matches!(self.kind, ActionKind::Terminal | ActionKind::WriteSubmit)
            && self
                .resource()
                .is_some_and(|r| r.kind != ResourceKind::Command)
        {
            return Some(Field::Resource);
        }
        if self.kind == ActionKind::Release
            && self
                .resource()
                .is_some_and(|r| r.kind == ResourceKind::Command)
        {
            return Some(Field::Resource);
        }
        if let (Some(resource), Some(report)) = (self.resource(), self.report)
            && !report.kind.measures(resource.kind)
        {
            return Some(Field::Report);
        }
        if let Some((start, len)) = self.span
            && (self.resource().is_none_or(|r| !r.kind.spanned())
                || start.checked_add(len).is_none()
                || (self.resource().is_some_and(|r| {
                    matches!(r.kind, ResourceKind::Extent | ResourceKind::WriteQuota)
                }) && len == 0))
        {
            return Some(Field::Resource);
        }
        if self.owner.is_some() && self.resource().is_none_or(|r| r.kind != ResourceKind::Slot) {
            return Some(Field::Resource);
        }
        if self.checkpoint == Some(Checkpoint::Isolated)
            && self.resource().is_none_or(|r| r.kind.client_buffer())
        {
            return Some(Field::Resource);
        }
        if (matches!(self.kind, ActionKind::Release | ActionKind::Take)
            || self.checkpoint == Some(Checkpoint::Isolated))
            && self.resource().is_some_and(|r| r.kind.incarnated())
            && self.incarnation.is_none()
        {
            return Some(Field::Incarnation);
        }
        if self.incarnation.is_some() && self.resource().is_some_and(|r| !r.kind.incarnated()) {
            return Some(Field::Incarnation);
        }
        if self.kind == ActionKind::Release && self.resource().is_some() && self.custodian.is_none()
        {
            return Some(Field::Custodian);
        }
        if self.kind == ActionKind::Receive
            && self.outcome.is_some()
            && self.payload.as_ref().is_some_and(|bytes| !bytes.is_empty())
        {
            return Some(Field::Payload);
        }
        if let Some(field) = malformed_put_field(self) {
            return Some(field);
        }
        if let Some(field) = self.malformed_tenure_field() {
            return Some(field);
        }
        if let (Some(invoked), Some(responded)) = (self.invoked, self.responded)
            && responded < invoked
        {
            return Some(Field::Response);
        }
        if let (Some(responded), Some(custody_end)) = (self.responded, self.custody_end)
            && custody_end <= responded
        {
            return Some(Field::CustodyEnd);
        }
        None
    }

    /// The tenure-order fields each sit on the kinds that carry them, a
    /// client's answer carries its tenure tag and the client's acceptance,
    /// and an acceptance names the client and the tag it judged and belongs
    /// only to an answer; a `Restart` activates a tenure.
    fn malformed_tenure_field(&self) -> Option<Field> {
        let request = matches!(
            self.kind,
            ActionKind::Fill
                | ActionKind::Publish
                | ActionKind::Replace
                | ActionKind::Invalidate
                | ActionKind::Lookup
        );
        if self.target.is_some() && !request {
            return Some(Field::Target);
        }
        if self.acceptance.is_some() && (self.client.is_none() || self.kind == ActionKind::Restart)
        {
            return Some(Field::Acceptance);
        }
        if self.version.is_some() && !matches!(self.kind, ActionKind::Publish | ActionKind::Replace)
        {
            return Some(Field::Version);
        }
        if let Some(cover) = self.covers
            && (self.kind != ActionKind::Invalidate
                || matches!(cover, Cover::Range { lo, hi } if lo > hi))
        {
            return Some(Field::Covers);
        }
        if self.cut.is_some()
            && !matches!(
                self.kind,
                ActionKind::Restart | ActionKind::Restore | ActionKind::Captured
            )
        {
            return Some(Field::Cut);
        }
        if self.captured_units.is_some() && self.kind != ActionKind::Captured {
            return Some(Field::CapturedUnits);
        }
        if self.damaged_unit.is_some() && self.kind != ActionKind::Damaged {
            return Some(Field::DamagedUnit);
        }
        if self.client.is_some() && self.outcome.is_some_and(Outcome::is_answer) {
            if self.tenure.is_none() {
                return Some(Field::Tenure);
            }
            if self.acceptance.is_none() {
                return Some(Field::Acceptance);
            }
        }
        if self.acceptance.is_some()
            && (self.tenure.is_none() || !self.outcome.is_some_and(Outcome::is_answer))
        {
            return Some(Field::Acceptance);
        }
        None
    }

    pub(crate) fn ordinals(&self) -> impl Iterator<Item = (Field, Ordinal)> {
        [
            (Field::Invocation, self.invoked),
            (Field::Response, self.responded),
            (Field::CustodyEnd, self.custody_end),
        ]
        .into_iter()
        .filter_map(|(field, ordinal)| ordinal.map(|o| (field, o)))
    }

    pub(crate) const fn new(op: OpId, kind: ActionKind) -> Self {
        Self {
            op,
            kind,
            evidence: Evidence::Live,
            subject: None,
            candidate_key: None,
            label: None,
            metadata_len: None,
            body_len: None,
            payload: None,
            session: None,
            incarnation: None,
            episode: None,
            invoked: None,
            responded: None,
            custody_end: None,
            outcome: None,
            clock: None,
            deadline: None,
            cause: None,
            report: None,
            fact: None,
            unresolved: None,
            custodian: None,
            checkpoint: None,
            span: None,
            owner: None,
            serial: None,
            fragment: None,
            receipt: None,
            grant: None,
            open: Open::Settled,
            frozen: None,
            commands: None,
            tenure: None,
            target: None,
            client: None,
            acceptance: None,
            version: None,
            covers: None,
            cut: None,
            captured_units: None,
            damaged_unit: None,
        }
    }

    pub(crate) const fn key(&self) -> Option<KeyId> {
        match self.subject {
            Some(Subject::Key(key)) => Some(key),
            _ => None,
        }
    }

    pub(crate) fn interval(&self) -> (u32, u32) {
        let response = self.responded.map_or(0, |o| o.0);
        let end = if self.pending_effect() {
            self.custody_end.map_or(u32::MAX, |o| o.0)
        } else {
            response
        };
        (self.invoked.map_or(response, |o| o.0), end)
    }

    /// Whether a fact row records its event: it carries no outcome or an
    /// informative one. A row whose outcome carries no information records
    /// nothing, so no judgment counts it as a removal, restore, capture,
    /// damage or activation.
    pub(crate) fn records_event(&self) -> bool {
        self.outcome.is_none_or(Outcome::carries_information)
    }

    pub(crate) fn pending_effect(&self) -> bool {
        matches!(
            self.kind,
            ActionKind::Publish | ActionKind::Replace | ActionKind::Invalidate
        ) && matches!(
            self.outcome,
            Some(Outcome::NoInformation(
                super::outcome::NoInformation::Cancelled | super::outcome::NoInformation::TimedOut
            ))
        )
    }

    /// An `Evict`, or a visibility end caused by eviction.
    pub(crate) fn is_logical_eviction(&self) -> bool {
        self.kind == ActionKind::Evict
            || (self.kind == ActionKind::VisibilityEnded
                && self.cause == Some(VisibilityCause::Eviction))
    }

    pub(crate) fn may_land(&self) -> bool {
        self.pending_effect() && self.clock != Some(ClockSample::Unavailable)
    }

    pub(crate) fn acquired_key(&self) -> Option<KeyId> {
        match (self.candidate_key, self.outcome) {
            (Some(key), Some(Outcome::Hit | Outcome::Expired)) => Some(key),
            _ => self.key(),
        }
    }

    pub(crate) const fn resource(&self) -> Option<ResourceId> {
        match self.subject {
            Some(Subject::Resource(resource)) => Some(resource),
            _ => None,
        }
    }

    /// Whether this delivery was refused before the read took over its
    /// lease, which the refusal returned whole; a cancelled, timed-out or
    /// dropped read had already consumed it.
    pub(crate) const fn refused_read(&self) -> bool {
        use super::outcome::NoInformation::{Cancelled, Dropped, TimedOut};
        matches!(self.kind, ActionKind::Deliver)
            && matches!(
                self.outcome,
                Some(Outcome::NoInformation(member)) if !matches!(member, Cancelled | TimedOut | Dropped)
            )
    }

    /// The whole-second clock sample this row took, when its action samples
    /// the clock and the sample was available.
    pub(crate) const fn sample(&self) -> Option<u64> {
        match self.clock {
            Some(ClockSample::Seconds(seconds)) if self.samples_clock() => Some(seconds),
            _ => None,
        }
    }

    /// Whether this action samples the cache's clock: lookups, expiries and
    /// publications consume a sample; other rows carry none.
    pub(crate) const fn samples_clock(&self) -> bool {
        matches!(
            self.kind,
            ActionKind::Lookup | ActionKind::Expire | ActionKind::Publish | ActionKind::Replace
        )
    }

    /// Whether the row's clock sample was compared against a deadline.
    pub(crate) const fn decided_by_clock(&self) -> bool {
        matches!(self.kind, ActionKind::Expire)
            || matches!(self.outcome, Some(Outcome::Hit | Outcome::Expired))
    }

    const fn has(&self, field: Field) -> bool {
        match field {
            Field::Key => self.key().is_some(),
            Field::Resource => self.resource().is_some(),
            Field::Subject => self.subject.is_some(),
            Field::Label => self.label.is_some(),
            Field::MetadataLength => self.metadata_len.is_some(),
            Field::BodyLength => self.body_len.is_some(),
            Field::Payload => self.payload.is_some(),
            Field::Session => self.session.is_some(),
            Field::Invocation => self.invoked.is_some(),
            Field::Response => self.responded.is_some(),
            Field::CustodyEnd => self.custody_end.is_some(),
            Field::Outcome => self.outcome.is_some(),
            Field::Clock => self.clock.is_some(),
            Field::Cause => self.cause.is_some(),
            Field::Report => self.report.is_some(),
            Field::Fact => self.fact.is_some(),
            Field::Episode => self.episode.is_some(),
            Field::Incarnation => self.incarnation.is_some(),
            Field::Custodian => self.custodian.is_some(),
            Field::Checkpoint => self.checkpoint.is_some(),
            Field::Serial => self.serial.is_some(),
            Field::Fragment => self.fragment.is_some(),
            Field::Receipt => self.receipt.is_some(),
            Field::Grant => self.grant.is_some(),
            Field::Frozen => self.frozen.is_some(),
            Field::Tenure => self.tenure.is_some(),
            Field::Target => self.target.is_some(),
            Field::Acceptance => self.acceptance.is_some(),
            Field::Version => self.version.is_some(),
            Field::Covers => self.covers.is_some(),
            Field::Cut => self.cut.is_some(),
            Field::CapturedUnits => self.captured_units.is_some(),
            Field::DamagedUnit => self.damaged_unit.is_some(),
            Field::Evidence | Field::Open => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Field {
    Key,
    Resource,
    Subject,
    Label,
    MetadataLength,
    BodyLength,
    Payload,
    Session,
    Invocation,
    Response,
    CustodyEnd,
    Outcome,
    Clock,
    Cause,
    Report,
    Fact,
    Episode,
    Incarnation,
    Custodian,
    Checkpoint,
    Evidence,
    Serial,
    Fragment,
    Receipt,
    Grant,
    /// The open facts a row declares.
    Open,
    /// The frozen identity an exclusion fact names.
    Frozen,
    Tenure,
    Target,
    Acceptance,
    Version,
    Covers,
    Cut,
    CapturedUnits,
    DamagedUnit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ReportKind {
    Pool,
    Table,
    Ledger,
    EngineBudget,
    RequestShares,
    RetainedChunks,
    WriteProgress,
    Mismatched,
}

impl ReportKind {
    pub(crate) const fn measures(self, resource: ResourceKind) -> bool {
        match self {
            Self::Pool => matches!(resource, ResourceKind::Buffer),
            Self::Table => matches!(resource, ResourceKind::Command),
            Self::Ledger => matches!(
                resource,
                ResourceKind::Slot | ResourceKind::Extent | ResourceKind::Credit
            ),
            Self::EngineBudget => matches!(resource, ResourceKind::BudgetCharge),
            Self::RequestShares => matches!(resource, ResourceKind::RequestShare),
            Self::RetainedChunks => matches!(resource, ResourceKind::RetainedChunk),
            Self::WriteProgress => matches!(resource, ResourceKind::WriteQuota),
            Self::Mismatched => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ReportState {
    Value(u64),
    Poisoned,
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Report {
    pub(crate) kind: ReportKind,
    pub(crate) state: ReportState,
}

impl Report {
    pub(crate) const fn rejection(self, op: OpId) -> Option<Inconclusive> {
        match self.state {
            ReportState::Value(_) => None,
            ReportState::Poisoned => Some(Inconclusive::PoisonedReport {
                op,
                report: self.kind,
            }),
            ReportState::Absent => Some(Inconclusive::AbsentReport {
                op,
                report: self.kind,
            }),
        }
    }
}
