//! A builder that writes golden histories with ordinals from one counter.

use std::collections::HashMap;

use super::action::ActionKind;
use super::attempt::{FRAGMENT_BYTES, Open as Pending, PutOutcome, Receipt, Serial};
use super::clients::Acceptance;
use super::content::expected_bytes;
use super::coverage::Cover;
use super::custody::{Checkpoint, Custodian};
use super::evidence::{Decision, DurableFact, Evidence};
use super::history::History;
use super::ids::{
    ClientId, ClockSample, CutId, Episode, Incarnation, KeyId, Label, OpId, ResourceId,
    ResourceKind, SessionId, Subject, Tenure,
};
use super::outcome::{NoInformation, Outcome, VisibilityCause};
use super::row::Row;
use super::tenure::Place;

pub(crate) const META: u32 = 8;
pub(crate) const SESSION: SessionId = SessionId(1);
pub(crate) const INCARNATION: Incarnation = Incarnation(1);

pub(crate) struct Open(Row);

impl Open {
    pub(crate) fn set_candidate(&mut self, owner: KeyId) {
        self.0.candidate_key = Some(owner);
    }

    pub(crate) fn set_evidence(&mut self, evidence: impl Into<Evidence>) {
        self.0.evidence = evidence.into();
    }

    pub(crate) fn set_deadline(&mut self, seconds: u64) {
        self.0.deadline = Some(seconds);
    }

    pub(crate) fn set_clock(&mut self, clock: ClockSample) {
        self.0.clock = Some(clock);
    }

    pub(crate) fn set_serial(&mut self, serial: Option<Serial>) {
        self.0.serial = serial;
    }

    pub(crate) fn set_target(&mut self, target: Place) {
        self.0.target = Some(target);
    }

    pub(crate) fn set_version(&mut self, version: u64) {
        self.0.version = Some(version);
    }

    pub(crate) fn set_covers(&mut self, covers: Cover) {
        self.0.covers = Some(covers);
    }
}

/// `tenure` and `client` stamp every row the script records from the call
/// that set them; each client's answer row records its acceptance against
/// `high_water`, the highest high-water any of that client's rows recorded,
/// raised to each tag it accepted. The client accepts
/// every answer except the one [`Script::reject_next`] names, and
/// [`Script::observe_next`] records a live client's report instead.
#[derive(Clone)]
pub(crate) struct Script {
    history: History,
    next_op: u32,
    tenure: Option<Tenure>,
    client: Option<ClientId>,
    high_water: HashMap<ClientId, Tenure>,
    reject: bool,
    uninformed: bool,
    observed: Option<Acceptance>,
}

impl Script {
    pub(crate) fn new() -> Self {
        Self {
            history: History::new(),
            next_op: 1,
            tenure: None,
            client: None,
            high_water: HashMap::new(),
            reject: false,
            uninformed: false,
            observed: None,
        }
    }

    pub(crate) fn finish(mut self) -> History {
        self.history.seal();
        self.history
    }

    fn fresh(&mut self) -> OpId {
        let op = OpId(self.next_op);
        self.next_op += 1;
        op
    }

    fn row(op: OpId, kind: ActionKind, key: KeyId, label: Option<Label>) -> Row {
        let mut row = Row::new(op, kind);
        row.subject = Some(Subject::Key(key));
        row.label = label;
        row.episode = Some(Episode(1));
        row
    }

    /// Tags every later row with `tenure`; `None` leaves owner rows to the
    /// tenure active at their invocation.
    pub(crate) fn in_tenure(&mut self, tenure: Option<Tenure>) {
        self.tenure = tenure;
    }

    /// Records every later row as `client`'s; `None` records owner rows.
    pub(crate) fn by_client(&mut self, client: Option<ClientId>) {
        self.client = client;
    }

    /// Stamps the current tenure and client on every row but a `Restart`,
    /// which names the tenure it activates and belongs to no client.
    fn stamp(&self, row: &mut Row) {
        if row.kind != ActionKind::Restart {
            row.tenure = row.tenure.or(self.tenure);
            row.client = row.client.or(self.client);
        }
    }

    /// The next row recorded carries a contended outcome, which carries no
    /// information, in place of the one its builder sets.
    pub(crate) fn without_information_next(&mut self) {
        self.uninformed = true;
    }

    /// The current client rejects its next tagged answer, which leaves its
    /// high-water unchanged.
    pub(crate) fn reject_next(&mut self) {
        self.reject = true;
    }

    /// The next tagged answer a client receives records `observed`, the
    /// high-water and the decision a live client reported, in place of the
    /// script's own.
    pub(crate) fn observe_next(&mut self, observed: Acceptance) {
        self.observed = Some(observed);
    }

    /// Stamps `row` and records a client's acceptance or rejection of a
    /// tagged answer. The client's high-water keeps the highest one any of
    /// its rows recorded, and an acceptance raises it to the answer's tag.
    fn push(&mut self, mut row: Row) {
        self.stamp(&mut row);
        if std::mem::take(&mut self.uninformed) {
            row.outcome = Some(Outcome::NoInformation(NoInformation::Contended));
        }
        let answered = row.outcome.is_some_and(Outcome::is_answer);
        if let (Some(client), Some(tenure), true) = (row.client, row.tenure, answered) {
            let scripted = Acceptance {
                high_water: self.high_water.get(&client).copied(),
                accepted: !std::mem::take(&mut self.reject),
            };
            let acceptance = self.observed.take().unwrap_or(scripted);
            row.acceptance = Some(acceptance);
            let accepted = acceptance.accepted.then_some(tenure);
            let kept = scripted.high_water.max(acceptance.high_water).max(accepted);
            if let Some(kept) = kept {
                self.high_water.insert(client, kept);
            }
        }
        self.history.push(row);
    }

    fn instant(&mut self, mut row: Row) {
        row.responded = Some(self.history.tick());
        self.push(row);
    }

    pub(crate) fn open(
        &mut self,
        op: OpId,
        kind: ActionKind,
        key: KeyId,
        label: Option<Label>,
    ) -> Open {
        let mut row = Self::row(op, kind, key, label);
        self.stamp(&mut row);
        row.invoked = Some(self.history.tick());
        Open(row)
    }

    pub(crate) fn close(&mut self, open: Open, outcome: Option<Outcome>) -> OpId {
        let Open(mut row) = open;
        row.responded = Some(self.history.tick());
        row.outcome = outcome;
        let op = row.op;
        self.push(row);
        op
    }

    /// Closes `open` with `outcome` and ends its custody at the next
    /// ordinal, where a cancelled or timed-out effect's landing window ends.
    pub(crate) fn close_custody(&mut self, open: Open, outcome: Outcome) -> OpId {
        let Open(mut row) = open;
        row.responded = Some(self.history.tick());
        row.custody_end = Some(self.history.tick());
        row.outcome = Some(outcome);
        let op = row.op;
        self.push(row);
        op
    }

    /// An admitted fill's row and its received bytes under `serial`; the
    /// caller records the write completion.
    fn fill_rows(
        &mut self,
        op: OpId,
        key: KeyId,
        label: Label,
        (metadata, body): (u32, u64),
        serial: Option<Serial>,
    ) {
        let mut open = self.open(op, ActionKind::Fill, key, Some(label));
        open.0.metadata_len = Some(metadata);
        open.0.body_len = Some(body);
        open.0.session = Some(SESSION);
        open.0.incarnation = Some(INCARNATION);
        open.0.serial = serial;
        self.close(open, Some(Outcome::Acknowledged));
        let mut receive = self.open(op, ActionKind::Receive, key, Some(label));
        receive.0.serial = serial;
        receive.0.payload = Some(expected_bytes(
            key,
            label,
            metadata as usize + body as usize,
        ));
        self.close(receive, None);
    }

    fn written(&mut self, op: OpId, key: KeyId, label: Label, serial: Option<Serial>) {
        let mut done = Self::row(op, ActionKind::WriteCompleted, key, Some(label));
        done.serial = serial;
        self.instant(done);
    }

    /// A fill of `label` invoked now and answered when the caller closes it.
    pub(crate) fn begin_fill(&mut self, key: KeyId, label: Label, body: u64) -> Open {
        let op = self.fresh();
        let mut open = self.open(op, ActionKind::Fill, key, Some(label));
        open.0.metadata_len = Some(META);
        open.0.body_len = Some(body);
        open.0.session = Some(SESSION);
        open.0.incarnation = Some(INCARNATION);
        open
    }

    pub(crate) fn fill(&mut self, key: KeyId, label: Label, body: u64) -> OpId {
        let op = self.fresh();
        self.fill_rows(op, key, label, (META, body), None);
        self.written(op, key, label, None);
        op
    }

    pub(crate) fn begin_publish(
        &mut self,
        key: KeyId,
        label: Label,
        body: u64,
        deadline: Option<u64>,
    ) -> Open {
        let op = self.fill(key, label, body);
        let mut open = self.open(op, ActionKind::Publish, key, Some(label));
        open.0.deadline = deadline;
        open
    }

    pub(crate) fn publish(&mut self, key: KeyId, label: Label, body: u64) -> OpId {
        let open = self.begin_publish(key, label, body, None);
        self.close(open, Some(Outcome::Acknowledged))
    }

    pub(crate) fn begin_replace(&mut self, key: KeyId, label: Label, body: u64) -> Open {
        let op = self.fill(key, label, body);
        self.open(op, ActionKind::Replace, key, Some(label))
    }

    pub(crate) fn begin_lookup(&mut self, key: KeyId, clock: ClockSample) -> Open {
        let op = self.fresh();
        let mut open = self.open(op, ActionKind::Lookup, key, None);
        open.0.clock = Some(clock);
        open
    }

    pub(crate) fn end_lookup(
        &mut self,
        mut open: Open,
        outcome: Outcome,
        label: Option<Label>,
    ) -> OpId {
        open.0.label = label;
        self.close(open, Some(outcome))
    }

    pub(crate) fn clock_unavailable(&mut self, mut open: Open, label: Label) -> OpId {
        open.0.label = Some(label);
        open.0.clock = Some(ClockSample::Unavailable);
        self.close(
            open,
            Some(Outcome::NoInformation(NoInformation::ClockUnavailable)),
        )
    }

    /// A lookup that decided by the clock records the fixture's sample at
    /// second one; any other lookup records no sample.
    fn sampled_lookup(&mut self, key: KeyId, outcome: Outcome) -> Open {
        let mut open = self.begin_lookup(key, ClockSample::Seconds(1));
        if !matches!(outcome, Outcome::Hit | Outcome::Expired) {
            open.0.clock = None;
        }
        open
    }

    pub(crate) fn lookup(&mut self, key: KeyId, outcome: Outcome, label: Option<Label>) -> OpId {
        let open = self.sampled_lookup(key, outcome);
        self.end_lookup(open, outcome, label)
    }

    pub(crate) fn candidate_lookup(
        &mut self,
        key: KeyId,
        owner: KeyId,
        outcome: Outcome,
        label: Option<Label>,
    ) -> OpId {
        let mut open = self.sampled_lookup(key, outcome);
        open.0.candidate_key = Some(owner);
        self.end_lookup(open, outcome, label)
    }

    pub(crate) fn publish_replacing(&mut self, key: KeyId, label: Label, body: u64) -> OpId {
        let open = self.begin_replace(key, label, body);
        self.close(open, Some(Outcome::Acknowledged))
    }

    pub(crate) fn publish_sized(&mut self, key: KeyId, label: Label, metadata: u32, body: u64) {
        let op = self.fresh();
        self.fill_rows(op, key, label, (metadata, body), None);
        self.written(op, key, label, None);
        let publish = self.open(op, ActionKind::Publish, key, Some(label));
        self.close(publish, Some(Outcome::Acknowledged));
    }

    pub(crate) fn evict(&mut self, key: KeyId, label: Label) {
        let op = self.fresh();
        self.instant(Self::row(op, ActionKind::Evict, key, Some(label)));
    }

    pub(crate) fn begin_invalidate(&mut self, key: KeyId) -> Open {
        let op = self.fresh();
        self.open(op, ActionKind::Invalidate, key, None)
    }

    pub(crate) fn invalidate(&mut self, key: KeyId, outcome: Outcome) -> OpId {
        let open = self.begin_invalidate(key);
        self.close(open, Some(outcome))
    }

    pub(crate) fn deliver(
        &mut self,
        op: OpId,
        key: KeyId,
        label: Label,
        body: u64,
        outcome: Outcome,
        payload: Vec<u8>,
    ) {
        self.deliver_sized(op, key, label, (META, body), outcome, payload);
    }

    pub(crate) fn deliver_sized(
        &mut self,
        op: OpId,
        key: KeyId,
        label: Label,
        (metadata, body): (u32, u64),
        outcome: Outcome,
        payload: Vec<u8>,
    ) {
        let mut row = Self::row(op, ActionKind::Deliver, key, Some(label));
        row.metadata_len = Some(metadata);
        row.body_len = Some(body);
        row.session = Some(SESSION);
        row.incarnation = Some(INCARNATION);
        row.payload = Some(payload);
        row.outcome = Some(outcome);
        row.invoked = Some(self.history.tick());
        row.responded = Some(self.history.tick());
        row.custody_end = Some(self.history.tick());
        self.push(row);
        self.instant(Self::row(op, ActionKind::Release, key, Some(label)));
    }

    pub(crate) fn close_cache(&mut self, outcome: Outcome) -> OpId {
        let op = self.fresh();
        let mut row = Row::new(op, ActionKind::Close);
        row.episode = Some(Episode(1));
        row.invoked = Some(self.history.tick());
        self.close(Open(row), Some(outcome))
    }

    pub(crate) fn session_change(&mut self, session: SessionId) {
        let op = self.fresh();
        let mut row = Row::new(op, ActionKind::SessionChange);
        row.session = Some(session);
        row.episode = Some(Episode(1));
        self.instant(row);
    }

    pub(crate) fn release_key(&mut self, op: OpId, key: KeyId) {
        self.instant(Self::row(op, ActionKind::Release, key, None));
    }

    pub(crate) fn release_resource(&mut self, op: OpId, resource: ResourceId) {
        let mut row = Row::new(op, ActionKind::Release);
        row.subject = Some(Subject::Resource(resource));
        row.incarnation = Some(Incarnation(1));
        row.custodian = Some(super::custody::Custodian::Reader);
        row.episode = Some(Episode(1));
        self.instant(row);
    }

    /// Storage's take of slot `index` holding `label`'s publication.
    pub(crate) fn hold_slot(&mut self, index: u32, held: (KeyId, Label)) {
        let row = Self::slot_row(self.fresh(), ActionKind::Take, index, held);
        self.instant(row);
    }

    /// Storage's release of slot `index`, ending `label`'s visibility by
    /// `cause`.
    pub(crate) fn end_slot_visibility(
        &mut self,
        index: u32,
        held: (KeyId, Label),
        cause: VisibilityCause,
    ) {
        let mut row = Self::slot_row(self.fresh(), ActionKind::Release, index, held);
        row.cause = Some(cause);
        self.instant(row);
    }

    /// Storage's row of `kind` on slot `index` holding `label` of `key`.
    fn slot_row(op: OpId, kind: ActionKind, index: u32, (key, label): (KeyId, Label)) -> Row {
        let mut row = Row::new(op, kind);
        row.subject = Some(Subject::Resource(ResourceId {
            kind: ResourceKind::Slot,
            index,
        }));
        row.incarnation = Some(Incarnation(1));
        row.custodian = Some(Custodian::Storage);
        row.episode = Some(Episode(1));
        row.owner = Some(key);
        row.label = Some(label);
        row
    }

    pub(crate) fn ended(&mut self, key: KeyId, label: Label, cause: VisibilityCause) {
        let op = self.fresh();
        let mut row = Self::row(op, ActionKind::VisibilityEnded, key, Some(label));
        row.cause = Some(cause);
        self.instant(row);
    }

    pub(crate) fn expire(&mut self, key: KeyId, label: Label, seconds: u64) {
        let op = self.fresh();
        let mut row = Self::row(op, ActionKind::Expire, key, Some(label));
        row.clock = Some(ClockSample::Seconds(seconds));
        self.instant(row);
    }

    fn evidence(
        &mut self,
        kind: ActionKind,
        evidence: impl Into<Evidence>,
        key: KeyId,
        label: Option<Label>,
    ) -> Row {
        let op = self.fresh();
        let mut row = Self::row(op, kind, key, label);
        row.evidence = evidence.into();
        row
    }

    pub(crate) fn fact(
        &mut self,
        evidence: impl Into<Evidence>,
        key: KeyId,
        label: Label,
        fact: DurableFact,
    ) {
        let mut row = self.evidence(ActionKind::Persistence, evidence, key, Some(label));
        row.fact = Some(fact);
        self.instant(row);
    }

    /// Records a recovery-safe exclusion of `label` that names the excluded
    /// binding's frozen identity.
    pub(crate) fn exclusion(
        &mut self,
        evidence: impl Into<Evidence>,
        key: KeyId,
        label: Label,
        frozen: u64,
    ) {
        let mut row = self.evidence(ActionKind::Persistence, evidence, key, Some(label));
        row.fact = Some(DurableFact::RecoveryExclusion);
        row.frozen = Some(frozen);
        self.instant(row);
    }

    /// Records `fact` for `label` resting on the open `decision`.
    pub(crate) fn open_fact(
        &mut self,
        evidence: impl Into<Evidence>,
        (key, label): (KeyId, Label),
        fact: DurableFact,
        decision: Decision,
    ) {
        let mut row = self.evidence(ActionKind::Persistence, evidence, key, Some(label));
        row.fact = Some(fact);
        row.unresolved = Some(decision);
        self.instant(row);
    }

    pub(crate) fn admission(&mut self, evidence: impl Into<Evidence>, key: KeyId, label: Label) {
        let row = self.evidence(ActionKind::Admission, evidence, key, Some(label));
        self.instant(row);
    }

    pub(crate) fn restart(&mut self, evidence: impl Into<Evidence>, key: KeyId) {
        let row = self.evidence(ActionKind::Restart, evidence, key, None);
        self.instant(row);
    }

    /// A `Restart` activating `tenure`, or the next generation when `None`,
    /// from the retained `cut` when it names one.
    pub(crate) fn activate(
        &mut self,
        evidence: impl Into<Evidence>,
        tenure: Option<Tenure>,
        cut: Option<CutId>,
    ) -> OpId {
        let mut row = self.evidence(ActionKind::Restart, evidence, KeyId(0), None);
        row.subject = None;
        row.tenure = tenure;
        row.cut = cut;
        let op = row.op;
        self.instant(row);
        op
    }

    /// The current tenure's restore of `label` from `cut`.
    pub(crate) fn restore(&mut self, key: KeyId, label: Label, cut: CutId) -> OpId {
        let op = self.fresh();
        let mut row = Self::row(op, ActionKind::Restore, key, Some(label));
        row.cut = Some(cut);
        self.instant(row);
        op
    }

    /// `cut`'s capture of `label` in row unit and payload unit `units`.
    pub(crate) fn captured(
        &mut self,
        evidence: impl Into<Evidence>,
        (key, label): (KeyId, Label),
        cut: CutId,
        units: (u32, u32),
    ) -> OpId {
        let mut row = self.evidence(ActionKind::Captured, evidence, key, Some(label));
        row.cut = Some(cut);
        row.captured_units = Some(units);
        let op = row.op;
        self.instant(row);
        op
    }

    /// Damage found in `unit`, or in the whole volume when `None`.
    pub(crate) fn damaged(&mut self, evidence: impl Into<Evidence>, unit: Option<u32>) {
        let mut row = self.evidence(ActionKind::Damaged, evidence, KeyId(0), None);
        row.subject = None;
        row.damaged_unit = unit;
        self.instant(row);
    }

    pub(crate) fn recovered_lookup(
        &mut self,
        evidence: impl Into<Evidence>,
        key: KeyId,
        outcome: Outcome,
        label: Option<Label>,
    ) {
        let mut row = self.evidence(ActionKind::Lookup, evidence, key, label);
        row.clock = Some(ClockSample::Seconds(1));
        row.invoked = Some(self.history.tick());
        row.outcome = Some(outcome);
        self.instant(row);
    }

    fn serial(op: OpId) -> Option<Serial> {
        Serial::new(u64::from(op.0))
    }

    fn attempt_row(op: OpId, kind: ActionKind, key: KeyId) -> Row {
        let mut row = Self::row(op, kind, key, None);
        row.serial = Self::serial(op);
        row
    }

    /// A client's remote PUT of `label`, declaring its terminal and
    /// publication open at the cut when `pending`; the attempt's later rows
    /// take the returned operation, and its serial is the operation's
    /// number.
    pub(crate) fn put_begin(&mut self, key: KeyId, label: Label, body: u64, pending: bool) -> OpId {
        let op = self.fresh();
        let mut open = self.open(op, ActionKind::PutBegin, key, Some(label));
        open.0.metadata_len = Some(META);
        open.0.body_len = Some(body);
        if pending {
            open.0.open = Pending::Pending;
        }
        self.close(open, None)
    }

    /// A begun upload the owner admitted and filled before its authority,
    /// prepared and received in full, with its writes completed when
    /// `written`.
    pub(crate) fn upload(&mut self, key: KeyId, label: Label, body: u64, written: bool) -> OpId {
        let op = self.put_begin(key, label, body, false);
        self.owner_receives(op, key, label, body, written);
        op
    }

    /// The owner rows of `op`'s attempt: its fill before its authority, its
    /// READY, each fragment it validated, the ACK of its full receipt, and
    /// its write completion when `written`.
    pub(crate) fn owner_receives(
        &mut self,
        op: OpId,
        key: KeyId,
        label: Label,
        body: u64,
        written: bool,
    ) {
        let serial = Self::serial(op);
        self.fill_rows(op, key, label, (META, body), serial);
        self.authority(op, key);
        let fragments = (u64::from(META) + body).div_ceil(FRAGMENT_BYTES as u64) as u32;
        let mut ready = Self::attempt_row(op, ActionKind::Ready, key);
        ready.label = Some(label);
        ready.metadata_len = Some(META);
        ready.body_len = Some(body);
        ready.grant = Some(fragments);
        self.instant(ready);
        for index in 0..fragments {
            self.owner_fragment(op, key, index, u64::from(META) + body);
        }
        let mut ack = Self::attempt_row(op, ActionKind::Ack, key);
        ack.receipt = Some(Receipt {
            base: fragments,
            mask: 0,
        });
        ack.grant = Some(fragments);
        self.instant(ack);
        if written {
            self.written(op, key, label, serial);
        }
    }

    pub(crate) fn authority(&mut self, op: OpId, key: KeyId) {
        self.instant(Self::attempt_row(op, ActionKind::Authority, key));
    }

    /// The owner's fill of the attempt, its received bytes and its write
    /// completion, each naming the attempt's serial.
    pub(crate) fn owner_fill(&mut self, op: OpId, key: KeyId, label: Label, body: u64) {
        let serial = Self::serial(op);
        self.fill_rows(op, key, label, (META, body), serial);
        self.written(op, key, label, serial);
    }

    pub(crate) fn owner_publish(&mut self, op: OpId, key: KeyId, label: Label) {
        let mut open = self.open(op, ActionKind::Publish, key, Some(label));
        open.0.serial = Self::serial(op);
        self.close(open, Some(Outcome::Acknowledged));
    }

    /// The client's result; `Published` names the attempt's label and
    /// serial, `Unknown` the serial and its open publication, and
    /// `NotStarted` neither.
    pub(crate) fn put_result(&mut self, op: OpId, key: KeyId, label: Label, outcome: PutOutcome) {
        let mut row = Self::row(op, ActionKind::PutResult, key, None);
        row.outcome = Some(Outcome::Put(outcome));
        if outcome != PutOutcome::NotStarted {
            row.serial = Self::serial(op);
        }
        match outcome {
            PutOutcome::Published => row.label = Some(label),
            PutOutcome::Unknown => row.open = Pending::Publication,
            PutOutcome::NotStarted | PutOutcome::Failed(_) => {}
        }
        self.instant(row);
    }

    pub(crate) fn retry(&mut self, op: OpId, key: KeyId, body: u64, outcome: Outcome) {
        let mut row = Self::attempt_row(op, ActionKind::Retry, key);
        row.metadata_len = Some(META);
        row.body_len = Some(body);
        row.invoked = Some(self.history.tick());
        row.outcome = Some(outcome);
        self.instant(row);
    }

    pub(crate) fn abandon(&mut self, op: OpId, key: KeyId) {
        self.instant(Self::row(op, ActionKind::Abandon, key, None));
    }

    /// A take or release (`kind`) of client source slot `slot` at
    /// `incarnation` by `custodian`, holding the attempt's `fragment`.
    pub(crate) fn source(
        &mut self,
        op: OpId,
        kind: ActionKind,
        custodian: Custodian,
        (slot, incarnation): (u32, u64),
        fragment: u32,
    ) {
        let mut row = Row::new(op, kind);
        row.subject = Some(Subject::Resource(ResourceId {
            kind: ResourceKind::SourceSlot,
            index: slot,
        }));
        row.episode = Some(Episode(1));
        row.custodian = Some(custodian);
        row.incarnation = Some(Incarnation(incarnation));
        row.fragment = Some(fragment);
        self.instant(row);
    }

    /// The client's cancel of client source slot `slot`'s tenure
    /// `incarnation`.
    pub(crate) fn cancel_source(&mut self, op: OpId, (slot, incarnation): (u32, u64)) {
        let mut row = Row::new(op, ActionKind::Cancel);
        row.subject = Some(Subject::Resource(ResourceId {
            kind: ResourceKind::SourceSlot,
            index: slot,
        }));
        row.episode = Some(Episode(1));
        row.incarnation = Some(Incarnation(incarnation));
        row.invoked = Some(self.history.tick());
        self.instant(row);
    }

    /// The owner's validated fragment `index` of the attempt.
    pub(crate) fn owner_fragment(&mut self, op: OpId, key: KeyId, index: u32, total: u64) {
        let mut row = Self::attempt_row(op, ActionKind::Fragment, key);
        row.fragment = Some(index);
        let start = u64::from(index) * FRAGMENT_BYTES as u64;
        let len = total.saturating_sub(start).min(FRAGMENT_BYTES as u64) as usize;
        row.payload = Some(vec![0x5A; len]);
        self.instant(row);
    }

    /// The owner's READY for the attempt's manifest, granting every
    /// fragment.
    pub(crate) fn ready(&mut self, op: OpId, key: KeyId, label: Label, body: u64) {
        let mut ready = Self::attempt_row(op, ActionKind::Ready, key);
        ready.label = Some(label);
        ready.metadata_len = Some(META);
        ready.body_len = Some(body);
        ready.grant = Some((u64::from(META) + body).div_ceil(FRAGMENT_BYTES as u64) as u32);
        self.instant(ready);
    }

    /// A cumulative receipt the client received for the attempt.
    pub(crate) fn receipt(&mut self, op: OpId, key: KeyId, base: u32, mask: u64) {
        let mut row = Self::attempt_row(op, ActionKind::Ack, key);
        row.receipt = Some(Receipt { base, mask });
        row.grant = Some(base.max(2));
        self.instant(row);
    }

    pub(crate) fn checkpoint(&mut self, checkpoint: Checkpoint) {
        let op = self.fresh();
        let mut row = Row::new(op, ActionKind::Checkpoint);
        row.episode = Some(Episode(1));
        row.checkpoint = Some(checkpoint);
        self.instant(row);
    }
}
