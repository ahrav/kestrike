//! Live adapters and hand-written custody histories share this row builder.

use super::action::ActionKind;
use super::attempt::{Open, PutOutcome, Receipt, Serial};
use super::command::CommandEvidence;
use super::content::expected_bytes;
use super::custody::{Checkpoint, Custodian};
use super::history::History;
use super::ids::{
    ClockSample, Episode, Incarnation, KeyId, Label, OpId, Ordinal, ResourceId, ResourceKind,
    SessionId, Subject,
};
use super::outcome::{Outcome, VisibilityCause};
use super::row::{Report, ReportKind, ReportState, Row};

pub(crate) struct Recorder {
    history: History,
    next_op: u32,
    episode: Episode,
}

impl Recorder {
    pub(crate) fn new(episode: u16) -> Self {
        Self {
            history: History::new(),
            next_op: 1,
            episode: Episode(u64::from(episode)),
        }
    }

    fn op(&mut self) -> OpId {
        let op = OpId(self.next_op);
        self.next_op += 1;
        op
    }

    pub(crate) fn finish(mut self) -> History {
        self.history.seal();
        self.history
    }

    pub(crate) fn unsealed(self) -> History {
        self.history
    }

    pub(crate) fn rows(&self) -> &[Row] {
        self.history.rows()
    }

    pub(crate) fn rebuilt(rows: impl IntoIterator<Item = Row>) -> History {
        let mut history = History::new();
        for row in rows {
            history.push(row);
        }
        history.seal();
        history
    }

    pub(crate) fn renumber(rows: &mut [Row]) {
        let mut next = 0;
        let mut tick = |at: &mut Option<Ordinal>| {
            if at.is_some() {
                next += 1;
                *at = Some(Ordinal(next));
            }
        };
        for row in rows {
            tick(&mut row.invoked);
            tick(&mut row.responded);
            tick(&mut row.custody_end);
        }
    }

    fn base(&self, op: OpId, kind: ActionKind, subject: Subject) -> Row {
        let mut row = Row::new(op, kind);
        row.subject = Some(subject);
        row.episode = Some(self.episode);
        row
    }

    fn push_at_once(&mut self, mut row: Row) -> OpId {
        row.responded = Some(self.history.tick());
        let op = row.op;
        self.history.push(row);
        op
    }

    fn push_span(&mut self, mut row: Row) -> OpId {
        row.invoked = Some(self.history.tick());
        row.responded = Some(self.history.tick());
        let op = row.op;
        self.history.push(row);
        op
    }

    pub(crate) fn content(key: KeyId, label: Label, metadata: u32, body: u64) -> Vec<u8> {
        expected_bytes(key, label, metadata as usize + body as usize)
    }

    /// Records an admitted fill, its received bytes, its write completion
    /// and its publication under the content's session and allocation
    /// `identity`.
    pub(crate) fn published(
        &mut self,
        key: KeyId,
        label: Label,
        metadata: u32,
        body: u64,
        identity: (u64, u64),
    ) -> OpId {
        let payload = Self::content(key, label, metadata, body);
        self.published_bytes(key, label, metadata, &payload, identity)
    }

    pub(crate) fn published_bytes(
        &mut self,
        key: KeyId,
        label: Label,
        metadata: u32,
        payload: &[u8],
        identity: (u64, u64),
    ) -> OpId {
        self.published_written(key, label, metadata, payload, identity, None)
    }

    /// [`published_bytes`](Self::published_bytes) for a fill a live device
    /// wrote: the write completion carries the device's `commands`, each
    /// with its delivered terminal. Without them the rows state an object
    /// placed before the episode's device opened.
    pub(crate) fn published_written(
        &mut self,
        key: KeyId,
        label: Label,
        metadata: u32,
        payload: &[u8],
        (session, incarnation): (u64, u64),
        commands: Option<Vec<CommandEvidence>>,
    ) -> OpId {
        let body = payload.len() as u64 - u64::from(metadata);
        let op = self.op();
        let mut fill = self.base(op, ActionKind::Fill, Subject::Key(key));
        fill.label = Some(label);
        fill.metadata_len = Some(metadata);
        fill.body_len = Some(body);
        fill.session = Some(SessionId(session));
        fill.incarnation = Some(Incarnation(incarnation));
        fill.outcome = Some(Outcome::Acknowledged);
        self.push_span(fill);
        let mut receive = self.base(op, ActionKind::Receive, Subject::Key(key));
        receive.label = Some(label);
        receive.payload = Some(payload.to_vec());
        self.push_span(receive);
        let mut written = self.base(op, ActionKind::WriteCompleted, Subject::Key(key));
        written.label = Some(label);
        written.commands = commands;
        self.push_at_once(written);
        let mut publish = self.base(op, ActionKind::Publish, Subject::Key(key));
        publish.label = Some(label);
        publish.outcome = Some(Outcome::Acknowledged);
        self.push_span(publish)
    }

    pub(crate) fn lookup(&mut self, key: KeyId, outcome: Outcome, label: Option<Label>) -> OpId {
        let clock =
            matches!(outcome, Outcome::Hit | Outcome::Expired).then_some(ClockSample::Seconds(1));
        self.lookup_at(key, outcome, label, clock)
    }

    pub(crate) fn lookup_at(
        &mut self,
        key: KeyId,
        outcome: Outcome,
        label: Option<Label>,
        clock: Option<ClockSample>,
    ) -> OpId {
        let op = self.op();
        let mut row = self.base(op, ActionKind::Lookup, Subject::Key(key));
        row.label = label;
        row.outcome = Some(outcome);
        row.clock = clock;
        self.push_span(row)
    }

    pub(crate) fn invalidate(&mut self, key: KeyId, outcome: Outcome) -> OpId {
        let op = self.op();
        let mut row = self.base(op, ActionKind::Invalidate, Subject::Key(key));
        row.outcome = Some(outcome);
        self.push_span(row)
    }

    /// Records an owner-wide close, a row with no key or resource subject.
    pub(crate) fn close(&mut self, outcome: Outcome) -> OpId {
        let op = self.op();
        let mut row = Row::new(op, ActionKind::Close);
        row.episode = Some(self.episode);
        row.outcome = Some(outcome);
        self.push_span(row)
    }

    pub(crate) fn delivered(
        &mut self,
        op: OpId,
        (key, label): (KeyId, Label),
        (metadata, body): (u32, u64),
        (session, incarnation): (u64, u64),
        outcome: Outcome,
        payload: Vec<u8>,
    ) {
        let mut row = self.base(op, ActionKind::Deliver, Subject::Key(key));
        row.label = Some(label);
        row.metadata_len = Some(metadata);
        row.body_len = Some(body);
        row.session = Some(SessionId(session));
        row.incarnation = Some(Incarnation(incarnation));
        row.outcome = Some(outcome);
        row.payload = Some(payload);
        row.invoked = Some(self.history.tick());
        row.responded = Some(self.history.tick());
        row.custody_end = Some(self.history.tick());
        self.history.push(row);
        let mut release = self.base(op, ActionKind::Release, Subject::Key(key));
        release.label = Some(label);
        self.push_at_once(release);
    }

    fn resource(kind: ResourceKind, index: u32) -> Subject {
        Subject::Resource(ResourceId { kind, index })
    }

    pub(crate) fn take(
        &mut self,
        resource: (ResourceKind, u32, u64),
        custodian: Custodian,
        span: Option<(u64, u64)>,
    ) -> OpId {
        let row = self.taking(resource, custodian);
        self.push_at_once(Row { span, ..row })
    }

    /// Records a slot take that binds the slot to the publication it holds.
    pub(crate) fn hold(
        &mut self,
        slot: (ResourceKind, u32, u64),
        custodian: Custodian,
        (key, label): (KeyId, Label),
    ) -> OpId {
        let row = self.taking(slot, custodian);
        self.push_at_once(Row {
            owner: Some(key),
            label: Some(label),
            ..row
        })
    }

    fn taking(
        &mut self,
        (kind, index, incarnation): (ResourceKind, u32, u64),
        custodian: Custodian,
    ) -> Row {
        let op = self.op();
        let mut row = self.base(op, ActionKind::Take, Self::resource(kind, index));
        row.incarnation = kind.incarnated().then_some(Incarnation(incarnation));
        row.custodian = Some(custodian);
        row
    }

    pub(crate) fn release(
        &mut self,
        (kind, index, incarnation): (ResourceKind, u32, u64),
        custodian: Custodian,
    ) -> OpId {
        let op = self.op();
        let mut row = self.base(op, ActionKind::Release, Self::resource(kind, index));
        row.incarnation = kind.incarnated().then_some(Incarnation(incarnation));
        row.custodian = Some(custodian);
        self.push_at_once(row)
    }

    pub(crate) fn end_visibility(
        &mut self,
        (kind, index, incarnation): (ResourceKind, u32, u64),
        custodian: Custodian,
        (key, label): (KeyId, Label),
        cause: VisibilityCause,
    ) -> OpId {
        let op = self.op();
        let mut row = self.base(op, ActionKind::Release, Self::resource(kind, index));
        row.incarnation = kind.incarnated().then_some(Incarnation(incarnation));
        row.custodian = Some(custodian);
        row.owner = Some(key);
        row.label = Some(label);
        row.cause = Some(cause);
        self.push_at_once(row)
    }

    pub(crate) fn cancel(&mut self, (kind, index, incarnation): (ResourceKind, u32, u64)) -> OpId {
        let op = self.op();
        let mut row = self.base(op, ActionKind::Cancel, Self::resource(kind, index));
        row.incarnation = Some(Incarnation(incarnation));
        self.push_span(row)
    }

    pub(crate) fn terminal(
        &mut self,
        (kind, index, incarnation): (ResourceKind, u32, u64),
        outcome: Outcome,
    ) -> OpId {
        let op = self.op();
        let mut row = self.base(op, ActionKind::Terminal, Self::resource(kind, index));
        row.incarnation = Some(Incarnation(incarnation));
        row.outcome = Some(outcome);
        self.push_at_once(row)
    }

    pub(crate) fn report(
        &mut self,
        kind: ResourceKind,
        report: ReportKind,
        state: ReportState,
    ) -> OpId {
        let op = self.op();
        let mut row = self.base(op, ActionKind::Report, Self::resource(kind, 0));
        row.report = Some(Report {
            kind: report,
            state,
        });
        self.push_at_once(row)
    }

    pub(crate) fn checkpoint(&mut self, checkpoint: Checkpoint) -> OpId {
        let op = self.op();
        let mut row = Row::new(op, ActionKind::Checkpoint);
        row.episode = Some(self.episode);
        row.checkpoint = Some(checkpoint);
        self.push_at_once(row)
    }

    /// Records the failed owner's stop retaining `resource`; one row per
    /// resource the failed owner holds.
    pub(crate) fn isolated(
        &mut self,
        (kind, index, incarnation): (ResourceKind, u32, u64),
    ) -> OpId {
        let op = self.op();
        let mut row = self.base(op, ActionKind::Checkpoint, Self::resource(kind, index));
        row.incarnation = kind.incarnated().then_some(Incarnation(incarnation));
        row.checkpoint = Some(Checkpoint::Isolated);
        self.push_at_once(row)
    }

    /// Records a client's remote PUT of `label` and returns the attempt's
    /// operation, which every later row of the attempt shares.
    pub(crate) fn put_begin(&mut self, key: KeyId, label: Label, metadata: u32, body: u64) -> OpId {
        let op = self.op();
        let mut row = self.base(op, ActionKind::PutBegin, Subject::Key(key));
        row.label = Some(label);
        row.metadata_len = Some(metadata);
        row.body_len = Some(body);
        self.push_span(row);
        op
    }

    /// Records the owner's admitted fill of attempt `op` under `serial` for
    /// the manifest `(metadata, body)`. A live adapter records it as the
    /// client first holds the authority the fill precedes.
    pub(crate) fn owner_fill(
        &mut self,
        op: OpId,
        (key, label): (KeyId, Label),
        (metadata, body): (u32, u64),
        ((session, incarnation), serial): ((u64, u64), Serial),
    ) {
        let mut fill = self.base(op, ActionKind::Fill, Subject::Key(key));
        fill.label = Some(label);
        fill.metadata_len = Some(metadata);
        fill.body_len = Some(body);
        fill.session = Some(SessionId(session));
        fill.incarnation = Some(Incarnation(incarnation));
        fill.outcome = Some(Outcome::Acknowledged);
        fill.serial = Some(serial);
        self.push_span(fill);
    }

    /// Records the owner's validated receipt of attempt `op`'s next
    /// fragment, in fragment order, with the bytes the client sent for it,
    /// under `serial`.
    pub(crate) fn owner_received(
        &mut self,
        op: OpId,
        (key, label): (KeyId, Label),
        payload: &[u8],
        serial: Serial,
    ) {
        let mut receive = self.base(op, ActionKind::Receive, Subject::Key(key));
        receive.label = Some(label);
        receive.payload = Some(payload.to_vec());
        receive.serial = Some(serial);
        self.push_span(receive);
    }

    /// Records the write commands the device accepted for attempt `op`
    /// under `serial`, each with the terminal it delivered, as one write
    /// completion row.
    pub(crate) fn owner_written(
        &mut self,
        op: OpId,
        (key, label): (KeyId, Label),
        serial: Serial,
        commands: Vec<CommandEvidence>,
    ) {
        let mut written = self.base(op, ActionKind::WriteCompleted, Subject::Key(key));
        written.label = Some(label);
        written.serial = Some(serial);
        written.commands = Some(commands);
        self.push_at_once(written);
    }

    /// Records the owner's observed publication of attempt `op` under
    /// `serial`.
    pub(crate) fn owner_publish(&mut self, op: OpId, (key, label): (KeyId, Label), serial: Serial) {
        let mut publish = self.base(op, ActionKind::Publish, Subject::Key(key));
        publish.label = Some(label);
        publish.outcome = Some(Outcome::Acknowledged);
        publish.serial = Some(serial);
        self.push_span(publish);
    }

    /// Records the owner's authority for attempt `op`, naming `serial`, as
    /// the client first holds it.
    pub(crate) fn put_authority(&mut self, op: OpId, key: KeyId, serial: Serial) {
        let mut row = self.base(op, ActionKind::Authority, Subject::Key(key));
        row.serial = Some(serial);
        self.push_at_once(row);
    }

    /// Records the owner's READY for attempt `op` as the client first holds
    /// its grant.
    pub(crate) fn put_ready(
        &mut self,
        op: OpId,
        (key, label): (KeyId, Label),
        (metadata, body): (u32, u64),
        serial: Serial,
        grant: u32,
    ) {
        let mut row = self.base(op, ActionKind::Ready, Subject::Key(key));
        row.label = Some(label);
        row.metadata_len = Some(metadata);
        row.body_len = Some(body);
        row.serial = Some(serial);
        row.grant = Some(grant);
        self.push_at_once(row);
    }

    /// Records the owner's validation of fragment `index` of attempt `op`,
    /// carrying `payload`.
    pub(crate) fn put_fragment(
        &mut self,
        op: OpId,
        key: KeyId,
        serial: Serial,
        index: u32,
        payload: &[u8],
    ) {
        let mut row = self.base(op, ActionKind::Fragment, Subject::Key(key));
        row.serial = Some(serial);
        row.fragment = Some(index);
        row.payload = Some(payload.to_vec());
        self.push_at_once(row);
    }

    /// Records the cumulative receipt and grant the client holds for
    /// attempt `op`.
    pub(crate) fn put_receipt(
        &mut self,
        op: OpId,
        key: KeyId,
        serial: Serial,
        (base, grant): (u32, u32),
    ) {
        let mut row = self.base(op, ActionKind::Ack, Subject::Key(key));
        row.serial = Some(serial);
        row.receipt = Some(Receipt { base, mask: 0 });
        row.grant = Some(grant);
        self.push_at_once(row);
    }

    /// Records the client's `outcome` for attempt `op`; `Published` names
    /// `label` and every outcome but `NotStarted` names `serial`.
    pub(crate) fn put_result(
        &mut self,
        op: OpId,
        (key, label): (KeyId, Label),
        serial: Option<Serial>,
        outcome: PutOutcome,
    ) {
        let mut row = self.base(op, ActionKind::PutResult, Subject::Key(key));
        row.outcome = Some(Outcome::Put(outcome));
        if outcome != PutOutcome::NotStarted {
            row.serial = serial;
        }
        match outcome {
            PutOutcome::Published => row.label = Some(label),
            PutOutcome::Unknown => row.open = Open::Publication,
            PutOutcome::Failed(_) | PutOutcome::NotStarted => {}
        }
        self.push_at_once(row);
    }

    /// Records a take, release or cancel (`kind`) of client source slot
    /// `slot` at `incarnation` by `custodian` for attempt `op`'s `fragment`;
    /// a cancel names neither custodian nor fragment, and both arguments are
    /// ignored.
    pub(crate) fn source(
        &mut self,
        op: OpId,
        kind: ActionKind,
        custodian: Custodian,
        (slot, incarnation): (u32, u64),
        fragment: u32,
    ) {
        let mut row = self.base(op, kind, Self::resource(ResourceKind::SourceSlot, slot));
        row.incarnation = Some(Incarnation(incarnation));
        if kind == ActionKind::Cancel {
            row.invoked = Some(self.history.tick());
        } else {
            row.custodian = Some(custodian);
            row.fragment = Some(fragment);
        }
        self.push_at_once(row);
    }
}
