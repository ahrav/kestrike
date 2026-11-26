//! A receipt covering every fragment moves the upload to
//! `Received`, which awaits PUT RESULT, the only reply that publishes; PUT PREPARE is resent on each
//! retry in `Received`, which is how a lost PUT RESULT is recovered.
//!
//! The scenario drives one upload core over a client namespace with no network: BEGIN, AUTHORITY, PREPARE
//! and READY, then the one fragment of an 8192-byte object is supplied and a PUT ACK whose receipt index
//! is the fragment count arrives at `RECEIPT_US`. From there each test plays a list of events, a tick and
//! a poll at a time or a PUT RESULT at a time, and records what each one showed: the kinds of the frames
//! the poll staged and the upload's outcome.
//!
//! - The RESULT is lost. The upload stays undecided, stages nothing before `RETRY_US` has passed since
//!   the receipt, then one PUT PREPARE at each retry interval. A RESULT that then arrives decides it
//!   `Published`, and a decided upload stages nothing more.
//! - The RESULT stays lost. The upload sends its first PREPARE and `ATTEMPTS` resends, one per interval,
//!   and only the retry after the last resend decides it `Unknown`.
//! - The RESULT arrives before the first retry. The upload is `Published` at once and never
//!   stages a PREPARE.
//!
//! Each test gathers its observations into plain values inside `played`, which drops the core, the
//! namespace and the arena before it returns, and asserts afterwards, so a failed check ends in libtest's
//! `FAILED` line.

use crate::storage::EngineBudget;
use crate::storage::owner_fixture::arena;

use super::client_namespace::ClientRequests;
use super::datagram::PeerId;
use super::fetch::Releases;
use super::frame::{Header, Kind};
use super::memory::sources;
use super::owner_tests::payload;
use super::requests::{RequestId, RequestTable};
use super::serve::{Manifest, header, manifest_header};
use super::session::{Admitted, Caps};
use super::upload::{SupplyRefused, UploadCore, UploadOutcome};
use super::upload_tests::ready_core;

/// The session `ready_core` admits its upload under.
const SESSION: Admitted = Admitted {
    peer: PeerId(0),
    epoch: 1,
    caps: Caps {
        slots: 4,
        window: 4,
    },
};

/// The retry interval and the resend budget of the core `ready_core` builds.
const RETRY_US: u64 = 1_000;
const ATTEMPTS: u64 = 3;
/// When the full receipt arrives; `ready_core` took READY at 30.
const RECEIPT_US: u64 = 200;
/// The upload's one fragment.
const OBJECT_LEN: usize = 8192;

/// One event after the full receipt.
#[derive(Debug, Clone, Copy)]
enum Event {
    /// A tick and a poll at this time.
    Turn(u64),
    /// A PUT RESULT received at this time.
    Result(u64),
}

/// What one event showed.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    /// The time of a tick and a poll, the kinds of the frames the poll staged, and the outcome after them.
    Turn(u64, Vec<Kind>, Option<UploadOutcome>),
    /// The time of a PUT RESULT, whether the core took it, and the outcome after it.
    Result(u64, bool, Option<UploadOutcome>),
}

/// What the full receipt itself showed, before any event.
#[derive(Debug, PartialEq, Eq)]
struct Receipt {
    /// The supply of the object's one fragment.
    supplied: Result<usize, SupplyRefused>,
    /// Whether the core took the PUT ACK.
    taken: bool,
    /// The upload's outcome right after the ACK.
    outcome: Option<UploadOutcome>,
    /// Whether a frame is due and the core's least timer right after the ACK.
    wake: (bool, Option<u64>),
}

impl Receipt {
    /// A full receipt taken with the fragment supplied, which decides nothing.
    fn undecided(&self) -> bool {
        self.supplied == Ok(OBJECT_LEN) && self.taken && self.outcome.is_none()
    }
}

/// A reply to upload `id` of `kind`, carrying the prepared manifest as the owner's READY, ACK and RESULT
/// do.
fn reply(
    id: RequestId,
    requests: &ClientRequests<'_>,
    kind: Kind,
    edit: impl FnOnce(&mut Header),
) -> Header {
    let upload = requests.upload(id).expect("the live upload");
    let (wire, key) = (upload.wire(), upload.key());
    let mut reply = match upload.prepared() {
        Some((metadata_len, body_len)) => {
            let manifest = Manifest {
                allocation: 5,
                metadata_len,
                body_len,
            };
            manifest_header(kind, wire, key, &manifest)
        }
        None => Header {
            allocation: 5,
            ..header(kind, wire, key)
        },
    };
    edit(&mut reply);
    reply
}

/// One tick and one poll at `now_us`: the kinds of the frames the poll staged.
fn turn(core: &mut UploadCore<'_>, requests: &mut ClientRequests<'_>, now_us: u64) -> Vec<Kind> {
    core.tick(requests, now_us);
    let mut kinds = Vec::new();
    core.poll(requests, now_us, 8, |_, header| {
        kinds.push(header.kind);
        true
    });
    kinds
}

/// Drives an upload to `Ready`, supplies its fragment, delivers the full receipt at [`RECEIPT_US`] and
/// plays `events` in order.
fn played(events: &[Event]) -> (Receipt, Vec<Seen>) {
    let shared = arena(2);
    let mut budget = EngineBudget::new(1 << 20);
    let slots = sources(&shared, 2, &mut budget).unwrap();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let (mut core, id) = ready_core(slots, &mut requests, &mut budget, OBJECT_LEN as u32);

    let supplied = core.supply(&mut requests, id, 0, &payload(OBJECT_LEN, 35));
    let full = reply(id, &requests, Kind::PutAck, |reply| {
        reply.index = 1;
        reply.grant = 64;
    });
    let taken = core.receive(&mut requests, SESSION, &full, RECEIPT_US);
    let receipt = Receipt {
        supplied,
        taken,
        outcome: core.outcome(&requests, id),
        wake: core.wake(&requests),
    };

    let seen = events
        .iter()
        .map(|&event| match event {
            Event::Turn(at) => {
                let kinds = turn(&mut core, &mut requests, at);
                Seen::Turn(at, kinds, core.outcome(&requests, id))
            }
            Event::Result(at) => {
                let result = reply(id, &requests, Kind::PutResult, |_| {});
                let taken = core.receive(&mut requests, SESSION, &result, at);
                Seen::Result(at, taken, core.outcome(&requests, id))
            }
        })
        .collect();
    (receipt, seen)
}

/// The time of the `n`th retry after the full receipt, counting the first as 1.
const fn retry(n: u64) -> u64 {
    RECEIPT_US + n * RETRY_US
}

/// A full receipt publishes nothing: the upload stays undecided and its next timer is the PREPARE retry.
/// With the RESULT lost it stages no frame before the retry interval has passed, then one PUT PREPARE
/// per interval, and the RESULT that answers a resend decides it `Published`.
#[test]
fn a_full_receipt_awaits_the_result_and_resends_prepare_each_retry_interval_until_it_arrives() {
    let (receipt, seen) = played(&[
        Event::Turn(retry(1) - RETRY_US / 2),
        Event::Turn(retry(1) - 1),
        Event::Turn(retry(1)),
        Event::Turn(retry(1) + RETRY_US / 2),
        Event::Turn(retry(2) - 1),
        Event::Turn(retry(2)),
        Event::Result(retry(2) + 100),
        Event::Turn(retry(3)),
        Event::Turn(retry(4)),
    ]);
    let published = Some(UploadOutcome::Published);

    assert!(
        receipt.undecided(),
        "a full receipt is not `Published`: {receipt:?}"
    );
    assert_eq!(
        receipt.wake,
        (false, Some(retry(1))),
        "the full receipt arms the PREPARE retry"
    );
    assert_eq!(
        seen,
        [
            Seen::Turn(retry(1) - RETRY_US / 2, vec![], None),
            Seen::Turn(retry(1) - 1, vec![], None),
            Seen::Turn(retry(1), vec![Kind::PutPrepare], None),
            Seen::Turn(retry(1) + RETRY_US / 2, vec![], None),
            Seen::Turn(retry(2) - 1, vec![], None),
            Seen::Turn(retry(2), vec![Kind::PutPrepare], None),
            Seen::Result(retry(2) + 100, true, published),
            Seen::Turn(retry(3), vec![], published),
            Seen::Turn(retry(4), vec![], published),
        ],
        "after the full receipt the upload resends PUT PREPARE at each retry interval until PUT RESULT decides it"
    );
}

/// While the RESULT stays lost the upload asks for it with its first PREPARE and each resend the budget
/// allows, one per interval and undecided throughout; the retry after the last resend ends it `Unknown`,
/// never `Published`.
#[test]
fn a_result_that_stays_lost_is_asked_for_at_every_retry_until_the_resends_run_out() {
    let last = 1 + ATTEMPTS;
    let (receipt, seen) = played(&[
        Event::Turn(retry(1)),
        Event::Turn(retry(2)),
        Event::Turn(retry(3)),
        Event::Turn(retry(4)),
        Event::Turn(retry(last + 1) - 1),
        Event::Turn(retry(last + 1)),
    ]);

    assert!(
        receipt.undecided(),
        "a full receipt is not `Published`: {receipt:?}"
    );
    assert_eq!(
        receipt.wake,
        (false, Some(retry(1))),
        "the full receipt arms the PREPARE retry"
    );
    assert_eq!(
        seen,
        [
            Seen::Turn(retry(1), vec![Kind::PutPrepare], None),
            Seen::Turn(retry(2), vec![Kind::PutPrepare], None),
            Seen::Turn(retry(3), vec![Kind::PutPrepare], None),
            Seen::Turn(retry(4), vec![Kind::PutPrepare], None),
            Seen::Turn(retry(last + 1) - 1, vec![], None),
            Seen::Turn(retry(last + 1), vec![], Some(UploadOutcome::Unknown)),
        ],
        "a lost PUT RESULT is asked for with PUT PREPARE at each retry while resends remain"
    );
}

/// The RESULT arrives before the first retry, so the upload is `Published` at once and no
/// PREPARE is resent.
#[test]
fn a_result_right_after_the_full_receipt_publishes_with_no_prepare_resent() {
    let (receipt, seen) = played(&[
        Event::Result(RECEIPT_US + 100),
        Event::Turn(retry(1)),
        Event::Turn(retry(2)),
    ]);
    let published = Some(UploadOutcome::Published);

    assert!(
        receipt.undecided(),
        "a full receipt is not `Published`: {receipt:?}"
    );
    assert_eq!(
        seen,
        [
            Seen::Result(RECEIPT_US + 100, true, published),
            Seen::Turn(retry(1), vec![], published),
            Seen::Turn(retry(2), vec![], published),
        ],
        "PUT RESULT is the reply that publishes, and a decided upload stages nothing"
    );
}
