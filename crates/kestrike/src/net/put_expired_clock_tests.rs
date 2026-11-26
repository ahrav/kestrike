//! An upload whose object TTL has passed on the storage clock when its writes finish ends with PUT ERROR
//! `Expired` and publishes nothing.
//!
//! Each scenario runs one upload of an object with bytes over the PUT scene. The storage clock reads 2.5 s
//! when the PREPARE arrives with a TTL of one second, so the storage's deadline is 3.5 s rounded down to
//! whole seconds, 3 s. The clock
//! is then moved before the turns in which the upload's writes finish and its publication is tried: to 3.2 s
//! or 10 s, past the deadline, or to 2.9 s, inside it. Past the deadline the uploader's only terminal is PUT
//! ERROR `Expired`, the PUT record is released, the owner counts a failed publication and no published one,
//! and a GET of the key ends `Missing`. Inside the deadline the same upload ends with one PUT RESULT and a
//! GET returns the uploaded bytes.
//!
//! Each test computes what the upload left into plain values inside the scene, lets the scene go, and
//! asserts last, so a failed check ends in the test's own result line.

use super::fetch::Outcome;
use super::frame::{Header, Kind, Status};
use super::geometry::{FRAGMENT_LEN, FragmentGeometry};
use super::owner_tests::{PRINCIPALS, payload};
use super::put_tests::{Scene, error, prepare, request, scene};
use crate::storage::owner_fixture::set_clock;

/// The key the uploads name.
const NAME: u8 = 5;
/// The uploading peer; peer 0 reads.
const UPLOADER: usize = 1;
/// The storage clock when the PREPARE arrives, in nanoseconds.
const PREPARED_AT: u64 = 2_500_000_000;
/// The object's TTL in the PREPARE, in milliseconds: with [`PREPARED_AT`] the storage's deadline is 3 s.
const TTL_MS: u32 = 1_000;
/// A clock value inside the deadline.
const INSIDE: u64 = 2_900_000_000;
/// Two clock values past the deadline.
const PAST: [u64; 2] = [3_200_000_000, 10_000_000_000];

/// What one upload left.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    /// The PREPARE was answered PUT READY before the clock moved.
    ready: bool,
    /// Every PUT RESULT and PUT ERROR the owner sent the uploader, with an error's status.
    terminals: Vec<(Kind, Option<Status>)>,
    /// The owner's live PUT records after the terminal.
    live: u32,
    /// The owner's counts of published PUTs and of failed publications.
    published: u64,
    failed_publish: u64,
    /// How a GET of the key by the other peer ended.
    get: Got,
}

/// The end of a GET of the uploaded key.
#[derive(Debug, PartialEq, Eq)]
enum Got {
    /// The owner holds no live object for the key, and the GET handed out no byte.
    Missing,
    /// The GET completed with exactly the uploaded bytes.
    Object,
    /// Any other end, with the bytes handed out.
    Other(Option<Outcome>, usize),
}

fn got(outcome: Option<Outcome>, bytes: &[u8], object: &[u8]) -> Got {
    match outcome {
        Some(Outcome::Missing) if bytes.is_empty() => Got::Missing,
        Some(Outcome::Complete) if bytes == object => Got::Object,
        other => Got::Other(other, bytes.len()),
    }
}

fn terminals(replies: &[Header]) -> Vec<(Kind, Option<Status>)> {
    replies
        .iter()
        .filter(|reply| matches!(reply.kind, Kind::PutResult | Kind::PutError))
        .map(|reply| (reply.kind, error(reply)))
        .collect()
}

/// Uploads `object` under [`TTL_MS`] prepared at [`PREPARED_AT`], with the storage clock moved to `late`
/// before the frames and turns that finish the upload's writes and try its publication.
fn upload(object: &[u8], late: u64) -> Seen {
    let mut seen = None;
    scene(&PRINCIPALS, |mut scene: Scene<'_, '_>| {
        let at = request(1, 1);
        let serial = scene.begin(UPLOADER, at, NAME);
        set_clock(scene.storage, &[Some(PREPARED_AT)]);
        let header = scene.frame(
            UPLOADER,
            Kind::PutPrepare,
            at,
            NAME,
            prepare(serial, object.len() as u32, TTL_MS),
        );
        scene.inject(UPLOADER, &header);
        scene.turns(4);
        let mut replies = scene.replies(UPLOADER);
        let ready = replies.len() == 1 && replies[0].kind == Kind::PutReady;
        set_clock(scene.storage, &[Some(late)]);
        let fragments = FragmentGeometry::fragments(object.len() as u64) as u32;
        for index in 0..fragments {
            let (data, body) = scene.fragment(at, serial, object, index);
            scene.inject_edited(UPLOADER, &data, &body, |_| {});
            scene.turns(4);
        }
        scene.turns(8);
        replies.extend(scene.replies(UPLOADER));
        let report = scene.owner.put_report();
        let live = scene.live();
        let (outcome, bytes) = scene.read(0, NAME, 0);
        seen = Some(Seen {
            ready,
            terminals: terminals(&replies),
            live,
            published: report.published,
            failed_publish: report.failed_publish,
            get: got(outcome, &bytes, object),
        });
    });
    seen.expect("the scene ran its body")
}

/// What an upload that expired before its publication leaves.
fn expired() -> Seen {
    Seen {
        ready: true,
        terminals: vec![(Kind::PutError, Some(Status::Expired))],
        live: 0,
        published: 0,
        failed_publish: 1,
        get: Got::Missing,
    }
}

/// What an upload published inside its TTL leaves.
fn published() -> Seen {
    Seen {
        ready: true,
        terminals: vec![(Kind::PutResult, None)],
        live: 0,
        published: 1,
        failed_publish: 0,
        get: Got::Object,
    }
}

/// An object of one fragment: its one write finishes after the clock passed the deadline.
#[test]
fn an_upload_whose_ttl_passed_before_its_write_finished_ends_expired_and_publishes_nothing() {
    let object = payload(FRAGMENT_LEN as usize, 19);
    let seen = PAST.map(|late| upload(&object, late));
    assert_eq!(seen, [expired(), expired()]);
}

/// The same upload with the clock moved to a value inside the deadline ends with PUT RESULT.
#[test]
fn an_upload_whose_write_finished_inside_its_ttl_ends_with_put_result() {
    let object = payload(FRAGMENT_LEN as usize, 19);
    assert_eq!(upload(&object, INSIDE), published());
}

/// An object of three fragments, the last one short: every write finishes after the clock passed the
/// deadline, and the same upload inside the deadline publishes the same bytes.
#[test]
fn a_three_fragment_upload_ends_expired_past_its_ttl_and_with_put_result_inside_it() {
    let object = payload(2 * FRAGMENT_LEN as usize + 100, 23);
    let seen = [PAST[0], INSIDE].map(|late| upload(&object, late));
    assert_eq!(seen, [expired(), published()]);
}
