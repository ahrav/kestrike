use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use kestrike::failover::attachments::{ControlPlane, Unlisted};
use kestrike::failover::records::VolumeId;
use kestrike::failover::standbys::Zone;
use kestrike::failover::zone_loop::evidence::{ListedVolumeState, VolumeCondition, VolumeStatus};
use kestrike::failover::zone_loop::sources::{ListedVolume, VolumeSource};

use super::{Volumes, ZONE_VOLUMES};
use crate::client::Client;
use crate::config::EC2;
use crate::ec2::error_code;
use crate::ec2::pages::ZoneListing;
use crate::ec2::replay::{
    Answer, Delayed, Replay, ZONE, adverse, answers, assert_each_fault_unlisted, assert_paged,
    assert_zone_names, client, client_in, edited, fixture, held, listing, listing_named,
    listing_of, ok, prepended, unusable,
};
use crate::loopback::{
    Answer as LoopbackAnswer, Manual, Resend, origin, reply, reset, serve, silent,
};
use crate::wire::{Https, Wire};

const VOLUME: &str = "vol-0a1b2c3d4e5f60718";
const DEADLINE: Duration = Duration::from_secs(1);

fn volume() -> VolumeId {
    VolumeId::new(VOLUME).unwrap()
}

fn volumes<W: Wire>(wire: W, host: &str) -> Volumes<W, Manual> {
    Volumes::new(client(wire, host, DEADLINE)).unwrap()
}

fn list(answer: Answer) -> (Result<Vec<String>, Unlisted>, Replay) {
    let replay = Replay::new([answer]);
    let outcome = volumes(replay.clone(), "fake").attachments(&volume());
    (outcome, replay)
}

/// The authored reply, in the shape the EC2 API reference documents, holds
/// eight attachment records: one in each of the five attachment states, one
/// without an instance ID, one whose instance ID is not canonical, and one
/// with two instance IDs. The listing keeps all eight in reply order, the
/// records without exactly one ID as the empty placeholder and the
/// non-canonical one as written, so `attachments::check` reads each of them.
#[test]
fn a_listing_holds_every_attachment_record_in_reply_order() {
    let (outcome, replay) = list(ok(&fixture("describe-volumes-attachments.xml")));
    assert_eq!(
        outcome.unwrap(),
        [
            "i-0123456789abcdef0",
            "i-0fedcba9876543210",
            "i-1a2b3c4d",
            "i-0aaaabbbbccccdddd",
            "i-0eeeeffff00001111",
            "",
            "I-0123&456789ABCDEF",
            "",
        ]
    );
    assert_eq!(replay.actions(), ["DescribeVolumes"]);
    let sent = replay.sent();
    assert_eq!(
        sent[0].body,
        format!("Action=DescribeVolumes&Version=2016-11-15&VolumeId.1={VOLUME}")
    );
    let content_type = sent[0]
        .headers
        .iter()
        .find(|(name, _)| name == "content-type")
        .map(|(_, value)| value.as_str());
    assert_eq!(
        content_type,
        Some("application/x-www-form-urlencoded; charset=utf-8")
    );
}

/// Two adjacent records that name one instance, in different states, list
/// as two entries in reply order, and a record whose instance ID holds an
/// element, and a record that holds text beside its elements, each list as
/// the empty placeholder.
#[test]
fn adjacent_records_of_one_instance_and_a_nested_id_each_list_once() {
    let reply = fixture("describe-volumes-attachments.xml")
        .replacen("i-0fedcba9876543210", "i-0123456789abcdef0", 1)
        .replacen("i-1a2b3c4d<", "i-1a2b3c4d<b/><", 1)
        .replacen(
            "<instanceId>i-0eeeeffff00001111",
            "text<instanceId>i-0eeeeffff00001111",
            1,
        );
    assert_eq!(
        list(ok(&reply)).0.unwrap(),
        [
            "i-0123456789abcdef0",
            "i-0123456789abcdef0",
            "",
            "i-0aaaabbbbccccdddd",
            "",
            "",
            "I-0123&456789ABCDEF",
            "",
        ]
    );
}

#[test]
fn a_volume_with_an_empty_attachment_set_lists_no_record() {
    let reply = fixture("describe-volumes-attachments.xml");
    let start = reply.find("<attachmentSet>").unwrap();
    let end = reply.find("</attachmentSet>").unwrap() + "</attachmentSet>".len();
    let empty = format!("{}<attachmentSet/>{}", &reply[..start], &reply[end..]);
    assert_eq!(list(ok(&empty)).0, Ok(Vec::new()));
}

/// An entry is its record's instance ID text byte for byte: an ID padded
/// with whitespace and an ID in upper case list as written, so
/// `attachments::check` reads the padded copy of its own instance's ID as
/// foreign. A record lists whatever it holds beside its ID: a record in a
/// state outside the documented five, a record without a state, and a
/// record that names another volume each list.
#[test]
fn a_record_lists_its_id_as_written_whatever_else_it_holds() {
    use kestrike::failover::attachments::{InstanceId, Mismatch, check};
    let mut reply = fixture("describe-volumes-attachments.xml")
        .replacen(
            "<instanceId>i-0123456789abcdef0<",
            "<instanceId> i-0123456789abcdef0\n<",
            1,
        )
        .replacen("i-0fedcba9876543210", "I-0FEDCBA9876543210", 1)
        .replacen(
            "<status>attaching</status>",
            "<status>migrating</status>",
            1,
        )
        .replacen("<status>detaching</status>", "", 1);
    let busy = reply.find("<instanceId>i-0eeeeffff00001111").unwrap();
    let named = reply[..busy].rfind(VOLUME).unwrap();
    reply.replace_range(named..named + VOLUME.len(), "vol-0bbbbccccddddeeee");
    let listed = list(ok(&reply)).0.unwrap();
    assert_eq!(
        listed,
        [
            " i-0123456789abcdef0\n",
            "I-0FEDCBA9876543210",
            "i-1a2b3c4d",
            "i-0aaaabbbbccccdddd",
            "i-0eeeeffff00001111",
            "",
            "I-0123&456789ABCDEF",
            "",
        ]
    );
    let own = InstanceId::new("i-0123456789abcdef0").unwrap();
    let peers: [InstanceId; 0] = [];
    assert_eq!(
        check(&listed, &own, &peers),
        Err(Mismatch::Foreign(" i-0123456789abcdef0\n".to_owned()))
    );
}

/// The listing holds the volume's records whatever the volume's own
/// state: a volume in each documented state, in an undocumented one, and
/// without a state lists all eight records, and in each of those states a
/// volume without its attachment set is unlisted.
#[test]
fn a_volume_in_any_state_lists_every_record() {
    let reply = fixture("describe-volumes-attachments.xml");
    let own = "<status>in-use</status>";
    assert_eq!(reply.matches(own).count(), 1);
    let expected = list(ok(&reply)).0.unwrap();
    assert_eq!(expected.len(), 8);
    for state in [
        "<status>creating</status>",
        "<status>available</status>",
        "<status>deleting</status>",
        "<status>deleted</status>",
        "<status>error</status>",
        "<status>optimizing</status>",
        "",
    ] {
        let stated = reply.replace(own, state);
        let listed = list(ok(&stated)).0;
        assert_eq!(listed.as_ref(), Ok(&expected), "{state}");
        let setless = stated.replace("attachmentSet>", "attachmentList>");
        assert_eq!(list(ok(&setless)).0, Err(Unlisted), "{state}");
    }
}

/// The listing reads a reply by the elements it names and holds every
/// record of a long set: a reply for a volume with a short ID, with
/// elements the adapter does not read at each level, and with forty
/// records lists forty entries in reply order.
#[test]
fn a_long_set_with_unread_elements_lists_every_record() {
    let short = VolumeId::new("vol-1a2b3c4d").unwrap();
    let unread = "<futureField><nested>x</nested></futureField>";
    let ids: Vec<String> = (1..=40).map(|at| format!("i-{at:017x}")).collect();
    let records: String = ids
        .iter()
        .map(|id| {
            format!("<item>{unread}<instanceId>{id}</instanceId><status>attached</status></item>")
        })
        .collect();
    let reply = format!(
        "<DescribeVolumesResponse>{unread}<volumeSet><item>{unread}<volumeId>vol-1a2b3c4d</volumeId><status>in-use</status><attachmentSet>{records}</attachmentSet></item></volumeSet></DescribeVolumesResponse>"
    );
    let replay = Replay::new([ok(&reply)]);
    let listed = volumes(replay.clone(), "fake").attachments(&short);
    assert_eq!(listed, Ok(ids));
    assert_eq!(
        replay.sent()[0].body,
        "Action=DescribeVolumes&Version=2016-11-15&VolumeId.1=vol-1a2b3c4d"
    );
}

/// Each read of one adapter sends its own request and lists only its own
/// reply: a changed listing replaces the earlier one, a read that fails
/// after a good read is unlisted, and the read after it lists again.
#[test]
fn each_read_lists_its_own_reply_and_a_failed_read_is_unlisted() {
    let first = fixture("describe-volumes-attachments.xml");
    let start = first.find("<attachmentSet>").unwrap();
    let end = first.find("</attachmentSet>").unwrap() + "</attachmentSet>".len();
    let record =
        "<item><instanceId>i-0aaaabbbbccccdddd</instanceId><status>attached</status></item>";
    let second = format!(
        "{}<attachmentSet>{record}</attachmentSet>{}",
        &first[..start],
        &first[end..]
    );
    let replay = Replay::new([
        ok(&first),
        ok(&second),
        Answer::Reply(503, fixture("request-limit-exceeded.xml")),
        ok(&second),
        ok(&first),
    ]);
    let mut volumes = volumes(replay.clone(), "fake");
    let one = Ok(vec!["i-0aaaabbbbccccdddd".to_owned()]);
    let mut starts = vec![Instant::now()];
    assert_eq!(volumes.attachments(&volume()).map(|all| all.len()), Ok(8));
    assert_eq!(replay.sent().len(), 1);
    starts.push(Instant::now());
    assert_eq!(volumes.attachments(&volume()), one);
    assert_eq!(replay.sent().len(), 2);
    starts.push(Instant::now());
    assert_eq!(volumes.attachments(&volume()), Err(Unlisted));
    assert_eq!(replay.sent().len(), 3);
    starts.push(Instant::now());
    assert_eq!(volumes.attachments(&volume()), one);
    starts.push(Instant::now());
    assert_eq!(volumes.attachments(&volume()).map(|all| all.len()), Ok(8));
    let end = Instant::now();
    let sent = replay.sent();
    assert_eq!(sent.len(), 5);
    assert!(sent.iter().all(|request| request.body == sent[0].body));
    for (request, start) in sent.iter().zip(&starts) {
        assert!(*start + DEADLINE <= request.deadline && request.deadline <= end + DEADLINE);
    }
}

/// Each adverse reply leaves the volume unlisted after its one request: an
/// error code of each class, a lost exchange, and 200 replies that do not
/// show exactly the requested volume's whole attachment set.
#[test]
fn every_adverse_reply_is_unlisted_after_one_request() {
    let reply = fixture("describe-volumes-attachments.xml");
    let page = |token: &str| {
        reply.replace(
            "</volumeSet>",
            &format!("</volumeSet>\n    <nextToken>{token}</nextToken>"),
        )
    };
    let start = reply.find("<item>").unwrap();
    let end = reply.rfind("</volumeSet>").unwrap();
    let item = &reply[start..end];
    let cases = [
        (
            "not found",
            Answer::Reply(400, fixture("invalid-volume-not-found.xml")),
        ),
        ("redirect", Answer::Reply(307, String::new())),
        (
            "error document on a 200",
            ok(&fixture("request-limit-exceeded.xml")),
        ),
        ("paginated", ok(&page("AAEAAexample+token/=="))),
        ("nested token", ok(&page("<token>a</token>"))),
        ("a listing on a 201", Answer::Reply(201, reply.clone())),
        (
            "another action's root",
            ok(&reply.replace("DescribeVolumesResponse", "DescribeVolumeStatusResponse")),
        ),
        (
            "text in the attachment set",
            ok(&reply.replacen("<attachmentSet>", "<attachmentSet>text", 1)),
        ),
        ("empty volume set", ok(&reply.replace(item, ""))),
        (
            "another volume",
            ok(&reply.replace(VOLUME, "vol-0bbbbccccddddeeee")),
        ),
        (
            "a volume ID one digit longer",
            ok(&reply.replace(VOLUME, &format!("{VOLUME}9"))),
        ),
        (
            "a volume ID that differs in its last digit",
            ok(&reply.replace(VOLUME, "vol-0a1b2c3d4e5f60719")),
        ),
        (
            "the volume ID in upper case",
            ok(&reply.replace(VOLUME, &VOLUME.to_uppercase())),
        ),
        (
            "the volume ID padded with a space",
            ok(&reply.replace(VOLUME, &format!("{VOLUME} "))),
        ),
        (
            "a root in another letter case",
            ok(&reply.replace("DescribeVolumesResponse", "describeVolumesResponse")),
        ),
        (
            "a volume set named in another letter case",
            ok(&reply.replace("volumeSet>", "VolumeSet>")),
        ),
        (
            "an attachment set named in another letter case",
            ok(&reply.replace("attachmentSet>", "AttachmentSet>")),
        ),
        (
            "a volume ID element named in another letter case",
            ok(&reply.replace("volumeId>", "VolumeId>")),
        ),
        ("two volumes", ok(&reply.replace(item, &item.repeat(2)))),
        (
            "no attachment set",
            ok(&reply.replace("attachmentSet>", "attachmentList>")),
        ),
        (
            "truncated",
            ok(&reply[..reply.floor_char_boundary(reply.len() / 2)]),
        ),
        (
            "text in the response root",
            ok(&reply.replacen("<requestId>", "text<requestId>", 1)),
        ),
        ("empty body", ok("")),
    ];
    let mut ran = 0;
    for (name, answer) in adverse(&reply).into_iter().chain(cases) {
        let (outcome, replay) = list(answer);
        assert_eq!(outcome, Err(Unlisted), "{name}");
        assert_eq!(replay.sent().len(), 1, "{name}");
        ran += 1;
    }
    assert_eq!(ran, 31);
}

/// A reply of any status but 200 is unlisted whatever its body, the
/// volume's own listing included, and so is a call lost in any way before
/// or after its first request byte. Each read sends one request, so no
/// status and no kind of loss is sent again.
#[test]
fn every_other_status_and_every_lost_call_is_unlisted_after_one_request() {
    let (names, answers): (Vec<String>, Vec<Answer>) =
        unusable(&fixture("describe-volumes-attachments.xml"))
            .into_iter()
            .unzip();
    let replay = Replay::new(answers);
    let mut volumes = volumes(replay.clone(), "fake");
    for (at, name) in names.iter().enumerate() {
        assert_eq!(volumes.attachments(&volume()), Err(Unlisted), "{name}");
        assert_eq!(replay.count(), at + 1, "{name}");
    }
}

#[test]
fn the_authored_error_replies_carry_their_codes() {
    for (name, code) in [
        ("invalid-volume-not-found.xml", "InvalidVolume.NotFound"),
        ("request-limit-exceeded.xml", "RequestLimitExceeded"),
        ("internal-error.xml", "InternalError"),
        ("unauthorized-operation.xml", "UnauthorizedOperation"),
    ] {
        assert_eq!(
            error_code(fixture(name).as_bytes()).as_deref(),
            Some(code),
            "{name}"
        );
    }
    let listing = fixture("describe-volumes-attachments.xml");
    assert_eq!(error_code(listing.as_bytes()), None);
}

/// Under each scripted transport fault and reply of the client tests, a
/// listing reads as unlisted after one send that ends as the fault
/// scripts, within the deadline plus the wire's slack.
#[test]
fn every_scripted_fault_is_unlisted_with_at_most_one_request() {
    assert_each_fault_unlisted(Duration::from_millis(500), |client| {
        Volumes::new(client).unwrap().attachments(&volume())
    });
}

/// The control for the sweep's count check: a sweep that judged every
/// scripted fault but the last one fails `assert_swept`.
#[test]
#[should_panic(expected = "30 faults, expected 31")]
fn a_sweep_one_fault_short_of_the_table_fails_the_count_check() {
    let table = crate::loopback::faults(Duration::from_millis(500));
    let mut ran: Vec<_> = (table.iter())
        .map(|fault| crate::ec2::replay::fault_class(&fault.expect))
        .collect();
    crate::ec2::replay::assert_swept(&ran);
    ran.pop();
    crate::ec2::replay::assert_swept(&ran);
}

/// The control for the one-attempt check: a wire that sends again after a
/// reset makes the server read two requests, and the check fails.
#[test]
fn a_wire_that_sends_again_fails_the_one_attempt_check() {
    let once = reset();
    let outcome = volumes(Https::plain(), &once.host).attachments(&volume());
    assert_eq!(outcome, Err(Unlisted));
    assert_eq!(once.one_attempt(), Ok(()));
    let twice = reset();
    let outcome = volumes(Resend(Https::plain()), &twice.host).attachments(&volume());
    assert_eq!(outcome, Err(Unlisted));
    assert_eq!(
        twice.one_attempt(),
        Err("reset after the request: 2 requests, expected 1".to_owned())
    );
}

fn zoned<W: Wire>(client: Client<W, Manual>, pages: u16) -> Volumes<W, Manual, ZoneListing> {
    Volumes::new(client)
        .unwrap()
        .for_zone(listing(pages))
        .unwrap()
}

/// The five authored pages of a zone read: three `DescribeVolumes` pages,
/// then two `DescribeVolumeStatus` pages.
fn zone_bodies() -> Vec<String> {
    let volumes = (1..=3).map(|page| fixture(&format!("describe-volumes-zone-{page}.xml")));
    let statuses = (1..=2).map(|page| fixture(&format!("describe-volume-status-zone-{page}.xml")));
    volumes.chain(statuses).collect()
}

fn zone_pages() -> Vec<Answer> {
    answers(&zone_bodies())
}

/// The authored zone pages with `from` replaced by `to` on page `at`.
fn zone_page(at: usize, from: &str, to: &str) -> Vec<Answer> {
    edited(&zone_bodies(), at, from, to)
}

/// The view of the authored zone pages, which a test compares a read
/// against.
fn authored() -> Vec<ListedVolume> {
    zone(zone_pages(), 3).0.unwrap()
}

/// A volume row in the authored shape: its ID, state, and one attached
/// record for each of `instances`, in order.
fn volume_row(id: &str, state: &str, instances: &[&str]) -> String {
    let records: String = instances
        .iter()
        .map(|instance| {
            format!(
                "<item><volumeId>{id}</volumeId><instanceId>{instance}</instanceId><status>attached</status></item>"
            )
        })
        .collect();
    format!(
        "<item><volumeId>{id}</volumeId><availabilityZone>us-east-1a</availabilityZone><status>{state}</status><attachmentSet>{records}</attachmentSet></item>"
    )
}

/// The authored zone pages with `row` placed first on the third volume
/// page.
fn with_third_page_row(row: &str) -> Vec<Answer> {
    let mut bodies = zone_bodies();
    bodies[2] = prepended(&bodies[2], "volumeSet", row);
    answers(&bodies)
}

/// A zone read of the zone named `name` with at most `pages` pages.
fn zone_in(
    name: &str,
    answers: Vec<Answer>,
    pages: u16,
) -> (Result<Vec<ListedVolume>, Unlisted>, Replay) {
    let replay = Replay::new(answers);
    let client = client(replay.clone(), "fake", DEADLINE);
    let mut volumes = Volumes::new(client)
        .unwrap()
        .for_zone(listing_named(name, pages))
        .unwrap();
    (volumes.volumes(ZONE), replay)
}

fn listed(
    volume: &str,
    state: ListedVolumeState,
    status: VolumeStatus,
    attachments: &[&str],
) -> ListedVolume {
    ListedVolume {
        volume: VolumeId::new(volume).unwrap(),
        condition: VolumeCondition { state, status },
        attachments: attachments.iter().map(|id| (*id).to_owned()).collect(),
    }
}

fn zone(answers: Vec<Answer>, pages: u16) -> (Result<Vec<ListedVolume>, Unlisted>, Replay) {
    let replay = Replay::new(answers);
    let mut volumes = zoned(client(replay.clone(), "fake", DEADLINE), pages);
    (volumes.volumes(ZONE), replay)
}

/// Three authored `DescribeVolumes` pages and two `DescribeVolumeStatus`
/// pages, each following the previous page's token, give one view in
/// volume-listing order with every state, status and attachment record as
/// reported. The volume the status listing leaves out reads
/// `insufficient-data`, and the status of a volume the volume listing
/// leaves out is dropped. Each page is one request with the zone filter,
/// and all five share the read's one deadline.
#[test]
fn a_zone_listing_joins_every_volume_page_with_its_status_as_reported() {
    use ListedVolumeState::{Available, Creating, Error, InUse};
    use VolumeStatus::{Impaired, InsufficientData, Ok, Warning};
    let start = Instant::now();
    let (view, replay) = zone(zone_pages(), 3);
    let end = Instant::now();
    assert_eq!(
        view.unwrap(),
        [
            listed("vol-00000000000000a01", InUse, Ok, &["i-0000000000000a001"]),
            listed("vol-00000000000000a02", Available, Warning, &[]),
            listed(
                "vol-00000000000000a03",
                Error,
                Impaired,
                &["i-0000000000000a003", "i-0000000000000a004"]
            ),
            listed(
                "vol-00000000000000a04",
                InUse,
                InsufficientData,
                &["i-0000000000000a005"]
            ),
            listed("vol-00000000000000a05", Creating, InsufficientData, &[]),
            listed("vol-00000000000000a06", InUse, Ok, &["i-0000000000000a006"]),
        ]
    );
    let sent = replay.sent();
    assert_eq!(
        replay.actions(),
        [
            "DescribeVolumes",
            "DescribeVolumes",
            "DescribeVolumes",
            "DescribeVolumeStatus",
            "DescribeVolumeStatus"
        ]
    );
    assert_paged(
        &sent[..3],
        "DescribeVolumes",
        "us-east-1a",
        "",
        "100",
        &[
            None,
            Some("eyJ2IjoyLCJjIjoiYTAyIn0%2B%2F%3D"),
            Some("eyJ2IjoyLCJjIjoiYTA0In0%2B%2F%3D"),
        ],
    );
    assert_paged(
        &sent[3..],
        "DescribeVolumeStatus",
        "us-east-1a",
        "",
        "1000",
        &[None, Some("c3RhdHVzLTI%3D")],
    );
    let deadline = sent[0].deadline;
    assert!(sent.iter().all(|request| request.deadline == deadline));
    assert!(start + DEADLINE <= deadline && deadline <= end + DEADLINE);
}

/// A fault on any of the five pages leaves the whole zone unlisted, with no
/// partial view, and the read sends no page after the faulted one.
#[test]
fn a_fault_on_any_page_leaves_the_zone_unlisted() {
    let bodies = zone_bodies();
    let mut ran = 0;
    for (at, body) in bodies.iter().enumerate() {
        for (name, fault) in adverse(body) {
            let mut script = answers(&bodies[..at]);
            script.push(fault);
            let (view, replay) = zone(script, 3);
            assert_eq!(view, Err(Unlisted), "{name} on page {at}");
            assert_eq!(replay.sent().len(), at + 1, "{name} on page {at}");
            ran += 1;
        }
    }
    assert_eq!(ran, 40);
}

/// A first page of any status but 200 leaves the zone unlisted whatever
/// its body, a volume listing included, and so does a call lost in any
/// way. Each read sends one request, so no status and no kind of loss is
/// sent again or read as an empty page.
#[test]
fn every_other_status_and_every_lost_call_leaves_the_zone_unlisted() {
    let (names, answers): (Vec<String>, Vec<Answer>) =
        unusable(&fixture("describe-volumes-zone-3.xml"))
            .into_iter()
            .unzip();
    let replay = Replay::new(answers);
    let mut volumes = zoned(client(replay.clone(), "fake", DEADLINE), 3);
    for (at, name) in names.iter().enumerate() {
        assert_eq!(volumes.volumes(ZONE), Err(Unlisted), "{name}");
        assert_eq!(replay.count(), at + 1, "{name}");
    }
}

/// A page set past the bound and a token that repeats one the read already
/// followed each leave the zone unlisted without sending the page they name.
#[test]
fn a_page_set_past_the_bound_or_a_repeated_token_is_unlisted() {
    let (view, replay) = zone(zone_pages(), 2);
    assert_eq!(view, Err(Unlisted));
    assert_eq!(replay.sent().len(), 2);
    let mut answers = zone_pages();
    let second = fixture("describe-volumes-zone-2.xml")
        .replace("eyJ2IjoyLCJjIjoiYTA0In0+/=", "eyJ2IjoyLCJjIjoiYTAyIn0+/=");
    answers[1] = ok(&second);
    let (view, replay) = zone(answers, 3);
    assert_eq!(view, Err(Unlisted));
    assert_eq!(replay.sent().len(), 2);
    let mut answers = zone_pages();
    let third = fixture("describe-volumes-zone-3.xml").replace(
        "</volumeSet>",
        "</volumeSet>\n    <nextToken>eyJ2IjoyLCJjIjoiYTAyIn0+/=</nextToken>",
    );
    answers[2] = ok(&third);
    let (view, replay) = zone(answers, 4);
    assert_eq!(view, Err(Unlisted));
    assert_eq!(replay.sent().len(), 3);
}

/// The page bound applies to each describe action of a read: a status
/// listing one page past the bound leaves the zone unlisted although the
/// volume listing fits, and the read sends no status page past the bound.
/// The same replies list under a bound of two.
#[test]
fn a_status_listing_past_the_bound_is_unlisted() {
    use ListedVolumeState::{Creating, InUse};
    use VolumeStatus::{InsufficientData, Ok};
    let bodies = zone_bodies();
    let (view, replay) = zone(answers(&bodies[2..]), 1);
    assert_eq!(view, Err(Unlisted));
    assert_eq!(
        replay.actions(),
        ["DescribeVolumes", "DescribeVolumeStatus"]
    );
    let (view, replay) = zone(answers(&bodies[2..]), 2);
    assert_eq!(
        view.unwrap(),
        [
            listed("vol-00000000000000a05", Creating, InsufficientData, &[]),
            listed("vol-00000000000000a06", InUse, Ok, &["i-0000000000000a006"]),
        ]
    );
    assert_eq!(replay.sent().len(), 3);
}

/// A continuation token goes into the next request as the reply holds it,
/// percent-encoded once and whole, a token of 4,000 characters included,
/// and tokens that differ only in letter case or in surrounding whitespace
/// are distinct tokens, so a read that meets them follows each once.
#[test]
fn tokens_that_differ_in_case_or_padding_are_followed_as_written() {
    let page = |token: &str| {
        ok(&format!(
            "<DescribeVolumesResponse><requestId>r</requestId><volumeSet/><nextToken>{token}</nextToken></DescribeVolumesResponse>"
        ))
    };
    let long = "T0ken".repeat(800);
    let mut script = vec![
        page("Tok"),
        page("tok"),
        page(" tok"),
        page("tok\n"),
        page("100%25"),
        page(&long),
    ];
    script.extend(zone_pages());
    let (view, replay) = zone(script, 9);
    assert_eq!(view, Result::Ok(authored()));
    assert_paged(
        &replay.sent()[..9],
        "DescribeVolumes",
        "us-east-1a",
        "",
        "100",
        &[
            None,
            Some("Tok"),
            Some("tok"),
            Some("%20tok"),
            Some("tok%0A"),
            Some("100%2525"),
            Some(&long),
            Some("eyJ2IjoyLCJjIjoiYTAyIn0%2B%2F%3D"),
            Some("eyJ2IjoyLCJjIjoiYTA0In0%2B%2F%3D"),
        ],
    );
}

/// A view holds every row its replies hold, whatever zone a row names:
/// the authored pages list the same view when their volume and status rows
/// name another zone and when they name none.
#[test]
fn a_row_lists_whatever_zone_it_names() {
    let named = "<availabilityZone>us-east-1a</availabilityZone>";
    for other in ["<availabilityZone>us-east-1b</availabilityZone>", ""] {
        let renamed = |body: &String| {
            assert!(body.contains(named));
            body.replace(named, other)
        };
        let bodies: Vec<String> = zone_bodies().iter().map(renamed).collect();
        assert_eq!(zone(answers(&bodies), 3).0, Ok(authored()), "{other}");
    }
}

/// A read takes a row by the elements it names: the authored pages list
/// the same view when every volume row, attachment record, status row and
/// status detail also holds an element the adapter never reads.
#[test]
fn a_row_with_an_extra_element_lists_the_same() {
    let extra = "<item><futureField><nested>x</nested></futureField>";
    let event =
        "<item><eventId>e</eventId><eventType>potential-data-inconsistency</eventType></item>";
    let bodies: Vec<String> = zone_bodies()
        .iter()
        .map(|body| {
            body.replace("<eventsSet/>", &format!("<eventsSet>{event}</eventsSet>"))
                .replace(
                    "<actionsSet/>",
                    &format!("<actionsSet>{event}</actionsSet>"),
                )
                .replace("<item>", extra)
        })
        .collect();
    assert!(bodies.iter().all(|body| body.contains(extra)));
    assert!(bodies[3].contains("<eventsSet><item>") && bodies[3].contains("<actionsSet><item>"));
    assert_eq!(zone(answers(&bodies), 3).0, Ok(authored()));
}

/// An unusable answer on any later page leaves the zone unlisted too:
/// after each prefix of whole pages of either action, every status but
/// 200 and every lost call is unlisted, and the read sends no page after
/// it, so no status and no kind of loss ends a listing early.
#[test]
fn every_other_status_and_every_lost_call_on_a_later_page_leaves_the_zone_unlisted() {
    let page = |action: &str, set: &str, token: &str| {
        format!("<{action}Response><{set}/><nextToken>{token}</nextToken></{action}Response>")
    };
    let pages = [
        page("DescribeVolumes", "volumeSet", "v1"),
        page("DescribeVolumes", "volumeSet", "v2"),
        page("DescribeVolumes", "volumeSet", ""),
        page("DescribeVolumeStatus", "volumeStatusSet", "s1"),
        page("DescribeVolumeStatus", "volumeStatusSet", ""),
    ];
    let (whole, replay) = zone(answers(&pages), 3);
    assert_eq!(whole, Ok(Vec::new()));
    assert_eq!(replay.count(), 5);
    for at in 1..pages.len() {
        let (names, unusable): (Vec<String>, Vec<Answer>) =
            unusable(&pages[at]).into_iter().unzip();
        let script = unusable
            .into_iter()
            .flat_map(|answer| answers(&pages[..at]).into_iter().chain([answer]));
        let replay = Replay::new(script);
        let mut volumes = zoned(client(replay.clone(), "fake", DEADLINE), 3);
        for (read, name) in names.iter().enumerate() {
            assert_eq!(volumes.volumes(ZONE), Err(Unlisted), "{name} on page {at}");
            assert_eq!(replay.count(), (read + 1) * (at + 1), "{name} on page {at}");
        }
    }
}

/// A view holds every volume of a listing longer than a page: 600 volumes
/// on six pages of 100, with their statuses on one page, list as 600 rows
/// in reply order.
#[test]
fn a_listing_of_six_hundred_volumes_lists_every_volume() {
    use ListedVolumeState::InUse;
    use VolumeStatus::Impaired;
    let ids: Vec<String> = (1..=600).map(|at| format!("vol-{at:017x}")).collect();
    let mut script: Vec<Answer> = ids
        .chunks(100)
        .enumerate()
        .map(|(page, ids)| {
            let rows: String = ids.iter().map(|id| volume_row(id, "in-use", &[])).collect();
            let token = match page {
                5 => String::new(),
                _ => format!("<nextToken>page-{page}</nextToken>"),
            };
            ok(&format!(
                "<DescribeVolumesResponse><volumeSet>{rows}</volumeSet>{token}</DescribeVolumesResponse>"
            ))
        })
        .collect();
    let statuses: String = ids.iter().map(|id| status_row(id, "impaired")).collect();
    script.push(ok(&format!(
        "<DescribeVolumeStatusResponse><volumeStatusSet>{statuses}</volumeStatusSet></DescribeVolumeStatusResponse>"
    )));
    let expected: Vec<ListedVolume> = ids
        .iter()
        .map(|id| listed(id, InUse, Impaired, &[]))
        .collect();
    let (view, replay) = zone(script, 6);
    assert_eq!(view, Ok(expected));
    assert_eq!(replay.sent().len(), 7);
}

/// An adapter reads the zone its listing is configured for, by number: one
/// configured for zone 7 lists zone 7 and refuses zone 1 before any
/// request.
#[test]
fn an_adapter_reads_the_zone_number_it_is_configured_for() {
    let replay = Replay::new(answers(&zone_bodies()[2..]));
    let mut volumes = Volumes::new(client(replay.clone(), "fake", DEADLINE))
        .unwrap()
        .for_zone(listing_of(Zone(7), "us-east-1c", 2))
        .unwrap();
    assert_eq!(volumes.volumes(ZONE), Err(Unlisted));
    assert_eq!(replay.count(), 0);
    assert_eq!(volumes.volumes(Zone(7)).map(|view| view.len()), Ok(2));
    assert_paged(
        &replay.sent()[..1],
        "DescribeVolumes",
        "us-east-1c",
        "",
        "100",
        &[None],
    );
}

/// The read follows tokens per describe action: a status listing whose
/// token equals one the volume listing carried lists, and each request
/// carries the token of its own action's previous page.
#[test]
fn a_status_listing_may_carry_a_token_of_the_volume_listing() {
    let page = |action: &str, set: &str, token: &str| {
        ok(&format!(
            "<{action}Response><{set}/><nextToken>{token}</nextToken></{action}Response>"
        ))
    };
    let script = vec![
        page("DescribeVolumes", "volumeSet", "same"),
        page("DescribeVolumes", "volumeSet", ""),
        page("DescribeVolumeStatus", "volumeStatusSet", "same"),
        page("DescribeVolumeStatus", "volumeStatusSet", ""),
    ];
    let (view, replay) = zone(script, 2);
    assert_eq!(view, Ok(Vec::new()));
    let sent = replay.sent();
    let tokens = [None, Some("same")];
    assert_paged(
        &sent[..2],
        "DescribeVolumes",
        "us-east-1a",
        "",
        "100",
        &tokens,
    );
    assert_paged(
        &sent[2..],
        "DescribeVolumeStatus",
        "us-east-1a",
        "",
        "1000",
        &tokens,
    );
}

/// In every state and with every status, a row that lacks an element the
/// read takes, or holds it empty, leaves the zone unlisted: no state
/// stands in for a missing volume ID, state, attachment set or status.
/// Each row lists before the element is taken out.
#[test]
fn a_row_without_an_element_it_needs_is_unlisted_in_every_state() {
    let id = "vol-00000000000000b01";
    let volumes = |rows: &str| {
        ok(&format!(
            "<DescribeVolumesResponse><volumeSet>{rows}</volumeSet></DescribeVolumesResponse>"
        ))
    };
    let statuses = |rows: &str| {
        ok(&format!(
            "<DescribeVolumeStatusResponse><volumeStatusSet>{rows}</volumeStatusSet></DescribeVolumeStatusResponse>"
        ))
    };
    let mut ran = 0;
    for state in [
        "creating",
        "available",
        "in-use",
        "deleting",
        "deleted",
        "error",
    ] {
        let row = volume_row(id, state, &["i-0000000000000b001"]);
        let whole = zone(vec![volumes(&row), statuses("")], 1).0;
        assert_eq!(whole.map(|view| view.len()), Ok(1), "{state}");
        let records = "<attachmentSet>";
        let (before, after) = row.split_once(records).unwrap();
        let (_, after) = after.split_once("</attachmentSet>").unwrap();
        let named = format!("<volumeId>{id}</volumeId>");
        let stated = format!("<status>{state}</status>");
        for broken in [
            row.replacen(&named, "", 1),
            row.replacen(&named, "<volumeId/>", 1),
            row.replacen(&stated, "", 1),
            row.replacen(&stated, "<status/>", 1),
            format!("{before}{after}"),
        ] {
            assert_ne!(broken, row);
            let (view, replay) = zone(vec![volumes(&broken)], 1);
            assert_eq!(view, Err(Unlisted), "{state}: {broken}");
            assert_eq!(replay.count(), 1);
            ran += 1;
        }
    }
    let volume = volume_row(id, "in-use", &[]);
    for status in ["ok", "warning", "impaired", "insufficient-data"] {
        let row = status_row(id, status);
        let whole = zone(vec![volumes(&volume), statuses(&row)], 1).0;
        assert_eq!(whole.map(|view| view.len()), Ok(1), "{status}");
        let named = format!("<volumeId>{id}</volumeId>");
        let summary = format!("<volumeStatus><status>{status}</status>");
        let (before, after) = row.split_once("<volumeStatus>").unwrap();
        let (_, after) = after.split_once("</volumeStatus>").unwrap();
        for broken in [
            row.replacen(&named, "", 1),
            row.replacen(&named, "<volumeId/>", 1),
            row.replacen(&summary, "<volumeStatus>", 1),
            row.replacen(&summary, "<volumeStatus><status/>", 1),
            format!("{before}{after}"),
        ] {
            assert_ne!(broken, row);
            let (view, replay) = zone(vec![volumes(&volume), statuses(&broken)], 1);
            assert_eq!(view, Err(Unlisted), "{status}: {broken}");
            assert_eq!(replay.count(), 2);
            ran += 1;
        }
    }
    assert_eq!(ran, 6 * 5 + 4 * 5);
}

/// A status row in the authored shape: its volume ID and summary status,
/// with a failed detail under every summary, so a view shows that it
/// takes the summary.
fn status_row(id: &str, status: &str) -> String {
    format!(
        "<item><volumeId>{id}</volumeId><availabilityZone>us-east-1a</availabilityZone><volumeStatus><status>{status}</status><details><item><name>io-enabled</name><status>failed</status></item></details></volumeStatus></item>"
    )
}

/// Each read of one adapter lists only its own replies, under its own
/// deadline. After a read of the authored pages, a read whose replies
/// drop four volumes, change the state and the attachment of one, and
/// leave it out of the status listing lists exactly those replies. A read
/// that fails after it is unlisted, and the read after that lists the
/// authored pages again.
#[test]
fn each_zone_read_lists_its_own_replies_and_a_failed_read_is_unlisted() {
    use ListedVolumeState::{Error, InUse};
    use VolumeStatus::{InsufficientData, Ok};
    let volumes = format!(
        "<DescribeVolumesResponse><requestId>r</requestId><volumeSet>{}{}</volumeSet></DescribeVolumesResponse>",
        volume_row("vol-00000000000000a01", "error", &["i-0000000000000b001"]),
        volume_row("vol-00000000000000a03", "in-use", &[])
    );
    let statuses = format!(
        "<DescribeVolumeStatusResponse><requestId>r</requestId><volumeStatusSet>{}</volumeStatusSet></DescribeVolumeStatusResponse>",
        status_row("vol-00000000000000a03", "ok")
    );
    let mut script = zone_pages();
    script.extend([ok(&volumes), ok(&statuses), ok(&volumes)]);
    script.push(Answer::Reply(503, fixture("request-limit-exceeded.xml")));
    script.extend(zone_pages());
    let replay = Replay::new(script);
    let mut adapter = zoned(client(replay.clone(), "fake", DEADLINE), 3);
    let changed = vec![
        listed(
            "vol-00000000000000a01",
            Error,
            InsufficientData,
            &["i-0000000000000b001"],
        ),
        listed("vol-00000000000000a03", InUse, Ok, &[]),
    ];
    let mut starts = vec![Instant::now()];
    assert_eq!(adapter.volumes(ZONE), Result::Ok(authored()));
    starts.push(Instant::now());
    assert_eq!(adapter.volumes(ZONE), Result::Ok(changed));
    starts.push(Instant::now());
    assert_eq!(adapter.volumes(ZONE), Err(Unlisted));
    starts.push(Instant::now());
    assert_eq!(adapter.volumes(ZONE), Result::Ok(authored()));
    let end = Instant::now();
    let sent = replay.sent();
    let reads = [&sent[..5], &sent[5..7], &sent[7..9], &sent[9..]];
    assert_eq!(reads[3].len(), 5);
    for (read, start) in reads.iter().zip(&starts) {
        let deadline = read[0].deadline;
        assert!(read.iter().all(|request| request.deadline == deadline));
        assert!(*start + DEADLINE <= deadline && deadline <= end + DEADLINE);
    }
}

/// A volume ID `VolumeId` refuses, an undocumented state or status, a
/// volume without its state or attachment set, a status item without its
/// status, two differing statuses or two differing rows for one volume, a
/// page without its set, a set holding text and a token holding an element
/// each leave the zone unlisted, and the read sends no page after the
/// refused one. A zone other than the configured one is unlisted before any
/// request.
#[test]
fn an_unreadable_value_leaves_the_zone_unlisted() {
    let cases = [
        (
            "volume ID",
            1,
            "vol-00000000000000a03",
            "vol-0000000000000000a03",
        ),
        ("state", 2, "<status>creating", "<status>optimizing"),
        (
            "no state",
            0,
            "<status>in-use</status>",
            "<state>in-use</state>",
        ),
        ("no attachment set", 0, "<attachmentSet/>", "<attachments/>"),
        ("status", 3, "<status>warning", "<status>degraded"),
        ("no volume status", 3, "volumeStatus>", "volumeHealth>"),
        ("status volume ID", 4, "vol-00000000000000a99", "volume-a99"),
        (
            "two statuses",
            4,
            "vol-00000000000000a99",
            "vol-00000000000000a02",
        ),
        (
            "two rows",
            2,
            "vol-00000000000000a05",
            "vol-00000000000000a02",
        ),
        (
            "differing attachments across pages",
            2,
            "vol-00000000000000a06",
            "vol-00000000000000a04",
        ),
        ("volume set", 0, "volumeSet>", "volumes>"),
        ("status set", 3, "volumeStatusSet>", "statuses>"),
        ("padded state", 0, "<status>available", "<status> available"),
        (
            "state in upper case",
            2,
            "<status>creating",
            "<status>CREATING",
        ),
        ("padded status", 3, "<status>warning<", "<status>warning <"),
        (
            "status in upper case",
            3,
            "<status>warning",
            "<status>Warning",
        ),
        (
            "padded volume ID",
            1,
            "<volumeId>vol-00000000000000a03<",
            "<volumeId> vol-00000000000000a03<",
        ),
        (
            "volume ID in upper case",
            2,
            "vol-00000000000000a05",
            "VOL-00000000000000A05",
        ),
        (
            "padded status volume ID",
            4,
            "vol-00000000000000a99<",
            "vol-00000000000000a99\n<",
        ),
        (
            "status volume ID in upper case",
            3,
            "vol-00000000000000a02",
            "VOL-00000000000000A02",
        ),
        (
            "volume set in another letter case",
            0,
            "volumeSet>",
            "VolumeSet>",
        ),
        (
            "volume status in another letter case",
            3,
            "volumeStatus>",
            "VolumeStatus>",
        ),
        ("text in a set", 1, "<volumeSet>", "<volumeSet>text"),
        (
            "nested token",
            1,
            "<nextToken>eyJ2IjoyLCJjIjoiYTA0In0+/=</nextToken>",
            "<nextToken><token>eyJ2IjoyLCJjIjoiYTA0In0+/=</token></nextToken>",
        ),
    ];
    for (name, at, from, to) in cases {
        let (view, replay) = zone(zone_page(at, from, to), 3);
        assert_eq!(view, Err(Unlisted), "{name}");
        assert_eq!(replay.sent().len(), at + 1, "{name}");
    }
    let replay = Replay::new([]);
    let mut volumes = zoned(client(replay.clone(), "fake", DEADLINE), 3);
    assert_eq!(volumes.volumes(Zone(2)), Err(Unlisted));
    assert_eq!(volumes.volumes(Zone(0)), Err(Unlisted));
    assert!(replay.sent().is_empty());
}

/// Volumes in states `deleting` and `deleted` list with those states.
#[test]
fn deleting_and_deleted_volumes_list_with_their_states() {
    let mut answers = zone_page(0, "<status>available", "<status>deleting");
    answers[2] = zone_page(2, "<status>creating", "<status>deleted").remove(2);
    let view = zone(answers, 3).0.unwrap();
    let states: Vec<ListedVolumeState> = view.iter().map(|volume| volume.condition.state).collect();
    use ListedVolumeState::{Deleted, Deleting, Error, InUse};
    assert_eq!(states, [InUse, Deleting, Error, InUse, Deleted, InUse]);
}

/// Under each scripted fault of the client tests, a zone listing is unlisted
/// after one request, and a fault on the second page after one complete
/// page leaves it unlisted after two.
#[test]
fn every_scripted_fault_leaves_the_zone_unlisted_with_one_request_per_page() {
    let deadline = Duration::from_millis(500);
    assert_each_fault_unlisted(deadline, |client| zoned(client, 3).volumes(ZONE));
    let first = fixture("describe-volumes-zone-1.xml");
    let count = AtomicUsize::new(0);
    let server = serve(move |_| match count.fetch_add(1, Ordering::SeqCst) {
        0 => LoopbackAnswer::Reply(reply("200 OK", first.as_bytes())),
        _ => LoopbackAnswer::Reset(Vec::new()),
    });
    let mut volumes = zoned(client(Https::plain(), &server.host(), deadline), 3);
    assert_eq!(volumes.volumes(ZONE), Err(Unlisted));
    thread::sleep(Duration::from_millis(100));
    assert_eq!(server.served.requests(), 2);
}

/// The control for the paged one-attempt check: under the planted re-send
/// wire, a zone listing makes the server read two requests for one page.
#[test]
fn a_wire_that_sends_again_fails_the_one_attempt_check_under_a_zone_listing() {
    let twice = reset();
    let mut volumes = zoned(client(Resend(Https::plain()), &twice.host, DEADLINE), 3);
    assert_eq!(volumes.volumes(ZONE), Err(Unlisted));
    assert_eq!(
        twice.one_attempt(),
        Err("reset after the request: 2 requests, expected 1".to_owned())
    );
}

/// A listing whose first page takes 40 percent of the deadline gives the
/// second page, which stalls on a new connection, only the time left, so
/// the read returns within the wire's slack of its one deadline.
#[test]
fn the_pages_of_one_listing_share_its_deadline() {
    let deadline = Duration::from_secs(1);
    let first = fixture("describe-volumes-zone-1.xml");
    let count = AtomicUsize::new(0);
    let server = serve(move |_| match count.fetch_add(1, Ordering::SeqCst) {
        0 => {
            thread::sleep(deadline * 4 / 10);
            LoopbackAnswer::Reply(reply("200 OK", first.as_bytes()))
        }
        _ => silent(deadline * 2),
    });
    let mut volumes = zoned(client(Https::plain(), &server.host(), deadline), 3);
    let start = Instant::now();
    assert_eq!(volumes.volumes(ZONE), Err(Unlisted));
    let elapsed = start.elapsed();
    assert!(elapsed >= deadline, "{elapsed:?}");
    assert!(
        elapsed < deadline + Duration::from_millis(250),
        "{elapsed:?}"
    );
    assert_eq!(server.served.requests(), 2);
}

/// A read sends nothing once its deadline has passed. A first page that
/// arrives after the deadline is the read's last request: the read sends
/// neither the continuation page its token names nor, when the volume
/// listing ends on that page, the status listing.
#[test]
fn a_read_sends_no_page_after_its_deadline() {
    let deadline = Duration::from_millis(50);
    let bodies = zone_bodies();
    for (name, first) in [("continuation", &bodies[0]), ("status listing", &bodies[2])] {
        let replay = Replay::new([ok(first), ok(&bodies[1]), ok(&bodies[2])]);
        let wire = Delayed {
            inner: replay.clone(),
            delay: deadline + Duration::from_millis(10),
        };
        let mut volumes = zoned(client(wire, "fake", deadline), 3);
        assert_eq!(volumes.volumes(ZONE), Err(Unlisted), "{name}");
        assert_eq!(replay.actions(), ["DescribeVolumes"], "{name}");
    }
}

/// Every volume state lists with every status and with its attachment
/// records as the replies hold them, so no state decides a volume's
/// status or its attachments. For each state, one volume the status
/// listing leaves out reads `insufficient-data`. Half of the volumes have
/// IDs of one or two digits, which `VolumeId` accepts.
#[test]
fn every_state_lists_with_every_status_and_its_attachment_records() {
    use ListedVolumeState::{Available, Creating, Deleted, Deleting, Error, InUse};
    use VolumeStatus::{Impaired, InsufficientData, Ok, Warning};
    let states = [
        ("creating", Creating),
        ("available", Available),
        ("in-use", InUse),
        ("deleting", Deleting),
        ("deleted", Deleted),
        ("error", Error),
    ];
    let statuses = [
        (Some("ok"), Ok),
        (Some("warning"), Warning),
        (Some("impaired"), Impaired),
        (Some("insufficient-data"), InsufficientData),
        (None, InsufficientData),
    ];
    let records = ["i-0000000000000c001", "i-0000000000000c002", ""];
    let (mut rows, mut status_rows, mut expected) = (String::new(), String::new(), Vec::new());
    for (at, (state_text, state)) in states.iter().enumerate() {
        for (with, (status_text, status)) in statuses.iter().enumerate() {
            let number = at * statuses.len() + with + 1;
            let id = match number % 2 {
                0 => format!("vol-{number:017x}"),
                _ => format!("vol-{number:x}"),
            };
            let attachments = &records[..(at + with) % (records.len() + 1)];
            rows.push_str(&volume_row(&id, state_text, attachments));
            if let Some(status_text) = status_text {
                status_rows.push_str(&status_row(&id, status_text));
            }
            expected.push(listed(&id, *state, *status, attachments));
        }
    }
    let script = vec![
        ok(&format!(
            "<DescribeVolumesResponse><requestId>r</requestId><volumeSet>{rows}</volumeSet></DescribeVolumesResponse>"
        )),
        ok(&format!(
            "<DescribeVolumeStatusResponse><requestId>r</requestId><volumeStatusSet>{status_rows}</volumeStatusSet></DescribeVolumeStatusResponse>"
        )),
    ];
    assert_eq!(expected.len(), 30);
    assert_eq!(zone(script, 1).0, Result::Ok(expected));
}

/// Element order inside a reply may vary: a page whose token precedes its
/// set, and status items that hold `volumeId` last, read the same.
#[test]
fn a_reply_in_another_element_order_lists_the_same_view() {
    let (expected, _) = zone(zone_pages(), 3);
    let mut answers = zone_pages();
    let first = fixture("describe-volumes-zone-1.xml");
    let (head, rest) = first.split_once("<volumeSet>").unwrap();
    let (set, tail) = rest.split_once("</volumeSet>").unwrap();
    let (token, end) = tail.split_once("</nextToken>").unwrap();
    let reordered = format!("{head}{token}</nextToken><volumeSet>{set}</volumeSet>{end}");
    answers[0] = ok(&reordered);
    let mut status = fixture("describe-volume-status-zone-2.xml");
    for id in ["a04", "a06", "a99"] {
        let element = format!("<volumeId>vol-00000000000000{id}</volumeId>");
        let (before, after) = status.split_once(&element).unwrap();
        let (item, rest) = after.split_once("<actionsSet/>").unwrap();
        status = format!("{before}{item}<actionsSet/>{element}{rest}");
    }
    answers[4] = ok(&status);
    let (view, _) = zone(answers, 3);
    assert_eq!(view, expected);
    assert!(view.is_ok());
}

/// A page whose set is empty but which carries a token continues the read,
/// so an empty middle page truncates nothing, and the next request carries
/// that token.
#[test]
fn an_empty_page_with_a_token_continues_the_listing() {
    let empty = r#"<DescribeVolumesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
    <requestId>1b2c3d4e-0000-4000-8000-0000000000ff</requestId>
    <volumeSet/>
    <nextToken>ZW1wdHk=</nextToken>
</DescribeVolumesResponse>"#;
    let mut script = zone_pages();
    script.insert(1, ok(empty));
    let (view, replay) = zone(script, 4);
    assert_eq!(view, Ok(authored()));
    let sent = replay.sent();
    assert_paged(
        &sent[..4],
        "DescribeVolumes",
        "us-east-1a",
        "",
        "100",
        &[
            None,
            Some("eyJ2IjoyLCJjIjoiYTAyIn0%2B%2F%3D"),
            Some("ZW1wdHk%3D"),
            Some("eyJ2IjoyLCJjIjoiYTA0In0%2B%2F%3D"),
        ],
    );
    assert_paged(
        &sent[4..],
        "DescribeVolumeStatus",
        "us-east-1a",
        "",
        "1000",
        &[None, Some("c3RhdHVzLTI%3D")],
    );
}

/// A status repeated with the same value for one volume lists once.
#[test]
fn a_repeated_identical_status_lists_the_volume_once() {
    let script = zone_page(4, "vol-00000000000000a99", "vol-00000000000000a06");
    assert_eq!(zone(script, 3).0, Ok(authored()));
}

/// A client of a region whose name the zone's name does not extend in the
/// shape of an AWS zone name builds no zone adapter, so a client of another
/// region cannot answer the zone filter with an empty listing. The check
/// reads the names only; it does not show that the account has the zone.
#[test]
fn a_client_outside_the_zones_region_builds_no_zone_adapter() {
    assert_zone_names(|client, listing| Volumes::new(client).unwrap().for_zone(listing).is_some());
}

#[test]
fn a_client_of_another_service_builds_no_adapter() {
    let service = crate::loopback::client(
        Replay::default(),
        "fake".to_owned(),
        crate::loopback::refused(),
        Manual::at(crate::loopback::origin()),
        DEADLINE,
    );
    assert!(Volumes::new(service).is_none());
}

/// A volume row repeated unchanged on a later page lists as reported, so
/// only differing repeats refuse the view.
#[test]
fn an_identical_repeated_volume_row_lists_as_reported() {
    let row = volume_row("vol-00000000000000a01", "in-use", &["i-0000000000000a001"]);
    let view = zone(with_third_page_row(&row), 3).0.unwrap();
    assert_eq!(view.len(), 7);
    assert_eq!(view[4], view[0]);
}

/// A volume row repeated on a later page with the same attachment entries
/// in another order lists as reported; a repeat with the same instances
/// but one entry counted twice leaves the zone unlisted after the page
/// that holds it.
#[test]
fn a_repeated_row_with_its_attachments_reordered_lists_as_reported() {
    let (a03, a04) = ("i-0000000000000a003", "i-0000000000000a004");
    let reordered = volume_row("vol-00000000000000a03", "error", &[a04, a03]);
    let view = zone(with_third_page_row(&reordered), 3).0.unwrap();
    assert_eq!(view.len(), 7);
    assert_eq!(view[4].volume, view[2].volume);
    assert_eq!(view[2].attachments, [a03, a04]);
    assert_eq!(view[4].attachments, [a04, a03]);
    let counted = volume_row("vol-00000000000000a03", "error", &[a03, a03, a04]);
    let (view, replay) = zone(with_third_page_row(&counted), 3);
    assert_eq!(view, Err(Unlisted));
    assert_eq!(replay.sent().len(), 3);
}

/// An empty zone lists as an empty view after one request of each action,
/// and every request names the local zone's name in its filter.
#[test]
fn an_empty_local_zone_lists_an_empty_view() {
    let replay = Replay::new([
        ok(
            "<DescribeVolumesResponse><requestId>r</requestId><volumeSet/></DescribeVolumesResponse>",
        ),
        ok(
            "<DescribeVolumeStatusResponse><requestId>r</requestId><volumeStatusSet/></DescribeVolumeStatusResponse>",
        ),
    ]);
    let client = client(replay.clone(), "fake", DEADLINE);
    let mut volumes = Volumes::new(client)
        .unwrap()
        .for_zone(listing_named("us-east-1-bos-1a", 3))
        .unwrap();
    assert_eq!(volumes.volumes(ZONE), Ok(Vec::new()));
    let sent = replay.sent();
    assert_paged(
        &sent[..1],
        "DescribeVolumes",
        "us-east-1-bos-1a",
        "",
        "100",
        &[None],
    );
    assert_paged(
        &sent[1..],
        "DescribeVolumeStatus",
        "us-east-1-bos-1a",
        "",
        "1000",
        &[None],
    );
}

/// A multi-page listing of a local zone names that zone in the filter of
/// every request of both actions, continuation requests included.
#[test]
fn a_local_zone_listing_names_its_zone_on_every_page() {
    let name = "us-east-1-bos-1a";
    let bodies: Vec<String> = zone_bodies()
        .iter()
        .map(|body| body.replace("us-east-1a<", &format!("{name}<")))
        .collect();
    let (view, replay) = zone_in(name, answers(&bodies), 3);
    assert_eq!(view, Ok(authored()));
    let sent = replay.sent();
    assert_paged(
        &sent[..3],
        "DescribeVolumes",
        name,
        "",
        "100",
        &[
            None,
            Some("eyJ2IjoyLCJjIjoiYTAyIn0%2B%2F%3D"),
            Some("eyJ2IjoyLCJjIjoiYTA0In0%2B%2F%3D"),
        ],
    );
    assert_paged(
        &sent[3..],
        "DescribeVolumeStatus",
        name,
        "",
        "1000",
        &[None, Some("c3RhdHVzLTI%3D")],
    );
}

/// A read after a read that failed on its first status page starts again
/// from the first volume page with no token and lists the healthy view,
/// with nothing kept from the failed read.
#[test]
fn a_read_after_an_unlisted_read_starts_from_the_first_page() {
    let mut script = zone_page(0, "i-0000000000000a001", "i-0000000000000b001");
    script.truncate(3);
    script.push(Answer::Reply(503, fixture("request-limit-exceeded.xml")));
    script.extend(zone_pages());
    let replay = Replay::new(script);
    let mut volumes = zoned(client(replay.clone(), "fake", DEADLINE), 3);
    assert_eq!(volumes.volumes(ZONE), Err(Unlisted));
    assert_eq!(replay.sent().len(), 4);
    assert_eq!(volumes.volumes(ZONE), Ok(authored()));
    let sent = replay.sent();
    assert_paged(
        &sent[4..7],
        "DescribeVolumes",
        "us-east-1a",
        "",
        "100",
        &[
            None,
            Some("eyJ2IjoyLCJjIjoiYTAyIn0%2B%2F%3D"),
            Some("eyJ2IjoyLCJjIjoiYTA0In0%2B%2F%3D"),
        ],
    );
    assert_paged(
        &sent[7..],
        "DescribeVolumeStatus",
        "us-east-1a",
        "",
        "1000",
        &[None, Some("c3RhdHVzLTI%3D")],
    );
}

/// A full page of the size a zone read asks for, whose volumes each carry
/// 50 tags with keys of 128 `k` characters and 256-character values, arrives
/// within the EC2 body cap and lists. The same page with tag text of
/// `&amp;` (the XML encoding of `&`) or of
/// four-byte characters passes the cap, and the read is unlisted after
/// that page.
#[test]
fn a_full_page_of_one_byte_tag_characters_fits_the_body_cap() {
    let per_page: usize = ZONE_VOLUMES.per_page.parse().unwrap();
    let page = |character: &str| {
        let tag = format!(
            "<item><key>{}</key><value>{}</value></item>",
            character.repeat(128),
            character.repeat(256)
        );
        let mut body = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<DescribeVolumesResponse xmlns=\"http://ec2.amazonaws.com/doc/2016-11-15/\"><requestId>r</requestId><volumeSet>",
        );
        for id in 1..=per_page {
            body.push_str(&format!(
                "<item><volumeId>vol-{id:017x}</volumeId><size>500</size><snapshotId/><availabilityZone>us-east-1a</availabilityZone><status>in-use</status><createTime>2026-01-01T00:00:00.000Z</createTime><attachmentSet><item><volumeId>vol-{id:017x}</volumeId><instanceId>i-{id:017x}</instanceId><device>/dev/sdf</device><status>attached</status><attachTime>2026-01-01T00:01:00.000Z</attachTime><deleteOnTermination>false</deleteOnTermination></item></attachmentSet><tagSet>{}</tagSet><volumeType>io2</volumeType><iops>16000</iops><encrypted>true</encrypted><multiAttachEnabled>true</multiAttachEnabled></item>",
                tag.repeat(50)
            ));
        }
        body.push_str("</volumeSet></DescribeVolumesResponse>");
        body
    };
    let read = |body: String| {
        let statuses = "<DescribeVolumeStatusResponse><requestId>r</requestId><volumeStatusSet/></DescribeVolumeStatusResponse>";
        let count = AtomicUsize::new(0);
        let server = serve(move |_| match count.fetch_add(1, Ordering::SeqCst) {
            0 => LoopbackAnswer::Reply(reply("200 OK", body.as_bytes())),
            _ => LoopbackAnswer::Reply(reply("200 OK", statuses.as_bytes())),
        });
        let client = client_in(
            "us-east-1",
            Https::plain(),
            &server.host(),
            Duration::from_secs(10),
            EC2.body_cap,
            held(),
            Manual::at(origin()),
        );
        let view = zoned(client, 3).volumes(ZONE);
        thread::sleep(Duration::from_millis(100));
        (view, server)
    };
    let plain = page("k");
    assert!(plain.len() > EC2.body_cap / 2 && plain.len() < EC2.body_cap);
    let (view, server) = read(plain);
    assert_eq!(view.map(|view| view.len()), Ok(per_page));
    assert_eq!(server.served.requests(), 2);
    let first = String::from_utf8(server.served.bodies()[0].clone()).unwrap();
    assert!(
        first.contains(&format!("&MaxResults={per_page}")),
        "{first}"
    );
    for character in ["&amp;", "\u{1D538}"] {
        let past = page(character);
        assert!(past.len() > EC2.body_cap, "{character}");
        let (view, server) = read(past);
        assert_eq!(view, Err(Unlisted), "{character}");
        assert_eq!(server.served.requests(), 1, "{character}");
    }
}
