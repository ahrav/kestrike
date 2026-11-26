use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kestrike::failover::attachments::{InstanceId, Unlisted};
use kestrike::failover::standbys::Zone;
use kestrike::failover::zone_loop::evidence::{Instance, InstanceState, StatusCheck};
use kestrike::failover::zone_loop::sources::InstanceSource;

use super::Instances;
use crate::credentials::Role;
use crate::ec2::replay::{
    Answer, Replay, ZONE, adverse, answers, assert_each_fault_unlisted, assert_paged,
    assert_zone_names, client, client_in, edited, fixture, listing, listing_named, listing_of, ok,
    prepended, unusable,
};
use crate::loopback::{Credentials, Manual, metadata, origin, refused};

const DEADLINE: Duration = Duration::from_secs(1);

const SET: &str = "instanceStatusSet";

fn bodies() -> Vec<String> {
    (1..=3)
        .map(|page| fixture(&format!("describe-instance-status-zone-{page}.xml")))
        .collect()
}

fn pages() -> Vec<Answer> {
    answers(&bodies())
}

fn read(answers: Vec<Answer>, bound: u16) -> (Result<Vec<Instance>, Unlisted>, Replay) {
    read_in("us-east-1a", answers, bound)
}

/// A read of the zone named `name` with at most `bound` pages.
fn read_in(
    name: &str,
    answers: Vec<Answer>,
    bound: u16,
) -> (Result<Vec<Instance>, Unlisted>, Replay) {
    let replay = Replay::new(answers);
    let client = client(replay.clone(), "fake", DEADLINE);
    let mut instances = Instances::new(client, listing_named(name, bound)).unwrap();
    (instances.instances(ZONE), replay)
}

/// The view of the authored pages, which a test compares a read against.
fn authored() -> Vec<Instance> {
    read(pages(), 3).0.unwrap()
}

fn instance(id: &str, state: InstanceState, system: StatusCheck, own: StatusCheck) -> Instance {
    Instance {
        instance: InstanceId::new(id).unwrap(),
        state,
        system_check: system,
        instance_check: own,
    }
}

/// One instance row in the authored shape: its state code and name, and
/// for each of the system and instance checks a summary status and its
/// reachability detail.
fn row(id: &str, (code, name): (u8, &str), system: (&str, &str), own: (&str, &str)) -> String {
    let check = |element: &str, (summary, detail): (&str, &str)| {
        format!(
            "<{element}><status>{summary}</status><details><item><name>reachability</name><status>{detail}</status></item></details></{element}>"
        )
    };
    format!(
        "<item><instanceId>{id}</instanceId><availabilityZone>us-east-1a</availabilityZone><instanceState><code>{code}</code><name>{name}</name></instanceState>{}{}<eventsSet/></item>",
        check("systemStatus", system),
        check("instanceStatus", own)
    )
}

/// A one-page reply holding `rows`.
fn single(rows: &str) -> String {
    format!(
        "<DescribeInstanceStatusResponse><requestId>r</requestId><{SET}>{rows}</{SET}></DescribeInstanceStatusResponse>"
    )
}

/// Three authored pages, each following the previous page's token, give one
/// view in reply order with every instance state and every status check as
/// reported. Each page is one request that asks for all instances with the
/// zone filter, and the three share the read's one deadline.
#[test]
fn a_zone_listing_holds_every_instance_page_as_reported() {
    use InstanceState::{Pending, Running, ShuttingDown, Stopped, Stopping, Terminated};
    use StatusCheck::{Impaired, Initializing, InsufficientData, NotApplicable, Ok};
    let start = Instant::now();
    let (view, replay) = read(pages(), 3);
    let end = Instant::now();
    assert_eq!(
        view.unwrap(),
        [
            instance("i-0000000000000a001", Running, Ok, Ok),
            instance("i-0000000000000a002", Running, Impaired, Ok),
            instance("i-0000000000000a003", Running, Ok, Initializing),
            instance(
                "i-0000000000000a004",
                Stopping,
                NotApplicable,
                NotApplicable
            ),
            instance("i-0000000000000a005", Stopped, NotApplicable, NotApplicable),
            instance("i-1a2b3c4d", Running, InsufficientData, Impaired),
            instance(
                "i-0000000000000a006",
                ShuttingDown,
                NotApplicable,
                NotApplicable
            ),
            instance(
                "i-0000000000000a007",
                Terminated,
                NotApplicable,
                NotApplicable
            ),
            instance("i-0000000000000a008", Pending, Initializing, Initializing),
        ]
    );
    assert_eq!(replay.actions(), ["DescribeInstanceStatus"; 3]);
    let sent = replay.sent();
    assert_paged(
        &sent,
        "DescribeInstanceStatus",
        "us-east-1a",
        "&IncludeAllInstances=true",
        "1000",
        &[None, Some("aW5zdGFuY2VzLTI%3D"), Some("aW5zdGFuY2VzLTM%3D")],
    );
    let deadline = sent[0].deadline;
    assert!(sent.iter().all(|request| request.deadline == deadline));
    assert!(start + DEADLINE <= deadline && deadline <= end + DEADLINE);
}

/// A fault on any page leaves the whole listing unlisted, never a listing
/// with instances missing, and the read sends no page after the faulted
/// one.
#[test]
fn a_fault_on_any_page_leaves_the_instances_unlisted() {
    let bodies = bodies();
    let mut ran = 0;
    for (at, body) in bodies.iter().enumerate() {
        for (name, fault) in adverse(body) {
            let mut script = answers(&bodies[..at]);
            script.push(fault);
            let (view, replay) = read(script, 3);
            assert_eq!(view, Err(Unlisted), "{name} on page {at}");
            assert_eq!(replay.sent().len(), at + 1, "{name} on page {at}");
            ran += 1;
        }
    }
    assert_eq!(ran, 24);
}

/// A first page of any status but 200 leaves the listing unlisted
/// whatever its body, an instance listing included, and so does a call
/// lost in any way. Each read sends one request, so no status and no kind
/// of loss is sent again or read as an empty page.
#[test]
fn every_other_status_and_every_lost_call_leaves_the_instances_unlisted() {
    let (names, answers): (Vec<String>, Vec<Answer>) =
        unusable(&fixture("describe-instance-status-zone-3.xml"))
            .into_iter()
            .unzip();
    let replay = Replay::new(answers);
    let mut instances =
        Instances::new(client(replay.clone(), "fake", DEADLINE), listing(3)).unwrap();
    for (at, name) in names.iter().enumerate() {
        assert_eq!(instances.instances(ZONE), Err(Unlisted), "{name}");
        assert_eq!(replay.count(), at + 1, "{name}");
    }
}

#[test]
fn a_page_set_past_the_bound_is_unlisted_without_its_last_page() {
    let (view, replay) = read(pages(), 2);
    assert_eq!(view, Err(Unlisted));
    assert_eq!(replay.sent().len(), 2);
}

/// An instance ID `InstanceId` refuses, an undocumented state or check, an
/// instance without its state or a check, a page without its set, a set or
/// a state holding text, and a token holding an element each leave the
/// listing unlisted, and the read sends no page after the refused one. A
/// zone other than the configured one is unlisted before any request.
#[test]
fn an_unreadable_value_leaves_the_instances_unlisted() {
    let cases = [
        ("instance ID", "i-1a2b3c4d", "i-1A2B3C4D"),
        ("state name", "<name>stopped", "<name>hibernated"),
        ("check", "<status>impaired", "<status>degraded"),
        ("system check", "systemStatus>", "systemHealth>"),
        ("instance check", "instanceStatus>", "instanceHealth>"),
        ("state", "instanceState>", "instanceStage>"),
        ("set", "instanceStatusSet>", "instances>"),
        (
            "text in the set",
            "<instanceStatusSet>",
            "<instanceStatusSet>text",
        ),
        ("text in a state", "<instanceState>", "<instanceState>text"),
        ("padded instance ID", "i-1a2b3c4d<", "i-1a2b3c4d <"),
        ("padded state name", "<name>stopped", "<name> stopped"),
        ("state name in upper case", "<name>stopped", "<name>Stopped"),
        ("padded check", "<status>impaired<", "<status>impaired\n<"),
        (
            "check in upper case",
            "<status>impaired",
            "<status>IMPAIRED",
        ),
        (
            "instance ID element in another letter case",
            "instanceId>",
            "InstanceId>",
        ),
        (
            "nested token",
            "<nextToken>aW5zdGFuY2VzLTM=</nextToken>",
            "<nextToken><token>aW5zdGFuY2VzLTM=</token></nextToken>",
        ),
    ];
    let bodies = bodies();
    for (name, from, to) in cases {
        let (view, replay) = read(edited(&bodies, 1, from, to), 3);
        assert_eq!(view, Err(Unlisted), "{name}");
        assert_eq!(replay.sent().len(), 2, "{name}");
    }
    let replay = Replay::new([]);
    let mut instances =
        Instances::new(client(replay.clone(), "fake", DEADLINE), listing(3)).unwrap();
    assert_eq!(instances.instances(Zone(2)), Err(Unlisted));
    assert_eq!(instances.instances(Zone(0)), Err(Unlisted));
    assert!(replay.sent().is_empty());
}

/// Under each scripted fault of the client tests, an instance listing is
/// unlisted after one send that ends as the fault scripts.
#[test]
fn every_scripted_fault_leaves_the_instances_unlisted_after_one_request() {
    assert_each_fault_unlisted(Duration::from_millis(500), |client| {
        Instances::new(client, listing(3)).unwrap().instances(ZONE)
    });
}

/// A page whose set is empty but which carries a token continues the read,
/// and the next request carries that token.
#[test]
fn an_empty_page_with_a_token_continues_the_instances() {
    let empty = r#"<DescribeInstanceStatusResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
    <requestId>3d4e5f60-0000-4000-8000-0000000000ff</requestId>
    <instanceStatusSet/>
    <nextToken>ZW1wdHk=</nextToken>
</DescribeInstanceStatusResponse>"#;
    let mut script = pages();
    script.insert(1, ok(empty));
    let (view, replay) = read(script, 4);
    assert_eq!(view, Ok(authored()));
    assert_paged(
        &replay.sent(),
        "DescribeInstanceStatus",
        "us-east-1a",
        "&IncludeAllInstances=true",
        "1000",
        &[
            None,
            Some("aW5zdGFuY2VzLTI%3D"),
            Some("ZW1wdHk%3D"),
            Some("aW5zdGFuY2VzLTM%3D"),
        ],
    );
}

/// A client of another service, or of a region whose name the zone's name
/// does not extend in the shape of an AWS zone name, builds no instance
/// adapter.
#[test]
fn a_client_of_another_service_or_region_builds_no_instance_adapter() {
    assert_zone_names(|client, listing| Instances::new(client, listing).is_some());
    let service = crate::loopback::client(
        Replay::default(),
        "fake".to_owned(),
        refused(),
        Manual::at(origin()),
        DEADLINE,
    );
    assert!(Instances::new(service, listing(3)).is_none());
}

/// An instance row repeated unchanged on a later page lists again in reply
/// order. A repeat on a page that carries a token, which differs in its
/// state, in either check, or in one check while both fold to the same
/// `Instance::checks`, leaves the listing unlisted with no later page sent.
/// Each differing row lists on its own.
#[test]
fn a_repeated_instance_row_lists_again_and_a_differing_one_is_unlisted() {
    let bodies = bodies();
    let repeated = |row: &str| {
        let mut bodies = bodies.clone();
        bodies[1] = prepended(&bodies[1], SET, row);
        read(answers(&bodies), 3)
    };
    let first = ("i-0000000000000a001", (16, "running"));
    let same = row(first.0, first.1, ("ok", "passed"), ("ok", "passed"));
    let mut expected = authored();
    let copy = expected[0];
    expected.insert(3, copy);
    let (view, replay) = repeated(&same);
    assert_eq!(view, Ok(expected));
    assert_eq!(replay.sent().len(), 3);
    let second = "i-0000000000000a002";
    let cases = [
        (
            "state",
            row(
                first.0,
                (64, "stopping"),
                ("ok", "passed"),
                ("ok", "passed"),
            ),
        ),
        (
            "system check",
            row(first.0, first.1, ("impaired", "failed"), ("ok", "passed")),
        ),
        (
            "instance check",
            row(first.0, first.1, ("ok", "passed"), ("impaired", "failed")),
        ),
        (
            "instance check under an impaired system check",
            row(
                second,
                (16, "running"),
                ("impaired", "failed"),
                ("initializing", "initializing"),
            ),
        ),
    ];
    for (name, differing) in &cases {
        let (alone, _) = read(vec![ok(&single(differing))], 1);
        assert_eq!(alone.map(|view| view.len()), Ok(1), "{name}");
        let (view, replay) = repeated(differing);
        assert_eq!(view, Err(Unlisted), "{name}");
        assert_eq!(replay.sent().len(), 2, "{name}");
    }
    let folded = read(vec![ok(&single(&cases[3].1))], 1).0.unwrap()[0];
    assert_eq!(folded.checks(), authored()[1].checks());
}

/// An empty zone lists as an empty view after one request that names the
/// local zone's name in its filter.
#[test]
fn an_empty_local_zone_lists_an_empty_view() {
    let (view, replay) = read_in("us-east-1-bos-1a", vec![ok(&single(""))], 3);
    assert_eq!(view, Ok(Vec::new()));
    assert_paged(
        &replay.sent(),
        "DescribeInstanceStatus",
        "us-east-1-bos-1a",
        "&IncludeAllInstances=true",
        "1000",
        &[None],
    );
}

/// A multi-page listing of a local zone names that zone in the filter of
/// every request, continuation requests included.
#[test]
fn a_local_zone_listing_names_its_zone_on_every_page() {
    let name = "us-east-1-bos-1a";
    let bodies: Vec<String> = bodies()
        .iter()
        .map(|body| body.replace("us-east-1a<", &format!("{name}<")))
        .collect();
    let (view, replay) = read_in(name, answers(&bodies), 3);
    assert_eq!(view, Ok(authored()));
    assert_paged(
        &replay.sent(),
        "DescribeInstanceStatus",
        name,
        "&IncludeAllInstances=true",
        "1000",
        &[None, Some("aW5zdGFuY2VzLTI%3D"), Some("aW5zdGFuY2VzLTM%3D")],
    );
}

/// A read after an unlisted read starts again from the first page with no
/// token and lists the healthy view.
#[test]
fn a_read_after_an_unlisted_read_starts_from_the_first_page() {
    let bodies = bodies();
    let mut script = edited(&bodies, 0, "i-0000000000000a001", "i-0000000000000b001");
    script.truncate(1);
    script.push(Answer::Reply(500, fixture("internal-error.xml")));
    script.extend(pages());
    let replay = Replay::new(script);
    let mut instances =
        Instances::new(client(replay.clone(), "fake", DEADLINE), listing(3)).unwrap();
    assert_eq!(instances.instances(ZONE), Err(Unlisted));
    assert_eq!(replay.sent().len(), 2);
    assert_eq!(instances.instances(ZONE), Ok(authored()));
    assert_paged(
        &replay.sent()[2..],
        "DescribeInstanceStatus",
        "us-east-1a",
        "&IncludeAllInstances=true",
        "1000",
        &[None, Some("aW5zdGFuY2VzLTI%3D"), Some("aW5zdGFuY2VzLTM%3D")],
    );
}

/// Each read of one adapter lists only its own replies, under its own
/// deadline. After a read of the authored pages, a read whose one page
/// holds the first instance in another state and one new instance lists
/// exactly those two. A read that fails after it is unlisted, and the read
/// after that lists the authored pages again.
#[test]
fn each_instance_read_lists_its_own_replies_and_a_failed_read_is_unlisted() {
    use InstanceState::{Running, Stopped};
    use StatusCheck::{NotApplicable, Ok};
    let rows = [
        row(
            "i-0000000000000a001",
            (80, "stopped"),
            ("not-applicable", "not-applicable"),
            ("not-applicable", "not-applicable"),
        ),
        row(
            "i-0000000000000b001",
            (16, "running"),
            ("ok", "passed"),
            ("ok", "passed"),
        ),
    ];
    let mut script = pages();
    script.push(ok(&single(&rows.concat())));
    script.push(Answer::Reply(503, fixture("request-limit-exceeded.xml")));
    script.extend(pages());
    let replay = Replay::new(script);
    let mut instances =
        Instances::new(client(replay.clone(), "fake", DEADLINE), listing(3)).unwrap();
    let changed = vec![
        instance("i-0000000000000a001", Stopped, NotApplicable, NotApplicable),
        instance("i-0000000000000b001", Running, Ok, Ok),
    ];
    let mut starts = vec![Instant::now()];
    assert_eq!(instances.instances(ZONE), Result::Ok(authored()));
    starts.push(Instant::now());
    assert_eq!(instances.instances(ZONE), Result::Ok(changed));
    starts.push(Instant::now());
    assert_eq!(instances.instances(ZONE), Err(Unlisted));
    starts.push(Instant::now());
    assert_eq!(instances.instances(ZONE), Result::Ok(authored()));
    let end = Instant::now();
    let sent = replay.sent();
    let reads = [&sent[..3], &sent[3..4], &sent[4..5], &sent[5..]];
    assert_eq!(reads[3].len(), 3);
    for (read, start) in reads.iter().zip(&starts) {
        let deadline = read[0].deadline;
        assert!(read.iter().all(|request| request.deadline == deadline));
        assert!(*start + DEADLINE <= deadline && deadline <= end + DEADLINE);
    }
}

/// A view holds every row its replies hold, whatever zone a row names:
/// the authored pages list the same view when their rows name another
/// zone and when they name none.
#[test]
fn a_row_lists_whatever_zone_it_names() {
    let named = "<availabilityZone>us-east-1a</availabilityZone>";
    for other in ["<availabilityZone>us-east-1b</availabilityZone>", ""] {
        let renamed = |body: &String| {
            assert!(body.contains(named));
            body.replace(named, other)
        };
        let bodies: Vec<String> = bodies().iter().map(renamed).collect();
        assert_eq!(read(answers(&bodies), 3).0, Ok(authored()), "{other}");
    }
}

/// A read takes a row by the elements it names and an instance's state
/// by its name: the authored pages list the same view when every row and
/// check detail also holds an element the adapter never reads, every row
/// holds a scheduled event and an impaired attached-EBS status, and each
/// state code has a bit of its high byte set.
#[test]
fn a_row_with_an_extra_element_or_another_state_code_lists_the_same() {
    let extra = "<item><futureField><nested>x</nested></futureField>";
    let event = "<item><code>instance-retirement</code><description>x</description></item>";
    let ebs = "<attachedEbsStatus>\n                <status>ok</status>";
    let bodies: Vec<String> = bodies()
        .iter()
        .map(|body| {
            assert!(body.contains(ebs));
            body.replace("<eventsSet/>", &format!("<eventsSet>{event}</eventsSet>"))
                .replace(ebs, &ebs.replace("ok", "impaired"))
                .replace("<item>", extra)
                .replace("<code>16</code>", "<code>272</code>")
                .replace("<code>80</code>", "<code>336</code>")
                .replace("<code>48</code>", "<code>304</code>")
        })
        .collect();
    assert!(bodies.iter().all(|body| body.contains(extra)));
    assert!(bodies[0].contains("<code>272</code>"));
    assert_eq!(read(answers(&bodies), 3).0, Ok(authored()));
}

/// A view holds every instance of a listing longer than a page: 1,500
/// instances on a page of 1,000 and a page of 500 list as 1,500 rows in
/// reply order.
#[test]
fn a_listing_of_fifteen_hundred_instances_lists_every_instance() {
    use InstanceState::Running;
    use StatusCheck::Ok;
    let ids: Vec<String> = (1..=1500).map(|at| format!("i-{at:017x}")).collect();
    let rows = |ids: &[String]| -> String {
        ids.iter()
            .map(|id| row(id, (16, "running"), ("ok", "passed"), ("ok", "passed")))
            .collect()
    };
    let first = format!(
        "<DescribeInstanceStatusResponse><{SET}>{}</{SET}><nextToken>page-2</nextToken></DescribeInstanceStatusResponse>",
        rows(&ids[..1000])
    );
    let expected: Vec<Instance> = ids.iter().map(|id| instance(id, Running, Ok, Ok)).collect();
    let (view, replay) = read(vec![ok(&first), ok(&single(&rows(&ids[1000..])))], 2);
    assert_eq!(view, Result::Ok(expected));
    assert_eq!(replay.sent().len(), 2);
}

/// An adapter reads the zone its listing is configured for, by number: one
/// configured for zone 7 lists zone 7 and refuses zone 1 before any
/// request.
#[test]
fn an_adapter_reads_the_zone_number_it_is_configured_for() {
    let replay = Replay::new([ok(&bodies()[2])]);
    let listing = listing_of(Zone(7), "us-east-1c", 1);
    let mut instances = Instances::new(client(replay.clone(), "fake", DEADLINE), listing).unwrap();
    assert_eq!(instances.instances(ZONE), Err(Unlisted));
    assert_eq!(replay.count(), 0);
    assert_eq!(instances.instances(Zone(7)).map(|view| view.len()), Ok(3));
    assert_paged(
        &replay.sent(),
        "DescribeInstanceStatus",
        "us-east-1c",
        "&IncludeAllInstances=true",
        "1000",
        &[None],
    );
}

/// In every state, a row that lacks an element the read takes, or holds
/// it empty, leaves the listing unlisted: no state stands in for a
/// missing instance ID, state name or status check. Each row lists before
/// the element is taken out.
#[test]
fn a_row_without_an_element_it_needs_is_unlisted_in_every_state() {
    let id = "i-0000000000000b001";
    let states = [
        (0, "pending"),
        (16, "running"),
        (32, "shutting-down"),
        (48, "terminated"),
        (64, "stopping"),
        (80, "stopped"),
    ];
    let mut ran = 0;
    for state in states {
        let row = row(id, state, ("ok", "passed"), ("impaired", "failed"));
        let whole = read(vec![ok(&single(&row))], 1).0;
        assert_eq!(whole.map(|view| view.len()), Ok(1), "{}", state.1);
        let without = |open: &str, close: &str| {
            let (before, after) = row.split_once(open).unwrap();
            let (_, after) = after.split_once(close).unwrap();
            format!("{before}{after}")
        };
        let named = format!("<instanceId>{id}</instanceId>");
        let stated = format!("<name>{}</name>", state.1);
        let system = "<systemStatus><status>ok</status>";
        let own = "<instanceStatus><status>impaired</status>";
        for broken in [
            row.replacen(&named, "", 1),
            row.replacen(&named, "<instanceId/>", 1),
            row.replacen(&stated, "", 1),
            row.replacen(&stated, "<name/>", 1),
            without("<instanceState>", "</instanceState>"),
            row.replacen(system, "<systemStatus>", 1),
            row.replacen(system, "<systemStatus><status/>", 1),
            without("<systemStatus>", "</systemStatus>"),
            row.replacen(own, "<instanceStatus>", 1),
            row.replacen(own, "<instanceStatus><status/>", 1),
            without("<instanceStatus>", "</instanceStatus>"),
        ] {
            assert_ne!(broken, row);
            let (view, replay) = read(vec![ok(&single(&broken))], 1);
            assert_eq!(view, Err(Unlisted), "{}: {broken}", state.1);
            assert_eq!(replay.count(), 1);
            ran += 1;
        }
    }
    assert_eq!(ran, 6 * 11);
}

/// Every instance state lists with every pair of status checks as the
/// reply holds them, so no state decides an instance's checks. Each check
/// holds a failed detail under its summary, so the view shows that it
/// takes the summary.
#[test]
fn every_state_lists_with_every_pair_of_checks() {
    use InstanceState::{Pending, Running, ShuttingDown, Stopped, Stopping, Terminated};
    use StatusCheck::{Impaired, Initializing, InsufficientData, NotApplicable, Ok};
    let states = [
        ((0, "pending"), Pending),
        ((16, "running"), Running),
        ((32, "shutting-down"), ShuttingDown),
        ((48, "terminated"), Terminated),
        ((64, "stopping"), Stopping),
        ((80, "stopped"), Stopped),
    ];
    let checks = [
        ("ok", Ok),
        ("impaired", Impaired),
        ("insufficient-data", InsufficientData),
        ("initializing", Initializing),
        ("not-applicable", NotApplicable),
    ];
    let (mut rows, mut expected) = (String::new(), Vec::new());
    for (state_text, state) in states {
        for (system_text, system) in checks {
            for (own_text, own) in checks {
                let id = format!("i-{:017x}", expected.len() + 1);
                let failed = |summary: &'static str| (summary, "failed");
                rows.push_str(&row(&id, state_text, failed(system_text), failed(own_text)));
                expected.push(instance(&id, state, system, own));
            }
        }
    }
    assert_eq!(expected.len(), 150);
    assert_eq!(read(vec![ok(&single(&rows))], 1).0, Result::Ok(expected));
}

/// A page bound above 255 is honored in full: a listing of 300 pages lists
/// under a bound of 300 after 300 requests, and is unlisted under a bound
/// of 299 after 299.
#[test]
fn a_bound_of_three_hundred_pages_admits_three_hundred_pages() {
    let last = single(&row(
        "i-0000000000000a001",
        (16, "running"),
        ("ok", "passed"),
        ("ok", "passed"),
    ));
    let script = || {
        let empty = (1..300).map(|page| {
            ok(&format!(
                "<DescribeInstanceStatusResponse><{SET}/><nextToken>page-{page}</nextToken></DescribeInstanceStatusResponse>"
            ))
        });
        empty.chain([ok(&last)]).collect::<Vec<Answer>>()
    };
    let (view, replay) = read(script(), 300);
    assert_eq!(view.map(|view| view.len()), Ok(1));
    assert_eq!(replay.sent().len(), 300);
    let (view, replay) = read(script(), 299);
    assert_eq!(view, Err(Unlisted));
    assert_eq!(replay.sent().len(), 299);
}

/// An unusable answer on a later page leaves the listing unlisted too:
/// after each prefix of whole pages, every status but 200 and every lost
/// call is unlisted, and the read sends no page after it, so no status
/// and no kind of loss ends a listing early.
#[test]
fn every_other_status_and_every_lost_call_on_a_later_page_leaves_the_instances_unlisted() {
    let page = |token: &str| {
        format!(
            "<DescribeInstanceStatusResponse><{SET}/><nextToken>{token}</nextToken></DescribeInstanceStatusResponse>"
        )
    };
    let pages = [page("a"), page("b"), page("")];
    let (whole, replay) = read(answers(&pages), 3);
    assert_eq!(whole, Ok(Vec::new()));
    assert_eq!(replay.count(), 3);
    for at in 1..pages.len() {
        let (names, unusable): (Vec<String>, Vec<Answer>) =
            unusable(&pages[at]).into_iter().unzip();
        let script = unusable
            .into_iter()
            .flat_map(|answer| answers(&pages[..at]).into_iter().chain([answer]));
        let replay = Replay::new(script);
        let mut instances =
            Instances::new(client(replay.clone(), "fake", DEADLINE), listing(3)).unwrap();
        for (read, name) in names.iter().enumerate() {
            assert_eq!(
                instances.instances(ZONE),
                Err(Unlisted),
                "{name} on page {at}"
            );
            assert_eq!(replay.count(), (read + 1) * (at + 1), "{name} on page {at}");
        }
    }
}

/// The pages of one read share one refresh attempt while the held
/// credentials are unexpired. A cold read fetches credentials inside the
/// refresh margin on its first page, and its later pages sign with them.
/// With the metadata service silent, a later read's first page waits for
/// one refresh and its later pages sign with the held credentials, so the
/// read lists. When the held credentials expire between pages, the next
/// page refreshes again, and the read is unlisted when that refresh fails.
#[test]
fn the_pages_of_one_read_share_one_refresh_attempt() {
    let credentials = Arc::new(Mutex::new(Credentials::Serve {
        key: "AKIDNEAR",
        expiry: origin() + Duration::from_secs(5 * 60),
    }));
    let service = metadata(Arc::clone(&credentials));
    let replay = Replay::new(pages().into_iter().chain(pages()).chain(pages()));
    let clock = Manual::at(origin());
    let client = client_in(
        "us-east-1",
        replay.clone(),
        "fake",
        DEADLINE,
        1024 * 1024,
        Role::at(service.address),
        clock.clone(),
    );
    let mut instances = Instances::new(client, listing(3)).unwrap();
    assert!(instances.instances(ZONE).is_ok());
    assert_eq!(service.served.await_requests(3), 3);
    *credentials.lock().unwrap() = Credentials::Silent;
    assert!(instances.instances(ZONE).is_ok());
    assert_eq!(service.served.await_requests(4), 4);
    assert_eq!(replay.sent().len(), 6);
    clock.set(origin() + Duration::from_secs(60));
    clock.step(Duration::from_secs(120));
    assert_eq!(instances.instances(ZONE), Err(Unlisted));
    assert_eq!(service.served.await_requests(6), 6);
    assert_eq!(replay.sent().len(), 7);
}
