//! `Replay` is a test wire that answers each request with the next scripted
//! answer and records every request it receives, so a test reads the exact
//! requests an adapter sent and counts them.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::io::ErrorKind;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant};

use kestrike::failover::attachments::Unlisted;
use kestrike::failover::records::Layout;
use kestrike::failover::standbys::Zone;
use kestrike::failover::zone_loop::config::{OwnerBounds, TICK_US, ZoneBounds, ZoneConfig};

use crate::client::{Client, Stage};
use crate::config::{Config, Service};
use crate::credentials::Role;
use crate::ec2::pages::ZoneListing;
use crate::loopback::{CAP, Expect, Manual, faults, origin, refused};
use crate::sign::Keys;
use crate::wire::{Https, Lost, LostAt, Reply, Request, Wire};

pub(crate) enum Answer {
    Reply(u16, String),
    Lost(LostAt, ErrorKind),
}

/// A reply of HTTP 200 with `body`.
pub(crate) fn ok(body: &str) -> Answer {
    Answer::Reply(200, body.to_owned())
}

/// The outcome class of a scripted fault, by what the fault expects of the
/// wire.
pub(crate) fn fault_class(expect: &crate::loopback::Expect) -> &'static str {
    use crate::client::Stage;
    use crate::loopback::Expect;
    match expect {
        Expect::Reply(200, _) => "a 200 that holds no listing",
        Expect::Reply(..) => "a status other than 200",
        Expect::Lost(Stage::Connect, _) => "a lost connect",
        Expect::Lost(_, ErrorKind::TimedOut) => "a timeout",
        Expect::Lost(_, ErrorKind::FileTooLarge) => "a reply past a size limit",
        Expect::Lost(..) => "a broken reply",
    }
}

/// Checks that a fault sweep judged the scripted faults: `ran` holds the
/// class of each fault it judged, which is exactly the 31 faults of
/// `loopback::faults` and at least one of each class of `fault_class`. A
/// sweep over an empty or a cut fault table fails here, and so does a table
/// that gained a fault until this count names it.
pub(crate) fn assert_swept(ran: &[&'static str]) {
    assert_eq!(ran.len(), 31, "{} faults, expected 31", ran.len());
    for class in [
        "a 200 that holds no listing",
        "a status other than 200",
        "a lost connect",
        "a timeout",
        "a reply past a size limit",
        "a broken reply",
    ] {
        assert!(ran.contains(&class), "{class}");
    }
}

/// Named answers that give no listing: every HTTP status but 200 with
/// `page`, with a not-found error document and with a throttling error
/// document as its body, and a lost call of each kind before and after its
/// first request byte.
pub(crate) fn unusable(page: &str) -> Vec<(String, Answer)> {
    let bodies = [
        ("the page", page.to_owned()),
        ("not found", fixture("invalid-volume-not-found.xml")),
        ("throttling", fixture("request-limit-exceeded.xml")),
    ];
    let mut answers = Vec::new();
    for status in (100..600).filter(|status| *status != 200) {
        for (name, body) in &bodies {
            let reply = Answer::Reply(status, body.clone());
            answers.push((format!("{status} with {name}"), reply));
        }
    }
    for kind in [
        ErrorKind::ConnectionRefused,
        ErrorKind::ConnectionReset,
        ErrorKind::ConnectionAborted,
        ErrorKind::NotConnected,
        ErrorKind::BrokenPipe,
        ErrorKind::TimedOut,
        ErrorKind::UnexpectedEof,
        ErrorKind::InvalidData,
        ErrorKind::InvalidInput,
        ErrorKind::WouldBlock,
        ErrorKind::Interrupted,
        ErrorKind::FileTooLarge,
        ErrorKind::Other,
    ] {
        for at in [LostAt::Connect, LostAt::Exchange] {
            answers.push((format!("{kind:?} at {at:?}"), Answer::Lost(at, kind)));
        }
    }
    assert_eq!(answers.len(), 499 * 3 + 13 * 2);
    answers
}

/// One request as the wire received it.
#[derive(Debug, Clone)]
pub(crate) struct Sent {
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: String,
    pub(crate) deadline: Instant,
}

impl Sent {
    /// The value of form parameter `name`, still percent-encoded.
    pub(crate) fn param(&self, name: &str) -> Option<&str> {
        self.body
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value)
    }
}

#[derive(Default)]
struct State {
    answers: VecDeque<Answer>,
    sent: Vec<Sent>,
}

/// Clones share one script and one record.
#[derive(Clone, Default)]
pub(crate) struct Replay(Rc<RefCell<State>>);

impl Replay {
    pub(crate) fn new(answers: impl IntoIterator<Item = Answer>) -> Self {
        let replay = Self::default();
        replay.0.borrow_mut().answers.extend(answers);
        replay
    }

    pub(crate) fn sent(&self) -> Vec<Sent> {
        self.0.borrow().sent.clone()
    }

    /// The `Action` parameter of each request, in arrival order.
    pub(crate) fn actions(&self) -> Vec<String> {
        let sent = self.sent();
        let action = |sent: &Sent| sent.param("Action").unwrap_or_default().to_owned();
        sent.iter().map(action).collect()
    }

    /// The number of requests the wire received.
    pub(crate) fn count(&self) -> usize {
        self.0.borrow().sent.len()
    }
}

impl Wire for Replay {
    /// Panics on a request past the script, which a test reads as an
    /// adapter sending more requests than the listing needs.
    fn send(&self, request: &Request<'_>, deadline: Instant) -> Result<Reply, Lost> {
        let mut state = self.0.borrow_mut();
        state.sent.push(Sent {
            headers: request.headers.to_vec(),
            body: String::from_utf8(request.body.to_vec()).unwrap(),
            deadline,
        });
        match state.answers.pop_front() {
            Some(Answer::Reply(status, body)) => Ok(Reply {
                status,
                body: body.into_bytes(),
            }),
            Some(Answer::Lost(at, kind)) => Err(Lost { at, kind }),
            None => panic!("request {} is past the script", state.sent.len()),
        }
    }
}

/// A role that holds credentials unexpired until an hour after `origin`,
/// whose metadata service refuses connections. Under a clock at `origin`, a
/// call signs with them and sends no metadata request, so a test's calls
/// wait on no metadata service.
pub(crate) fn held() -> Role {
    let keys = Keys {
        access_key_id: "AKIDEC2".to_owned(),
        secret_access_key: "secret-AKIDEC2".to_owned(),
        session_token: Some("token-AKIDEC2".to_owned()),
    };
    Role::holding(keys, origin() + Duration::from_secs(3600), refused())
}

/// A client of the EC2 service in `us-east-1` whose requests go to `host`
/// through `wire`, with a `deadline` per call and a 1 MiB body cap.
pub(crate) fn client<W: Wire>(wire: W, host: &str, deadline: Duration) -> Client<W, Manual> {
    let clock = Manual::at(origin());
    client_in(
        "us-east-1",
        wire,
        host,
        deadline,
        1024 * 1024,
        held(),
        clock,
    )
}

/// A client of the EC2 service in `region` whose requests go to `host`
/// through `wire`, with a `deadline` per call, a `body_cap`, credentials
/// from `role` and `clock`.
pub(crate) fn client_in<W: Wire>(
    region: &str,
    wire: W,
    host: &str,
    deadline: Duration,
    body_cap: usize,
    role: Role,
    clock: Manual,
) -> Client<W, Manual> {
    let service = Service {
        name: "ec2",
        deadline,
        body_cap,
    };
    let config = Config::new(service, region).unwrap().at(host.to_owned());
    Client::new(config, wire, role, clock)
}

/// A client of the EC2 service in `region` for constructor tests, whose
/// metadata service refuses connections.
pub(crate) fn offline(region: &str) -> Client<Replay, Manual> {
    let deadline = Duration::from_secs(1);
    let clock = Manual::at(origin());
    client_in(
        region,
        Replay::default(),
        "fake",
        deadline,
        1024,
        Role::at(refused()),
        clock,
    )
}

/// Each case is a client region, a zone name, and whether a zone adapter
/// builds for them: the standard, local and wavelength zone names of the
/// client's region build one, and other regions, malformed suffixes and
/// network border group names build none.
pub(crate) const ZONE_NAMES: [(&str, &str, bool); 20] = [
    ("us-east-1", "us-east-1a", true),
    ("us-east-1", "us-east-1-bos-1a", true),
    ("us-east-1", "us-east-1-atl-2b", true),
    ("us-east-1", "us-east-1-wl1-bos-wlz-1", true),
    ("eu-west-2", "eu-west-2-wl2-man-wlz-1", true),
    ("us-west-2", "us-east-1a", false),
    ("us-east-10", "us-east-1a", false),
    ("us-east", "us-east-1a", false),
    ("eu-west-1", "us-east-1a", false),
    ("us-east-1", "us-east-10a", false),
    ("us-east-1", "us-east-12", false),
    ("us-east-1", "us-east-1", false),
    ("us-east-1", "us-east-1aa", false),
    ("us-east-1", "us-east-1a-extra", false),
    ("us-east-1", "us-east-1-", false),
    ("us-east-1", "us-east-1--bos-1a", false),
    ("us-east-1", "us-east-1-bos-", false),
    ("us-east-1", "us-east-1-bos-1", false),
    ("us-east-1", "us-east-1-wl1", false),
    ("us-east-1", "us-east-1-1", false),
];

/// Checks `built`, which builds a zone adapter for a client and a listing,
/// against every case of `ZONE_NAMES`.
pub(crate) fn assert_zone_names(built: impl Fn(Client<Replay, Manual>, ZoneListing) -> bool) {
    for (region, name, served) in ZONE_NAMES {
        let outcome = built(offline(region), listing_named(name, 3));
        assert_eq!(outcome, served, "{region} {name}");
    }
}

/// HTTP 200 answers holding `bodies`, in order.
pub(crate) fn answers(bodies: &[String]) -> Vec<Answer> {
    bodies.iter().map(|body| ok(body)).collect()
}

/// The answers of `bodies` with every `from` on page `at` replaced by `to`.
pub(crate) fn edited(bodies: &[String], at: usize, from: &str, to: &str) -> Vec<Answer> {
    assert!(bodies[at].contains(from), "page {at}: {from}");
    let mut bodies = bodies.to_vec();
    bodies[at] = bodies[at].replace(from, to);
    answers(&bodies)
}

/// `body` with `row` placed first in its `set`.
pub(crate) fn prepended(body: &str, set: &str, row: &str) -> String {
    let open = format!("<{set}>");
    assert!(body.contains(&open), "{set}");
    body.replacen(&open, &format!("{open}{row}"), 1)
}

/// A wire that waits for `delay` before each send of the wire it wraps, so
/// a test spends a read's deadline before the reply arrives.
pub(crate) struct Delayed<W> {
    pub(crate) inner: W,
    pub(crate) delay: Duration,
}

impl<W: Wire> Wire for Delayed<W> {
    fn send(&self, request: &Request<'_>, deadline: Instant) -> Result<Reply, Lost> {
        std::thread::sleep(self.delay);
        self.inner.send(request, deadline)
    }
}

/// A wire that records the outcome of each send of the wire it wraps.
pub(crate) struct Observed<W> {
    inner: W,
    outcomes: Rc<RefCell<Vec<Result<Reply, Lost>>>>,
}

impl<W: Wire> Wire for Observed<W> {
    fn send(&self, request: &Request<'_>, deadline: Instant) -> Result<Reply, Lost> {
        let outcome = self.inner.send(request, deadline);
        self.outcomes.borrow_mut().push(outcome.clone());
        outcome
    }
}

/// Under each scripted fault of the client tests, `read` on an EC2 client
/// of the fault's host, with the loopback body cap the faults measure
/// against, is unlisted within `deadline` plus the wire's slack. The wire
/// sends once and ends with the fault's expected outcome, and the server
/// reads the fault's request count. The sweep judges every fault of
/// `loopback::faults` and one of each outcome class, which `assert_swept`
/// checks.
pub(crate) fn assert_each_fault_unlisted<T: Debug + PartialEq>(
    deadline: Duration,
    read: impl Fn(Client<Observed<Https>, Manual>) -> Result<T, Unlisted>,
) {
    assert_each_fault_gives(deadline, &Err(Unlisted), read);
}

/// `assert_each_fault_unlisted` for a call whose every scripted fault gives
/// `expected`.
pub(crate) fn assert_each_fault_gives<O: Debug + PartialEq>(
    deadline: Duration,
    expected: &O,
    read: impl Fn(Client<Observed<Https>, Manual>) -> O,
) {
    let mut ran = Vec::new();
    for fault in faults(deadline) {
        ran.push(fault_class(&fault.expect));
        let outcomes = Rc::default();
        let wire = Observed {
            inner: if fault.tls {
                Https::new()
            } else {
                Https::plain()
            },
            outcomes: Rc::clone(&outcomes),
        };
        let clock = Manual::at(origin());
        let client = client_in("us-east-1", wire, &fault.host, deadline, CAP, held(), clock);
        let start = Instant::now();
        let outcome = read(client);
        let elapsed = start.elapsed();
        assert_eq!(&outcome, expected, "{}", fault.name);
        fault.one_attempt().unwrap();
        let sent = match fault.expect {
            Expect::Reply(status, body) => Ok(Reply {
                status,
                body: body.to_vec(),
            }),
            Expect::Lost(Stage::Connect, kind) => Err(Lost {
                at: LostAt::Connect,
                kind,
            }),
            Expect::Lost(Stage::Exchange, kind) => Err(Lost {
                at: LostAt::Exchange,
                kind,
            }),
            Expect::Lost(Stage::Credentials, _) => panic!("{}: a credential fault", fault.name),
        };
        assert_eq!(*outcomes.borrow(), [sent], "{}", fault.name);
        assert!(
            elapsed < deadline + Duration::from_millis(250),
            "{}: {elapsed:?}",
            fault.name
        );
    }
    assert_swept(&ran);
}

/// The text of fixture `name` under `ec2/fixtures`.
pub(crate) fn fixture(name: &str) -> String {
    let path = format!("{}/src/ec2/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"))
}

/// The zone of every listing test, `Zone(1)`, named `us-east-1a`.
pub(crate) const ZONE: Zone = Zone(1);

/// The listing of `ZONE` with at most `pages` pages per describe action,
/// from a configuration that `ZoneConfig::validate` accepts.
pub(crate) fn listing(pages: u16) -> ZoneListing {
    listing_named("us-east-1a", pages)
}

/// The listing of `ZONE` under the availability-zone name `name`.
pub(crate) fn listing_named(name: &str, pages: u16) -> ZoneListing {
    listing_of(ZONE, name, pages)
}

/// The listing of `zone` under the availability-zone name `name`.
pub(crate) fn listing_of(zone: Zone, name: &str, pages: u16) -> ZoneListing {
    ZoneListing::new(&bounds_of(zone, name), NonZeroU16::new(pages).unwrap())
}

/// The bounds of a configuration of `zone` named `name` that
/// `ZoneConfig::validate` accepts, with a replacement layout of 64 units.
pub(crate) fn bounds_of(zone: Zone, name: &str) -> ZoneBounds {
    let layout = Layout {
        units: 64,
        slots: 3,
        slot_units: 3,
        entries: 64,
    };
    bounds_with(zone, name, layout)
}

pub(crate) fn bounds_with(zone: Zone, name: &str, replacement: Layout) -> ZoneBounds {
    let owner = OwnerBounds {
        registrant_max: 8,
        retry_max: 2,
        window: 36,
        report_deadline: 10,
        report_period: 20,
        clock_error: 5,
    };
    let config = ZoneConfig::defaults(
        zone,
        name.into(),
        8,
        owner,
        replacement,
        PathBuf::from("/etc/kestrike/zone-1.directory"),
        TICK_US,
    );
    config.validate().unwrap()
}

/// Each request of a paged read of `action` is, in order, exactly the
/// body with the zone filter for `zone`, then `params` as written, then
/// `per_page` results, and from the second request on `&NextToken=` and
/// the token of `tokens` as written, percent-encoded; no two requests are
/// identical.
pub(crate) fn assert_paged(
    sent: &[Sent],
    action: &str,
    zone: &str,
    params: &str,
    per_page: &str,
    tokens: &[Option<&str>],
) {
    let bodies: Vec<&str> = sent.iter().map(|request| request.body.as_str()).collect();
    let expected: Vec<String> = tokens
        .iter()
        .map(|token| {
            let token = token.map_or(String::new(), |token| format!("&NextToken={token}"));
            format!(
                "Action={action}&Version=2016-11-15&Filter.1.Name=availability-zone&Filter.1.Value.1={zone}{params}&MaxResults={per_page}{token}"
            )
        })
        .collect();
    assert_eq!(bodies, expected);
    let mut distinct = bodies.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), sent.len());
}

/// The adverse answers each page of a listing faces in the fails-whole
/// tests: a lost connect, a timeout, a throttle, an error code, a
/// not-found code, a server error, a server error that holds `page`, the
/// page the answer replaces, and a 200 that holds `page` with its root's
/// end tag cut off.
pub(crate) fn adverse(page: &str) -> Vec<(&'static str, Answer)> {
    let cut = page.rfind("</").unwrap();
    assert!(page[cut..].trim_end().ends_with("Response>"), "{page}");
    let truncated = &page[..cut];
    vec![
        (
            "connect failure",
            Answer::Lost(LostAt::Connect, ErrorKind::ConnectionRefused),
        ),
        (
            "timeout",
            Answer::Lost(LostAt::Exchange, ErrorKind::TimedOut),
        ),
        (
            "throttle",
            Answer::Reply(503, fixture("request-limit-exceeded.xml")),
        ),
        (
            "error code",
            Answer::Reply(403, fixture("unauthorized-operation.xml")),
        ),
        (
            "not found",
            Answer::Reply(400, fixture("invalid-volume-not-found.xml")),
        ),
        (
            "server error",
            Answer::Reply(500, fixture("internal-error.xml")),
        ),
        (
            "the page on a server error",
            Answer::Reply(500, page.to_owned()),
        ),
        ("truncated document", ok(truncated)),
    ]
}
