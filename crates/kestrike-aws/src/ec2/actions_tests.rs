use std::io::{self, ErrorKind};
use std::time::{Duration, Instant};

use kestrike::failover::attachments::InstanceId;
use kestrike::failover::loss::{CreateError, Provider};
use kestrike::failover::reconcile::{Detachable, Reconciler, Relisted};
use kestrike::failover::records::{
    AttachmentEvent, CreationSource, EventKind, Host, Layout, Lineage, MIN_ERA, Namespace,
    VolumeId, VolumeRecord, VolumeState,
};
use kestrike::failover::zone_loop::sources::{
    AttachRefusal, AttachReply, Attacher, DetachReply, Witness,
};
use kestrike::storage::store::{
    self, Item, Key, Outcome, Store, Tracked, Unavailable, Version, Watermark, WatermarkLog, Write,
};

use super::{DEVICES, PAIRS, VolumeActions, VolumeSpec, candidate, device, pair_hash};
use crate::client::Client;
use crate::credentials::Role;
use crate::ec2::replay::{
    Answer, Replay, Sent, ZONE, ZONE_NAMES, assert_each_fault_gives, bounds_of, bounds_with,
    client, client_in, fixture, offline, ok, unusable,
};
use crate::loopback::{Manual, Resend, origin, refused, reset};
use crate::wire::{Https, LostAt, Wire};

const VOLUME: &str = "vol-0a1b2c3d4e5f60718";
const INSTANCE: &str = "i-0123456789abcdef0";
const CREATED: &str = "vol-0f1e2d3c4b5a69788";
const TOKEN: &str = "000102030405060708090a0b0c0d0e0f-00000007-00000002-00000001";
const DEADLINE: Duration = Duration::from_secs(1);
const FAULT_DEADLINE: Duration = Duration::from_millis(500);

const LAYOUT: Layout = Layout {
    units: 64,
    slots: 5,
    slot_units: 4,
    entries: 100,
};

fn spec() -> VolumeSpec {
    VolumeSpec {
        size_gib: 500,
        iops: 16_000,
        kms_key: Some("alias/kestrike".to_owned()),
    }
}

fn actions_in<W: Wire>(
    client: Client<W, Manual>,
    zone: &str,
    spec: VolumeSpec,
) -> VolumeActions<W, Manual> {
    VolumeActions::new(client, &bounds_of(ZONE, zone), spec).unwrap()
}

fn actions_with<W: Wire>(client: Client<W, Manual>, spec: VolumeSpec) -> VolumeActions<W, Manual> {
    actions_in(client, "us-east-1a", spec)
}

fn actions(replay: &Replay) -> VolumeActions<Replay, Manual> {
    actions_with(client(replay.clone(), "fake", DEADLINE), spec())
}

fn volume() -> VolumeId {
    VolumeId::new(VOLUME).unwrap()
}

fn instance() -> InstanceId {
    InstanceId::new(INSTANCE).unwrap()
}

struct Held(Vec<u8>);

impl Store for Held {
    fn read(&mut self, _: &Key) -> Result<Option<Item>, Unavailable> {
        Ok(Some(Item {
            version: Version::FIRST,
            value: self.0.clone(),
        }))
    }

    fn write(&mut self, _: &Key, _: &Write) -> Outcome {
        Outcome::Unknown
    }

    fn namespace(&self) -> Namespace {
        Namespace::new([1; 16]).unwrap()
    }
}

struct Unmarked;

impl WatermarkLog for Unmarked {
    fn load(&self) -> io::Result<Watermark> {
        Ok(Watermark::default())
    }

    fn record(&mut self, _: &Watermark) -> io::Result<()> {
        Ok(())
    }
}

/// A reconciler over one volume record whose only entry is host 7's entry
/// of `kind`, naming `instance()`.
fn reconciler(kind: EventKind) -> Reconciler<Held, Unmarked> {
    let record = VolumeRecord {
        volume: volume(),
        state: VolumeState::Active,
        source: CreationSource::Provisioned,
        lineage: Lineage::None,
        modification: None,
        layout: LAYOUT,
        next: 1,
        forced: false,
        fence: 0,
        pairs: Vec::new(),
        events: vec![AttachmentEvent {
            seq: 0,
            kind,
            host: host(),
            era: MIN_ERA,
            instance: Some(instance()),
        }],
    };
    let key = Key::Volume(volume());
    let held = Held(record.encoded(&key).unwrap());
    Reconciler::new(store::Client::open(held, Unmarked).unwrap())
}

fn host() -> Host {
    Host::new(7).unwrap()
}

fn witness() -> Detachable {
    let witness = reconciler(EventKind::Ended)
        .detachable(volume(), host())
        .unwrap();
    assert_eq!(
        (witness.volume(), witness.instance()),
        (volume(), instance())
    );
    witness
}

fn error(code: &str, message: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Response><Errors><Error><Code>{code}</Code><Message>{message}</Message></Error></Errors><RequestID>0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d</RequestID></Response>"
    )
}

fn half(page: &str) -> &str {
    &page[..page.floor_char_boundary(page.len() / 2)]
}

const DETACH_BODY: &str = "Action=DetachVolume&Version=2016-11-15&InstanceId=i-0123456789abcdef0&VolumeId=vol-0a1b2c3d4e5f60718";

const CREATE_BODY: &str = "Action=CreateVolume&Version=2016-11-15&AvailabilityZone=us-east-1a&ClientToken=000102030405060708090a0b0c0d0e0f-00000007-00000002-00000001&Encrypted=true&Iops=16000&KmsKeyId=alias%2Fkestrike&MultiAttachEnabled=true&Size=500&TagSpecification.1.ResourceType=volume&TagSpecification.1.Tag.1.Key=kestrike%3Acreate-token&TagSpecification.1.Tag.1.Value=000102030405060708090a0b0c0d0e0f-00000007-00000002-00000001&TagSpecification.1.Tag.2.Key=kestrike%3Alayout&TagSpecification.1.Tag.2.Value=64%2F5%2F4%2F100&VolumeType=io2";

/// A create sends the receipt token unchanged as `ClientToken`; a rebuilt
/// create request sends the same body, and a changed input changes it.
#[test]
fn a_create_carries_the_token_and_a_rebuilt_request_sends_the_same_body() {
    let created = VolumeId::new(CREATED).unwrap();
    let page = fixture("create-volume.xml");
    let replay = Replay::new([
        ok(&page),
        ok(&page.replace(">creating<", ">available<")),
        ok(&page.replace(">creating<", ">error<")),
    ]);
    let mut first = actions(&replay);
    assert_eq!(first.create(TOKEN, LAYOUT), Ok(created));
    assert_eq!(first.create(TOKEN, LAYOUT), Ok(created));
    assert_eq!(actions(&replay).create(TOKEN, LAYOUT), Ok(created));
    let sent = replay.sent();
    assert_eq!(sent.len(), 3);
    for request in &sent {
        assert_eq!(request.body, CREATE_BODY);
    }
    assert_eq!(sent[0].param("ClientToken"), Some(TOKEN));

    let next = TOKEN.replace("-00000001", "-00000002");
    let wider = Layout {
        units: 65,
        slots: 6,
        slot_units: 5,
        entries: 150,
    };
    let changes: [(&str, &str, VolumeSpec, &str, Layout, String); 7] = [
        (
            "attempt",
            "us-east-1a",
            spec(),
            &next,
            LAYOUT,
            CREATE_BODY.replace(TOKEN, &next),
        ),
        (
            "token bytes",
            "us-east-1a",
            spec(),
            " Receipt+7/A=b&c%~. ",
            LAYOUT,
            CREATE_BODY.replace(TOKEN, "%20Receipt%2B7%2FA%3Db%26c%25~.%20"),
        ),
        (
            "layout tag",
            "us-east-1a",
            spec(),
            TOKEN,
            wider,
            CREATE_BODY.replace("64%2F5%2F4%2F100", "65%2F6%2F5%2F150"),
        ),
        (
            "size",
            "us-east-1a",
            VolumeSpec {
                size_gib: 501,
                ..spec()
            },
            TOKEN,
            LAYOUT,
            CREATE_BODY.replace("&Size=500&", "&Size=501&"),
        ),
        (
            "iops",
            "us-east-1a",
            VolumeSpec {
                iops: 16_001,
                ..spec()
            },
            TOKEN,
            LAYOUT,
            CREATE_BODY.replace("&Iops=16000&", "&Iops=16001&"),
        ),
        (
            "key",
            "us-east-1a",
            VolumeSpec {
                kms_key: None,
                ..spec()
            },
            TOKEN,
            LAYOUT,
            CREATE_BODY.replace("&KmsKeyId=alias%2Fkestrike", ""),
        ),
        (
            "zone",
            "us-east-1b",
            spec(),
            TOKEN,
            LAYOUT,
            CREATE_BODY.replace("AvailabilityZone=us-east-1a", "AvailabilityZone=us-east-1b"),
        ),
    ];
    for (name, zone, spec, token, layout, body) in changes {
        let replay = Replay::new([ok(&page.replace("us-east-1a", zone))]);
        let mut changed = actions_in(client(replay.clone(), "fake", DEADLINE), zone, spec);
        assert_eq!(changed.create(token, layout), Ok(created), "{name}");
        let sent = replay.sent();
        assert_eq!(sent.len(), 1, "{name}");
        assert_eq!(sent[0].body, body, "{name}");
        assert_ne!(sent[0].body, CREATE_BODY, "{name}");
    }
}

/// A create returns a volume only from a 200 naming one; each other reply
/// reads as unknown after exactly one request.
#[test]
fn every_create_reply_but_a_named_volume_is_unknown_after_one_request() {
    let page = fixture("create-volume.xml");
    let mut answers = unusable(&page);
    for (code, status) in [
        ("IdempotentParameterMismatch", 400),
        ("VolumeLimitExceeded", 400),
        ("MaxIOPSLimitExceeded", 400),
        ("InsufficientVolumeCapacity", 400),
        ("InvalidParameterValue", 400),
        ("InvalidZone.NotFound", 400),
        ("UnauthorizedOperation", 403),
        ("RequestLimitExceeded", 503),
        ("InternalError", 500),
    ] {
        answers.push((
            code.to_owned(),
            Answer::Reply(status, error(code, "refused")),
        ));
    }
    let mismatch = fixture("idempotent-parameter-mismatch.xml");
    answers.push(("mismatch fixture".to_owned(), Answer::Reply(400, mismatch)));
    let id = format!("<volumeId>{CREATED}</volumeId>");
    let zone = "<availabilityZone>us-east-1a</availabilityZone>";
    for (name, body) in [
        ("no volume", page.replace(&id, "")),
        ("bad volume", page.replace(CREATED, "vol-XYZ")),
        ("empty volume", page.replace(CREATED, "")),
        ("two volumes", page.replace(&id, &format!("{id}{id}"))),
        (
            "another zone",
            page.replace(zone, &zone.replace("1a", "1b")),
        ),
        (
            "a zone name this one begins",
            page.replace(zone, &zone.replace("1a", "1ab")),
        ),
        (
            "a zone name that begins this one",
            page.replace(zone, &zone.replace("1a", "1")),
        ),
        ("no zone", page.replace(zone, "")),
        (
            "other root",
            page.replace("CreateVolumeResponse", "AttachVolumeResponse"),
        ),
        ("truncated", half(&page).to_owned()),
        ("error document", error("InternalError", "on a 200")),
    ] {
        answers.push((name.to_owned(), ok(&body)));
    }
    for (name, answer) in answers {
        let replay = Replay::new([answer]);
        let outcome = actions(&replay).create(TOKEN, LAYOUT);
        assert_eq!(outcome, Err(CreateError::Unknown), "{name}");
        assert_eq!(replay.count(), 1, "{name}");
    }
}

/// A token outside the `ClientToken` form and a layout that fills the
/// volume read as unknown with no request.
#[test]
fn an_unsendable_create_is_unknown_before_any_request() {
    let units = 500 << 18;
    let long = "a".repeat(65);
    for (name, token, layout) in [
        ("empty token", "", LAYOUT),
        ("long token", long.as_str(), LAYOUT),
        ("non-ASCII token", "jeton-é", LAYOUT),
        ("layout fills the volume", TOKEN, Layout { units, ..LAYOUT }),
        (
            "layout past u64",
            TOKEN,
            Layout {
                units: u64::MAX,
                ..LAYOUT
            },
        ),
        ("too few slots", TOKEN, Layout { slots: 2, ..LAYOUT }),
        (
            "slot units",
            TOKEN,
            Layout {
                slot_units: 3,
                ..LAYOUT
            },
        ),
        (
            "below the floor",
            TOKEN,
            Layout {
                units: 20,
                ..LAYOUT
            },
        ),
        (
            "at the floor",
            TOKEN,
            Layout {
                units: 21,
                ..LAYOUT
            },
        ),
    ] {
        let replay = Replay::default();
        let outcome = actions(&replay).create(token, layout);
        assert_eq!(outcome, Err(CreateError::Unknown), "{name}");
        assert_eq!(replay.count(), 0, "{name}");
    }
    let longest = "a".repeat(64);
    for (fits, tag) in [(units - 1, "131071999"), (22, "22")] {
        let replay = Replay::new([ok(&fixture("create-volume.xml"))]);
        let layout = Layout {
            units: fits,
            ..LAYOUT
        };
        let created = actions(&replay).create(&longest, layout);
        assert_eq!(created, Ok(VolumeId::new(CREATED).unwrap()), "{fits}");
        let sent = replay.sent();
        assert_eq!(sent.len(), 1, "{fits}");
        assert_eq!(sent[0].param("ClientToken"), Some(longest.as_str()));
        let token = sent[0].param("TagSpecification.1.Tag.1.Value");
        assert_eq!(token, Some(longest.as_str()));
        let encoded = format!("{tag}%2F5%2F4%2F100");
        let layout = sent[0].param("TagSpecification.1.Tag.2.Value");
        assert_eq!(layout, Some(encoded.as_str()), "{fits}");
    }
}

/// Each attach reply maps to its outcome after one request naming the pair.
#[test]
fn attach_replies_map_to_accepted_listed_refused_or_unknown() {
    use AttachRefusal::{Limit, Other, State};
    use AttachReply::{Accepted, AlreadyListed, Refused, Unknown};
    let page = fixture("attach-volume.xml");
    let coded = |status, code, message: &str| Answer::Reply(status, error(code, message));
    let named = "vol-0a1b2c3d4e5f60718 is already attached to instance i-0123456789abcdef0.";
    let mut cases: Vec<(&str, Answer, AttachReply)> = vec![
        ("attaching", ok(&page), Accepted),
        (
            "attached",
            ok(&page.replace(">attaching<", ">attached<")),
            Accepted,
        ),
        (
            "in use, this pair",
            coded(400, "VolumeInUse", named),
            AlreadyListed,
        ),
        (
            "in use, this pair, no final period",
            coded(400, "VolumeInUse", named.trim_end_matches('.')),
            AlreadyListed,
        ),
        (
            "in use, this pair, two final periods",
            coded(400, "VolumeInUse", &format!("{named}.")),
            Refused(State),
        ),
        (
            "in use, unnamed",
            Answer::Reply(400, fixture("volume-in-use.xml")),
            Refused(State),
        ),
        (
            "in use, another holder",
            coded(
                400,
                "VolumeInUse",
                "vol-0a1b2c3d4e5f60718 is attached to i-0123456789abcdef1 and cannot be attached to i-0123456789abcdef0",
            ),
            Refused(State),
        ),
        (
            "in use, another volume",
            coded(
                400,
                "VolumeInUse",
                "vol-0a1b2c3d4e5f60719 is already attached to instance i-0123456789abcdef0.",
            ),
            Refused(State),
        ),
        (
            "in use, an id this one begins",
            coded(
                400,
                "VolumeInUse",
                "vol-0a1b2c3d4e5f60718 attached to i-0123456789abcdef01",
            ),
            Refused(State),
        ),
        (
            "in use, an id this one ends",
            coded(
                400,
                "VolumeInUse",
                "vol-0a1b2c3d4e5f60718 attached to xi-0123456789abcdef0",
            ),
            Refused(State),
        ),
        (
            "in use, the sentence and more",
            coded(
                400,
                "VolumeInUse",
                "vol-0a1b2c3d4e5f60718 is already attached to instance i-0123456789abcdef0 and to instance i-0123456789abcdef1",
            ),
            Refused(State),
        ),
        (
            "in use, the sentence for an id this one begins",
            coded(
                400,
                "VolumeInUse",
                "vol-0a1b2c3d4e5f60718 is already attached to instance i-0123456789abcdef01",
            ),
            Refused(State),
        ),
        (
            "in use, the sentence after other text",
            coded(
                400,
                "VolumeInUse",
                "Volume vol-0a1b2c3d4e5f60718 is already attached to instance i-0123456789abcdef0",
            ),
            Refused(State),
        ),
        (
            "in use, no message",
            Answer::Reply(
                400,
                "<Response><Errors><Error><Code>VolumeInUse</Code></Error></Errors></Response>"
                    .to_owned(),
            ),
            Refused(State),
        ),
        ("in use on a 500", coded(500, "VolumeInUse", named), Unknown),
        (
            "volume state",
            coded(400, "IncorrectState", "creating"),
            Refused(State),
        ),
        (
            "instance state",
            coded(400, "IncorrectInstanceState", "stopping"),
            Refused(State),
        ),
        (
            "limit",
            coded(400, "AttachmentLimitExceeded", "full"),
            Refused(Limit),
        ),
        (
            "another device in use",
            coded(
                400,
                "InvalidParameterValue",
                "Attachment point /dev/sdf is already in use",
            ),
            Refused(Other),
        ),
        ("the sent device in use", taken("/dev/sdy"), Unknown),
        (
            "a device the sent one begins, by a digit",
            coded(
                400,
                "InvalidParameterValue",
                "Attachment point /dev/sdy1 is already in use",
            ),
            Refused(Other),
        ),
        (
            "a device the sent one begins, by a hyphen",
            coded(
                400,
                "InvalidParameterValue",
                "Attachment point /dev/sdy-1 is already in use",
            ),
            Refused(Other),
        ),
        (
            "a device the sent one ends",
            coded(
                400,
                "InvalidParameterValue",
                "Attachment point b/dev/sdy is already in use",
            ),
            Refused(Other),
        ),
        (
            "in use, this instance as the destination",
            coded(
                400,
                "VolumeInUse",
                "vol-0a1b2c3d4e5f60718 cannot be attached to instance i-0123456789abcdef0: it is already attached to an instance",
            ),
            Refused(State),
        ),
        (
            "in use, naming the sent device",
            coded(
                400,
                "VolumeInUse",
                "vol-0a1b2c3d4e5f60718 is in use at /dev/sdy",
            ),
            Refused(State),
        ),
        (
            "zone mismatch, volume id spelling",
            coded(400, "InvalidVolumeID.ZoneMismatch", "zone"),
            Refused(Other),
        ),
        (
            "encryption unsupported",
            coded(400, "EncryptedVolumesNotSupported", "instance type"),
            Refused(Other),
        ),
        (
            "malformed volume",
            coded(400, "InvalidVolumeID.Malformed", "bad id"),
            Refused(Other),
        ),
        (
            "malformed instance",
            coded(400, "InvalidInstanceID.Malformed", "bad id"),
            Refused(Other),
        ),
        (
            "unknown volume",
            Answer::Reply(400, fixture("invalid-volume-not-found.xml")),
            Refused(Other),
        ),
        (
            "unknown instance",
            coded(400, "InvalidInstanceID.NotFound", "gone"),
            Refused(Other),
        ),
        (
            "zone mismatch",
            coded(400, "InvalidVolume.ZoneMismatch", "zone"),
            Refused(Other),
        ),
        (
            "denied",
            Answer::Reply(403, fixture("unauthorized-operation.xml")),
            Refused(Other),
        ),
        (
            "throttle on a 400",
            Answer::Reply(400, fixture("request-limit-exceeded.xml")),
            Unknown,
        ),
        (
            "throttle on a 503",
            Answer::Reply(503, fixture("request-limit-exceeded.xml")),
            Unknown,
        ),
        (
            "server error",
            Answer::Reply(500, fixture("internal-error.xml")),
            Unknown,
        ),
        (
            "refusal code on a 500",
            coded(500, "IncorrectState", "creating"),
            Unknown,
        ),
        (
            "refusal code on a 200",
            ok(&error("IncorrectState", "creating")),
            Unknown,
        ),
        (
            "4xx without a code",
            Answer::Reply(400, "{}".to_owned()),
            Unknown,
        ),
        (
            "another volume",
            ok(&page.replace(VOLUME, "vol-0a1b2c3d4e5f60719")),
            Unknown,
        ),
        (
            "another instance",
            ok(&page.replace(INSTANCE, "i-0123456789abcdef1")),
            Unknown,
        ),
        (
            "a volume id this one begins",
            ok(&page.replace(VOLUME, "vol-0a1b2c3d4e5f607180")),
            Unknown,
        ),
        (
            "an instance id this one begins",
            ok(&page.replace(INSTANCE, "i-0123456789abcdef01")),
            Unknown,
        ),
        (
            "no volume",
            ok(&page.replace("<volumeId>vol-0a1b2c3d4e5f60718</volumeId>", "")),
            Unknown,
        ),
        (
            "no instance",
            ok(&page.replace("<instanceId>i-0123456789abcdef0</instanceId>", "")),
            Unknown,
        ),
        (
            "detaching",
            ok(&page.replace(">attaching<", ">detaching<")),
            Unknown,
        ),
        (
            "detached",
            ok(&page.replace(">attaching<", ">detached<")),
            Unknown,
        ),
        ("busy", ok(&page.replace(">attaching<", ">busy<")), Unknown),
        (
            "no status",
            ok(&page.replace("<status>attaching</status>", "")),
            Unknown,
        ),
        (
            "other root",
            ok(&page.replace("AttachVolumeResponse", "DetachVolumeResponse")),
            Unknown,
        ),
        ("truncated", ok(half(&page)), Unknown),
        (
            "lost at connect",
            Answer::Lost(LostAt::Connect, ErrorKind::ConnectionRefused),
            Unknown,
        ),
        (
            "lost in the exchange",
            Answer::Lost(LostAt::Exchange, ErrorKind::TimedOut),
            Unknown,
        ),
    ];
    for code in [
        "RequestLimitExceeded",
        "ThrottlingException",
        "Unavailable",
        "ServiceUnavailable",
        "InternalError",
        "InternalFailure",
        "ServerInternal",
        "AnUnfamiliarCode",
    ] {
        cases.push((code, coded(400, code, "try again"), Unknown));
    }
    for (name, answer, expected) in cases {
        let replay = Replay::new([answer]);
        let outcome = actions(&replay).attach(volume(), instance());
        assert_eq!(outcome, expected, "{name}");
        let sent = replay.sent();
        assert_eq!(sent.len(), 1, "{name}");
        assert_eq!(sent[0].param("Action"), Some("AttachVolume"), "{name}");
        assert_eq!(sent[0].param("Device"), Some("%2Fdev%2Fsdy"), "{name}");
        assert_eq!(sent[0].param("VolumeId"), Some(VOLUME), "{name}");
        assert_eq!(sent[0].param("InstanceId"), Some(INSTANCE), "{name}");
    }
}

fn devices(replay: &Replay) -> Vec<String> {
    let name = |sent: &Sent| sent.param("Device").unwrap().replace("%2F", "/");
    replay.sent().iter().map(name).collect()
}

/// After an unaccepted attach, the pair's next request names the next
/// device candidate; an accepted attach starts the pair at its hash again
/// and leaves the walks of the volume's and the instance's other pairs
/// where they stood. Every request holds exactly the device, the instance
/// and the volume.
#[test]
fn an_unaccepted_attach_moves_the_next_request_to_the_next_device_name() {
    let in_use = || Answer::Reply(400, error("InvalidParameterValue", "in use"));
    let replay = Replay::new([
        in_use(),
        Answer::Lost(LostAt::Exchange, ErrorKind::TimedOut),
        ok(&fixture("attach-volume.xml")),
        in_use(),
        in_use(),
        in_use(),
        ok(&fixture("attach-volume.xml")),
        in_use(),
        in_use(),
    ]);
    let mut actions = actions(&replay);
    let other = InstanceId::new("i-0123456789abcdef1").unwrap();
    let second = VolumeId::new("vol-0a1b2c3d4e5f60719").unwrap();
    let refused = AttachReply::Refused(AttachRefusal::Other);
    assert_eq!(actions.attach(volume(), instance()), refused);
    assert_eq!(actions.attach(volume(), instance()), AttachReply::Unknown);
    assert_eq!(actions.attach(volume(), instance()), AttachReply::Accepted);
    assert_eq!(actions.attach(volume(), instance()), refused);
    assert_eq!(actions.attach(volume(), other), refused);
    assert_eq!(actions.attach(second, instance()), refused);
    assert_eq!(actions.attach(volume(), instance()), AttachReply::Accepted);
    assert_eq!(actions.attach(volume(), other), refused);
    assert_eq!(actions.attach(second, instance()), refused);
    let body = |device: &str, instance: &str, volume: &str| {
        format!(
            "Action=AttachVolume&Version=2016-11-15&Device=%2Fdev%2F{device}&InstanceId={instance}&VolumeId={volume}"
        )
    };
    let (other, second) = ("i-0123456789abcdef1", "vol-0a1b2c3d4e5f60719");
    let expected = [
        body("sdy", INSTANCE, VOLUME),
        body("sdz", INSTANCE, VOLUME),
        body("xvdbb", INSTANCE, VOLUME),
        body("sdy", INSTANCE, VOLUME),
        body("sdn", other, VOLUME),
        body("xvdbw", INSTANCE, second),
        body("sdz", INSTANCE, VOLUME),
        body("sdo", other, VOLUME),
        body("xvdbx", INSTANCE, second),
    ];
    let sent: Vec<String> = replay.sent().into_iter().map(|sent| sent.body).collect();
    assert_eq!(sent, expected);
}

fn taken(name: &str) -> Answer {
    taken_on(400, name)
}

fn taken_on(status: u16, name: &str) -> Answer {
    let message =
        format!("Invalid value '{name}' for unixDevice. Attachment point {name} is already in use");
    Answer::Reply(status, error("InvalidParameterValue", &message))
}

#[test]
fn a_taken_device_name_is_unknown_until_the_walk_has_tried_every_name() {
    let names = [
        "/dev/sdy",
        "/dev/sdz",
        "/dev/xvdbb",
        "/dev/xvdbc",
        "/dev/xvdbd",
    ];
    let mut answers: Vec<Answer> = names.iter().map(|name| taken(name)).collect();
    answers.push(ok(&fixture("attach-volume.xml")));
    let replay = Replay::new(answers);
    let mut first = actions(&replay);
    for name in names {
        let outcome = first.attach(volume(), instance());
        assert_eq!(outcome, AttachReply::Unknown, "{name}");
    }
    assert_eq!(first.attach(volume(), instance()), AttachReply::Accepted);
    let mut expected = names.to_vec();
    expected.push("/dev/xvdbe");
    assert_eq!(devices(&replay), expected);

    let walk: Vec<String> = (0..DEVICES).map(|at| device((19 + at) % DEVICES)).collect();
    let replay = Replay::new(walk.iter().map(|name| taken(name)));
    let mut walker = actions(&replay);
    for name in &walk[..DEVICES - 1] {
        let outcome = walker.attach(volume(), instance());
        assert_eq!(outcome, AttachReply::Unknown, "{name}");
    }
    let refused = AttachReply::Refused(AttachRefusal::Other);
    assert_eq!(walker.attach(volume(), instance()), refused);
    assert_eq!(devices(&replay), walk);

    let named = "vol-0a1b2c3d4e5f60718 is already attached to instance i-0123456789abcdef0.";
    let mut answers: Vec<Answer> = (0..DEVICES - 1)
        .map(|_| Answer::Lost(LostAt::Exchange, ErrorKind::TimedOut))
        .collect();
    answers.push(taken(&device(candidate(19, DEVICES - 1))));
    answers.push(taken("/dev/sdy"));
    answers.push(Answer::Reply(400, error("VolumeInUse", named)));
    answers.push(taken("/dev/sdy"));
    let replay = Replay::new(answers);
    let mut lossy = actions(&replay);
    for _ in 0..DEVICES - 1 {
        assert_eq!(lossy.attach(volume(), instance()), AttachReply::Unknown);
    }
    assert_eq!(lossy.attach(volume(), instance()), AttachReply::Unknown);
    assert_eq!(lossy.attach(volume(), instance()), AttachReply::Unknown);
    let listed = lossy.attach(volume(), instance());
    assert_eq!(listed, AttachReply::AlreadyListed);
    assert_eq!(lossy.attach(volume(), instance()), AttachReply::Unknown);
    let sent = devices(&replay);
    assert_eq!(sent[DEVICES..], ["/dev/sdy", "/dev/sdz", "/dev/sdy"]);

    let replay = Replay::new(walk.iter().chain(&walk[..1]).map(|name| taken(name)));
    let mut past = actions(&replay);
    for _ in 0..DEVICES - 1 {
        assert_eq!(past.attach(volume(), instance()), AttachReply::Unknown);
    }
    assert_eq!(past.attach(volume(), instance()), refused);
    assert_eq!(past.attach(volume(), instance()), refused);
    assert_eq!(devices(&replay)[DEVICES], "/dev/sdy");
}

/// The taken count rises only on a 4xx reply naming the sent device: after
/// 45 replies of each other kind, the next taken name reads as unknown.
#[test]
fn only_a_4xx_reply_naming_the_sent_device_counts_as_a_taken_name() {
    use AttachRefusal::{Other, State};
    type Kind = (&'static str, fn(&str) -> Answer, AttachReply);
    let kinds: [Kind; 5] = [
        (
            "lost",
            |_| Answer::Lost(LostAt::Exchange, ErrorKind::TimedOut),
            AttachReply::Unknown,
        ),
        (
            "the sent name on a 500",
            |name| taken_on(500, name),
            AttachReply::Unknown,
        ),
        (
            "a throttle",
            |_| Answer::Reply(400, fixture("request-limit-exceeded.xml")),
            AttachReply::Unknown,
        ),
        (
            "another name",
            |_| taken("/dev/sda1"),
            AttachReply::Refused(Other),
        ),
        (
            "a state refusal",
            |_| Answer::Reply(400, error("IncorrectState", "creating")),
            AttachReply::Refused(State),
        ),
    ];
    let walk: Vec<String> = (0..DEVICES).map(|at| device((19 + at) % DEVICES)).collect();
    for (kind, answer, outcome) in kinds {
        let mut answers: Vec<Answer> = walk[..DEVICES - 1]
            .iter()
            .map(|name| answer(name))
            .collect();
        answers.push(taken(&walk[DEVICES - 1]));
        let replay = Replay::new(answers);
        let mut actions = actions(&replay);
        for name in &walk[..DEVICES - 1] {
            let reply = actions.attach(volume(), instance());
            assert_eq!(reply, outcome, "{kind} {name}");
        }
        let reply = actions.attach(volume(), instance());
        assert_eq!(reply, AttachReply::Unknown, "{kind}");
        assert_eq!(devices(&replay), walk, "{kind}");
    }
}

/// A name EC2 rejects on every lap of the walk counts once. With one taken
/// name and lost calls for the other 45, 47 laps read as unknown, because
/// 45 names stay unrejected. On the next lap each of those 45 names is
/// taken, and the reply that rejects the last of them reads as refused.
#[test]
fn a_name_rejected_again_on_a_later_lap_counts_once() {
    let lost = || Answer::Lost(LostAt::Exchange, ErrorKind::TimedOut);
    let walk: Vec<String> = (0..DEVICES).map(|at| device((19 + at) % DEVICES)).collect();
    let laps = DEVICES + 1;
    let lap = || std::iter::once(taken(&walk[0])).chain((1..DEVICES).map(|_| lost()));
    let mut answers: Vec<Answer> = (0..laps).flat_map(|_| lap()).collect();
    answers.extend(walk.iter().map(|name| taken(name)));
    let replay = Replay::new(answers);
    let mut actions = actions(&replay);
    for lap in 0..laps {
        for name in &walk {
            let reply = actions.attach(volume(), instance());
            assert_eq!(reply, AttachReply::Unknown, "lap {lap} {name}");
        }
    }
    for name in &walk[..DEVICES - 1] {
        let reply = actions.attach(volume(), instance());
        assert_eq!(reply, AttachReply::Unknown, "the last lap {name}");
    }
    let refused = AttachReply::Refused(AttachRefusal::Other);
    assert_eq!(actions.attach(volume(), instance()), refused);
    let sent = devices(&replay);
    assert_eq!(sent.len(), (laps + 1) * DEVICES);
    for lap in sent.chunks(DEVICES) {
        assert_eq!(lap, walk);
    }
}

/// `Accepted` and `AlreadyListed` clear the pair's taken count: after 45
/// taken names and either reply, 45 more taken names read as unknown and
/// the 46th as refused.
#[test]
fn an_ended_walk_starts_its_taken_count_again() {
    let walk: Vec<String> = (0..DEVICES).map(|at| device((19 + at) % DEVICES)).collect();
    let named = "vol-0a1b2c3d4e5f60718 is already attached to instance i-0123456789abcdef0.";
    let ends = [
        (ok(&fixture("attach-volume.xml")), AttachReply::Accepted),
        (
            Answer::Reply(400, error("VolumeInUse", named)),
            AttachReply::AlreadyListed,
        ),
    ];
    for (end, ended) in ends {
        let mut answers: Vec<Answer> = walk[..DEVICES - 1].iter().map(|name| taken(name)).collect();
        answers.push(end);
        answers.extend(walk.iter().map(|name| taken(name)));
        let replay = Replay::new(answers);
        let mut actions = actions(&replay);
        for name in &walk[..DEVICES - 1] {
            let reply = actions.attach(volume(), instance());
            assert_eq!(reply, AttachReply::Unknown, "{ended:?} {name}");
        }
        assert_eq!(actions.attach(volume(), instance()), ended);
        for name in &walk[..DEVICES - 1] {
            let reply = actions.attach(volume(), instance());
            assert_eq!(reply, AttachReply::Unknown, "{ended:?} {name}");
        }
        let refused = AttachReply::Refused(AttachRefusal::Other);
        assert_eq!(actions.attach(volume(), instance()), refused, "{ended:?}");
        let sent = devices(&replay);
        assert_eq!(sent[..DEVICES], walk, "{ended:?}");
        assert_eq!(sent[DEVICES..], walk, "{ended:?}");
    }
}

#[test]
fn a_full_walk_map_drops_the_walk_asked_least_recently() {
    let lost = || Answer::Lost(LostAt::Exchange, ErrorKind::TimedOut);
    let other = InstanceId::new("i-0123456789abcdef1").unwrap();
    let idle = |at: usize| InstanceId::new(&format!("i-f{at:016x}")).unwrap();
    let mut answers: Vec<Answer> = (0..PAIRS).map(|_| lost()).collect();
    for name in [
        "/dev/sdy",
        "/dev/sdn",
        "/dev/sdz",
        "/dev/sdo",
        "/dev/xvdbb",
        "/dev/sdp",
    ] {
        answers.push(taken(name));
    }
    answers.push(lost());
    answers.push(lost());
    let replay = Replay::new(answers);
    let mut actions = actions(&replay);
    for at in 0..PAIRS {
        assert_eq!(actions.attach(volume(), idle(at)), AttachReply::Unknown);
    }
    assert_eq!(actions.walks.len(), PAIRS);
    for _ in 0..3 {
        assert_eq!(actions.attach(volume(), instance()), AttachReply::Unknown);
        assert_eq!(actions.attach(volume(), other), AttachReply::Unknown);
        assert_eq!(actions.walks.len(), PAIRS);
    }
    assert!(!actions.walks.contains_key(&(volume(), idle(0))));
    assert!(!actions.walks.contains_key(&(volume(), idle(1))));
    assert!(actions.walks.contains_key(&(volume(), idle(2))));
    let _ = actions.attach(volume(), idle(2));
    let _ = actions.attach(volume(), idle(0));
    assert_eq!(actions.walks.len(), PAIRS);
    assert!(actions.walks.contains_key(&(volume(), idle(2))));
    assert!(!actions.walks.contains_key(&(volume(), idle(3))));
    let sent = devices(&replay);
    let interleaved = [
        "/dev/sdy",
        "/dev/sdn",
        "/dev/sdz",
        "/dev/sdo",
        "/dev/xvdbb",
        "/dev/sdp",
    ];
    assert_eq!(sent[PAIRS..PAIRS + 6], interleaved);
    assert_eq!(
        sent[PAIRS + 6],
        device(candidate(pair_hash(volume(), idle(2)), 1))
    );
    assert_eq!(sent[PAIRS + 7], sent[0]);
    assert_eq!(replay.count(), PAIRS + 8);
}

#[test]
fn the_device_walk_keeps_at_most_its_bound_of_pairs() {
    let lost = || Answer::Lost(LostAt::Exchange, ErrorKind::TimedOut);
    let replay = Replay::new((0..PAIRS + 8).map(|_| lost()));
    let mut actions = actions(&replay);
    for at in 0..PAIRS + 8 {
        let instance = InstanceId::new(&format!("i-{at:017x}")).unwrap();
        assert_eq!(actions.attach(volume(), instance), AttachReply::Unknown);
        assert!(actions.walks.len() <= PAIRS, "{at}");
    }
    assert_eq!(actions.walks.len(), 1024);
    assert_eq!(replay.count(), 1032);
}

/// The candidates are `/dev/sdf` to `/dev/sdz` and `/dev/xvdbb` to
/// `/dev/xvdbz`, counted modulo their number.
#[test]
fn the_device_candidates_are_the_documented_data_volume_names() {
    let names: Vec<String> = (0..DEVICES).map(device).collect();
    let mut expected: Vec<String> = ('f'..='z').map(|c| format!("/dev/sd{c}")).collect();
    expected.extend(('b'..='z').map(|c| format!("/dev/xvdb{c}")));
    assert_eq!(names, expected);
    let start = (u64::MAX % DEVICES as u64) as usize;
    let walk: Vec<usize> = (0..=DEVICES).map(|n| candidate(u64::MAX, n)).collect();
    let expected: Vec<usize> = (0..=DEVICES).map(|n| (start + n) % DEVICES).collect();
    assert_eq!(walk, expected);
    assert_eq!(walk[..2], [5, 6]);
}

/// A detach body holds exactly the instance and the volume, so it carries
/// no `Force`; each reply maps to its outcome after one request.
#[test]
fn a_detach_names_the_instance_without_force_and_maps_its_replies() {
    use DetachReply::{Accepted, AlreadyDetached, Unknown};
    let page = fixture("detach-volume.xml");
    let not_attached = fixture("invalid-attachment-not-found.xml");
    let cases: Vec<(&str, Answer, DetachReply)> = vec![
        ("detaching", ok(&page), Accepted),
        (
            "detached",
            ok(&page.replace(">detaching<", ">detached<")),
            Accepted,
        ),
        (
            "not attached",
            Answer::Reply(400, not_attached.clone()),
            AlreadyDetached,
        ),
        (
            "not attached on a 500",
            Answer::Reply(500, not_attached),
            Unknown,
        ),
        (
            "volume state",
            Answer::Reply(400, error("IncorrectState", "available")),
            Unknown,
        ),
        (
            "unknown volume",
            Answer::Reply(400, fixture("invalid-volume-not-found.xml")),
            Unknown,
        ),
        (
            "denied",
            Answer::Reply(403, fixture("unauthorized-operation.xml")),
            Unknown,
        ),
        (
            "throttle",
            Answer::Reply(503, fixture("request-limit-exceeded.xml")),
            Unknown,
        ),
        (
            "server error",
            Answer::Reply(500, fixture("internal-error.xml")),
            Unknown,
        ),
        (
            "attaching",
            ok(&page.replace(">detaching<", ">attaching<")),
            Unknown,
        ),
        (
            "attached",
            ok(&page.replace(">detaching<", ">attached<")),
            Unknown,
        ),
        ("busy", ok(&page.replace(">detaching<", ">busy<")), Unknown),
        (
            "no status",
            ok(&page.replace("<status>detaching</status>", "")),
            Unknown,
        ),
        (
            "another instance",
            ok(&page.replace(INSTANCE, "i-0123456789abcdef1")),
            Unknown,
        ),
        (
            "an instance id this one begins",
            ok(&page.replace(INSTANCE, "i-0123456789abcdef01")),
            Unknown,
        ),
        (
            "another volume",
            ok(&page.replace(VOLUME, "vol-0a1b2c3d4e5f60719")),
            Unknown,
        ),
        (
            "a volume id this one begins",
            ok(&page.replace(VOLUME, "vol-0a1b2c3d4e5f607180")),
            Unknown,
        ),
        (
            "no volume",
            ok(&page.replace("<volumeId>vol-0a1b2c3d4e5f60718</volumeId>", "")),
            Unknown,
        ),
        (
            "no instance",
            ok(&page.replace("<instanceId>i-0123456789abcdef0</instanceId>", "")),
            Unknown,
        ),
        (
            "other root",
            ok(&page.replace("DetachVolumeResponse", "AttachVolumeResponse")),
            Unknown,
        ),
        (
            "lost in the exchange",
            Answer::Lost(LostAt::Exchange, ErrorKind::ConnectionReset),
            Unknown,
        ),
    ];
    let witness = witness();
    for (name, answer, expected) in cases {
        let replay = Replay::new([answer]);
        assert_eq!(
            actions(&replay).detach(Witness::Ended(&witness)),
            expected,
            "{name}"
        );
        let sent = replay.sent();
        assert_eq!(sent.len(), 1, "{name}");
        assert_eq!(sent[0].body, DETACH_BODY, "{name}");
    }
}

fn relisted() -> Relisted {
    let witness = reconciler(EventKind::Gone)
        .relisted(volume(), host())
        .unwrap();
    assert_eq!(
        (witness.volume(), witness.instance()),
        (volume(), instance())
    );
    witness
}

/// A detach under a relisted witness, a gone entry whose instance lists
/// again, sends the same graceful body as one under an ended witness of the
/// same pair, and reads the reply by the same rule.
#[test]
fn a_relisted_witness_detaches_its_pair_like_an_ended_one() {
    let witness = relisted();
    for (answer, expected) in [
        (ok(&fixture("detach-volume.xml")), DetachReply::Accepted),
        (
            Answer::Reply(400, fixture("invalid-attachment-not-found.xml")),
            DetachReply::AlreadyDetached,
        ),
        (
            Answer::Lost(LostAt::Exchange, ErrorKind::TimedOut),
            DetachReply::Unknown,
        ),
    ] {
        let replay = Replay::new([answer]);
        assert_eq!(
            actions(&replay).detach(Witness::Relisted(&witness)),
            expected
        );
        let sent = replay.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].body, DETACH_BODY);
    }
}

/// Each detach of a pair sends the same two-parameter body, after 128
/// detaches of the pair in a row that read as unknown, after ones that
/// read as already detached and as accepted, and after an attach call for
/// another volume and instance.
#[test]
fn every_detach_of_a_pair_sends_the_same_body_without_force() {
    let unknown = |at: usize| match at % 4 {
        0 => Answer::Lost(LostAt::Exchange, ErrorKind::TimedOut),
        1 => Answer::Reply(500, fixture("internal-error.xml")),
        2 => Answer::Reply(503, fixture("request-limit-exceeded.xml")),
        _ => Answer::Reply(400, error("IncorrectState", "busy")),
    };
    let mut answers: Vec<Answer> = (0..128).map(unknown).collect();
    answers.push(Answer::Reply(
        400,
        fixture("invalid-attachment-not-found.xml"),
    ));
    answers.push(unknown(0));
    answers.push(ok(&fixture("detach-volume.xml")));
    answers.push(unknown(0));
    answers.push(unknown(1));
    let replay = Replay::new(answers);
    let mut actions = actions(&replay);
    let witness = witness();
    for at in 0..128 {
        assert_eq!(
            actions.detach(Witness::Ended(&witness)),
            DetachReply::Unknown,
            "{at}"
        );
    }
    assert_eq!(
        actions.detach(Witness::Ended(&witness)),
        DetachReply::AlreadyDetached
    );
    assert_eq!(
        actions.detach(Witness::Ended(&witness)),
        DetachReply::Unknown
    );
    assert_eq!(
        actions.detach(Witness::Ended(&witness)),
        DetachReply::Accepted
    );
    let other = InstanceId::new("i-0123456789abcdef1").unwrap();
    let second = VolumeId::new("vol-0a1b2c3d4e5f60719").unwrap();
    assert_eq!(actions.attach(second, other), AttachReply::Unknown);
    assert_eq!(
        actions.detach(Witness::Ended(&witness)),
        DetachReply::Unknown
    );
    let sent = replay.sent();
    assert_eq!(sent.len(), 133);
    let detaches = sent
        .iter()
        .filter(|request| request.param("Action") == Some("DetachVolume"));
    assert_eq!(detaches.clone().count(), 132);
    for (at, request) in detaches.enumerate() {
        assert_eq!(request.body, DETACH_BODY, "{at}");
    }
}

/// Of the 419 error codes the EC2 API reference lists, each on a 400 after
/// one request: a create reads as unknown for every code, an attach as a
/// refusal for 13 codes and as unknown for the rest, and a detach as already
/// detached for `InvalidAttachment.NotFound` and as unknown for the rest.
#[test]
fn each_listed_error_code_maps_as_its_action_states() {
    use AttachRefusal::{Limit, Other, State};
    let listed = fixture("error-codes.txt");
    let codes: Vec<&str> = listed.lines().collect();
    assert_eq!(codes.len(), 419);
    let witness = witness();
    let mut refused = Vec::new();
    let mut detached = Vec::new();
    for code in codes {
        let reply = || Answer::Reply(400, error(code, "refused"));
        let replay = Replay::new([reply(), reply(), reply()]);
        let mut actions = actions(&replay);
        let created = actions.create(TOKEN, LAYOUT);
        assert_eq!(created, Err(CreateError::Unknown), "{code}");
        match actions.attach(volume(), instance()) {
            AttachReply::Unknown => {}
            AttachReply::Refused(refusal) => refused.push((code, refusal)),
            other => panic!("{code}: {other:?}"),
        }
        match actions.detach(Witness::Ended(&witness)) {
            DetachReply::Unknown => {}
            other => detached.push((code, other)),
        }
        assert_eq!(replay.count(), 3, "{code}");
    }
    let refusals = [
        ("AttachmentLimitExceeded", Limit),
        ("EncryptedVolumesNotSupported", Other),
        ("IncorrectInstanceState", State),
        ("IncorrectState", State),
        ("InvalidInstanceID.Malformed", Other),
        ("InvalidInstanceID.NotFound", Other),
        ("InvalidParameterValue", Other),
        ("InvalidVolume.NotFound", Other),
        ("InvalidVolume.ZoneMismatch", Other),
        ("InvalidVolumeID.Malformed", Other),
        ("InvalidVolumeID.ZoneMismatch", Other),
        ("UnauthorizedOperation", Other),
        ("VolumeInUse", State),
    ];
    assert_eq!(refused, refusals);
    let absent = [("InvalidAttachment.NotFound", DetachReply::AlreadyDetached)];
    assert_eq!(detached, absent);
}

/// A refusal code counts on each status from 400 to 499 and on no other:
/// the same body on any other status reads as unknown.
#[test]
fn a_refusal_code_counts_on_each_4xx_status_and_on_no_other() {
    let state = error("IncorrectState", "creating");
    let absent = fixture("invalid-attachment-not-found.xml");
    let witness = witness();
    for status in 100..600 {
        let refused = (400..=499).contains(&status);
        let replay = Replay::new([
            Answer::Reply(status, state.clone()),
            Answer::Reply(status, absent.clone()),
        ]);
        let mut actions = actions(&replay);
        let attached = match refused {
            true => AttachReply::Refused(AttachRefusal::State),
            false => AttachReply::Unknown,
        };
        assert_eq!(actions.attach(volume(), instance()), attached, "{status}");
        let detached = match refused {
            true => DetachReply::AlreadyDetached,
            false => DetachReply::Unknown,
        };
        assert_eq!(
            actions.detach(Witness::Ended(&witness)),
            detached,
            "{status}"
        );
        assert_eq!(replay.count(), 2, "{status}");
    }
}

#[test]
fn each_action_sends_under_a_deadline_taken_at_its_call() {
    let lost = || Answer::Lost(LostAt::Exchange, ErrorKind::TimedOut);
    let replay = Replay::new((0..6).map(|_| lost()));
    let mut actions = actions(&replay);
    let witness = witness();
    let mut windows = Vec::new();
    for _ in 0..2 {
        let start = Instant::now();
        let _ = actions.create(TOKEN, LAYOUT);
        windows.push((start, Instant::now()));
        let start = Instant::now();
        let _ = actions.attach(volume(), instance());
        windows.push((start, Instant::now()));
        let start = Instant::now();
        let _ = actions.detach(Witness::Ended(&witness));
        windows.push((start, Instant::now()));
    }
    let sent = replay.sent();
    assert_eq!(sent.len(), windows.len());
    for (request, (start, end)) in sent.iter().zip(windows) {
        assert!(start + DEADLINE <= request.deadline && request.deadline <= end + DEADLINE);
    }
}

/// Under each scripted fault of the client tests, every action reads as
/// unknown after one send, within its deadline plus the wire's slack.
#[test]
fn every_scripted_fault_leaves_a_create_unknown_with_at_most_one_request() {
    assert_each_fault_gives(FAULT_DEADLINE, &Err(CreateError::Unknown), |client| {
        actions_with(client, spec()).create(TOKEN, LAYOUT)
    });
}

#[test]
fn every_scripted_fault_leaves_an_attach_unknown_with_at_most_one_request() {
    assert_each_fault_gives(FAULT_DEADLINE, &AttachReply::Unknown, |client| {
        actions_with(client, spec()).attach(volume(), instance())
    });
}

#[test]
fn every_scripted_fault_leaves_a_detach_unknown_with_at_most_one_request() {
    assert_each_fault_gives(FAULT_DEADLINE, &DetachReply::Unknown, |client| {
        actions_with(client, spec()).detach(Witness::Ended(&witness()))
    });
}

/// Each action's request declares its body as a UTF-8 form, once.
#[test]
fn each_action_declares_its_body_as_a_form() {
    let lost = || Answer::Lost(LostAt::Exchange, ErrorKind::TimedOut);
    let replay = Replay::new([lost(), lost(), lost()]);
    let mut actions = actions(&replay);
    let _ = actions.create(TOKEN, LAYOUT);
    let _ = actions.attach(volume(), instance());
    let _ = actions.detach(Witness::Ended(&witness()));
    let sent = replay.sent();
    assert_eq!(sent.len(), 3);
    for request in &sent {
        let declared: Vec<&str> = request
            .headers
            .iter()
            .filter(|(name, _)| name == "content-type")
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(
            declared,
            ["application/x-www-form-urlencoded; charset=utf-8"]
        );
    }
}

/// A call that ends at the credential lookup gives each action's unknown
/// outcome and sends no request.
#[test]
fn a_call_that_finds_no_credentials_is_unknown_and_sends_nothing() {
    let replay = Replay::default();
    let clock = Manual::at(origin());
    let role = Role::at(refused());
    let client = client_in(
        "us-east-1",
        replay.clone(),
        "fake",
        DEADLINE,
        1024,
        role,
        clock,
    );
    let mut actions = actions_with(client, spec());
    assert_eq!(actions.create(TOKEN, LAYOUT), Err(CreateError::Unknown));
    assert_eq!(actions.attach(volume(), instance()), AttachReply::Unknown);
    assert_eq!(
        actions.detach(Witness::Ended(&witness())),
        DetachReply::Unknown
    );
    assert_eq!(replay.count(), 0);
}

type Call<W> = fn(&mut VolumeActions<W, Manual>);

fn calls<W: Wire>() -> [(&'static str, Call<W>); 3] {
    [
        ("create", |actions| {
            assert_eq!(actions.create(TOKEN, LAYOUT), Err(CreateError::Unknown));
        }),
        ("attach", |actions| {
            assert_eq!(actions.attach(volume(), instance()), AttachReply::Unknown);
        }),
        ("detach", |actions| {
            assert_eq!(
                actions.detach(Witness::Ended(&witness())),
                DetachReply::Unknown
            );
        }),
    ]
}

/// The control for the one-attempt check: a wire that sends again after a
/// reset makes the server read two requests per action, and the check fails.
#[test]
fn a_wire_that_sends_again_fails_the_one_attempt_check() {
    for (name, call) in calls::<Https>() {
        let once = reset();
        call(&mut actions_with(
            client(Https::plain(), &once.host, DEADLINE),
            spec(),
        ));
        assert_eq!(once.one_attempt(), Ok(()), "{name}");
    }
    for (name, call) in calls::<Resend<Https>>() {
        let twice = reset();
        let wire = Resend(Https::plain());
        call(&mut actions_with(
            client(wire, &twice.host, DEADLINE),
            spec(),
        ));
        assert_eq!(
            twice.one_attempt(),
            Err("reset after the request: 2 requests, expected 1".to_owned()),
            "{name}"
        );
    }
}

/// The adapter builds for an EC2 client of the zone's region with a spec of
/// `io2` values that holds the replacement layout.
#[test]
fn the_adapter_builds_only_for_its_zone_and_a_spec_that_holds_the_layout() {
    for (region, name, served) in ZONE_NAMES {
        let standard = name
            .strip_prefix(region)
            .is_some_and(|suffix| suffix.len() == 1);
        let built = VolumeActions::new(offline(region), &bounds_of(ZONE, name), spec());
        assert_eq!(built.is_some(), served && standard, "{region} {name}");
    }
    for (name, built) in [
        ("us-east-1a", true),
        ("us-east-1-bos-1a", false),
        ("us-east-1-atl-2b", false),
        ("us-east-1-wl1-bos-wlz-1", false),
    ] {
        let actions = VolumeActions::new(offline("us-east-1"), &bounds_of(ZONE, name), spec());
        assert_eq!(actions.is_some(), built, "{name}");
    }
    let dynamo = crate::loopback::client(
        Replay::default(),
        "fake".to_owned(),
        crate::loopback::refused(),
        Manual::at(crate::loopback::origin()),
        DEADLINE,
    );
    let bounds = bounds_of(ZONE, "us-east-1a");
    assert!(VolumeActions::new(dynamo, &bounds, spec()).is_none());
    let builds = |spec| VolumeActions::new(offline("us-east-1"), &bounds, spec).is_some();
    for (size_gib, iops, built) in [
        (4, 100, true),
        (65_536, 256_000, true),
        (4, 4_000, true),
        (4, 4_001, false),
        (256, 256_000, true),
        (255, 256_000, false),
        (3, 1_000, false),
        (65_537, 16_000, false),
        (500, 99, false),
        (500, 256_001, false),
    ] {
        let spec = VolumeSpec {
            size_gib,
            iops,
            kms_key: None,
        };
        assert_eq!(builds(spec), built, "{size_gib} GiB, {iops} IOPS");
    }
    for (key, built) in [
        (String::new(), false),
        ("k".repeat(2048), true),
        ("k".repeat(2049), false),
        ("clé".to_owned(), false),
    ] {
        let spec = VolumeSpec {
            kms_key: Some(key.clone()),
            ..spec()
        };
        assert_eq!(builds(spec), built, "{} bytes", key.len());
    }
    let four = VolumeSpec {
        size_gib: 4,
        iops: 4_000,
        kms_key: None,
    };
    for (units, built) in [((4 << 18) - 1, true), (4 << 18, false)] {
        let replacement = Layout {
            units,
            slots: 3,
            slot_units: 3,
            entries: 64,
        };
        let bounds = bounds_with(ZONE, "us-east-1a", replacement);
        let built_actions = VolumeActions::new(offline("us-east-1"), &bounds, four.clone());
        assert_eq!(built_actions.is_some(), built, "{units} units");
    }
}
