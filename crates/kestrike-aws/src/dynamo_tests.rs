use std::cell::RefCell;
use std::collections::BTreeSet;
use std::num::{NonZeroU16, NonZeroU32};
use std::rc::Rc;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use kestrike::failover::records::{CoveragePage, Host, Namespace, ShardRecord, VolumeId};
use kestrike::failover::standbys::Zone;
use kestrike::net::EntropyError;
use kestrike::net::ownership::{Shard, ShardGeneration};
use kestrike::storage::store::dynamo::{Dynamo, Exchange, Fault, classify};
use kestrike::storage::store::{
    Client as StoreClient, ITEM_LIMIT, Item, Key, Outcome, Refusal, Regression, Store, StoreError,
    Unavailable, Version, Watermark, WatermarkLog, Write,
};
use serde_json::{Value, json};

use super::{OpenError, Table};
use crate::DYNAMODB;
use crate::client::Stage;
use crate::config::Config;
use crate::fake_table::{FakeTable, ITEM_BYTES, Plant, TABLE_ID};
use crate::loopback::{
    Answer, CAP, Counting, Credentials, Expect, Manual, Resend, Scripted, Server, faults, metadata,
    origin, reply, serve, service, settled, silent, warmed,
};
use crate::wire::{Https, Lost, Reply, Request, Wire};

const NAME: &str = "kestrike-store";
const NONCE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const DEADLINE: Duration = Duration::from_secs(1);
const CONDITION_FAILED: &str = "com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException";

fn metadata_address() -> std::net::SocketAddr {
    static METADATA: OnceLock<Server> = OnceLock::new();
    METADATA
        .get_or_init(|| {
            metadata(Arc::new(Mutex::new(Credentials::Serve {
                key: "AKIDTABLE",
                expiry: origin() + Duration::from_secs(3600),
            })))
        })
        .address
}

fn store_client<W: Wire>(wire: W, host: &str, deadline: Duration) -> crate::Client<W, Manual> {
    let clock = Manual::at(origin());
    let role = warmed(metadata_address(), &clock);
    let config = Config::new(service(deadline), "us-east-1")
        .unwrap()
        .at(host.to_owned());
    crate::Client::new(config, wire, role, clock)
}

fn table_at<W: Wire>(wire: W, host: &str, deadline: Duration) -> Table<W, Manual> {
    Table {
        client: store_client(wire, host, deadline),
        name: NAME.to_owned(),
        namespace: Namespace::new([0x5a; 16]).unwrap(),
        nonce: NONCE,
        writes: 0,
    }
}

fn opened(fake: &FakeTable) -> Table<FakeTable, Manual> {
    Table::open(store_client(fake.clone(), "fake", DEADLINE), NAME).unwrap()
}

#[derive(Clone, Default)]
struct Log(Rc<RefCell<Watermark>>);

impl WatermarkLog for Log {
    fn load(&self) -> std::io::Result<Watermark> {
        Ok(self.0.borrow().clone())
    }

    fn record(&mut self, mark: &Watermark) -> std::io::Result<()> {
        *self.0.borrow_mut() = mark.clone();
        Ok(())
    }
}

type Over = StoreClient<Dynamo<Table<FakeTable, Manual>>, Log>;

fn over(fake: &FakeTable) -> Over {
    logged(fake, &Log::default())
}

fn logged(fake: &FakeTable, log: &Log) -> Over {
    StoreClient::open(Dynamo(opened(fake)), log.clone()).unwrap()
}

fn shard() -> Shard {
    Shard::new(7).unwrap()
}

fn record() -> ShardRecord {
    ShardRecord {
        shard: shard(),
        generation: ShardGeneration::new(3).unwrap(),
        active: VolumeId::new("vol-0a").unwrap(),
        owner: Host::new(11).unwrap(),
        attempts: 0,
        spare: Some((VolumeId::new("vol-0b").unwrap(), Host::new(12).unwrap())),
        checkpoint: None,
        cut: 0,
        pages: NonZeroU16::new(2).unwrap(),
        page_cap: NonZeroU32::new(4096).unwrap(),
        namespace: Namespace::new(super::uuid(TABLE_ID).unwrap()).unwrap(),
        ancestry: Default::default(),
        standby: None,
    }
}

fn seeded() -> FakeTable {
    let fake = FakeTable::new();
    over(&fake).create_shard(record()).unwrap();
    fake
}

fn attempts(fake: &FakeTable) -> u32 {
    let mut reader = over(fake);
    reader
        .read::<ShardRecord>(Key::Shard(shard()))
        .unwrap()
        .value()
        .attempts
}

fn described(fields: &Value) -> String {
    let mut table = json!({
        "TableName": NAME,
        "TableId": TABLE_ID,
        "AttributeDefinitions": [{ "AttributeName": "pk", "AttributeType": "S" }],
        "KeySchema": [{ "AttributeName": "pk", "KeyType": "HASH" }],
    });
    for (name, value) in fields.as_object().unwrap() {
        table[name] = value.clone();
    }
    json!({ "Table": table }).to_string()
}

fn image(field: &str, value: &Value) -> Value {
    let mut item = json!({
        "pk": { "S": "shard#7" },
        "ver": { "N": "4" },
        "val": { "B": "cmVjb3Jk" },
        "wid": { "B": "AQIDBAUGBwgAAAAAAAAAAQ==" },
    });
    item[field] = value.clone();
    item
}

fn without(field: &str) -> Value {
    let mut item = image(field, &Value::Null);
    item.as_object_mut().unwrap().remove(field);
    item
}

#[test]
fn open_takes_the_table_id_as_the_namespace() {
    let fake = FakeTable::new();
    let table = opened(&fake);
    assert_eq!(
        table.namespace().bytes(),
        [
            0x8c, 0x2b, 0x0d, 0x9e, 0x6f, 0x1a, 0x4c, 0x3e, 0x9b, 0x7d, 0x2a, 0x5e, 0x4f, 0x6c,
            0x1d, 0x03
        ]
    );
    assert_eq!(
        fake.requests(),
        [("DescribeTable".to_owned(), json!({ "TableName": NAME }))]
    );
}

#[test]
fn a_table_prints_its_name_and_namespace_and_no_other_field() {
    let table = opened(&FakeTable::new());
    assert_eq!(
        format!("{table:?}"),
        format!(
            "Table {{ name: {NAME:?}, namespace: {:?}, .. }}",
            table.namespace()
        )
    );
}

#[test]
fn every_request_names_the_opened_table() {
    let fake = FakeTable::with_id("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0");
    let mut table =
        Table::open(store_client(fake.clone(), "fake", DEADLINE), "other-table").unwrap();
    assert_eq!(
        table.namespace().bytes(),
        [
            0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2,
            0xe1, 0xf0
        ]
    );
    table.write("shard#7", &Write::Create(Vec::new())).unwrap();
    table.get("shard#7").unwrap();
    let actions: Vec<(String, Value)> = fake
        .requests()
        .into_iter()
        .map(|(action, body)| (action, body["TableName"].clone()))
        .collect();
    assert_eq!(
        actions,
        [
            ("DescribeTable".to_owned(), json!("other-table")),
            ("PutItem".to_owned(), json!("other-table")),
            ("GetItem".to_owned(), json!("other-table")),
        ]
    );
}

#[test]
fn open_refuses_a_failed_call_a_coded_reply_and_an_unusable_table_id() {
    for table_id in [
        "00000000-0000-0000-0000-000000000000",
        "8c2b0d9e6f1a4c3e9b7d2a5e4f6c1d03",
        "8c2b0d9e-6f1a-4c3e-9b7d-2a5e4f6c1dzz",
        "8c2b0d9e-6f1a-4c3e-9b7d-2a5e4f6c1d0",
        "+c2b0d9e-6f1a-4c3e-9b7d-2a5e4f6c1d03",
        "8c2b0d9e-6f1a-4c3e-9b7d-2a5e4f6c1dé",
    ] {
        let fake = FakeTable::with_id(table_id);
        assert_eq!(
            Table::open(store_client(fake, "fake", DEADLINE), NAME).err(),
            Some(OpenError::Reply),
            "{table_id}"
        );
    }
    let fake = FakeTable::new();
    fake.plant(Plant::Lose { apply: true });
    assert!(matches!(
        Table::open(store_client(fake.clone(), "fake", DEADLINE), NAME),
        Err(OpenError::Call(fault)) if fault.action == "DescribeTable" && fault.stage == Stage::Exchange
    ));
    for status in [400, 500] {
        fake.plant(Plant::Reply {
            apply: false,
            status,
            body: r#"{"__type":"com.amazonaws.dynamodb.v20120810#ResourceNotFoundException"}"#
                .into(),
        });
        assert_eq!(
            Table::open(store_client(fake.clone(), "fake", DEADLINE), NAME).err(),
            Some(OpenError::Code(
                "com.amazonaws.dynamodb.v20120810#ResourceNotFoundException".into()
            )),
            "{status}"
        );
        for code in ["Bad\nCode".to_owned(), "x".repeat(257)] {
            fake.plant(Plant::Reply {
                apply: false,
                status,
                body: json!({ "__type": code }).to_string(),
            });
            assert_eq!(
                Table::open(store_client(fake.clone(), "fake", DEADLINE), NAME).err(),
                Some(OpenError::Reply),
                "{status} {code:?}"
            );
        }
    }
    assert_eq!(
        OpenError::Code("Bad\nCode".into()).to_string(),
        r#"DescribeTable returned "Bad\nCode""#
    );
}

#[test]
fn open_refuses_an_unusable_reply_or_a_table_keyed_otherwise() {
    let valid = described(&json!({}));
    let tagged =
        json!({ "__type": "x", "Table": serde_json::from_str::<Value>(&valid).unwrap()["Table"] });
    let replies = [
        (307, valid.clone()),
        (201, valid.clone()),
        (500, "[]".to_owned()),
        (400, r#"{"message":"no code"}"#.to_owned()),
        (200, tagged.to_string()),
        (200, "{}".to_owned()),
        (200, r#"{"Table":{}}"#.to_owned()),
        (200, described(&json!({ "TableId": 7 }))),
        (200, described(&json!({ "TableId": null }))),
        (200, {
            let mut table: Value = serde_json::from_str(&valid).unwrap();
            table["Table"].as_object_mut().unwrap().remove("TableId");
            table.to_string()
        }),
        (200, {
            let mut reply: Value = serde_json::from_str(&valid).unwrap();
            reply["Table"].as_object_mut().unwrap().remove("TableId");
            reply["TableId"] = json!(TABLE_ID);
            reply["Table"]["TableDescription"] = json!({ "TableId": TABLE_ID });
            reply.to_string()
        }),
        (200, {
            let mut table: Value = serde_json::from_str(&valid).unwrap();
            let members = table["Table"].as_object_mut().unwrap();
            members.remove("TableId");
            for member in [
                "TableName",
                "TableArn",
                "TableStatus",
                "LatestStreamArn",
                "LatestStreamLabel",
            ] {
                members.insert(member.to_owned(), json!(TABLE_ID));
            }
            table.to_string()
        }),
        (
            200,
            described(&json!({ "KeySchema": [
                { "AttributeName": "pk", "KeyType": "HASH" },
                { "AttributeName": "wid", "KeyType": "RANGE" },
            ]})),
        ),
        (
            200,
            described(&json!({ "KeySchema": [{ "AttributeName": "wid", "KeyType": "HASH" }] })),
        ),
        (
            200,
            described(&json!({ "KeySchema": [{ "AttributeName": "pk", "KeyType": "RANGE" }] })),
        ),
        (
            200,
            described(
                &json!({ "AttributeDefinitions": [{ "AttributeName": "pk", "AttributeType": "N" }] }),
            ),
        ),
        (200, described(&json!({ "AttributeDefinitions": null }))),
        (200, described(&json!({ "KeySchema": null }))),
        (200, {
            let mut table: Value = serde_json::from_str(&valid).unwrap();
            table["Table"].as_object_mut().unwrap().remove("KeySchema");
            table.to_string()
        }),
        (200, described(&json!({ "KeySchema": [] }))),
        (200, described(&json!({ "AttributeDefinitions": [] }))),
        (
            200,
            described(
                &json!({ "AttributeDefinitions": [{ "AttributeName": "gsi", "AttributeType": "S" }] }),
            ),
        ),
        (
            200,
            described(&json!({ "AttributeDefinitions": [
                { "AttributeName": "pk", "AttributeType": "S" },
                { "AttributeName": "pk", "AttributeType": "N" },
            ]})),
        ),
        (
            200,
            described(&json!({ "Replicas": [{ "RegionName": "us-west-2" }] })),
        ),
        (200, described(&json!({ "Replicas": {} }))),
        (200, {
            let mut table: Value = serde_json::from_str(&valid).unwrap();
            table["Item"] = image("ver", &json!({ "N": "4" }));
            table.to_string()
        }),
    ];
    for (status, body) in replies {
        let fake = FakeTable::new();
        fake.plant(Plant::Reply {
            apply: false,
            status,
            body: body.clone(),
        });
        let opened = Table::open_with(store_client(fake.clone(), "fake", DEADLINE), NAME, || {
            panic!("a refused reply draws no nonce")
        });
        assert_eq!(opened.err(), Some(OpenError::Reply), "{status} {body}");
        assert_eq!(fake.requests().len(), 1, "{status} {body}: one request");
    }
    let indexed = described(&json!({
        "AttributeDefinitions": [
            { "AttributeName": "gsi", "AttributeType": "S" },
            { "AttributeName": "pk", "AttributeType": "S", "Extra": 1 },
        ],
        "KeySchema": [{ "AttributeName": "pk", "KeyType": "HASH", "Extra": 1 }],
        "Replicas": [],
    }));
    let upper = described(&json!({ "TableId": TABLE_ID.to_uppercase() }));
    for body in [valid, indexed, upper] {
        let fake = FakeTable::new();
        fake.plant(Plant::Reply {
            apply: false,
            status: 200,
            body: body.clone(),
        });
        let opened = Table::open(store_client(fake, "fake", DEADLINE), NAME);
        assert_eq!(
            opened.map(|table| table.namespace()),
            Ok(Namespace::new(super::uuid(TABLE_ID).unwrap()).unwrap()),
            "{body}"
        );
    }
}

#[test]
fn open_takes_its_nonce_from_the_draw_after_the_reply_checks() {
    let fake = FakeTable::new();
    let failed = Table::open_with(store_client(fake.clone(), "fake", DEADLINE), NAME, || {
        Err(EntropyError::Unavailable { code: 5 })
    });
    assert_eq!(
        failed.err(),
        Some(OpenError::Entropy(EntropyError::Unavailable { code: 5 }))
    );
    assert_eq!(
        fake.requests().len(),
        1,
        "one DescribeTable before the draw"
    );

    let drawn = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0, 0, 0, 0, 0, 0, 0, 9,
    ];
    let fake = FakeTable::new();
    let mut table = Table::open_with(store_client(fake.clone(), "fake", DEADLINE), NAME, || {
        Ok(drawn)
    })
    .unwrap();
    table.write("shard#7", &Write::Create(Vec::new())).unwrap();
    let wid = fake.commits().pop().unwrap().wid;
    assert_eq!(
        wid,
        [
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0, 0, 0, 0, 0, 0, 0, 0
        ]
    );
}

#[test]
fn get_reads_strongly_and_returns_the_stored_item_or_none() {
    let fake = FakeTable::new();
    fake.seed("shard#7", 3, b"record", [9; 16]);
    let mut table = opened(&fake);
    assert_eq!(
        table.get("shard#7"),
        Ok(Some(Item {
            version: Version::new(3).unwrap(),
            value: b"record".to_vec()
        }))
    );
    assert_eq!(table.get("shard#8"), Ok(None));
    let reads: Vec<Value> = fake
        .requests()
        .into_iter()
        .filter(|(action, _)| action == "GetItem")
        .map(|(_, body)| body)
        .collect();
    assert_eq!(
        reads,
        [
            json!({ "TableName": NAME, "Key": { "pk": { "S": "shard#7" } }, "ConsistentRead": true }),
            json!({ "TableName": NAME, "Key": { "pk": { "S": "shard#8" } }, "ConsistentRead": true }),
        ]
    );
}

#[test]
fn each_record_kind_is_stored_and_read_under_its_pk() {
    let fake = FakeTable::new();
    let mut store = Dynamo(opened(&fake));
    let kinds = [
        (Key::Shard(shard()), "shard#7"),
        (
            Key::Volume(VolumeId::new("vol-0a").unwrap()),
            "volume#vol-0a",
        ),
        (Key::Page(shard(), 3), "page#7#3"),
        (Key::Standbys(Zone(2)), "standbys#2"),
        (Key::Replacement(shard()), "replacement#7"),
    ];
    for (key, pk) in &kinds {
        let value = pk.as_bytes().to_vec();
        assert_eq!(
            store.write(key, &Write::Create(value.clone())),
            Outcome::Committed(Version::FIRST),
            "{pk}"
        );
        let stored = fake.item(pk).map(|item| item["pk"].clone());
        assert_eq!(stored, Some(json!({ "S": pk })), "an item under {pk}");
        let version = Version::FIRST;
        assert_eq!(store.read(key), Ok(Some(Item { version, value })), "{pk}");
    }
    let stored: Vec<String> = fake
        .commits()
        .into_iter()
        .map(|commit| commit.key)
        .collect();
    assert_eq!(stored, kinds.map(|(_, pk)| pk), "one item per record");
}

#[test]
fn a_second_create_of_one_key_fails_its_condition_with_one_request_each() {
    let fake = FakeTable::new();
    let mut store = Dynamo(opened(&fake));
    let key = Key::Shard(shard());
    assert_eq!(
        store.write(&key, &Write::Create(b"one".to_vec())),
        Outcome::Committed(Version::FIRST)
    );
    assert_eq!(fake.requests().len(), 2, "DescribeTable, then one PutItem");
    assert_eq!(
        store.write(&key, &Write::Create(b"two".to_vec())),
        Outcome::NotCommitted(Refusal::Condition)
    );
    assert_eq!(fake.requests().len(), 3);
    assert_eq!(fake.commits().len(), 1);
    let exact = Write::Exact {
        expect: Version::FIRST,
        value: Vec::new(),
    };
    assert_eq!(
        store.write(&Key::Shard(Shard::new(8).unwrap()), &exact),
        Outcome::NotCommitted(Refusal::Condition),
        "an exact write to an absent item fails its condition"
    );
}

#[test]
fn an_exact_write_conditions_on_its_version_and_commits_the_next() {
    let fake = FakeTable::new();
    fake.seed("shard#7", 4, b"old", [9; 16]);
    let mut table = opened(&fake);
    let write = Write::Exact {
        expect: Version::new(4).unwrap(),
        value: b"new".to_vec(),
    };
    assert_eq!(table.write("shard#7", &write), Ok(Version::new(5).unwrap()));
    let (_, body) = fake.requests().pop().unwrap();
    assert_eq!(body["ConditionExpression"], "ver = :expect");
    assert_eq!(
        body["ExpressionAttributeValues"],
        json!({ ":expect": { "N": "4" } })
    );
    assert_eq!(body["Item"]["ver"], json!({ "N": "5" }));
    assert_eq!(body["ReturnValues"], "ALL_OLD");
    assert_eq!(fake.item("shard#7").unwrap()["ver"], json!({ "N": "5" }));
}

#[test]
fn each_write_request_carries_the_nonce_and_its_own_count() {
    let fake = FakeTable::new();
    let mut table = opened(&fake);
    let nonce = table.nonce;
    let rejected = Err(Fault::Error("ValidationException".into()));
    let last = Write::Exact {
        expect: Version::new(u64::MAX).unwrap(),
        value: Vec::new(),
    };
    assert_eq!(table.write("a", &last), rejected, "an overflowing version");
    assert_eq!(
        table.write("a", &Write::Create(vec![0; ITEM_BYTES])),
        rejected,
        "an oversized value"
    );
    table.write("a", &Write::Create(Vec::new())).unwrap();
    assert_eq!(
        table.write("a", &Write::Create(Vec::new())),
        Err(Fault::Error(CONDITION_FAILED.into()))
    );
    table.get("a").unwrap();
    fake.plant(Plant::Lose { apply: false });
    assert_eq!(
        table.write("b", &Write::Create(Vec::new())),
        Err(Fault::Transport)
    );
    table.write("b", &Write::Create(Vec::new())).unwrap();
    let wids: Vec<Vec<u8>> = fake
        .requests()
        .iter()
        .filter(|(action, _)| action == "PutItem")
        .map(|(_, body)| {
            STANDARD
                .decode(body["Item"]["wid"]["B"].as_str().unwrap())
                .unwrap()
        })
        .collect();
    let expected: Vec<Vec<u8>> = (0..4u64)
        .map(|count| [nonce.as_slice(), &count.to_be_bytes()].concat())
        .collect();
    assert_eq!(wids, expected, "rejected writes take no count");
    assert_ne!(opened(&fake).nonce, nonce, "each table draws its own nonce");

    let fake = FakeTable::new();
    let mut table = opened(&fake);
    table.writes = u64::MAX - 1;
    table.write("c", &Write::Create(Vec::new())).unwrap();
    assert_eq!(
        fake.commits().pop().unwrap().wid[8..],
        (u64::MAX - 1).to_be_bytes(),
        "the last count"
    );
    assert_eq!(
        table.write("d", &Write::Create(Vec::new())),
        rejected,
        "every count used"
    );
    assert_eq!(
        fake.requests().len(),
        2,
        "the exhausted write sends nothing"
    );
}

#[test]
fn a_lost_reply_after_a_commit_is_unknown_and_adopts_nothing() {
    let fake = seeded();
    let log = Log::default();
    let mut owner = logged(&fake, &log);
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let before = log.load().unwrap();
    let sent = fake.requests().len();
    fake.plant(Plant::Lose { apply: true });
    assert_eq!(owner.bump(&read), Err(StoreError::Unknown));
    assert_eq!(fake.requests().len(), sent + 1, "one request");
    assert_eq!(log.load().unwrap(), before, "nothing adopted");
    assert_eq!(attempts(&fake), 1, "the next read shows the commit");
}

#[test]
fn unknown_outcomes_adopt_nothing() {
    let internal = r#"{"__type":"com.amazonaws.dynamodb.v20120810#InternalServerError"}"#;
    let refused = format!(r#"{{"__type":"{CONDITION_FAILED}"}}"#);
    let coded = |apply, status, body: &str| Plant::Reply {
        apply,
        status,
        body: body.to_owned(),
    };
    let get_shaped = json!({ "Item": image("ver", &json!({ "N": "1" })) }).to_string();
    for (plant, commits) in [
        (Plant::Lose { apply: true }, true),
        (Plant::Lose { apply: false }, false),
        (coded(true, 500, internal), true),
        (coded(false, 500, internal), false),
        (coded(true, 500, &refused), true),
        (coded(false, 200, &get_shaped), false),
    ] {
        let fake = seeded();
        let log = Log::default();
        let mut first = logged(&fake, &log);
        let read = first.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        let before = log.load().unwrap();
        let commits_before = fake.commits().len();
        fake.plant(plant.clone());
        assert_eq!(first.bump(&read), Err(StoreError::Unknown), "{plant:?}");
        assert_eq!(log.load().unwrap(), before, "{plant:?}: nothing adopted");
        assert_eq!(
            fake.commits().len(),
            commits_before + usize::from(commits),
            "{plant:?}"
        );
        let mut second = over(&fake);
        let current = second.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        let bumped = second.bump(&current).unwrap();
        assert_eq!(
            bumped.attempt(),
            u32::from(commits),
            "{plant:?}: the second attempt's own n"
        );
    }
}

#[test]
fn contract_arms_adopt_only_acknowledged_values() {
    let key = Key::Shard(shard());

    let fake = seeded();
    let mut owner = over(&fake);
    let read = owner.read::<ShardRecord>(key).unwrap();
    let commits = fake.commits().len();
    fake.plant(Plant::Duplicate);
    let bumped = owner.bump(&read).unwrap();
    assert_eq!(bumped.attempt(), 0);
    assert_eq!(attempts(&fake), 1);
    assert_eq!(fake.commits().len(), commits + 1, "one commit");
    let redeliveries = fake.redeliveries();
    assert_eq!(redeliveries.len(), 1, "one second delivery");
    let (status, body) = &redeliveries[0];
    assert_eq!(*status, 400);
    assert_eq!(
        serde_json::from_str::<Value>(body).unwrap()["__type"],
        CONDITION_FAILED,
        "the second delivery fails its condition"
    );

    let fake = seeded();
    let mut owner = over(&fake);
    let read = owner.read::<ShardRecord>(key).unwrap();
    fake.plant(Plant::Lose { apply: false });
    assert_eq!(
        owner.read::<ShardRecord>(key).map(drop),
        Err(StoreError::Unavailable)
    );
    fake.plant(Plant::Lose { apply: false });
    assert_eq!(owner.bump(&read), Err(StoreError::Unknown));
    assert_eq!(attempts(&fake), 0, "an unavailable store commits nothing");

    let put_shaped = json!({ "Attributes": image("ver", &json!({ "N": "1" })) }).to_string();
    let fake = seeded();
    let mut marked = over(&fake);
    marked.read::<ShardRecord>(key).unwrap();
    for client in [&mut marked, &mut over(&fake)] {
        fake.plant(Plant::Reply {
            apply: false,
            status: 200,
            body: put_shaped.clone(),
        });
        assert_eq!(
            client.read::<ShardRecord>(key).map(drop),
            Err(StoreError::Unavailable),
            "a PutItem reply to a read"
        );
        assert!(client.read::<ShardRecord>(key).is_ok(), "still admitted");
    }

    let fake = seeded();
    let (mut a, mut b) = (over(&fake), over(&fake));
    let stale = a.read::<ShardRecord>(key).unwrap();
    let current = b.read::<ShardRecord>(key).unwrap();
    b.bump(&current).unwrap();
    let before = (fake.item("shard#7"), fake.commits());
    assert_eq!(
        a.replace(&stale, *stale.value()).map(drop),
        Err(StoreError::Refused(Refusal::Condition))
    );
    assert_eq!(
        (fake.item("shard#7"), fake.commits()),
        before,
        "a stale replacement leaves the item as it was"
    );
}

#[test]
fn a_misreported_old_version_regresses_and_withdraws_the_client() {
    let key = Key::Shard(shard());
    let misreport = |ver: u64| Plant::Reply {
        apply: true,
        status: 200,
        body: json!({ "Attributes": {
            "pk": { "S": "shard#7" },
            "ver": { "N": ver.to_string() },
            "val": { "B": "" },
            "wid": { "B": "AAAAAAAAAAAAAAAAAAAAAA==" },
        }})
        .to_string(),
    };
    let fake = FakeTable::new();
    let mut creator = over(&fake);
    fake.plant(misreport(1));
    assert_eq!(
        creator.create(key, record()).map(drop),
        Err(StoreError::Regression(Regression::Value(key)))
    );
    assert_eq!(
        fake.item("shard#7").unwrap()["ver"],
        json!({ "N": "1" }),
        "the create committed"
    );
    assert_eq!(
        creator.read::<ShardRecord>(key).map(drop),
        Err(StoreError::Withdrawn)
    );

    let no_old_item = Plant::Reply {
        apply: true,
        status: 200,
        body: "{}".into(),
    };
    for (name, offset) in [
        ("ahead", Some(5)),
        ("behind", Some(-1)),
        ("no old item", None),
    ] {
        let fake = seeded();
        let mut owner = over(&fake);
        let current = owner.read::<ShardRecord>(key).unwrap();
        owner.bump(&current).unwrap();
        let read = owner.read::<ShardRecord>(key).unwrap();
        let mut writer = over(&fake);
        fake.plant(match offset {
            Some(offset) => misreport(read.version().get().checked_add_signed(offset).unwrap()),
            None => no_old_item.clone(),
        });
        assert_eq!(
            writer.replace(&read, *read.value()).map(drop),
            Err(StoreError::Regression(Regression::Value(key))),
            "{name}"
        );
        assert_eq!(
            fake.item("shard#7").unwrap()["ver"],
            json!({ "N": "3" }),
            "{name}: the replacement committed"
        );
        assert_eq!(
            writer.read::<ShardRecord>(key).map(drop),
            Err(StoreError::Withdrawn),
            "{name}"
        );
    }
}

#[test]
fn a_create_at_a_version_the_watermark_holds_regresses_and_withdraws_the_client() {
    let page = Key::Page(shard(), 1);
    let log = Log::default();
    logged(&FakeTable::new(), &log)
        .create(page, CoveragePage::default())
        .unwrap();
    // The log holds a mark for the page and this table holds no item, so the
    // page's create commits at version 1, which the watermark already holds.
    let emptied = FakeTable::new();
    let mut host = logged(&emptied, &log);
    assert_eq!(
        host.create_shard(record()).map(drop),
        Err(StoreError::Regression(Regression::Value(page)))
    );
    assert_eq!(
        emptied.item("page#7#1").unwrap()["ver"],
        json!({ "N": "1" }),
        "the page's create committed"
    );
    assert_eq!(emptied.item("shard#7"), None, "no shard record follows");
    assert_eq!(
        host.read::<CoveragePage>(page).map(drop),
        Err(StoreError::Withdrawn)
    );
}

#[test]
fn items_within_the_size_limit_commit_and_larger_ones_are_rejected() {
    let fake = seeded();
    let mut owner = over(&fake);
    let key = Key::Page(shard(), 1);
    let read = owner.read::<CoveragePage>(key).unwrap();
    let fits = CoveragePage {
        entries: (0..390 * 1024).map(|i: u32| (i % 251) as u8).collect(),
        ..read.value().clone()
    };
    let committed = owner.replace(&read, fits).unwrap();
    let sent = fake.requests().len();
    let over_limit = CoveragePage {
        entries: vec![7; ITEM_BYTES],
        ..committed.value().clone()
    };
    assert_eq!(
        owner.replace(&committed, over_limit).map(drop),
        Err(StoreError::Refused(Refusal::Rejected))
    );
    assert_eq!(fake.requests().len(), sent, "rejected before sending");
    let unchanged = owner.read::<CoveragePage>(key).unwrap();
    assert_eq!(unchanged.version(), committed.version());
    assert_eq!(unchanged.value(), committed.value());

    let page_key = "page#7#1";
    for (key, text) in [(Key::Shard(shard()), "shard#7"), (key, page_key)] {
        let budget = ITEM_LIMIT - ("pkvervalwid".len() + text.len() + 11 + 16);
        let value: Vec<u8> = (0..budget).map(|i| (i % 251) as u8).collect();
        let fake = FakeTable::new();
        assert_eq!(
            Dynamo(opened(&fake)).write(&key, &Write::Create(value.clone())),
            Outcome::Committed(Version::FIRST),
            "{text}: a {budget}-byte value"
        );
        assert_eq!(fake.requests().len(), 2, "{text}");
        let stored = fake.item(text).unwrap();
        assert_eq!(stored["ver"], json!({ "N": "1" }), "{text}");
        assert_eq!(
            stored["val"],
            json!({ "B": STANDARD.encode(&value) }),
            "{text}"
        );

        let fake = FakeTable::new();
        assert_eq!(
            Dynamo(opened(&fake)).write(&key, &Write::Create(vec![0; budget + 1])),
            Outcome::NotCommitted(Refusal::Rejected),
            "{text}: one byte over"
        );
        assert_eq!(fake.requests().len(), 1, "{text}: rejected before sending");
        assert_eq!(fake.item(text), None, "{text}");

        let fake = FakeTable::new();
        fake.seed(text, u64::MAX - 1, b"old", [9; 16]);
        let at_last = Write::Exact {
            expect: Version::new(u64::MAX - 1).unwrap(),
            value: value.clone(),
        };
        assert_eq!(
            Dynamo(opened(&fake)).write(&key, &at_last),
            Outcome::Committed(Version::new(u64::MAX).unwrap()),
            "{text}: a budget-sized value fits at the largest version"
        );
        let item = fake.item(text).unwrap();
        assert_eq!(item["ver"], json!({ "N": u64::MAX.to_string() }), "{text}");
        assert_eq!(
            item["val"],
            json!({ "B": STANDARD.encode(&value) }),
            "{text}"
        );
        for envelope in ["Item", "Attributes"] {
            let reply = json!({ envelope: item }).to_string();
            assert!(
                reply.len() <= DYNAMODB.body_cap,
                "{text} {envelope}: a {}-byte reply",
                reply.len()
            );
        }
    }

    let fake = FakeTable::new();
    let mut table = opened(&fake);
    let long = "k".repeat(ITEM_LIMIT);
    for write in [
        Write::Create(Vec::new()),
        Write::Exact {
            expect: Version::FIRST,
            value: Vec::new(),
        },
    ] {
        assert_eq!(
            table.write(&long, &write),
            Err(Fault::Error("ValidationException".into())),
            "an empty value under a key that fills the item"
        );
    }
    assert_eq!(fake.requests().len(), 1, "no PutItem");
    table.write("shard#7", &Write::Create(Vec::new())).unwrap();
    assert_eq!(
        fake.commits().pop().unwrap().wid[8..],
        0u64.to_be_bytes(),
        "the rejected writes took no count"
    );

    let fake = FakeTable::new();
    fake.set_limit(64);
    assert_eq!(
        Dynamo(opened(&fake)).write(&key, &Write::Create(vec![0; 64])),
        Outcome::NotCommitted(Refusal::Rejected),
        "the table's own size refusal"
    );
    assert!(fake.commits().is_empty());
    assert_eq!(fake.item(page_key), None);
}

fn put(fake: &FakeTable, body: &Value) -> (u16, Value) {
    send(fake, "PutItem", &body.to_string())
}

fn send(fake: &FakeTable, action: &str, body: &str) -> (u16, Value) {
    let headers = [(
        "x-amz-target".to_owned(),
        format!("DynamoDB_20120810.{action}"),
    )];
    let reply = fake
        .send(
            &Request {
                host: "fake",
                headers: &headers,
                body: body.as_bytes(),
                body_cap: CAP,
            },
            Instant::now(),
        )
        .unwrap();
    (reply.status, serde_json::from_slice(&reply.body).unwrap())
}

#[test]
fn the_fake_table_sizes_items_by_its_rule_and_refuses_what_it_cannot_size() {
    let create = |item: Value| {
        json!({
            "TableName": NAME,
            "Item": item,
            "ConditionExpression": "attribute_not_exists(pk)",
            "ReturnValues": "ALL_OLD",
        })
    };
    let validation = "com.amazon.coral.validate#ValidationException";
    for limit in [None, Some(usize::MAX)] {
        for val in [json!({ "B": "!" }), json!({ "BOOL": true })] {
            let fake = FakeTable::new();
            if let Some(limit) = limit {
                fake.set_limit(limit);
            }
            let (status, reply) = put(&fake, &create(image("val", &val)));
            assert_eq!(status, 400, "{val} {limit:?}");
            assert_eq!(reply["__type"], validation, "{val} {limit:?}");
            assert!(fake.commits().is_empty(), "{val} {limit:?}");
            assert_eq!(fake.item("shard#7"), None, "{val} {limit:?}");
        }
    }
    for (length, fits) in [(409_555, true), (409_556, false)] {
        let fake = FakeTable::new();
        let item = json!({
            "pk": { "S": "shard#7" },
            "ver": { "N": u64::MAX.to_string() },
            "val": { "B": STANDARD.encode(vec![1; length]) },
            "wid": { "B": STANDARD.encode([2; 16]) },
        });
        let (status, reply) = put(&fake, &create(item));
        if fits {
            assert_eq!((status, fake.commits().len()), (200, 1), "{length}");
        } else {
            assert_eq!(status, 400, "{length}");
            assert_eq!(reply["__type"], validation, "{length}");
            assert!(fake.commits().is_empty(), "{length}");
            assert_eq!(fake.item("shard#7"), None, "{length}");
        }
    }
}

#[test]
fn the_fake_table_returns_the_old_item_only_when_the_request_asks_for_all_old() {
    let replace = |returns: Option<&str>| {
        let fake = FakeTable::new();
        fake.seed("shard#7", 4, b"record", [9; 16]);
        let old = fake.item("shard#7").unwrap();
        let mut body = json!({
            "TableName": NAME,
            "Item": image("ver", &json!({ "N": "5" })),
            "ConditionExpression": "ver = :expect",
            "ExpressionAttributeValues": { ":expect": { "N": "4" } },
        });
        if let Some(returns) = returns {
            body["ReturnValues"] = json!(returns);
        }
        let (status, reply) = put(&fake, &body);
        assert_eq!(status, 200, "{returns:?}");
        (reply, old)
    };
    let (reply, old) = replace(Some("ALL_OLD"));
    assert_eq!(reply, json!({ "Attributes": old }));
    for returns in [None, Some("NONE")] {
        assert_eq!(replace(returns).0, json!({}), "{returns:?}");
    }
}

#[test]
fn the_fake_table_refuses_an_oversized_replacement_and_keeps_the_item() {
    let fake = FakeTable::new();
    fake.seed("shard#7", 4, b"record", [9; 16]);
    let before = (fake.item("shard#7"), fake.commits());
    fake.set_limit(64);
    let body = json!({
        "TableName": NAME,
        "Item": image("val", &json!({ "B": STANDARD.encode([7; 64]) })),
        "ConditionExpression": "ver = :expect",
        "ExpressionAttributeValues": { ":expect": { "N": "4" } },
        "ReturnValues": "ALL_OLD",
    });
    let (status, reply) = put(&fake, &body);
    assert_eq!(status, 400);
    assert_eq!(
        reply["__type"],
        "com.amazon.coral.validate#ValidationException"
    );
    assert_eq!((fake.item("shard#7"), fake.commits()), before);
}

type Seen = (Vec<(String, String)>, Value);

struct Replay {
    status: u16,
    body: Vec<u8>,
    seen: Mutex<Vec<Seen>>,
}

impl Replay {
    fn new(status: u16, body: &str) -> Self {
        Self {
            status,
            body: body.as_bytes().to_vec(),
            seen: Mutex::default(),
        }
    }

    fn sent(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

impl Wire for &Replay {
    fn send(&self, request: &Request<'_>, _deadline: Instant) -> Result<Reply, Lost> {
        self.seen.lock().unwrap().push((
            request.headers.to_vec(),
            serde_json::from_slice(request.body).unwrap(),
        ));
        Ok(Reply {
            status: self.status,
            body: self.body.clone(),
        })
    }
}

fn fixtures() -> Vec<Value> {
    serde_json::from_str(include_str!("dynamo_replay.json")).unwrap()
}

#[test]
fn each_transcribed_exchange_builds_its_request_and_maps_its_reply() {
    let cases = fixtures();
    let exact = Write::Exact {
        expect: Version::new(4).unwrap(),
        value: b"record".to_vec(),
    };
    let create = Write::Create(b"record".to_vec());
    let code = |name: &str| format!("com.amazonaws.dynamodb.v20120810#{name}");
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let response = case["response"]
            .as_object()
            .unwrap_or_else(|| panic!("{name}: a response object"));
        let status = u16::try_from(case["status"].as_u64().unwrap()).unwrap();
        let body = Value::Object(response.clone()).to_string();
        let replay = Replay::new(status, &body);
        let second = Replay::new(status, &body);
        let key = Key::Shard(shard());
        let mut table = table_at(&replay, "fake", DEADLINE);
        let mut store = Dynamo(table_at(&second, "fake", DEADLINE));
        match name {
            "describe-table" => {
                let table = Table::open(store_client(&replay, "fake", DEADLINE), NAME).unwrap();
                assert_eq!(
                    table.namespace(),
                    Namespace::new(super::uuid(TABLE_ID).unwrap()).unwrap()
                );
            }
            "get-item" => assert_eq!(
                Dynamo(table).read(&key),
                Ok(Some(Item {
                    version: Version::new(3).unwrap(),
                    value: b"record".to_vec()
                }))
            ),
            "get-item-absent" => assert_eq!(Dynamo(table).read(&key), Ok(None)),
            "get-item-throttled" => {
                assert_eq!(
                    table.get("shard#7"),
                    Err(Fault::Error(code("ThrottlingException")))
                );
                assert_eq!(store.read(&key), Err(Unavailable));
                assert_eq!(second.sent(), 1, "{name}: one request through the store");
            }
            "put-item-create" => assert_eq!(
                Dynamo(table).write(&key, &create),
                Outcome::Committed(Version::FIRST)
            ),
            "put-item-exact" => assert_eq!(
                Dynamo(table).write(&key, &exact),
                Outcome::Committed(Version::new(5).unwrap())
            ),
            "conditional-check-failed" => assert_eq!(
                Dynamo(table).write(&key, &exact),
                Outcome::NotCommitted(Refusal::Condition)
            ),
            "validation-item-size" => assert_eq!(
                Dynamo(table).write(&key, &create),
                Outcome::NotCommitted(Refusal::Rejected)
            ),
            "access-denied" => assert_eq!(
                Dynamo(table).write(&key, &create),
                Outcome::NotCommitted(Refusal::Denied)
            ),
            "throttling" | "provisioned-throughput-exceeded" => {
                let expected = if name == "throttling" {
                    code("ThrottlingException")
                } else {
                    code("ProvisionedThroughputExceededException")
                };
                assert_eq!(classify(&expected), Outcome::Unknown, "{name}");
                assert_eq!(
                    table.write("shard#7", &create),
                    Err(Fault::Error(expected)),
                    "{name}"
                );
                assert_eq!(store.write(&key, &create), Outcome::Unknown, "{name}");
                assert_eq!(second.sent(), 1, "{name}: one request through the store");
            }
            "internal-server-error" => {
                assert_eq!(status, 500);
                assert_eq!(response["__type"], code("InternalServerError"));
                assert_eq!(table.write("shard#7", &create), Err(Fault::Transport));
                assert_eq!(store.write(&key, &create), Outcome::Unknown);
                assert_eq!(second.sent(), 1, "{name}: one request through the store");
            }
            other => panic!("no expectation for {other}"),
        }
        let seen = replay.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "{name}: one request");
        let (headers, body) = &seen[0];
        let header = |wanted: &str| {
            headers
                .iter()
                .find(|(name, _)| name == wanted)
                .map(|(_, value)| value.clone())
        };
        assert_eq!(
            header("x-amz-target"),
            Some(format!(
                "DynamoDB_20120810.{}",
                case["action"].as_str().unwrap()
            )),
            "{name}"
        );
        assert_eq!(
            header("content-type").as_deref(),
            Some("application/x-amz-json-1.0"),
            "{name}"
        );
        assert!(header("authorization").is_some(), "{name}: signed");
        assert_eq!(body, &case["request"], "{name}");
    }
    let names: BTreeSet<&str> = cases
        .iter()
        .map(|case| case["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), cases.len(), "each name once");
    assert_eq!(
        names,
        BTreeSet::from([
            "access-denied",
            "conditional-check-failed",
            "describe-table",
            "get-item",
            "get-item-absent",
            "get-item-throttled",
            "internal-server-error",
            "provisioned-throughput-exceeded",
            "put-item-create",
            "put-item-exact",
            "throttling",
            "validation-item-size",
        ])
    );
}

#[test]
fn the_fake_table_answers_each_transcribed_request_it_models() {
    let skipped = BTreeSet::from([
        "access-denied",
        "get-item-throttled",
        "internal-server-error",
        "provisioned-throughput-exceeded",
        "throttling",
    ]);
    let wid = |item: &Value| -> [u8; 16] {
        STANDARD
            .decode(item["wid"]["B"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    let mut modeled = BTreeSet::new();
    let cases = fixtures();
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        if skipped.contains(name) {
            continue;
        }
        let response = &case["response"];
        let fake = FakeTable::new();
        match name {
            "get-item" => fake.seed("shard#7", 3, b"record", wid(&response["Item"])),
            "put-item-exact" => fake.seed("shard#7", 4, b"record", wid(&response["Attributes"])),
            "conditional-check-failed" => fake.seed("shard#7", 5, b"record", [0; 16]),
            "validation-item-size" => fake.set_limit(8),
            _ => {}
        }
        let body = case["request"].to_string();
        let before = (fake.item("shard#7"), fake.commits());
        let (status, answer) = send(&fake, case["action"].as_str().unwrap(), &body);
        assert_eq!(u64::from(status), case["status"], "{name}");
        if status != 200 {
            assert_eq!(
                (fake.item("shard#7"), fake.commits()),
                before,
                "{name}: a refusal leaves the table as it was"
            );
        }
        if name == "describe-table" {
            for field in ["TableId", "KeySchema", "AttributeDefinitions"] {
                assert_eq!(
                    answer["Table"][field], response["Table"][field],
                    "{name}: {field}"
                );
            }
        } else if status == 200 {
            assert_eq!(&answer, response, "{name}");
        } else {
            assert_eq!(answer["__type"], response["__type"], "{name}");
        }
        modeled.insert(name);
    }
    assert_eq!(
        modeled,
        BTreeSet::from([
            "conditional-check-failed",
            "describe-table",
            "get-item",
            "get-item-absent",
            "put-item-create",
            "put-item-exact",
            "validation-item-size",
        ])
    );
}

#[test]
fn only_a_wholly_parsed_success_commits_and_every_other_reply_is_a_transport_fault() {
    let item = |field: &str, value: Value| json!({ "Item": image(field, &value) }).to_string();
    let reads = [
        (200, "{\"Item\":".to_owned()),
        (200, "[]".to_owned()),
        (200, "{}x".to_owned()),
        (200, String::new()),
        (200, "x{}".to_owned()),
        (200, "\u{feff}{}".to_owned()),
        (200, r#"{"Item":null}"#.to_owned()),
        (200, r#"{"ConsumedCapacity":{}}"#.to_owned()),
        (200, format!("{}x", item("ver", json!({ "N": "4" })))),
        (200, format!("x{}", item("ver", json!({ "N": "4" })))),
        (200, item("ver", json!({ "N": "0" }))),
        (200, item("ver", json!({ "N": "03" }))),
        (200, item("ver", json!({ "N": "+4" }))),
        (200, item("ver", json!({ "N": " 4" }))),
        (200, item("ver", json!({ "N": "4 " }))),
        (200, item("ver", json!({ "N": "18446744073709551616" }))),
        (200, item("ver", json!({ "S": "4" }))),
        (200, item("pk", json!({ "S": "shard#70" }))),
        (200, item("pk", json!({ "S": "shard#" }))),
        (200, item("val", json!({ "S": "cmVjb3Jk" }))),
        (204, "{}".to_owned()),
        (299, item("ver", json!({ "N": "4" }))),
        (
            399,
            r#"{"__type":"com.amazonaws.dynamodb.v20120810#ThrottlingException"}"#.to_owned(),
        ),
        (200, item("val", json!({ "B": "not base64!" }))),
        (200, json!({ "Item": without("val") }).to_string()),
        (
            200,
            json!({ "__type": null, "Item": image("ver", &json!({ "N": "4" })) }).to_string(),
        ),
        (400, r#"{"__type":7}"#.to_owned()),
        (200, item("pk", json!({ "S": "shard#8" }))),
        (
            200,
            json!({ "Attributes": image("ver", &json!({ "N": "4" })) }).to_string(),
        ),
        (200, described(&json!({}))),
        (
            200,
            r#"{"__type":"com.amazonaws.dynamodb.v20120810#InternalServerError"}"#.to_owned(),
        ),
        (201, "{}".to_owned()),
        (307, "{}".to_owned()),
        (
            307,
            r#"{"__type":"com.amazonaws.dynamodb.v20120810#ThrottlingException"}"#.to_owned(),
        ),
        (400, "{\"message\":\"no code\"}".to_owned()),
        (
            400,
            r#"{"message":"The conditional request failed"}"#.to_owned(),
        ),
        (200, r#"{"__type":""}"#.to_owned()),
        (200, r#"{"__type":null}"#.to_owned()),
        (
            200,
            json!({ "__type": "", "Item": image("ver", &json!({ "N": "4" })) }).to_string(),
        ),
        (400, "{\"__type\":".to_owned()),
        (400, format!(r#"{{"__type":"{CONDITION_FAILED}"}}x"#)),
        (500, format!(r#"{{"__type":"{CONDITION_FAILED}"}}"#)),
        (500, String::new()),
    ];
    let good = image("ver", &json!({ "N": "4" }));
    let malformed = [
        without("wid"),
        image("wid", &json!({ "B": "AQID" })),
        image("wid", &json!({ "B": STANDARD.encode([1; 17]) })),
        image("wid", &json!({ "B": "not base64!" })),
        image("wid", &json!({ "S": "AQIDBAUGBwgAAAAAAAAAAQ==" })),
        image("ver", &json!({ "N": "4", "S": "4" })),
        image("pk", &json!({ "S": "shard#7", "N": "7" })),
        image(
            "val",
            &json!({ "B": STANDARD.encode(vec![0; ITEM_LIMIT + 1]) }),
        ),
    ];
    let reads = reads.into_iter().chain(
        malformed
            .iter()
            .map(|image| json!({ "Item": image }))
            .chain([
                json!({ "Item": good, "Attributes": good }),
                json!({ "Item": good, "Table": {} }),
            ])
            .map(|body| (200, body.to_string())),
    );
    for (status, body) in reads {
        let replay = Replay::new(status, &body);
        assert_eq!(
            table_at(&replay, "fake", DEADLINE).get("shard#7"),
            Err(Fault::Transport),
            "{status} {body}"
        );
        assert_eq!(replay.sent(), 1, "{status} {body}: one request");
    }
    for (body, expected) in [
        ("{} \n".to_owned(), Ok(None)),
        (
            json!({ "Item": image("ver", &json!({ "N": "4" })), "ConsumedCapacity": {} })
                .to_string(),
            Ok(Some(Item {
                version: Version::new(4).unwrap(),
                value: b"record".to_vec(),
            })),
        ),
        (
            item("ver", json!({ "N": "4" })),
            Ok(Some(Item {
                version: Version::new(4).unwrap(),
                value: b"record".to_vec(),
            })),
        ),
        (
            json!({ "Item": image(
                "val",
                &json!({ "B": STANDARD.encode(vec![7; ITEM_LIMIT]) }),
            ) })
            .to_string(),
            Ok(Some(Item {
                version: Version::new(4).unwrap(),
                value: vec![7; ITEM_LIMIT],
            })),
        ),
    ] {
        let replay = Replay::new(200, &body);
        assert_eq!(
            table_at(&replay, "fake", DEADLINE).get("shard#7"),
            expected,
            "{body}"
        );
    }

    let old = |field: &str, value: Value| json!({ "Attributes": image(field, &value) }).to_string();
    let exact = Write::Exact {
        expect: Version::new(4).unwrap(),
        value: Vec::new(),
    };
    let writes = [
        (200, old("pk", json!({ "S": "shard#8" }))),
        (200, old("ver", json!({ "N": "0" }))),
        (200, old("ver", json!({ "N": "18446744073709551615" }))),
        (200, old("ver", json!({ "N": "-1" }))),
        (200, old("ver", json!({ "N": "4.0" }))),
        (200, old("val", json!({ "B": "not base64!" }))),
        (200, json!({ "Attributes": without("val") }).to_string()),
        (
            200,
            json!({ "__type": null, "Attributes": image("ver", &json!({ "N": "4" })) }).to_string(),
        ),
        (400, r#"{"__type":7}"#.to_owned()),
        (200, "{\"Attributes\":{}}".to_owned()),
        (200, "{".to_owned()),
        (200, "{}x".to_owned()),
        (200, String::new()),
        (200, "x{}".to_owned()),
        (200, r#"{"Attributes":null}"#.to_owned()),
        (200, format!("x{}", old("ver", json!({ "N": "4" })))),
        (200, old("ver", json!({ "N": "+4" }))),
        (200, old("ver", json!({ "N": "18446744073709551616" }))),
        (200, old("pk", json!({ "S": "shard#70" }))),
        (201, old("ver", json!({ "N": "4" }))),
        (299, "{}".to_owned()),
        (399, format!(r#"{{"__type":"{CONDITION_FAILED}"}}"#)),
        (
            400,
            r#"{"message":"The conditional request failed"}"#.to_owned(),
        ),
        (200, r#"{"__type":""}"#.to_owned()),
        (200, r#"{"__type":null}"#.to_owned()),
        (
            200,
            json!({ "__type": "", "Attributes": image("ver", &json!({ "N": "4" })) }).to_string(),
        ),
        (400, format!(r#"x{{"__type":"{CONDITION_FAILED}"}}"#)),
        (200, r#"{"ConsumedCapacity":{}}"#.to_owned()),
        (
            200,
            json!({ "Item": image("ver", &json!({ "N": "4" })) }).to_string(),
        ),
        (400, format!(r#"{{"__type":"{CONDITION_FAILED}"}}x"#)),
        (
            400,
            json!({ "__type": format!("{CONDITION_FAILED}\n") }).to_string(),
        ),
        (400, json!({ "__type": "x".repeat(257) }).to_string()),
        (500, format!(r#"{{"__type":"{CONDITION_FAILED}"}}"#)),
    ];
    let writes = writes.into_iter().chain(
        malformed
            .iter()
            .map(|image| json!({ "Attributes": image }))
            .chain([
                json!({ "Attributes": good, "Item": good }),
                json!({ "Attributes": good, "Table": {} }),
            ])
            .map(|body| (200, body.to_string())),
    );
    for (status, body) in writes {
        let replay = Replay::new(status, &body);
        assert_eq!(
            table_at(&replay, "fake", DEADLINE).write("shard#7", &exact),
            Err(Fault::Transport),
            "{status} {body}"
        );
        assert_eq!(replay.sent(), 1, "{status} {body}: one request");
    }
    for (status, body, expected) in [
        (200, old("ver", json!({ "N": "4" })), Ok(5)),
        (200, old("ver", json!({ "N": "9" })), Ok(10)),
        (200, old("ver", json!({ "N": "5" })), Ok(6)),
        (200, old("ver", json!({ "N": "3" })), Ok(4)),
        (200, old("ver", json!({ "N": "1" })), Ok(2)),
        (
            200,
            old("ver", json!({ "N": (u64::MAX - 1).to_string() })),
            Ok(u64::MAX),
        ),
        (200, "{} ".to_owned(), Ok(1)),
        (
            200,
            json!({ "Attributes": image("ver", &json!({ "N": "4" })), "ConsumedCapacity": {} })
                .to_string(),
            Ok(5),
        ),
        (
            400,
            format!(r#"{{"__type":"{CONDITION_FAILED}"}} "#),
            Err(Fault::Error(CONDITION_FAILED.into())),
        ),
        (
            499,
            format!(r#"{{"__type":"{CONDITION_FAILED}"}}"#),
            Err(Fault::Error(CONDITION_FAILED.into())),
        ),
    ] {
        let replay = Replay::new(status, &body);
        assert_eq!(
            table_at(&replay, "fake", DEADLINE).write("shard#7", &exact),
            expected.map(|ver| Version::new(ver).unwrap()),
            "{status} {body}"
        );
    }

    let replay = Replay::new(200, "{}");
    let last = Write::Exact {
        expect: Version::new(u64::MAX).unwrap(),
        value: Vec::new(),
    };
    assert_eq!(
        Dynamo(table_at(&replay, "fake", DEADLINE)).write(&Key::Shard(shard()), &last),
        Outcome::NotCommitted(Refusal::Rejected)
    );
    assert_eq!(replay.sent(), 0, "nothing sent");
}

#[test]
fn an_error_code_passes_whole_at_4xx_and_is_a_transport_fault_at_every_other_status() {
    let service = |name: &str| format!("com.amazonaws.dynamodb.v20120810#{name}");
    let codes = [
        service("ResourceNotFoundException"),
        "ResourceNotFoundException".to_owned(),
        CONDITION_FAILED.to_owned(),
        "com.amazon.coral.validate#ValidationException".to_owned(),
        "com.amazon.coral.service#AccessDeniedException".to_owned(),
        "com.amazon.coral.service#UnrecognizedClientException".to_owned(),
        "com.amazon.coral.service#ExpiredTokenException".to_owned(),
        service("ThrottlingException"),
        service("ProvisionedThroughputExceededException"),
        service("RequestLimitExceeded"),
        service("ItemCollectionSizeLimitExceededException"),
        service("TransactionConflictException"),
        service("InternalServerError"),
        "x".repeat(256),
        String::new(),
    ];
    let writes = [
        Write::Create(Vec::new()),
        Write::Exact {
            expect: Version::new(4).unwrap(),
            value: Vec::new(),
        },
    ];
    for code in &codes {
        let body = json!({ "__type": code, "message": "refused" }).to_string();
        for status in [
            200, 201, 299, 300, 307, 399, 400, 403, 404, 413, 429, 499, 500, 503, 599,
        ] {
            let expected = if (400..=499).contains(&status) {
                Err(Fault::Error(code.clone()))
            } else {
                Err(Fault::Transport)
            };
            let replay = Replay::new(status, &body);
            let mut table = table_at(&replay, "fake", DEADLINE);
            assert_eq!(
                table.get("shard#7").map(drop),
                expected,
                "get {status} {code}"
            );
            for write in &writes {
                assert_eq!(
                    table.write("shard#7", write).map(drop),
                    expected,
                    "{write:?} {status} {code}"
                );
            }
            assert_eq!(replay.sent(), 3, "{status} {code}: one request per call");
        }
    }
}

#[test]
fn the_fake_table_takes_planted_replies_in_arrival_order() {
    let fake = FakeTable::new();
    for status in [500, 503] {
        fake.plant(Plant::Reply {
            apply: false,
            status,
            body: "{}".into(),
        });
    }
    let get = json!({ "Key": { "pk": { "S": "shard#7" } }, "ConsistentRead": true }).to_string();
    let statuses = [(); 3].map(|()| send(&fake, "GetItem", &get).0);
    assert_eq!(statuses, [500, 503, 200]);
}

fn coded_server_fault() -> Scripted {
    let body = br#"{"__type":"com.amazonaws.dynamodb.v20120810#InternalServerError"}"#;
    let server = serve(move |_| Answer::Reply(reply("500 Internal Server Error", body)));
    Scripted {
        name: "coded HTTP 500",
        host: server.host(),
        served: Some(server.served),
        tls: false,
        requests: 1,
        expect: Expect::Reply(500, body),
    }
}

#[test]
fn every_scripted_fault_sends_at_most_one_request_and_maps_to_its_fault() {
    let deadline = Duration::from_millis(500);
    for write in [false, true] {
        let scripted: Vec<Scripted> = faults(deadline)
            .into_iter()
            .chain([coded_server_fault()])
            .collect();
        for fault in &scripted {
            let wire = Counting::new(if fault.tls {
                Https::new()
            } else {
                Https::plain()
            });
            let sends = Rc::clone(&wire.sends);
            let mut table = table_at(wire, &fault.host, deadline);
            let start = Instant::now();
            let outcome = if write {
                table.write("shard#7", &Write::Create(Vec::new())).map(drop)
            } else {
                table.get("shard#7").map(drop)
            };
            assert!(
                start.elapsed() < deadline + Duration::from_millis(250),
                "{}",
                fault.name
            );
            let expected = match &fault.expect {
                Expect::Reply(status, body) => {
                    match (*status, serde_json::from_slice::<Value>(body).ok()) {
                        (200, Some(Value::Object(object))) if !object.contains_key("__type") => {
                            Ok(())
                        }
                        (400..=499, Some(object)) if object["__type"].is_string() => {
                            Err(Fault::Error(object["__type"].as_str().unwrap().into()))
                        }
                        _ => Err(Fault::Transport),
                    }
                }
                Expect::Lost(..) => Err(Fault::Transport),
            };
            assert_eq!(outcome, expected, "{} write={write}", fault.name);
            assert_eq!(sends.get(), 1, "{}: one send", fault.name);
        }
        assert_eq!(settled(&scripted), Ok(()), "write={write}");
    }
}

#[test]
fn a_wire_that_resends_a_write_fails_the_one_attempt_check() {
    let deadline = Duration::from_millis(500);
    let reset = faults(deadline)
        .into_iter()
        .find(|fault| fault.name == "reset after the request")
        .unwrap();
    let mut table = table_at(Resend(Https::plain()), &reset.host, deadline);
    assert_eq!(
        table.write("shard#7", &Write::Create(Vec::new())),
        Err(Fault::Transport)
    );
    assert_eq!(
        reset.one_attempt(),
        Err("reset after the request: 2 requests, expected 1".to_owned())
    );
}

#[test]
fn a_silent_table_ends_the_write_at_its_deadline_with_one_request() {
    let silence = Duration::from_secs(2);
    let server = serve(move |_| silent(silence));
    let deadline = Duration::from_millis(200);
    let mut table = table_at(Https::plain(), &server.host(), deadline);
    let counts = || (server.served.connections(), server.served.requests());
    assert_eq!(counts(), (0, 0), "building the table reaches no service");
    let start = Instant::now();
    assert_eq!(
        table.write("shard#7", &Write::Create(Vec::new())),
        Err(Fault::Transport)
    );
    let elapsed = start.elapsed();
    assert!(elapsed >= deadline, "{elapsed:?}");
    assert!(elapsed < silence / 2, "{elapsed:?}");
    server.served.await_requests(1);
    thread::sleep(Duration::from_millis(100));
    assert_eq!(counts(), (1, 1));
}

#[test]
fn a_throttling_reply_to_a_read_returns_as_soon_as_it_is_parsed() {
    let body = br#"{"__type":"com.amazonaws.dynamodb.v20120810#ThrottlingException"}"#;
    // After the reply, the server keeps the connection open past the call's
    // deadline. A reader that stops at `Content-Length` can finish before the
    // deadline; a reader waiting for EOF reaches the deadline.
    let server =
        serve(move |_| Answer::Stall(reply("400 Bad Request", body), Duration::from_secs(2)));
    let mut table = table_at(Https::plain(), &server.host(), DEADLINE);
    let throttled = Err(Fault::Error(
        "com.amazonaws.dynamodb.v20120810#ThrottlingException".into(),
    ));
    for call in 1..=2 {
        let start = Instant::now();
        assert_eq!(table.get("shard#7"), throttled, "call {call}");
        let elapsed = start.elapsed();
        assert!(elapsed < DEADLINE / 2, "call {call}: {elapsed:?}");
    }
    thread::sleep(Duration::from_millis(100));
    assert_eq!(server.served.requests(), 2, "one request per call");
}

#[test]
fn a_table_over_the_production_transport_is_send() {
    fn send<T: Send>() {}
    send::<Table<Https>>();
}
