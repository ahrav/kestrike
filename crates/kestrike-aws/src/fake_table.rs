//! `FakeTable` is a test wire that answers as a DynamoDB table holding
//! items keyed by the string attribute `pk`. It applies `GetItem`,
//! `PutItem` conditioned on `attribute_not_exists(pk)` or `ver = :expect`,
//! and `DescribeTable`; rejects an item over its size limit with
//! `ValidationException`; logs every commit with its `ver` and `wid`; and
//! lets a test plant, for the next request, a lost request, a lost reply,
//! a second delivery, or a reply of its choice.

use std::collections::{BTreeMap, VecDeque};
use std::io::ErrorKind;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

use crate::{Lost, LostAt, Reply, Request, Wire};

/// `ITEM_BYTES` is DynamoDB's per-item size limit.
pub(crate) const ITEM_BYTES: usize = 400 * 1024;

pub(crate) const TABLE_ID: &str = "8c2b0d9e-6f1a-4c3e-9b7d-2a5e4f6c1d03";

/// Each `Plant` controls how the table handles one request, in arrival
/// order.
#[derive(Debug, Clone)]
pub(crate) enum Plant {
    /// The table applies the request when `apply`, and the sender loses the
    /// reply.
    Lose { apply: bool },
    /// The table applies the request when `apply`, and the sender receives
    /// `status` and `body`.
    Reply {
        apply: bool,
        status: u16,
        body: String,
    },
    /// The table applies a `PutItem` twice, and the sender receives the
    /// first reply.
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Commit {
    pub(crate) key: String,
    pub(crate) ver: u64,
    pub(crate) wid: Vec<u8>,
}

#[derive(Default)]
struct State {
    items: BTreeMap<String, Value>,
    commits: Vec<Commit>,
    plants: VecDeque<Plant>,
    requests: Vec<(String, Value)>,
    redeliveries: Vec<(u16, String)>,
    limit: usize,
}

#[derive(Clone)]
pub(crate) struct FakeTable {
    state: Arc<Mutex<State>>,
    table_id: &'static str,
}

impl FakeTable {
    pub(crate) fn new() -> Self {
        Self::with_id(TABLE_ID)
    }

    pub(crate) fn with_id(table_id: &'static str) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                limit: ITEM_BYTES,
                ..State::default()
            })),
            table_id,
        }
    }

    pub(crate) fn plant(&self, plant: Plant) {
        self.state.lock().unwrap().plants.push_back(plant);
    }

    pub(crate) fn set_limit(&self, limit: usize) {
        self.state.lock().unwrap().limit = limit;
    }

    pub(crate) fn requests(&self) -> Vec<(String, Value)> {
        self.state.lock().unwrap().requests.clone()
    }

    pub(crate) fn commits(&self) -> Vec<Commit> {
        self.state.lock().unwrap().commits.clone()
    }

    /// `redeliveries` returns the second reply of each `Plant::Duplicate`.
    pub(crate) fn redeliveries(&self) -> Vec<(u16, String)> {
        self.state.lock().unwrap().redeliveries.clone()
    }

    pub(crate) fn item(&self, key: &str) -> Option<Value> {
        self.state.lock().unwrap().items.get(key).cloned()
    }

    pub(crate) fn seed(&self, key: &str, ver: u64, val: &[u8], wid: [u8; 16]) {
        let item = json!({
            "pk": { "S": key },
            "ver": { "N": ver.to_string() },
            "val": { "B": STANDARD.encode(val) },
            "wid": { "B": STANDARD.encode(wid) },
        });
        let mut state = self.state.lock().unwrap();
        state.items.insert(key.to_owned(), item);
        state.commits.push(Commit {
            key: key.to_owned(),
            ver,
            wid: wid.to_vec(),
        });
    }

    fn apply(&self, action: &str, body: &Value) -> (u16, String) {
        let mut state = self.state.lock().unwrap();
        match action {
            "DescribeTable" => (
                200,
                json!({ "Table": {
                    "TableName": body["TableName"],
                    "TableId": self.table_id,
                    "TableStatus": "ACTIVE",
                    "AttributeDefinitions": [{ "AttributeName": "pk", "AttributeType": "S" }],
                    "KeySchema": [{ "AttributeName": "pk", "KeyType": "HASH" }],
                }})
                .to_string(),
            ),
            "GetItem" => {
                assert_eq!(body["ConsistentRead"], json!(true), "a strong read");
                let key = body["Key"]["pk"]["S"].as_str().expect("a string pk");
                let reply = match state.items.get(key) {
                    Some(item) => json!({ "Item": item }),
                    None => json!({}),
                };
                (200, reply.to_string())
            }
            "PutItem" => state.put(body),
            other => panic!("unexpected action {other}"),
        }
    }
}

impl State {
    fn put(&mut self, body: &Value) -> (u16, String) {
        let item = &body["Item"];
        let key = item["pk"]["S"].as_str().expect("a string pk").to_owned();
        if size(item).is_none_or(|size| size > self.limit) {
            return error(
                "com.amazon.coral.validate#ValidationException",
                "Item size has exceeded the maximum allowed size",
            );
        }
        let old = self.items.get(&key);
        let holds = match body["ConditionExpression"].as_str() {
            Some("attribute_not_exists(pk)") => old.is_none(),
            Some("ver = :expect") => {
                old.is_some_and(|old| old["ver"] == body["ExpressionAttributeValues"][":expect"])
            }
            other => panic!("unexpected condition {other:?}"),
        };
        if !holds {
            return error(
                "com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException",
                "The conditional request failed",
            );
        }
        let reply = match (old, body["ReturnValues"].as_str()) {
            (Some(old), Some("ALL_OLD")) => json!({ "Attributes": old }),
            _ => json!({}),
        };
        self.commits.push(Commit {
            key: key.clone(),
            ver: item["ver"]["N"]
                .as_str()
                .and_then(|ver| ver.parse().ok())
                .expect("a numeric ver"),
            wid: STANDARD
                .decode(item["wid"]["B"].as_str().expect("a binary wid"))
                .expect("a base64 wid"),
        });
        self.items.insert(key, item.clone());
        (200, reply.to_string())
    }
}

fn error(code: &str, message: &str) -> (u16, String) {
    (
        400,
        json!({ "__type": code, "message": message }).to_string(),
    )
}

fn size(item: &Value) -> Option<usize> {
    item.as_object()?
        .iter()
        .map(|(name, value)| {
            let bytes = match (value.get("S"), value.get("N"), value.get("B")) {
                (Some(Value::String(text)), _, _) => text.len(),
                (_, Some(Value::String(digits)), _) => {
                    digits.trim_matches('0').len().div_ceil(2) + 1
                }
                (_, _, Some(Value::String(bytes))) => STANDARD.decode(bytes).ok()?.len(),
                _ => return None,
            };
            name.len().checked_add(bytes)
        })
        .try_fold(0, |total: usize, bytes| total.checked_add(bytes?))
}

impl Wire for FakeTable {
    fn send(&self, request: &Request<'_>, _deadline: Instant) -> Result<Reply, Lost> {
        let action = request
            .headers
            .iter()
            .find(|(name, _)| name == "x-amz-target")
            .and_then(|(_, value)| value.strip_prefix("DynamoDB_20120810."))
            .expect("a DynamoDB target")
            .to_owned();
        let body: Value = serde_json::from_slice(request.body).expect("a JSON body");
        let plant = {
            let mut state = self.state.lock().unwrap();
            state.requests.push((action.clone(), body.clone()));
            state.plants.pop_front()
        };
        let reply = |(status, body): (u16, String)| Reply {
            status,
            body: body.into_bytes(),
        };
        let lost = Lost {
            at: LostAt::Exchange,
            kind: ErrorKind::TimedOut,
        };
        match plant {
            None => Ok(reply(self.apply(&action, &body))),
            Some(Plant::Lose { apply }) => {
                if apply {
                    self.apply(&action, &body);
                }
                Err(lost)
            }
            Some(Plant::Reply {
                apply,
                status,
                body: answer,
            }) => {
                if apply {
                    self.apply(&action, &body);
                }
                Ok(reply((status, answer)))
            }
            Some(Plant::Duplicate) => {
                assert_eq!(action, "PutItem", "a second delivery of a write");
                let first = self.apply(&action, &body);
                let second = self.apply(&action, &body);
                self.state.lock().unwrap().redeliveries.push(second);
                Ok(reply(first))
            }
        }
    }
}
