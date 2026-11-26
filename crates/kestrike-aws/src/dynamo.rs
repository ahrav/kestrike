//! `Table` is the store exchange over one DynamoDB table, the production
//! `Exchange` under `Dynamo`. Each `get` and each `write` makes at most one
//! `Client::send` call, under that call's single deadline.
//!
//! - An item holds `pk` (S, the record key `dynamo::text` builds), `ver`
//!   (N, the record version), `val` (B, the record's encoded bytes) and
//!   `wid` (B, the 16-byte write ID of the request that stored the item).
//! - A stored item decodes when each of its four attributes carries one
//!   type tag of the type above, `pk` is the requested key, `ver` is a
//!   positive canonical decimal, `val` decodes to at most `ITEM_LIMIT`
//!   bytes and `wid` decodes to 16 bytes.
//! - An HTTP 200 is a success when its body is one JSON object without
//!   `__type` and without another action's result member, and either holds
//!   the action's member (`Item` for `GetItem`, `Attributes` for `PutItem`)
//!   as a stored item for the requested key or is the empty object. A
//!   write's committed version is the old item's `ver + 1` from
//!   `ReturnValues = ALL_OLD`, or 1 when the reply is empty. An HTTP 4xx
//!   whose whole body parses as JSON with a `__type` of at most `CODE_MAX`
//!   visible ASCII characters is `Fault::Error` with that code. Every other
//!   reply, a coded 5xx included, and every call fault is
//!   `Fault::Transport`, so a write whose reply was lost or unusable reads
//!   as unknown.
//! - Before taking a write ID or sending a request, `write` rejects a write
//!   whose next version overflows `u64` or whose item could exceed
//!   DynamoDB's 400 KB item limit at some version, a key that alone leaves
//!   no room for a value included. It also rejects a write when the
//!   `Table` has used every write-ID count. The rejection is
//!   `Fault::Error("ValidationException")`, the code DynamoDB gives an item
//!   it cannot store, so `Dynamo` reads it as "not committed". The item
//!   bound counts `ver` at its largest, so a value that fits at one version
//!   fits at every later one.
//! - A write ID is the 8-byte nonce a `Table` draws from the operating
//!   system at open, followed by that `Table`'s 8-byte big-endian count of
//!   the write requests it built, lost ones included. The count separates
//!   the write requests of one `Table`; the random nonce separates those of
//!   two `Table` values while their nonces differ. The count runs from 0
//!   to `u64::MAX - 1`, so no `Table` issues one write ID twice.
//! - `Table::open` admits a table keyed by `pk` alone whose `DescribeTable`
//!   reply lists no `Replicas`, reads `TableId` once, and the table reports
//!   that value as its namespace for its whole life. A version 2017.11.29
//!   global table exposes its replicas through `DescribeGlobalTable`, so
//!   the table's owner keeps the table single-Region. The namespace relies
//!   on DynamoDB giving every created or restored table its own `TableId`.
//!   Requests address the table by name. When DynamoDB recreates or
//!   restores the table under that name, an existing `Table` keeps the old
//!   namespace, and a `Table` opened afterwards reads the new one.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use kestrike::failover::records::Namespace;
use kestrike::net::{EntropyError, boot_nonce};
use kestrike::storage::store::dynamo::{Exchange, Fault};
use kestrike::storage::store::{ITEM_LIMIT, Item, Version, Write};
use serde_json::{Map, Value, json};

use crate::client::{Call, Client, Fault as CallFault};
use crate::clock::{Clock, SystemClock};
use crate::wire::{Reply, Wire};

const CONTENT_TYPE: &str = "application/x-amz-json-1.0";

/// The longest error code a reply's `__type` may carry.
const CODE_MAX: usize = 256;

/// The result members of the three actions: `Table` for `DescribeTable`,
/// `Item` for `GetItem` and `Attributes` for `PutItem`.
const RESULTS: [&str; 3] = ["Table", "Item", "Attributes"];

/// The bytes of an item outside `pk`'s value and `val`'s bytes, by
/// DynamoDB's item sizing: the attribute names `pk`, `ver`, `val` and `wid`
/// (11 bytes), `ver` at its largest (a 20-digit number, 11 bytes), and the
/// 16-byte `wid`.
const FIXED_BYTES: usize = 11 + 11 + 16;

/// The code of a write `Table` rejects before sending.
const REFUSED: &str = "ValidationException";

/// `Table` provides the store exchange for one DynamoDB table. Its
/// namespace is the `TableId` that `open` read, for the value's whole
/// life, and its requests address the table by name. A `Table` keeps that
/// namespace when the name is later bound to a recreated, restored or
/// repointed table, so its holder drops it and opens a new `Table` before
/// using the replacement.
pub struct Table<W, C = SystemClock> {
    client: Client<W, C>,
    name: String,
    namespace: Namespace,
    nonce: [u8; 8],
    writes: u64,
}

impl<W, C> fmt::Debug for Table<W, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Table")
            .field("name", &self.name)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

/// The error of `Table::open`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// `DescribeTable` ended before a complete reply.
    Call(CallFault),
    /// `DescribeTable` returned a 4xx or 5xx with this string `__type`,
    /// including any `#` namespace.
    Code(String),
    /// The reply is not a 4xx or 5xx with a well-formed string `__type`, and
    /// it fails `open`'s checks: HTTP 200, a JSON object without `__type`
    /// or another action's result member, a `Table` keyed by one `HASH` key
    /// `pk` of type `S` with no `Replicas`, and a nonzero UUID at `TableId`.
    Reply,
    /// The operating system's entropy failed to supply a write-ID nonce.
    Entropy(EntropyError),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Call(fault) => write!(f, "DescribeTable call failed: {fault:?}"),
            Self::Code(code) => write!(f, "DescribeTable returned {code:?}"),
            Self::Reply => f.write_str("DescribeTable reply is unusable"),
            Self::Entropy(error) => write!(f, "write-ID nonce draw failed: {error:?}"),
        }
    }
}

impl std::error::Error for OpenError {}

enum Failure {
    Call(CallFault),
    /// A 4xx reply's error code.
    Code(String),
    /// A 5xx reply's error code.
    Server(String),
    Unparsed,
}

/// Store calls keep a 4xx error code and map every other failure to
/// `Fault::Transport`: a coded 5xx can follow a committed write.
impl From<Failure> for Fault {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Code(code) => Fault::Error(code),
            Failure::Call(_) | Failure::Server(_) | Failure::Unparsed => Fault::Transport,
        }
    }
}

impl From<Failure> for OpenError {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Call(fault) => OpenError::Call(fault),
            Failure::Code(code) | Failure::Server(code) => OpenError::Code(code),
            Failure::Unparsed => OpenError::Reply,
        }
    }
}

impl<W: Wire, C: Clock> Table<W, C> {
    /// `open` makes one `Client::send` call, which sends at most one
    /// `DescribeTable` for `name`. It checks that the table is keyed by `pk`
    /// alone and that the reply's `Replicas` is absent or empty, and takes
    /// the table's `TableId` as its namespace for the life of the returned
    /// `Table`.
    /// `open` does not watch the name afterwards: after the name is bound to
    /// a recreated, restored or repointed table, the holder opens a new
    /// `Table`.
    ///
    /// # Errors
    ///
    /// `open` returns `OpenError::Call` when the call ends before a reply,
    /// `OpenError::Code` for a coded 4xx or 5xx reply, `OpenError::Reply`
    /// for any other unusable reply, key schema, replica list or `TableId`,
    /// and `OpenError::Entropy` when the nonce draw fails.
    pub fn open(client: Client<W, C>, name: &str) -> Result<Self, OpenError> {
        Self::open_with(client, name, boot_nonce)
    }

    /// `open` with the nonce drawn by `draw`, after the reply checks pass.
    fn open_with(
        mut client: Client<W, C>,
        name: &str,
        draw: impl FnOnce() -> Result<[u8; 16], EntropyError>,
    ) -> Result<Self, OpenError> {
        let reply = call(
            &mut client,
            "DescribeTable",
            "Table",
            &json!({ "TableName": name }),
        )?;
        let namespace = reply
            .get("Table")
            .filter(|table| keyed_by_pk(table) && single_region(table))
            .and_then(|table| table.get("TableId"))
            .and_then(Value::as_str)
            .and_then(uuid)
            .and_then(Namespace::new)
            .ok_or(OpenError::Reply)?;
        let drawn = draw().map_err(OpenError::Entropy)?;
        let mut nonce = [0; 8];
        nonce.copy_from_slice(&drawn[..8]);
        Ok(Self {
            client,
            name: name.to_owned(),
            namespace,
            nonce,
            writes: 0,
        })
    }

    /// The next write ID: the nonce, then the count of write requests
    /// built before this one. Advances the count, and returns `None` once
    /// the count reaches `u64::MAX`.
    fn next_wid(&mut self) -> Option<[u8; 16]> {
        let count = self.writes;
        self.writes = count.checked_add(1)?;
        let mut wid = [0; 16];
        wid[..8].copy_from_slice(&self.nonce);
        wid[8..].copy_from_slice(&count.to_be_bytes());
        Some(wid)
    }
}

impl<W: Wire, C: Clock> Exchange for Table<W, C> {
    fn get(&mut self, key: &str) -> Result<Option<Item>, Fault> {
        let request = json!({
            "TableName": self.name,
            "Key": { "pk": { "S": key } },
            "ConsistentRead": true,
        });
        let reply = call(&mut self.client, "GetItem", "Item", &request)?;
        member(&reply, "Item", key)
    }

    /// A write whose next version overflows, whose value exceeds the key's
    /// value budget, or that finds every write-ID count used returns
    /// `Fault::Error("ValidationException")` without sending.
    fn write(&mut self, key: &str, write: &Write) -> Result<Version, Fault> {
        let (value, version, condition, values) = match write {
            Write::Create(value) => (
                value,
                Some(Version::FIRST),
                "attribute_not_exists(pk)",
                None,
            ),
            Write::Exact { expect, value } => (
                value,
                expect.next(),
                "ver = :expect",
                Some(json!({ ":expect": { "N": expect.get().to_string() } })),
            ),
        };
        let Some((version, wid)) = version
            .filter(|_| budget(key).is_some_and(|budget| value.len() <= budget))
            .and_then(|version| Some((version, self.next_wid()?)))
        else {
            return Err(Fault::Error(REFUSED.to_owned()));
        };
        let mut request = json!({
            "TableName": self.name,
            "Item": {
                "pk": { "S": key },
                "ver": { "N": version.get().to_string() },
                "val": { "B": STANDARD.encode(value) },
                "wid": { "B": STANDARD.encode(wid) },
            },
            "ConditionExpression": condition,
            "ReturnValues": "ALL_OLD",
        });
        if let Some(values) = values {
            request["ExpressionAttributeValues"] = values;
        }
        let reply = call(&mut self.client, "PutItem", "Attributes", &request)?;
        match member(&reply, "Attributes", key)? {
            Some(old) => old.version.next().ok_or(Fault::Transport),
            None => Ok(Version::FIRST),
        }
    }

    fn namespace(&self) -> Namespace {
        self.namespace
    }
}

/// The largest value whose item under `key` fits DynamoDB's item limit at
/// every version, or `None` when the key alone leaves no room.
fn budget(key: &str) -> Option<usize> {
    ITEM_LIMIT.checked_sub(FIXED_BYTES + key.len())
}

/// `call` makes one `Client::send` call, which sends at most one
/// `DynamoDB_20120810.<action>` request with `body`. It returns the reply
/// object of an HTTP 200 that carries no result member of `RESULTS` other
/// than `member`.
fn call<W: Wire, C: Clock>(
    client: &mut Client<W, C>,
    action: &'static str,
    member: &str,
    body: &Value,
) -> Result<Map<String, Value>, Failure> {
    let target = format!("DynamoDB_20120810.{action}");
    let bytes = body.to_string().into_bytes();
    let reply = client
        .send(&Call {
            action,
            headers: &[("content-type", CONTENT_TYPE), ("x-amz-target", &target)],
            body: &bytes,
        })
        .map_err(Failure::Call)?;
    let object = answer(&reply)?;
    if RESULTS
        .iter()
        .any(|result| *result != member && object.contains_key(*result))
    {
        return Err(Failure::Unparsed);
    }
    Ok(object)
}

/// A body that parses whole as a JSON object is a success at HTTP 200
/// without `__type`, and a coded failure at 4xx or 5xx with a well-formed
/// string `__type`. Every other reply is unparsed.
fn answer(reply: &Reply) -> Result<Map<String, Value>, Failure> {
    let Ok(Value::Object(mut object)) = serde_json::from_slice::<Value>(&reply.body) else {
        return Err(Failure::Unparsed);
    };
    match (reply.status, object.remove("__type")) {
        (200, None) => Ok(object),
        (400..=499, Some(Value::String(code))) if well_formed(&code) => Err(Failure::Code(code)),
        (500..=599, Some(Value::String(code))) if well_formed(&code) => Err(Failure::Server(code)),
        _ => Err(Failure::Unparsed),
    }
}

/// The success rule shared by `get` and `write`: the reply's member `name`
/// as a stored item for `key`, or `None` when the reply is the empty
/// object. Any other reply is `Fault::Transport`.
fn member(reply: &Map<String, Value>, name: &str, key: &str) -> Result<Option<Item>, Fault> {
    match reply.get(name) {
        Some(item) => stored(item, key).map(Some).ok_or(Fault::Transport),
        None if reply.is_empty() => Ok(None),
        None => Err(Fault::Transport),
    }
}

/// A code is well formed when it holds at most `CODE_MAX` visible ASCII
/// characters. Any other `__type` is unparsed, so a stray line break or
/// prefix cannot turn a reply into a refusal code.
fn well_formed(code: &str) -> bool {
    code.len() <= CODE_MAX && code.bytes().all(|byte| byte.is_ascii_graphic())
}

/// A table is keyed by `pk` alone when its key schema is one `HASH` key
/// named `pk` and its attribute definitions give `pk` the string type.
/// DynamoDB evaluates a conditional write against the item at the request's
/// full primary key, so `attribute_not_exists(pk)` admits one item per
/// record key only when `pk` is the whole primary key.
fn keyed_by_pk(table: &Value) -> bool {
    let schema = table
        .get("KeySchema")
        .and_then(Value::as_array)
        .is_some_and(|keys| {
            matches!(keys.as_slice(), [key] if key["AttributeName"] == "pk" && key["KeyType"] == "HASH")
        });
    let typed = table
        .get("AttributeDefinitions")
        .and_then(Value::as_array)
        .is_some_and(|definitions| {
            let pk: Vec<&Value> = definitions
                .iter()
                .filter(|definition| definition["AttributeName"] == "pk")
                .collect();
            matches!(pk.as_slice(), [definition] if definition["AttributeType"] == "S")
        });
    schema && typed
}

/// `open` rejects a version 2019.11.21 global table when `DescribeTable`
/// lists `Replicas`. With multi-Region eventual consistency, two Regions
/// can each satisfy the write condition against the same item version and
/// commit conflicting successors. Version 2017.11.29 exposes replica
/// membership through `DescribeGlobalTable`, so the owner must keep the
/// table single-Region.
fn single_region(table: &Value) -> bool {
    table
        .get("Replicas")
        .is_none_or(|replicas| replicas.as_array().is_some_and(Vec::is_empty))
}

/// A returned item decodes to a record when its `pk` equals `key`, its
/// `ver` is a positive canonical decimal, its `val` decodes to at most
/// `ITEM_LIMIT` bytes, and its `wid` decodes to 16 bytes.
fn stored(item: &Value, key: &str) -> Option<Item> {
    if attribute(item, "pk", "S")? != key {
        return None;
    }
    let text = attribute(item, "ver", "N")?;
    let version = text
        .parse::<u64>()
        .ok()
        .filter(|number| number.to_string() == text)
        .and_then(Version::new)?;
    let value = STANDARD
        .decode(attribute(item, "val", "B")?)
        .ok()
        .filter(|value| value.len() <= ITEM_LIMIT)?;
    STANDARD
        .decode(attribute(item, "wid", "B")?)
        .ok()
        .filter(|wid| wid.len() == 16)?;
    Some(Item { version, value })
}

/// The string of `item`'s attribute `name` when that attribute carries the
/// one type tag `tag`.
fn attribute<'a>(item: &'a Value, name: &str, tag: &str) -> Option<&'a str> {
    let value = item.get(name)?.as_object()?;
    if value.len() != 1 {
        return None;
    }
    value.get(tag)?.as_str()
}

/// `uuid` reads 32 hexadecimal digits in hyphen-separated groups of 8, 4,
/// 4, 4 and 12 as 16 bytes.
fn uuid(text: &str) -> Option<[u8; 16]> {
    let shaped = text.split('-').map(str::len).eq([8, 4, 4, 4, 12])
        && text
            .bytes()
            .all(|byte| byte == b'-' || byte.is_ascii_hexdigit());
    if !shaped {
        return None;
    }
    u128::from_str_radix(&text.replace('-', ""), 16)
        .ok()
        .map(u128::to_be_bytes)
}

#[cfg(test)]
#[path = "dynamo_tests.rs"]
mod tests;
