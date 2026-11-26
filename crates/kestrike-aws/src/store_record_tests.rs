//! `store_record` records store request histories at the wire, through the
//! production `Client` and `Table`, in the JSON-lines history format the
//! `store_history` target of `kestrike` reads.
//!
//! - `Recorder` sits below `Table`. For each `GetItem` and `PutItem` it
//!   puts a pending line in the in-memory journal before it calls the inner
//!   wire: `op`, `key`, `invoke`, a read's `consistent` (true only for an
//!   explicit `ConsistentRead: true`), and a write's `wid` (lowercase hex of
//!   the request's 16 bytes) and `expect` (0 for `attribute_not_exists(pk)`).
//!   The line stays `unknown` with `complete = invoke` until the send
//!   returns. `DescribeTable` passes through unjournaled, and any other
//!   request panics.
//! - When the send returns, the line takes `complete` and its outcome, and
//!   the recorder appends it to `<scenario>.jsonl` with one `write_all` of
//!   the whole line, holding the file lock and not the journal lock. A
//!   scenario's first line creates its file, which must not exist yet, and
//!   the journal keeps the file open for the later lines. A short write
//!   followed by an error leaves a partial last line, which the checker
//!   refuses to parse.
//! - A line is `ok` when `Table` accepts the reply: an HTTP 200 JSON object
//!   without `__type` and without another action's result member, which is
//!   empty or holds the action's member as a stored item for the line's key
//!   (`Item` for a read, `Attributes`, the old item, for a write). A stored
//!   item gives each of `pk`, `ver`, `val` and `wid` one type tag, a
//!   positive canonical `ver`, a base64 `val` of at most `ITEM_LIMIT` bytes
//!   and a 16-byte `wid`, and a write's old `ver` is below `u64::MAX`. An
//!   `ok` read records the item's `ver` and `wid`, neither for an absent
//!   item. An `ok` write records as `reported` the version `Table` takes
//!   from the reply: the old `ver + 1`, or 1 for an empty reply.
//! - A line is `fail` for a 4xx read with a well-formed `__type`, and for a
//!   4xx write whose well-formed `__type` `dynamo::classify` maps to not
//!   committed. `Table` reads a coded 5xx as a transport fault, so a `fail`
//!   write is exactly a write the client reports as refused. Every other
//!   reply is `unknown`. The `code` of a line that is not `ok` holds the
//!   service's bare code, `lost <at> <kind>` for a lost send, or
//!   `HTTP <status>` for a reply without a usable code.
//! - A line reaches its file when its send returns, or when the journal
//!   drops, as `unknown` with the code `PENDING` and `complete` stamped at
//!   the drop. A process killed between the two loses the pending line. A
//!   committed write among them leaves a commit whose write ID no history
//!   carries, which the checker reports under ST7; a lost read, or a lost
//!   write that did not commit, leaves no trace. Each manual run therefore
//!   puts `<test>.recording` in its campaign directory before its first
//!   request and removes it only after every assertion passed. The checker
//!   refuses a directory holding any entry other than a history or the
//!   commit log, so it judges only a directory whose runs all finished.
//! - Times are nanoseconds from the first `now()` call in the process, so
//!   one campaign directory holds the histories of one process. The manual
//!   runs claim `STORE_HISTORY_DIR` once per process with `claim`, and both
//!   ignored tests run in one invocation:
//!   `cargo test -p kestrike-aws -- --ignored --nocapture` runs the
//!   package's ignored tests.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use crate::{
    Client, Config, DYNAMODB, Https, IDLE_AGE, Lost, LostAt, Reply, Request, Role, SystemClock,
    Table, Wire,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use kestrike::failover::records::{CoveragePage, Host, Namespace, ShardRecord, VolumeId};
use kestrike::net::ownership::{Shard, ShardGeneration};
use kestrike::storage::store::dynamo::{Dynamo, Exchange as _, Fault, classify, text};
use kestrike::storage::store::{
    Client as StoreClient, ITEM_LIMIT, Key, Outcome, Refusal, Store, StoreError, Version,
    Watermark, WatermarkLog, Write,
};
use serde_json::{Map, Value, json};

use crate::fake_table::{FakeTable, Plant};
use crate::loopback::warmed;

#[allow(
    dead_code,
    reason = "the recorder tests reach the checker through `check_campaign`"
)]
mod check {
    include!("../../kestrike/tests/support/store_check.rs");

    pub(crate) fn violations(dir: &Path) -> Vec<String> {
        check_campaign(dir).1.violations
    }
}

const REGION: &str = "us-east-1";
const NAME: &str = "kestrike-store";

const CONDITION_FAILED: &str = "ConditionalCheckFailedException";

/// How long `Transport::Late` holds a client's first read, far longer than
/// an in-memory client takes from its read's reply to its write's send.
const LATE: Duration = Duration::from_millis(20);

/// The code of a line the journal wrote at its drop, still pending.
const PENDING: &str = "pending at journal drop";

/// The longest `__type` `Table` reads as an error code.
const CODE_MAX: usize = 256;

/// The coverage pages of a recorded shard.
const PAGES: u16 = 4;

const ONE_ITEM_CLIENTS: [&str; 4] = ["c1", "c2", "paused", "short"];

/// The page-fences clients; each name's number is its tenure.
const PAGE_CLIENTS: [&str; 3] = ["t1", "t2", "t3"];

const CREDENTIAL_REFUSALS: [&str; 4] = [
    "ExpiredTokenException",
    "ExpiredToken",
    "UnrecognizedClientException",
    "InvalidSignatureException",
];

fn now() -> u64 {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    let nanos = ORIGIN.get_or_init(Instant::now).elapsed().as_nanos();
    u64::try_from(nanos).expect("a run shorter than 584 years")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

type Line = Map<String, Value>;

/// The journal's lines in invoke order, whether each has been formatted for
/// its file, and per client the access key IDs that signed its requests.
#[derive(Default)]
struct Lines {
    lines: Vec<Line>,
    written: Vec<bool>,
    signers: BTreeMap<String, BTreeSet<String>>,
}

impl Lines {
    fn push(&mut self, line: Line) -> usize {
        self.lines.push(line);
        self.written.push(false);
        self.lines.len() - 1
    }

    /// Marks line `at` written and returns its scenario and its text with
    /// the newline. A line counts as written before its file write, so a
    /// failed or partial write is never repeated.
    fn take(&mut self, at: usize) -> (String, String) {
        self.written[at] = true;
        let line = &self.lines[at];
        let scenario = line["scenario"].as_str().unwrap().to_owned();
        let mut text = serde_json::to_string(line).unwrap();
        text.push('\n');
        (scenario, text)
    }
}

/// The scenario files of one journal, each created by its first line and
/// held open for the rest.
struct Files {
    dir: PathBuf,
    open: BTreeMap<String, File>,
}

impl Files {
    /// Appends `text` to `<scenario>.jsonl` with one `write_all`. The first
    /// line of a scenario creates the file and fails when any entry of that
    /// name, a link included, already exists, which keeps that entry's
    /// bytes.
    fn append(&mut self, scenario: &str, text: &str) -> Result<(), String> {
        let path = self.dir.join(format!("{scenario}.jsonl"));
        let failed = |error: std::io::Error| format!("{}: {error}", path.display());
        let file = match self.open.entry(scenario.to_owned()) {
            Entry::Occupied(file) => file.into_mut(),
            Entry::Vacant(slot) => slot.insert(
                OpenOptions::new()
                    .append(true)
                    .create_new(true)
                    .open(&path)
                    .map_err(failed)?,
            ),
        };
        file.write_all(text.as_bytes()).map_err(failed)
    }
}

struct Shared {
    lines: Mutex<Lines>,
    files: Mutex<Files>,
}

/// Writes every pending line as `unknown` with the code `PENDING`,
/// completed at the drop. A failed write is reported on stderr through a
/// write whose own error is dropped, so a drop during an unwind never
/// panics.
impl Drop for Shared {
    fn drop(&mut self) {
        let lines = self.lines.get_mut().unwrap_or_else(PoisonError::into_inner);
        let files = self.files.get_mut().unwrap_or_else(PoisonError::into_inner);
        let done = now();
        for at in 0..lines.lines.len() {
            if !lines.written[at] {
                lines.lines[at].insert("complete".into(), json!(done));
                lines.lines[at].insert("code".into(), json!(PENDING));
                let (scenario, text) = lines.take(at);
                if let Err(error) = files.append(&scenario, &text) {
                    let _ = writeln!(std::io::stderr(), "a pending history line is lost: {error}");
                }
            }
        }
    }
}

#[derive(Clone)]
struct Journal(Arc<Shared>);

impl Journal {
    /// A journal writing into the existing directory `dir`.
    fn new(dir: &Path) -> Self {
        Self(Arc::new(Shared {
            lines: Mutex::new(Lines::default()),
            files: Mutex::new(Files {
                dir: dir.to_owned(),
                open: BTreeMap::new(),
            }),
        }))
    }

    /// Runs `read` over the journal's lines under its lock.
    fn read<R>(&self, read: impl FnOnce(&[Line]) -> R) -> R {
        read(&self.0.lines.lock().unwrap().lines)
    }

    fn len(&self) -> usize {
        self.read(<[Line]>::len)
    }

    fn line(&self, at: usize) -> Option<Line> {
        self.read(|lines| lines.get(at).cloned())
    }

    /// The number of distinct access key IDs that signed a journaled
    /// request of `client`; the IDs stay in memory.
    fn signers(&self, client: &str) -> usize {
        let lines = self.0.lines.lock().unwrap();
        lines.signers.get(client).map_or(0, BTreeSet::len)
    }
}

fn header<'a>(request: &'a Request<'_>, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(header, _)| header == name)
        .map(|(_, value)| value.as_str())
}

fn action<'a>(request: &'a Request<'_>) -> &'a str {
    header(request, "x-amz-target")
        .and_then(|value| value.strip_prefix("DynamoDB_20120810."))
        .expect("a DynamoDB target")
}

fn intent(action: &str, body: &Value) -> Option<Line> {
    let mut line = Map::new();
    match action {
        "DescribeTable" => return None,
        "GetItem" => {
            line.insert("op".into(), json!("read"));
            line.insert("key".into(), body["Key"]["pk"]["S"].clone());
            // DynamoDB serves an eventually consistent read unless the
            // request sets `ConsistentRead` to true.
            line.insert(
                "consistent".into(),
                json!(body["ConsistentRead"] == json!(true)),
            );
        }
        "PutItem" => {
            let item = &body["Item"];
            let wid = STANDARD
                .decode(item["wid"]["B"].as_str().expect("a binary wid"))
                .expect("a base64 wid");
            assert_eq!(wid.len(), 16, "a PutItem carries a 16-byte write ID");
            let expect: u64 = match body["ConditionExpression"].as_str() {
                Some("attribute_not_exists(pk)") => 0,
                Some("ver = :expect") => body["ExpressionAttributeValues"][":expect"]["N"]
                    .as_str()
                    .and_then(|n| n.parse().ok())
                    .expect("a numeric expected version"),
                other => panic!("a PutItem conditioned on {other:?}"),
            };
            line.insert("op".into(), json!("cas"));
            line.insert("key".into(), item["pk"]["S"].clone());
            line.insert("wid".into(), json!(hex(&wid)));
            line.insert("expect".into(), json!(expect));
        }
        other => panic!("a request the recorder cannot journal: {other}"),
    }
    assert!(line["key"].is_string(), "{action} names a string key");
    Some(line)
}

/// The string of `item`'s attribute `name` when it carries the one type
/// tag `tag`.
fn attribute<'a>(item: &'a Value, name: &str, tag: &str) -> Option<&'a str> {
    let value = item.get(name)?.as_object()?;
    if value.len() != 1 {
        return None;
    }
    value.get(tag)?.as_str()
}

/// The `ver` and hex `wid` of `item` when `Table` accepts it as the stored
/// item at `key`.
fn stored(item: &Value, key: &Value) -> Option<(u64, String)> {
    if key.as_str() != Some(attribute(item, "pk", "S")?) {
        return None;
    }
    let text = attribute(item, "ver", "N")?;
    let ver = text
        .parse::<u64>()
        .ok()
        .filter(|ver| *ver > 0 && ver.to_string() == text)?;
    STANDARD
        .decode(attribute(item, "val", "B")?)
        .ok()
        .filter(|val| val.len() <= ITEM_LIMIT)?;
    let wid = STANDARD
        .decode(attribute(item, "wid", "B")?)
        .ok()
        .filter(|wid| wid.len() == 16)?;
    Some((ver, hex(&wid)))
}

/// What `Table` makes of an HTTP 200 object it accepts.
enum Accepted {
    /// A read that found no item.
    Absent,
    /// A read's item: its `ver` and hex `wid`.
    Item(u64, String),
    /// A write's committed version as `Table` takes it from the reply.
    Committed(u64),
}

/// How `Table` reads the HTTP 200 object `body` for `line`: `None` when it
/// refuses the reply.
fn accepted(line: &Line, body: &Line) -> Option<Accepted> {
    let read = line["op"] == "read";
    let member = if read { "Item" } else { "Attributes" };
    if ["Table", "Item", "Attributes"]
        .iter()
        .any(|other| *other != member && body.contains_key(*other))
    {
        return None;
    }
    let Some(item) = body.get(member) else {
        let absent = if read {
            Accepted::Absent
        } else {
            Accepted::Committed(1)
        };
        return body.is_empty().then_some(absent);
    };
    let (ver, wid) = stored(item, &line["key"])?;
    if read {
        Some(Accepted::Item(ver, wid))
    } else {
        ver.checked_add(1).map(Accepted::Committed)
    }
}

fn complete(line: &mut Line, result: &Result<Reply, Lost>, done: u64) {
    line.insert("complete".into(), json!(done));
    let reply = match result {
        Ok(reply) => reply,
        Err(Lost { at, kind }) => {
            line.insert("code".into(), json!(format!("lost {at:?} {kind:?}")));
            return;
        }
    };
    let unusable = json!(format!("HTTP {}", reply.status));
    let Ok(Value::Object(body)) = serde_json::from_slice::<Value>(&reply.body) else {
        line.insert("code".into(), unusable);
        return;
    };
    match (reply.status, body.get("__type")) {
        (200, None) => match accepted(line, &body) {
            Some(accepted) => {
                line.insert("outcome".into(), json!("ok"));
                match accepted {
                    Accepted::Absent => {}
                    Accepted::Item(ver, wid) => {
                        line.insert("ver".into(), json!(ver));
                        line.insert("wid".into(), json!(wid));
                    }
                    Accepted::Committed(ver) => {
                        line.insert("reported".into(), json!(ver));
                    }
                }
            }
            None => {
                line.insert("code".into(), unusable);
            }
        },
        (400..=599, Some(Value::String(code)))
            if code.len() <= CODE_MAX && code.bytes().all(|byte| byte.is_ascii_graphic()) =>
        {
            let bare = code
                .rsplit_once('#')
                .map_or(code.as_str(), |(_, bare)| bare);
            // `Table` hands a 4xx code to `classify` and reads a coded 5xx
            // as a transport fault, which leaves a write unknown.
            let refused = reply.status < 500
                && (line["op"] == "read" || matches!(classify(bare), Outcome::NotCommitted(_)));
            let outcome = if refused { "fail" } else { "unknown" };
            line.insert("outcome".into(), json!(outcome));
            let code = if bare.is_empty() {
                unusable
            } else {
                json!(bare)
            };
            line.insert("code".into(), code);
        }
        _ => {
            line.insert("code".into(), unusable);
        }
    }
}

/// `Recorder` journals each `GetItem` and `PutItem` and sends it under the
/// earlier of the call's deadline and `limit` from the send, so a short
/// limit bounds the item exchange and leaves `DescribeTable` and the
/// credential fetch under the call's deadline.
struct Recorder<W> {
    inner: W,
    journal: Journal,
    scenario: String,
    client: String,
    limit: Duration,
}

impl<W: Wire> Wire for Recorder<W> {
    fn send(&self, request: &Request<'_>, deadline: Instant) -> Result<Reply, Lost> {
        let body = serde_json::from_slice(request.body).unwrap_or(Value::Null);
        let Some(mut line) = intent(action(request), &body) else {
            return self.inner.send(request, deadline);
        };
        line.insert("scenario".into(), json!(self.scenario));
        line.insert("client".into(), json!(self.client));
        line.insert("outcome".into(), json!("unknown"));
        line.insert("code".into(), json!(""));
        let signer = header(request, "authorization")
            .and_then(|value| value.split("Credential=").nth(1))
            .and_then(|value| value.split('/').next());
        let at = {
            let mut lines = self.journal.0.lines.lock().unwrap();
            if let Some(signer) = signer {
                match lines.signers.get_mut(&self.client) {
                    Some(keys) if keys.contains(signer) => {}
                    Some(keys) => {
                        keys.insert(signer.to_owned());
                    }
                    None => {
                        let keys = BTreeSet::from([signer.to_owned()]);
                        lines.signers.insert(self.client.clone(), keys);
                    }
                }
            }
            // Stamped after the lock wait, so the interval starts at the
            // send and excludes other clients' journal work.
            let invoke = now();
            line.insert("invoke".into(), json!(invoke));
            line.insert("complete".into(), json!(invoke));
            lines.push(line)
        };
        let result = self
            .inner
            .send(request, deadline.min(Instant::now() + self.limit));
        // Read before the lock wait, so the interval ends at the reply.
        let done = now();
        let (scenario, text) = {
            let mut lines = self.journal.0.lines.lock().unwrap();
            complete(&mut lines.lines[at], &result, done);
            lines.take(at)
        };
        // The file write holds only the file lock, so a slow write delays
        // no other client's dispatch, and its error panics with no lock
        // held.
        let appended = self
            .journal
            .0
            .files
            .lock()
            .unwrap()
            .append(&scenario, &text);
        appended.unwrap_or_else(|error| panic!("{error}"));
        result
    }
}

enum Transport {
    Https(Https),
    Fake(FakeTable),
    Probe(FakeTable, Journal),
    Retry(FakeTable),
    /// Holds its first `GetItem` for `LATE` before the table receives it.
    Late(FakeTable, AtomicBool),
}

impl Wire for Transport {
    fn send(&self, request: &Request<'_>, deadline: Instant) -> Result<Reply, Lost> {
        match self {
            Self::Https(https) => https.send(request, deadline),
            Self::Fake(fake) => fake.send(request, deadline),
            Self::Probe(fake, journal) => {
                let body: Value = serde_json::from_slice(request.body).unwrap();
                if let Some(intent) = intent(action(request), &body) {
                    let pending = journal
                        .len()
                        .checked_sub(1)
                        .and_then(|at| journal.line(at))
                        .expect("a journaled request");
                    assert_eq!(pending["outcome"], "unknown");
                    assert_eq!(pending["complete"], pending["invoke"]);
                    if pending["op"] == "read" {
                        assert_eq!(pending["consistent"], true, "a strong read");
                    }
                    for (field, value) in intent {
                        assert_eq!(pending[&field], value, "{field}");
                    }
                }
                fake.send(request, deadline)
            }
            Self::Retry(fake) => {
                if action(request) == "PutItem" {
                    fake.plant(Plant::Lose { apply: true });
                    let _ = fake.send(request, deadline);
                }
                fake.send(request, deadline)
            }
            Self::Late(fake, held) => {
                if action(request) == "GetItem" && !held.swap(true, Ordering::Relaxed) {
                    thread::sleep(LATE);
                }
                fake.send(request, deadline)
            }
        }
    }
}

#[derive(Default)]
struct Log(Watermark);

impl WatermarkLog for Log {
    fn load(&self) -> std::io::Result<Watermark> {
        Ok(self.0.clone())
    }

    fn record(&mut self, mark: &Watermark) -> std::io::Result<()> {
        self.0 = mark.clone();
        Ok(())
    }
}

type RecordedTable = Table<Recorder<Transport>>;
type Recorded = StoreClient<Dynamo<RecordedTable>, Log>;

enum Target {
    Aws {
        table: String,
        region: String,
    },
    Fake(FakeTable),
    Probe(FakeTable),
    Retry(FakeTable),
    /// The in-memory table, on which the named client's first read is
    /// late.
    Late(FakeTable, &'static str),
}

struct Bench {
    target: Target,
    journal: Journal,
}

impl Bench {
    fn new(target: Target, dir: &Path) -> Self {
        Self {
            target,
            journal: Journal::new(dir),
        }
    }

    /// Opens a recorded table under `DYNAMODB`'s deadline whose item
    /// exchanges each end within `limit` of their send.
    fn table(&self, scenario: &str, client: &str, limit: Duration) -> RecordedTable {
        let (inner, table, region, role) = match &self.target {
            Target::Aws { table, region } => (
                Transport::Https(Https::new()),
                table.as_str(),
                region.as_str(),
                Role::instance(),
            ),
            Target::Fake(fake) => (Transport::Fake(fake.clone()), NAME, REGION, metadata()),
            Target::Probe(fake) => (
                Transport::Probe(fake.clone(), self.journal.clone()),
                NAME,
                REGION,
                metadata(),
            ),
            Target::Retry(fake) => (Transport::Retry(fake.clone()), NAME, REGION, metadata()),
            Target::Late(fake, late) => {
                let inner = if client == *late {
                    Transport::Late(fake.clone(), AtomicBool::new(false))
                } else {
                    Transport::Fake(fake.clone())
                };
                (inner, NAME, REGION, metadata())
            }
        };
        let wire = Recorder {
            inner,
            journal: self.journal.clone(),
            scenario: scenario.to_owned(),
            client: client.to_owned(),
            limit,
        };
        let config = Config::new(DYNAMODB, region).expect("a valid region");
        Table::open(Client::new(config, wire, role, SystemClock), table)
            .unwrap_or_else(|error| panic!("{client}: {error}"))
    }

    /// Opens a recorded store client over `table`.
    fn client(&self, scenario: &str, client: &str, limit: Duration) -> (Recorded, Namespace) {
        let store = Dynamo(self.table(scenario, client, limit));
        let namespace = store.namespace();
        (StoreClient::open(store, Log::default()).unwrap(), namespace)
    }
}

/// A role holding the credentials of a loopback instance metadata double
/// that serves one long-lived credential set. Each connection has its own thread, at most 64 at once; a
/// connection past that bound or whose thread the system refuses is
/// dropped unanswered, as is a request head over 8 KiB or slower than one
/// second.
fn metadata() -> Role {
    static ADDRESS: OnceLock<SocketAddr> = OnceLock::new();
    static ACTIVE: Mutex<usize> = Mutex::new(0);
    let address = *ADDRESS.get_or_init(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let leave = || *ACTIVE.lock().unwrap() -= 1;
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                {
                    let mut active = ACTIVE.lock().unwrap();
                    if *active >= 64 {
                        continue;
                    }
                    *active += 1;
                }
                let spawned = thread::Builder::new().spawn(move || {
                    serve_metadata(stream);
                    leave();
                });
                if spawned.is_err() {
                    leave();
                }
            }
        });
        address
    });
    warmed(address, &SystemClock)
}

fn serve_metadata(mut stream: std::net::TcpStream) {
    let end = Instant::now() + Duration::from_secs(1);
    let mut head = Vec::new();
    let mut byte = [0];
    while !head.ends_with(b"\r\n\r\n") {
        let left = end.saturating_duration_since(Instant::now());
        if head.len() >= 8192 || left.is_zero() || stream.set_read_timeout(Some(left)).is_err() {
            return;
        }
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let head = String::from_utf8_lossy(&head);
    let body = match head.split(' ').nth(1).unwrap_or("") {
        "/latest/api/token" => "token".to_owned(),
        "/latest/meta-data/iam/security-credentials/" => "recorder".to_owned(),
        "/latest/meta-data/iam/security-credentials/recorder" => json!({
            "Code": "Success",
            "LastUpdated": "2026-01-01T00:00:00Z",
            "Type": "AWS-HMAC",
            "AccessKeyId": "AKIDRECORDER",
            "SecretAccessKey": "secret",
            "Token": "token",
            "Expiration": "2099-01-01T00:00:00Z",
        })
        .to_string(),
        _ => String::new(),
    };
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

struct Plan {
    run: Duration,
    pause: Duration,
    short: Duration,
}

fn qualification() -> Plan {
    Plan {
        run: Duration::from_secs(180),
        pause: Duration::from_secs(90),
        short: Duration::from_millis(30),
    }
}

/// The in-memory table answers at once, so its short client runs under the
/// ordinary deadline and `planted_faults` supplies the unknown writes.
fn in_memory() -> Plan {
    Plan {
        run: Duration::from_millis(150),
        pause: Duration::from_millis(10),
        short: DYNAMODB.deadline,
    }
}

/// The write faults `planted_faults` plants, in order: a lost reply and an
/// HTTP 500 each after a commit, then the same two without one.
fn plants() -> [Plant; 4] {
    let internal = r#"{"__type":"com.amazonaws.dynamodb.v20120810#InternalServerError"}"#;
    let error = |apply| Plant::Reply {
        apply,
        status: 500,
        body: internal.into(),
    };
    [
        Plant::Lose { apply: true },
        error(true),
        Plant::Lose { apply: false },
        error(false),
    ]
}

fn record(shard: Shard, namespace: Namespace) -> ShardRecord {
    ShardRecord {
        shard,
        generation: ShardGeneration::new(1).unwrap(),
        active: VolumeId::new("vol-0a").unwrap(),
        owner: Host::new(11).unwrap(),
        attempts: 0,
        spare: None,
        checkpoint: None,
        cut: 0,
        pages: std::num::NonZeroU16::new(PAGES).unwrap(),
        page_cap: std::num::NonZeroU32::new(4096).unwrap(),
        namespace,
        ancestry: Default::default(),
        standby: None,
    }
}

fn create(bench: &Bench, scenario: &str, shard: Shard) {
    let (mut init, namespace) = bench.client(scenario, "init", DYNAMODB.deadline);
    init.create_shard(record(shard, namespace))
        .unwrap_or_else(|error| panic!("{scenario}: create: {error:?}"));
}

/// The errors the workload provokes and the history records: a condition
/// refusal from a race on one version, and an unknown write or an
/// unavailable read from a lost, slow or refused exchange.
fn allowed(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::Refused(Refusal::Condition) | StoreError::Unknown | StoreError::Unavailable
    )
}

/// Runs each client's turns on its own thread until `plan.run` has passed,
/// each client taking at least one turn. A turn that ends in an `allowed`
/// error is counted and the client goes on; any other error is a finding
/// and ends that client. Prints the counts per client and error, which
/// include calls that ended before the wire and left no journal line.
fn drive(
    plan: &Plan,
    clients: Vec<(String, Recorded)>,
    turn: impl Fn(&str, &mut Recorded, u64) -> Result<(), StoreError> + Sync,
) -> Vec<String> {
    let findings = Mutex::new(Vec::new());
    let tolerated = Mutex::new(BTreeMap::<String, usize>::new());
    let end = Instant::now() + plan.run;
    thread::scope(|scope| {
        for (name, mut client) in clients {
            let (findings, tolerated, turn) = (&findings, &tolerated, &turn);
            scope.spawn(move || {
                let mut count = 0;
                loop {
                    count += 1;
                    match turn(&name, &mut client, count) {
                        Err(error) if allowed(&error) => {
                            let mut tolerated = tolerated.lock().unwrap();
                            *tolerated.entry(format!("{name}: {error:?}")).or_default() += 1;
                        }
                        Err(error) => {
                            findings.lock().unwrap().push(format!("{name}: {error:?}"));
                            return;
                        }
                        Ok(()) => {}
                    }
                    if Instant::now() >= end {
                        return;
                    }
                }
            });
        }
    });
    for (what, count) in tolerated.into_inner().unwrap() {
        println!("{what}: {count} turns");
    }
    findings.into_inner().unwrap()
}

/// The first-turn gate of a scenario. Each client enters the gate before
/// its first read and waits at it after the read, and `Entered::wait`
/// returns once every client has arrived. A client that unwinds before it
/// waits arrives when its `Entered` drops, so a client that panics in its
/// first read leaves the others free to go on, and its panic ends the run.
struct Gate {
    absent: Mutex<usize>,
    arrival: Condvar,
}

/// One client's place at a `Gate`, from before its first read.
struct Entered<'a> {
    gate: &'a Gate,
    arrived: bool,
}

impl Gate {
    fn new(clients: usize) -> Self {
        Self {
            absent: Mutex::new(clients),
            arrival: Condvar::new(),
        }
    }

    fn enter(&self) -> Entered<'_> {
        Entered {
            gate: self,
            arrived: false,
        }
    }
}

impl Entered<'_> {
    fn arrive(&mut self) {
        if !self.arrived {
            self.arrived = true;
            let mut absent = self
                .gate
                .absent
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            *absent -= 1;
            self.gate.arrival.notify_all();
        }
    }

    /// Arrives, then returns once no client is absent.
    fn wait(mut self) {
        self.arrive();
        let mut absent = self
            .gate
            .absent
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        while *absent > 0 {
            absent = self
                .gate
                .arrival
                .wait(absent)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

impl Drop for Entered<'_> {
    fn drop(&mut self) {
        self.arrive();
    }
}

/// Four clients race on one shard record. Every client's first read
/// completes before any client's first write, so the first writes condition
/// on one version and all but one fail. `paused` holds each read for
/// `plan.pause` before it writes, so its write conditions on a version the
/// others have usually advanced; `short` sends its item requests under
/// `plan.short`, so a slow reply turns its write unknown.
fn one_item(bench: &Bench, plan: &Plan, shard: Shard) -> Vec<String> {
    let scenario = "one-item";
    let clients: Vec<(String, Recorded)> = ONE_ITEM_CLIENTS
        .into_iter()
        .map(|name| {
            let limit = if name == "short" {
                plan.short
            } else {
                DYNAMODB.deadline
            };
            (name.to_owned(), bench.client(scenario, name, limit).0)
        })
        .collect();
    create(bench, scenario, shard);
    let key = Key::Shard(shard);
    let first = Gate::new(clients.len());
    drive(plan, clients, |name, client, turn| {
        let entered = (turn == 1).then(|| first.enter());
        let read = client.read::<ShardRecord>(key);
        if let Some(entered) = entered {
            entered.wait();
        }
        let read = read?;
        if name == "paused" {
            thread::sleep(plan.pause);
        }
        if turn.is_multiple_of(2) {
            client.bump(&read).map(drop)
        } else {
            client.replace(&read, *read.value()).map(drop)
        }
    })
}

/// Three clients raise the fences of the shard's coverage pages, each
/// writing one above the higher of the fence it read and its own tenure.
/// Every client's first read completes before any client's first write, so
/// the first writes race on one page and version. After a condition
/// failure a client writes once more on the same stale read, a new request
/// with a new write ID, so the history holds a refused stale-version write;
/// the store refuses it because the page's version has moved past the read.
fn page_fences(bench: &Bench, plan: &Plan, shard: Shard) -> Vec<String> {
    let scenario = "page-fences";
    let clients: Vec<(String, Recorded)> = PAGE_CLIENTS
        .into_iter()
        .map(|name| {
            let client = bench.client(scenario, name, DYNAMODB.deadline).0;
            (name.to_owned(), client)
        })
        .collect();
    create(bench, scenario, shard);
    let first = Gate::new(clients.len());
    drive(plan, clients, |name, client, turn| {
        let tenure: u64 = name[1..].parse().unwrap();
        let page = u16::try_from(turn % u64::from(PAGES)).unwrap();
        let entered = (turn == 1).then(|| first.enter());
        let read = client.read::<CoveragePage>(Key::Page(shard, page));
        if let Some(entered) = entered {
            entered.wait();
        }
        let read = read?;
        let next = CoveragePage {
            fence: read.value().fence.max(tenure) + 1,
            ..read.value().clone()
        };
        match client.replace(&read, next.clone()) {
            Err(StoreError::Refused(Refusal::Condition)) => client.replace(&read, next).map(drop),
            written => written.map(drop),
        }
    })
}

/// One client bumps the shard record once per plant in `plants()`, each
/// plant queued on the table after the read so the bump's `PutItem` takes
/// it, then writes once each on a stale shard record and a stale page. It
/// runs before any other client sends on `fake`.
fn planted_faults(bench: &Bench, fake: &FakeTable, shard: Shard) {
    let scenario = "planted-faults";
    create(bench, scenario, shard);
    let key = Key::Shard(shard);
    let (mut client, _) = bench.client(scenario, "f1", DYNAMODB.deadline);
    for plant in plants() {
        let read = client.read::<ShardRecord>(key).unwrap();
        fake.plant(plant.clone());
        assert_eq!(
            client.bump(&read).map(drop),
            Err(StoreError::Unknown),
            "{plant:?}"
        );
    }
    let stale = client.read::<ShardRecord>(key).unwrap();
    client.bump(&stale).unwrap();
    assert_eq!(
        client.bump(&stale).map(drop),
        Err(StoreError::Refused(Refusal::Condition))
    );
    let page = Key::Page(shard, 0);
    let stale = client.read::<CoveragePage>(page).unwrap();
    let raised = CoveragePage {
        fence: 1,
        ..stale.value().clone()
    };
    client.replace(&stale, raised.clone()).unwrap();
    assert_eq!(
        client.replace(&stale, raised).map(drop),
        Err(StoreError::Refused(Refusal::Condition))
    );
}

/// Writes `text` to a new file `name` in `dir`. An existing entry of that
/// name, a link included, fails the test and keeps its bytes.
fn write_new(dir: &Path, name: &str, text: &str) {
    let path = dir.join(name);
    File::create_new(&path)
        .and_then(|mut file| file.write_all(text.as_bytes()))
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
}

fn write_commits(fake: &FakeTable, dir: &Path) {
    let text: String = fake
        .commits()
        .iter()
        .map(|commit| {
            let line = json!({ "key": commit.key, "ver": commit.ver, "wid": hex(&commit.wid) });
            format!("{line}\n")
        })
        .collect();
    write_new(dir, "commits.jsonl", &text);
}

/// A new campaign directory under the system's temporary directory,
/// created by this call with owner-only permissions; an existing entry of
/// the same name fails the test.
fn campaign(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "store_record-{name}-{}-{}",
        std::process::id(),
        now()
    ));
    DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
    dir
}

fn read_lines(dir: &Path, name: &str) -> Vec<Line> {
    std::fs::read_to_string(dir.join(name))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn tally(lines: &[Line]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for line in lines {
        let key = ["scenario", "client", "op", "outcome", "code"]
            .map(|field| line[field].as_str().unwrap_or_default())
            .join(" ");
        *counts.entry(key).or_default() += 1;
    }
    counts
}

/// Percentiles of `complete - invoke` over the `ok` lines per scenario and
/// op of every client but `short`, whose item exchanges end at its limit
/// and so leave its slow calls out of the `ok` lines: the recorder's
/// interval from the journal entry before the inner send to the reply's
/// return. Credential lookup and signing precede it, so it is the wire
/// interval, not the client call's latency.
fn latency(lines: &[Line]) -> Vec<String> {
    let mut times: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for line in lines
        .iter()
        .filter(|line| line["outcome"] == "ok" && line["client"] != "short")
    {
        let key = ["scenario", "op"]
            .map(|field| line[field].as_str().unwrap())
            .join(" ");
        let took = line["complete"].as_u64().unwrap() - line["invoke"].as_u64().unwrap();
        times.entry(key).or_default().push(took);
    }
    times
        .into_iter()
        .map(|(key, mut took)| {
            took.sort_unstable();
            let at = |q: usize| took[(took.len() - 1) * q / 100] as f64 / 1e6;
            format!(
                "{key}: {} ok calls outside short, recorder wire interval p50 {:.2} ms, p99 {:.2} ms",
                took.len(),
                at(50),
                at(99)
            )
        })
        .collect()
}

/// What the qualification run must show beyond a clean history: worker
/// writes that succeeded and failed in each scenario, a write from each
/// named client, a write from `short` left unknown by a lost exchange, a
/// refused write from `paused`, a worker write on each coverage page, and a
/// page-fences refusal its client followed with a write on the same key and
/// expected version under a new write ID.
fn coverage(lines: &[Line], pages: Shard) -> Vec<String> {
    let writes = |filter: &[(&str, &str)]| -> Vec<&Line> {
        lines
            .iter()
            .filter(|line| line["op"] == "cas" && line["client"] != "init")
            .filter(|line| filter.iter().all(|(field, value)| line[*field] == *value))
            .collect()
    };
    let sent = |filter: &[(&str, &str)]| !writes(filter).is_empty();
    let mut missing = Vec::new();
    for (scenario, clients) in [
        ("one-item", &ONE_ITEM_CLIENTS[..]),
        ("page-fences", &PAGE_CLIENTS[..]),
    ] {
        for outcome in ["ok", "fail"] {
            if !sent(&[("scenario", scenario), ("outcome", outcome)]) {
                missing.push(format!("{scenario}: no {outcome} worker write"));
            }
        }
        for client in clients {
            if !sent(&[("scenario", scenario), ("client", client)]) {
                missing.push(format!("{scenario}: no write from {client}"));
            }
        }
    }
    let lost = writes(&[
        ("scenario", "one-item"),
        ("client", "short"),
        ("outcome", "unknown"),
    ])
    .iter()
    .any(|line| {
        line["code"]
            .as_str()
            .is_some_and(|code| code.starts_with("lost Exchange"))
    });
    if !lost {
        missing.push("one-item: no write from short left unknown by a lost exchange".to_owned());
    }
    if !sent(&[
        ("scenario", "one-item"),
        ("client", "paused"),
        ("outcome", "fail"),
    ]) {
        missing.push("one-item: no refused write from paused".to_owned());
    }
    for page in 0..PAGES {
        let key = text(&Key::Page(pages, page));
        if !sent(&[("scenario", "page-fences"), ("key", &key)]) {
            missing.push(format!("page-fences: no worker write on {key}"));
        }
    }
    let retried = PAGE_CLIENTS.iter().any(|client| {
        let own = writes(&[("scenario", "page-fences"), ("client", client)]);
        own.windows(2).any(|pair| {
            pair[0]["outcome"] == "fail"
                && pair[0]["code"] == CONDITION_FAILED
                && pair[1]["key"] == pair[0]["key"]
                && pair[1]["expect"] == pair[0]["expect"]
                && pair[1]["wid"] != pair[0]["wid"]
        })
    });
    if !retried {
        missing.push("page-fences: no refused write retried on its key and version".to_owned());
    }
    missing
}

/// Whether a worker write in `scenario` failed its condition on a key and
/// expected version on which another worker's write succeeded.
fn contended(lines: &[Line], scenario: &str) -> bool {
    let writes = || {
        lines.iter().filter(|line| {
            line["scenario"] == scenario && line["op"] == "cas" && line["client"] != "init"
        })
    };
    writes()
        .filter(|line| line["outcome"] == "fail" && line["code"] == CONDITION_FAILED)
        .any(|failed| {
            writes().any(|won| {
                won["outcome"] == "ok"
                    && won["key"] == failed["key"]
                    && won["expect"] == failed["expect"]
                    && won["client"] != failed["client"]
            })
        })
}

/// The pool reuses a connection idle for less than `IDLE_AGE`; ureq reports
/// no reuse, so the label names only eligibility.
fn pool(gap: Duration) -> &'static str {
    if gap < IDLE_AGE {
        "eligible for reuse"
    } else {
        "past the idle age"
    }
}

/// The spaced run's first hour: gaps of 1, 5, 20, 60 and 300 seconds in
/// turn, which fall on both sides of `IDLE_AGE`, each taken only when it
/// ends within the hour.
fn idle_gaps() -> Vec<Duration> {
    let hour = Duration::from_secs(3600);
    let mut gaps = Vec::new();
    let mut elapsed = Duration::ZERO;
    for gap in [1, 5, 20, 60, 300]
        .map(Duration::from_secs)
        .into_iter()
        .cycle()
    {
        if elapsed + gap > hour {
            break;
        }
        gaps.push(gap);
        elapsed += gap;
    }
    gaps
}

/// Sorts one spaced read by the client's result and its journal line, if
/// the read left one: `None` for a successful read, otherwise the group it
/// belongs to and a description.
fn spaced_call(
    result: &Result<(), StoreError>,
    line: Option<&Line>,
) -> Option<(&'static str, String)> {
    match line {
        None => match result {
            Err(StoreError::Unavailable) => Some((
                "refused for credentials",
                "no credentials before the wire".to_owned(),
            )),
            other => Some(("ended before the wire", format!("{other:?}"))),
        },
        Some(line) => {
            let code = line["code"].as_str().unwrap_or_default();
            if CREDENTIAL_REFUSALS.contains(&code) {
                Some(("refused for credentials", code.to_owned()))
            } else if line["outcome"] != "ok" {
                Some((
                    "not ok at the wire",
                    format!("{} {code}", line["outcome"].as_str().unwrap_or_default()),
                ))
            } else {
                result
                    .as_ref()
                    .err()
                    .map(|error| ("refused by the client", format!("{error:?}")))
            }
        }
    }
}

/// What the first-turn gate of a scenario provides: every client's
/// first read ends before any client's first write begins, so the first
/// writes carry one key and expected version and exactly one commits.
fn first_turns(lines: &[Line], scenario: &str, clients: &[&str]) -> Result<(), String> {
    let first = |client: &str, op: &str| {
        lines
            .iter()
            .find(|line| {
                line["scenario"] == scenario && line["client"] == client && line["op"] == op
            })
            .ok_or(format!("{scenario}: {client} sent no {op}"))
    };
    let mut read_by = 0;
    let mut writes = Vec::new();
    for client in clients {
        read_by = read_by.max(first(client, "read")?["complete"].as_u64().unwrap());
        writes.push(first(client, "cas")?);
    }
    let begun = |line: &&Line| line["invoke"].as_u64().unwrap();
    let written_from = writes.iter().map(begun).min().unwrap_or(u64::MAX);
    if written_from < read_by {
        return Err(format!(
            "{scenario}: a first write began at {written_from}, before the last first read ended at {read_by}"
        ));
    }
    let target = |line: &Line| (line["key"].clone(), line["expect"].clone());
    let won = writes.iter().filter(|line| line["outcome"] == "ok").count();
    if won != 1 || writes.iter().any(|line| target(line) != target(writes[0])) {
        return Err(format!(
            "{scenario}: the first writes do not race on one version: {writes:#?}"
        ));
    }
    Ok(())
}

fn recorded_campaign(fake: &FakeTable, dir: &Path) {
    let bench = Bench::new(Target::Fake(fake.clone()), dir);
    let plan = in_memory();
    planted_faults(&bench, fake, Shard::new(3).unwrap());
    let mut findings = one_item(&bench, &plan, Shard::new(1).unwrap());
    findings.extend(page_fences(&bench, &plan, Shard::new(2).unwrap()));
    assert!(findings.is_empty(), "{findings:#?}");
    drop(bench);
    write_commits(fake, dir);
}

#[test]
fn recorded_scenarios_over_an_in_memory_table_satisfy_the_store_contract() {
    let fake = FakeTable::new();
    let dir = campaign("clean");
    recorded_campaign(&fake, &dir);
    assert_eq!(check::violations(&dir), Vec::<String>::new());
    let lines: Vec<Line> = [
        "planted-faults.jsonl",
        "one-item.jsonl",
        "page-fences.jsonl",
    ]
    .iter()
    .flat_map(|name| read_lines(&dir, name))
    .collect();
    let sent = fake
        .requests()
        .iter()
        .filter(|(action, _)| action != "DescribeTable")
        .count();
    assert_eq!(lines.len(), sent, "one line per item request");
    let committed: Vec<Value> = fake
        .commits()
        .iter()
        .map(|commit| json!(hex(&commit.wid)))
        .collect();
    let planted: Vec<(&str, &str, bool)> = lines
        .iter()
        .filter(|line| line["client"] == "f1" && line["op"] == "cas")
        .take(4)
        .map(|line| {
            (
                line["outcome"].as_str().unwrap(),
                line["code"].as_str().unwrap(),
                committed.contains(&line["wid"]),
            )
        })
        .collect();
    assert_eq!(
        planted,
        [
            ("unknown", "lost Exchange TimedOut", true),
            ("unknown", "InternalServerError", true),
            ("unknown", "lost Exchange TimedOut", false),
            ("unknown", "InternalServerError", false),
        ],
        "each planted write and its commit"
    );
    let failed = |key: &str| {
        lines.iter().any(|line| {
            line["key"] == key
                && line["op"] == "cas"
                && line["outcome"] == "fail"
                && line["code"] == CONDITION_FAILED
        })
    };
    assert!(
        failed("shard#3") && failed("page#3#0"),
        "the planted stale writes"
    );
    let unexpected: Vec<&Line> = lines
        .iter()
        .filter(|line| line["scenario"] != "planted-faults")
        .filter(|line| {
            line["outcome"] != "ok"
                && !(line["op"] == "cas"
                    && line["outcome"] == "fail"
                    && line["code"] == CONDITION_FAILED)
        })
        .collect();
    assert!(unexpected.is_empty(), "{unexpected:#?}");
    for (scenario, clients) in [
        ("one-item", &ONE_ITEM_CLIENTS[..]),
        ("page-fences", &PAGE_CLIENTS[..]),
    ] {
        for client in clients {
            assert!(
                lines.iter().any(|line| line["scenario"] == scenario
                    && line["client"] == *client
                    && line["op"] == "cas"),
                "{scenario}: {client} sent no write"
            );
        }
        assert!(contended(&lines, scenario), "{scenario}: no write race");
        first_turns(&lines, scenario, clients).unwrap_or_else(|error| panic!("{error}"));
    }
    let time = |client: &str, op: &str, field: &str| {
        lines
            .iter()
            .find(|line| line["client"] == client && line["op"] == op)
            .unwrap()[field]
            .as_u64()
            .unwrap()
    };
    let paused = time("paused", "cas", "invoke") - time("paused", "read", "complete");
    assert!(
        Duration::from_nanos(paused) >= in_memory().pause,
        "paused wrote {paused} ns after its read"
    );
    // A page starts at fence zero and each commit writes a fence above the
    // one its read returned, so the raced page's fence exceeds its count of
    // commits.
    let raced = text(&Key::Page(Shard::new(2).unwrap(), 1));
    let commits = lines
        .iter()
        .filter(|line| line["key"] == raced.as_str() && line["op"] == "cas")
        .filter(|line| line["client"] != "init" && line["outcome"] == "ok")
        .count();
    let stored = fake.item(&raced).unwrap()["val"]["B"]
        .as_str()
        .unwrap()
        .to_owned();
    let page = CoveragePage::decode_owned(STANDARD.decode(stored).unwrap()).unwrap();
    assert!(commits >= 1, "the raced page's first writes commit one");
    assert!(
        page.fence > commits as u64,
        "{commits} commits on {raced} left its fence at {}",
        page.fence
    );
    let retried = "page-fences: no refused write retried on its key and version";
    let missing = coverage(&lines, Shard::new(2).unwrap());
    assert!(
        !missing.iter().any(|witness| witness == retried),
        "{retried}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn every_first_read_ends_before_any_first_write_when_one_client_reads_late() {
    // A run with no time left gives each client its first turn alone.
    let plan = Plan {
        run: Duration::ZERO,
        ..in_memory()
    };
    let shard = Shard::new(1).unwrap();
    for (scenario, clients, late) in [
        ("one-item", &ONE_ITEM_CLIENTS[..], "c2"),
        ("page-fences", &PAGE_CLIENTS[..], "t2"),
    ] {
        let dir = campaign("late");
        let bench = Bench::new(Target::Late(FakeTable::new(), late), &dir);
        let findings = if scenario == "one-item" {
            one_item(&bench, &plan, shard)
        } else {
            page_fences(&bench, &plan, shard)
        };
        assert!(findings.is_empty(), "{findings:#?}");
        let lines = bench.journal.read(<[Line]>::to_vec);
        let held = lines
            .iter()
            .find(|line| line["client"] == late && line["op"] == "read")
            .unwrap();
        let took = held["complete"].as_u64().unwrap() - held["invoke"].as_u64().unwrap();
        assert!(
            Duration::from_nanos(took) >= LATE,
            "{late}'s first read was held: {held:?}"
        );
        first_turns(&lines, scenario, clients).unwrap_or_else(|error| panic!("{error}"));
        drop(bench);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[test]
fn a_client_that_unwinds_before_the_gate_does_not_hold_the_others() {
    let gate = Arc::new(Gate::new(3));
    let (done, waited) = std::sync::mpsc::channel();
    for _ in 0..2 {
        let (gate, done) = (Arc::clone(&gate), done.clone());
        thread::spawn(move || {
            gate.enter().wait();
            done.send(()).unwrap();
        });
    }
    let hold = Duration::from_millis(50);
    assert!(
        waited.recv_timeout(hold).is_err(),
        "two of three clients wait for the third"
    );
    let failing = Arc::clone(&gate);
    let failed = thread::spawn(move || {
        let _entered = failing.enter();
        panic!("the first read fails");
    });
    assert!(failed.join().is_err());
    for _ in 0..2 {
        waited
            .recv_timeout(Duration::from_secs(5))
            .expect("the failed client's exit releases the gate");
    }
}

#[test]
fn the_first_turn_check_names_a_write_before_a_read_and_a_race_that_is_none() {
    let line = |client: &str, op: &str, invoke: u64, complete: u64| -> Line {
        json!({
            "scenario": "one-item", "client": client, "op": op, "key": "shard#1",
            "expect": 1, "invoke": invoke, "complete": complete,
            "outcome": "fail", "code": CONDITION_FAILED,
        })
        .as_object()
        .unwrap()
        .clone()
    };
    let set = |mut line: Line, field: &str, value: Value| {
        line.insert(field.into(), value);
        line
    };
    let won = |line: Line| set(line, "outcome", json!("ok"));
    let clients = ["c1", "c2"];
    // Both first reads end by 20, the time at which the first write begins.
    let raced = [
        line("c1", "read", 1, 10),
        line("c2", "read", 2, 20),
        won(line("c1", "cas", 20, 30)),
        line("c2", "cas", 25, 35),
        line("c2", "cas", 5, 6),
    ];
    assert_eq!(first_turns(&raced, "one-item", &clients), Ok(()));
    let check = |at: usize, changed: Line| {
        let mut lines = raced.to_vec();
        lines[at] = changed;
        first_turns(&lines, "one-item", &clients).unwrap_err()
    };
    let early = check(2, won(line("c1", "cas", 19, 30)));
    assert!(early.contains("began at 19, before"), "{early}");
    for (what, at, changed) in [
        ("no commit", 2, line("c1", "cas", 20, 30)),
        ("two commits", 3, won(line("c2", "cas", 25, 35))),
        (
            "another version",
            3,
            set(raced[3].clone(), "expect", json!(2)),
        ),
        (
            "another key",
            3,
            set(raced[3].clone(), "key", json!("shard#2")),
        ),
    ] {
        let found = check(at, changed);
        assert!(
            found.contains("do not race on one version"),
            "{what}: {found}"
        );
    }
    let missing = first_turns(&raced[..3], "one-item", &clients).unwrap_err();
    assert_eq!(missing, "one-item: c2 sent no cas");
    let unread = first_turns(&raced[1..], "one-item", &clients).unwrap_err();
    assert_eq!(unread, "one-item: c1 sent no read");
}

#[test]
fn the_driver_reports_each_error_outside_the_allowed_set_and_ends_that_client() {
    let fake = FakeTable::new();
    let dir = campaign("drive");
    let bench = Bench::new(Target::Fake(fake), &dir);
    // No turn sends a request, and the run ends when both clients have ended
    // on an error outside the allowed set, long before the plan's five
    // seconds.
    let plan = Plan {
        run: Duration::from_secs(5),
        ..in_memory()
    };
    let clients = ["stops", "goes-on"]
        .map(|name| (name.to_owned(), bench.client("drive", name, plan.short).0))
        .into();
    let last = Mutex::new(BTreeMap::new());
    let mut findings = drive(&plan, clients, |name, _, turn| {
        last.lock().unwrap().insert(name.to_owned(), turn);
        match (name, turn) {
            ("stops", 2) => Err(StoreError::Withdrawn),
            ("goes-on", 1) => Err(StoreError::Unknown),
            ("goes-on", 2) => Err(StoreError::Unavailable),
            ("goes-on", 3) => Err(StoreError::Refused(Refusal::Condition)),
            ("goes-on", 4) => Err(StoreError::Refused(Refusal::Rejected)),
            _ => Ok(()),
        }
    });
    findings.sort();
    assert_eq!(
        findings,
        ["goes-on: Refused(Rejected)", "stops: Withdrawn"],
        "one finding per error outside the allowed set"
    );
    assert_eq!(
        last.into_inner().unwrap(),
        BTreeMap::from([("goes-on".to_owned(), 4), ("stops".to_owned(), 2)]),
        "an allowed error leaves its client running and a finding ends it"
    );
    let ended = Plan {
        run: Duration::ZERO,
        ..in_memory()
    };
    let turns = Mutex::new(Vec::new());
    let clients = ["first", "second"]
        .map(|name| (name.to_owned(), bench.client("drive", name, ended.short).0))
        .into();
    let findings = drive(&ended, clients, |name, _, turn| {
        turns.lock().unwrap().push((name.to_owned(), turn));
        Ok(())
    });
    assert_eq!(findings, Vec::<String>::new());
    let mut turns = turns.into_inner().unwrap();
    turns.sort();
    assert_eq!(
        turns,
        [("first".to_owned(), 1), ("second".to_owned(), 1)],
        "each client takes one turn in a run that has no time left"
    );
    drop(bench);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_tally_counts_lines_by_scenario_client_op_outcome_and_code() {
    let line = |client: &str, op: &str, outcome: &str, code: &str| -> Line {
        json!({ "scenario": "one-item", "client": client, "op": op, "outcome": outcome, "code": code })
            .as_object()
            .unwrap()
            .clone()
    };
    let lines = [
        line("c1", "cas", "fail", CONDITION_FAILED),
        line("c1", "cas", "fail", CONDITION_FAILED),
        line("c1", "cas", "fail", "ValidationException"),
        line("c1", "cas", "ok", ""),
        line("c1", "read", "ok", ""),
        line("c2", "cas", "ok", ""),
    ];
    assert_eq!(
        tally(&lines),
        BTreeMap::from([
            (format!("one-item c1 cas fail {CONDITION_FAILED}"), 2),
            ("one-item c1 cas fail ValidationException".to_owned(), 1),
            ("one-item c1 cas ok ".to_owned(), 1),
            ("one-item c1 read ok ".to_owned(), 1),
            ("one-item c2 cas ok ".to_owned(), 1),
        ])
    );
}

#[test]
fn a_race_is_a_refusal_and_another_clients_commit_on_one_key_and_version() {
    let cas = |client: &str, key: &str, expect: u64, outcome: &str, code: &str| -> Line {
        json!({
            "scenario": "one-item", "client": client, "op": "cas", "key": key,
            "expect": expect, "outcome": outcome, "code": code,
        })
        .as_object()
        .unwrap()
        .clone()
    };
    let refused = cas("c1", "shard#1", 1, "fail", CONDITION_FAILED);
    for (won, raced) in [
        (cas("c2", "shard#1", 1, "ok", ""), true),
        (cas("c1", "shard#1", 1, "ok", ""), false),
        (cas("c2", "shard#1", 2, "ok", ""), false),
        (cas("c2", "shard#2", 1, "ok", ""), false),
        (cas("init", "shard#1", 1, "ok", ""), false),
        (cas("c2", "shard#1", 1, "unknown", "HTTP 500"), false),
    ] {
        let lines = [refused.clone(), won];
        assert_eq!(contended(&lines, "one-item"), raced, "{:?}", lines[1]);
        assert!(!contended(&lines, "page-fences"), "another scenario");
    }
    let won = cas("c2", "shard#1", 1, "ok", "");
    for other in [
        cas("c1", "shard#1", 1, "fail", "ValidationException"),
        cas("c1", "shard#1", 1, "unknown", CONDITION_FAILED),
        cas("init", "shard#1", 1, "fail", CONDITION_FAILED),
    ] {
        let lines = [other, won.clone()];
        assert!(!contended(&lines, "one-item"), "{:?}", lines[0]);
    }
}

#[test]
fn recorded_times_count_nanoseconds() {
    let before = now();
    thread::sleep(Duration::from_millis(20));
    let elapsed = now() - before;
    assert!(
        (20_000_000..20_000_000_000).contains(&elapsed),
        "{elapsed} over a 20 ms sleep"
    );
}

#[test]
fn the_recorder_journals_each_request_before_sending_it() {
    let fake = FakeTable::new();
    let dir = campaign("probe");
    let bench = Bench::new(Target::Probe(fake.clone()), &dir);
    let shard = Shard::new(1).unwrap();
    create(&bench, "probe", shard);
    let (mut client, _) = bench.client("probe", "c1", DYNAMODB.deadline);
    let key = Key::Shard(shard);
    let read = client.read::<ShardRecord>(key).unwrap();
    client.bump(&read).unwrap();
    assert!(client.bump(&read).is_err(), "a stale bump");
    let current = client.read::<ShardRecord>(key).unwrap();
    fake.plant(Plant::Lose { apply: true });
    assert_eq!(client.bump(&current).map(drop), Err(StoreError::Unknown));
    let sent = fake
        .requests()
        .iter()
        .filter(|(action, _)| action != "DescribeTable")
        .count();
    let commits = fake.commits();
    bench.journal.read(|lines| {
        assert_eq!(lines.len(), sent);
        for line in lines.iter().filter(|line| line.contains_key("ver")) {
            let commit = commits
                .iter()
                .find(|c| json!(c.key) == line["key"] && json!(c.ver) == line["ver"])
                .expect("a committed version");
            assert_eq!(line["wid"], json!(hex(&commit.wid)));
        }
        let tail: Vec<&str> = lines[lines.len() - 4..]
            .iter()
            .map(|line| line["outcome"].as_str().unwrap())
            .collect();
        assert_eq!(tail, ["ok", "fail", "ok", "unknown"]);
        assert!(
            commits
                .iter()
                .any(|commit| json!(hex(&commit.wid)) == lines[lines.len() - 1]["wid"]),
            "the lost bump committed"
        );
    });
    drop((client, bench));
    write_commits(&fake, &dir);
    assert_eq!(check::violations(&dir), Vec::<String>::new());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_recorder_reads_its_fields_from_the_request_and_reply_bytes() {
    let put = json!({
        "Item": {
            "pk": { "S": "shard#9" },
            "ver": { "N": "8" },
            "val": { "B": "" },
            "wid": { "B": "AAECAwQFBgcICQoLDA0ODw==" },
        },
        "ConditionExpression": "ver = :expect",
        "ExpressionAttributeValues": { ":expect": { "N": "7" } },
    });
    let wid = "000102030405060708090a0b0c0d0e0f";
    let write = intent("PutItem", &put).unwrap();
    assert_eq!(
        Value::Object(write.clone()),
        json!({ "op": "cas", "key": "shard#9", "wid": wid, "expect": 7 })
    );
    let create = json!({ "Item": put["Item"], "ConditionExpression": "attribute_not_exists(pk)" });
    assert_eq!(intent("PutItem", &create).unwrap()["expect"], 0);
    let mut skewed = put.clone();
    skewed["Item"]["ver"] = json!({ "N": "12" });
    assert_eq!(
        intent("PutItem", &skewed).unwrap()["expect"],
        7,
        "the condition's value, whatever version the item carries"
    );
    let get = |consistent: Option<Value>| {
        let mut body = json!({ "Key": { "pk": { "S": "shard#9" } } });
        if let Some(consistent) = consistent {
            body["ConsistentRead"] = consistent;
        }
        intent("GetItem", &body).unwrap()
    };
    let read = get(Some(json!(true)));
    assert_eq!(
        Value::Object(read.clone()),
        json!({ "op": "read", "key": "shard#9", "consistent": true })
    );
    assert_eq!(get(None)["consistent"], false);
    assert_eq!(get(Some(json!("true")))["consistent"], false);

    let pending = |line: &Line| {
        let mut line = line.clone();
        line.insert("outcome".into(), json!("unknown"));
        line.insert("code".into(), json!(""));
        line
    };
    let reply = |status: u16, body: &str| {
        Ok(Reply {
            status,
            body: body.as_bytes().to_vec(),
        })
    };
    let item = |fields: Value| {
        let mut item = json!({
            "pk": { "S": "shard#9" },
            "ver": { "N": "8" },
            "val": { "B": "" },
            "wid": { "B": "AAECAwQFBgcICQoLDA0ODw==" },
        });
        for (name, value) in fields.as_object().unwrap() {
            item[name] = value.clone();
        }
        item
    };
    let found = |member: &str, fields: Value| json!({ member: item(fields) }).to_string();
    let coded = |code: &str| json!({ "__type": code }).to_string();
    let refused = json!(["unknown", "HTTP 200"]);
    let long = "A".repeat(CODE_MAX + 1);
    let cases: Vec<(&Line, Result<Reply, Lost>, Value)> = vec![
        (&read, reply(200, "{}"), json!(["ok", ""])),
        (
            &read,
            reply(200, &found("Item", json!({}))),
            json!(["ok", "", 8, wid]),
        ),
        (
            &read,
            reply(200, &found("Item", json!({ "pk": { "S": "shard#1" } }))),
            refused.clone(),
        ),
        (
            &read,
            reply(200, &found("Item", json!({ "ver": null }))),
            refused.clone(),
        ),
        (
            &read,
            reply(200, &found("Item", json!({ "ver": { "N": "0" } }))),
            refused.clone(),
        ),
        (
            &read,
            reply(200, &found("Item", json!({ "val": { "B": "!" } }))),
            refused.clone(),
        ),
        (
            &read,
            reply(200, &found("Item", json!({ "wid": { "B": "AA==" } }))),
            refused.clone(),
        ),
        (
            &read,
            reply(
                200,
                &found("Item", json!({ "ver": { "N": "8", "S": "8" } })),
            ),
            refused.clone(),
        ),
        (&read, reply(200, r#"{"Other":1}"#), refused.clone()),
        (
            &read,
            reply(200, &found("Attributes", json!({}))),
            refused.clone(),
        ),
        (&read, reply(200, r#"{"__type":null}"#), refused.clone()),
        (
            &read,
            reply(
                200,
                &json!({ "__type": "InternalServerError", "Item": item(json!({})) }).to_string(),
            ),
            refused.clone(),
        ),
        (
            &read,
            reply(
                400,
                &coded("com.amazon.coral.service#ExpiredTokenException"),
            ),
            json!(["fail", "ExpiredTokenException"]),
        ),
        (
            &read,
            reply(400, &coded("vendor#")),
            json!(["fail", "HTTP 400"]),
        ),
        (
            &read,
            reply(503, &coded("ServiceUnavailable")),
            json!(["unknown", "ServiceUnavailable"]),
        ),
        (
            &read,
            reply(503, "Service Unavailable"),
            json!(["unknown", "HTTP 503"]),
        ),
        (
            &read,
            Err(Lost {
                at: LostAt::Exchange,
                kind: ErrorKind::TimedOut,
            }),
            json!(["unknown", "lost Exchange TimedOut"]),
        ),
        (&write, reply(200, "{}"), json!(["ok", "", 1])),
        (
            &write,
            reply(200, &found("Attributes", json!({ "ver": { "N": "7" } }))),
            json!(["ok", "", 8]),
        ),
        (
            &write,
            reply(200, &found("Attributes", json!({ "ver": { "N": "9" } }))),
            json!(["ok", "", 10]),
        ),
        (
            &write,
            reply(200, &found("Attributes", json!({ "ver": { "N": "8" } }))),
            json!(["ok", "", 9]),
        ),
        (
            &write,
            reply(200, &found("Attributes", json!({ "ver": { "N": "6" } }))),
            json!(["ok", "", 7]),
        ),
        (
            &write,
            reply(
                200,
                &json!({ "__type": null, "Attributes": item(json!({ "ver": { "N": "7" } })) })
                    .to_string(),
            ),
            refused.clone(),
        ),
        (
            &write,
            reply(200, r#"{"Attributes":{"ver":{"N":"7"}}}"#),
            refused.clone(),
        ),
        (
            &write,
            reply(200, &found("Attributes", json!({ "ver": { "N": "07" } }))),
            refused.clone(),
        ),
        (
            &write,
            reply(
                200,
                &found(
                    "Attributes",
                    json!({ "ver": { "N": u64::MAX.to_string() } }),
                ),
            ),
            refused.clone(),
        ),
        (
            &write,
            reply(200, &found("Item", json!({}))),
            refused.clone(),
        ),
        (
            &write,
            reply(
                400,
                &coded("com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException"),
            ),
            json!(["fail", CONDITION_FAILED]),
        ),
        (
            &write,
            reply(400, &coded("ValidationException")),
            json!(["fail", "ValidationException"]),
        ),
        (
            &write,
            reply(400, &coded("AccessDeniedException")),
            json!(["fail", "AccessDeniedException"]),
        ),
        (
            &write,
            reply(400, &coded("ThrottlingException")),
            json!(["unknown", "ThrottlingException"]),
        ),
        (
            &write,
            reply(400, &coded(&format!("{CONDITION_FAILED}\n"))),
            json!(["unknown", "HTTP 400"]),
        ),
        (
            &write,
            reply(400, &coded(&long)),
            json!(["unknown", "HTTP 400"]),
        ),
        (
            &write,
            reply(500, &coded(CONDITION_FAILED)),
            json!(["unknown", CONDITION_FAILED]),
        ),
        (
            &write,
            reply(500, &coded("InternalServerError")),
            json!(["unknown", "InternalServerError"]),
        ),
        (
            &write,
            reply(503, &coded("")),
            json!(["unknown", "HTTP 503"]),
        ),
    ];
    for (base, result, expected) in cases {
        let mut line = pending(base);
        complete(&mut line, &result, 42);
        let mut found = vec![line["outcome"].clone(), line["code"].clone()];
        if line.contains_key("ver") {
            found.extend([line["ver"].clone(), line["wid"].clone()]);
        }
        if let Some(reported) = line.get("reported") {
            found.push(reported.clone());
        }
        assert_eq!(Value::Array(found), expected, "{result:?}");
        assert_eq!(line["complete"], 42);
        if base["op"] == "cas" {
            assert_eq!(line["wid"], wid, "a write keeps its request's write ID");
        }
    }
    let lost = [
        (
            LostAt::Connect,
            ErrorKind::ConnectionRefused,
            "lost Connect ConnectionRefused",
        ),
        (
            LostAt::Connect,
            ErrorKind::TimedOut,
            "lost Connect TimedOut",
        ),
        (
            LostAt::Connect,
            ErrorKind::NotFound,
            "lost Connect NotFound",
        ),
        (
            LostAt::Exchange,
            ErrorKind::ConnectionReset,
            "lost Exchange ConnectionReset",
        ),
        (
            LostAt::Exchange,
            ErrorKind::UnexpectedEof,
            "lost Exchange UnexpectedEof",
        ),
        (
            LostAt::Exchange,
            ErrorKind::InvalidData,
            "lost Exchange InvalidData",
        ),
        (
            LostAt::Exchange,
            ErrorKind::FileTooLarge,
            "lost Exchange FileTooLarge",
        ),
    ];
    for (at, kind, code) in lost {
        for base in [&read, &write] {
            let mut line = pending(base);
            complete(&mut line, &Err(Lost { at, kind }), 42);
            assert_eq!(
                (&line["outcome"], &line["code"]),
                (&json!("unknown"), &json!(code)),
                "{} lost",
                base["op"]
            );
        }
    }
}

#[test]
fn the_journal_outcome_is_ok_exactly_when_the_table_accepts_the_reply() {
    let fake = FakeTable::new();
    let dir = campaign("agree");
    let bench = Bench::new(Target::Fake(fake.clone()), &dir);
    let shard = Shard::new(1).unwrap();
    create(&bench, "agree", shard);
    let key = text(&Key::Shard(shard));
    let mut table = bench.table("agree", "c1", DYNAMODB.deadline);
    let item = fake.item(&key).unwrap();
    let with = |name: &str, value: Value| {
        let mut item = item.clone();
        item[name] = value;
        item
    };
    let items = [
        item.clone(),
        with("pk", json!({ "S": "shard#2" })),
        with("pk", json!({ "S": format!("{key}0") })),
        with("ver", json!({ "N": "0" })),
        with("ver", json!({ "N": "01" })),
        with("ver", json!({ "N": "+1" })),
        with("ver", json!({ "S": "1" })),
        with("ver", json!({ "N": u64::MAX.to_string() })),
        with("ver", json!({ "N": "41" })),
        with("val", json!({ "B": "!" })),
        with(
            "val",
            json!({ "B": STANDARD.encode(vec![0; ITEM_LIMIT + 1]) }),
        ),
        with("wid", json!({ "B": "AA==" })),
        with("pk", json!({ "S": key, "N": "1" })),
    ];
    let bodies = |member: &str| {
        let mut bodies: Vec<String> = items
            .iter()
            .map(|item| json!({ member: item }).to_string())
            .collect();
        bodies.extend(
            ["{}", r#"{"Other":1}"#, r#"{"Table":{}}"#, "[]", "", "x{}"].map(str::to_owned),
        );
        bodies.push(format!("x{}", json!({ member: item })));
        let other = if member == "Item" {
            "Attributes"
        } else {
            "Item"
        };
        bodies.extend(
            [
                json!({ member: null }),
                json!({ member: item, other: item }),
                json!({ member: item, "Table": {} }),
                json!({ member: item, "__type": null }),
                json!({ member: item, "__type": "InternalServerError" }),
            ]
            .map(|body| body.to_string()),
        );
        bodies
    };
    // `Table` accepts a reply only at HTTP 200, so every body is also sent
    // under other 2xx statuses.
    let replies = |member: &str| -> Vec<(u16, String)> {
        [200, 201, 204, 299]
            .into_iter()
            .flat_map(|status| bodies(member).into_iter().map(move |body| (status, body)))
            .collect()
    };
    let mut accepted = BTreeSet::new();
    for (status, body) in replies("Item") {
        fake.plant(Plant::Reply {
            apply: false,
            status,
            body: body.clone(),
        });
        let before = bench.journal.len();
        let got = table.get(&key);
        let line = bench.journal.line(before).unwrap();
        assert_eq!(
            line["outcome"] == "ok",
            got.is_ok(),
            "{status} {body}: {got:?}"
        );
        accepted.insert(("read", got.is_ok()));
        if let Ok(Some(found)) = &got {
            assert_eq!(line["ver"], json!(found.version.get()), "{body}");
        }
    }
    for apply in [false, true] {
        for (status, body) in replies("Attributes") {
            let current = fake.item(&key).unwrap()["ver"]["N"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            let write = Write::Exact {
                expect: Version::new(current).unwrap(),
                value: Vec::new(),
            };
            fake.plant(Plant::Reply {
                apply,
                status,
                body: body.clone(),
            });
            let before = bench.journal.len();
            let got = table.write(&key, &write);
            let line = bench.journal.line(before).unwrap();
            assert_eq!(
                line["outcome"] == "ok",
                got.is_ok(),
                "{status} {body}: {got:?}"
            );
            accepted.insert(("write", got.is_ok()));
            if let Ok(version) = got {
                assert_eq!(line["reported"], json!(version.get()), "{body}");
            }
        }
    }
    assert_eq!(accepted.len(), 4, "accepted and refused reads and writes");
    // The reported version follows the reply's old item wherever its
    // version lies against the expected one.
    let expect = 7;
    let write = Write::Exact {
        expect: Version::new(expect).unwrap(),
        value: Vec::new(),
    };
    for old in [1, expect - 1, expect, expect + 1, expect + 2] {
        fake.plant(Plant::Reply {
            apply: false,
            status: 200,
            body: json!({ "Attributes": with("ver", json!({ "N": old.to_string() })) }).to_string(),
        });
        let before = bench.journal.len();
        let got = table.write(&key, &write).map(Version::get);
        assert_eq!(got, Ok(old + 1));
        let line = bench.journal.line(before).unwrap();
        assert_eq!(
            (&line["outcome"], &line["reported"], &line["expect"]),
            (&json!("ok"), &json!(old + 1), &json!(expect)),
            "an old item at version {old}"
        );
    }
    drop((table, bench));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_journal_line_is_fail_exactly_when_the_table_returns_a_refusal() {
    let fake = FakeTable::new();
    let dir = campaign("refusals");
    let bench = Bench::new(Target::Fake(fake.clone()), &dir);
    let shard = Shard::new(1).unwrap();
    create(&bench, "refusals", shard);
    let key = text(&Key::Shard(shard));
    let mut table = bench.table("refusals", "c1", DYNAMODB.deadline);
    let write = Write::Exact {
        expect: Version::FIRST,
        value: Vec::new(),
    };
    let codes = [
        json!("com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException"),
        json!(CONDITION_FAILED),
        json!("ValidationException"),
        json!("com.amazon.coral.service#AccessDeniedException"),
        json!("com.amazonaws.dynamodb.v20120810#ThrottlingException"),
        json!("InternalServerError"),
        json!("ExpiredTokenException"),
        json!(""),
        json!("vendor#"),
        json!(format!("{CONDITION_FAILED}\n")),
        json!(format!(" {CONDITION_FAILED}")),
        json!("A".repeat(CODE_MAX)),
        json!("A".repeat(CODE_MAX + 1)),
        json!(7),
        Value::Null,
    ];
    let mut bodies: Vec<String> = codes
        .iter()
        .map(|code| json!({ "__type": code }).to_string())
        .collect();
    bodies.push(r#"{"message":"no code"}"#.to_owned());
    bodies.push(format!(r#"{{"__type":"{CONDITION_FAILED}"}}x"#));
    bodies.push(format!(r#"x{{"__type":"{CONDITION_FAILED}"}}"#));
    let mut seen = BTreeSet::new();
    for status in [200, 299, 300, 307, 399, 400, 404, 499, 500, 503, 599] {
        for body in &bodies {
            let plant = Plant::Reply {
                apply: false,
                status,
                body: body.clone(),
            };
            fake.plant(plant.clone());
            let before = bench.journal.len();
            let got = table.get(&key);
            let line = bench.journal.line(before).unwrap();
            // The client reads every coded read fault as unavailable, and
            // the journal marks the ones that carry the service's code.
            let coded = matches!(got, Err(Fault::Error(_)));
            assert_eq!(line["outcome"] == "fail", coded, "{status} {body}: {got:?}");
            assert_ne!(line["outcome"], "ok", "{status} {body}");
            seen.insert(("read", coded));

            fake.plant(plant);
            let before = bench.journal.len();
            let got = table.write(&key, &write);
            let line = bench.journal.line(before).unwrap();
            // A write is refused when `Dynamo` maps the fault to "not
            // committed"; every other fault leaves the write unknown.
            let refused = matches!(
                &got,
                Err(Fault::Error(code)) if matches!(classify(code), Outcome::NotCommitted(_))
            );
            assert_eq!(
                line["outcome"] == "fail",
                refused,
                "{status} {body}: {got:?}"
            );
            assert_ne!(line["outcome"], "ok", "{status} {body}");
            seen.insert(("write", refused));
        }
    }
    assert_eq!(
        seen.len(),
        4,
        "coded and uncoded reads, refused and unknown writes"
    );
    drop((table, bench));
    std::fs::remove_dir_all(&dir).unwrap();
}

struct Unwinds;

impl Wire for Unwinds {
    fn send(&self, _: &Request<'_>, _: Instant) -> Result<Reply, Lost> {
        panic!("the wire unwinds");
    }
}

#[derive(Default)]
struct Deadlines(Mutex<Vec<(String, Instant)>>);

impl Wire for Deadlines {
    fn send(&self, request: &Request<'_>, deadline: Instant) -> Result<Reply, Lost> {
        let mut seen = self.0.lock().unwrap();
        seen.push((action(request).to_owned(), deadline));
        Ok(Reply {
            status: 200,
            body: b"{}".to_vec(),
        })
    }
}

/// Dropping the release sender unblocks `Gated::send` if `inside` unwinds.
struct Gated {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
}

impl Wire for Gated {
    fn send(&self, _: &Request<'_>, _: Instant) -> Result<Reply, Lost> {
        let _ = self.entered.send(());
        let _ = self.release.recv();
        Ok(Reply {
            status: 200,
            body: b"{}".to_vec(),
        })
    }
}

/// `while_sending` calls `inside` after `Gated::send` signals entry and
/// returns the result of `inside` after the worker exits. `inside` can
/// release the gate through its callback; returning or unwinding also
/// releases the gate. If the worker panics before entry, dropping `Gated`
/// wakes the caller, which resumes the panic.
fn while_sending<T>(send: impl FnOnce(Gated) + Send, inside: impl FnOnce(&dyn Fn()) -> T) -> T {
    thread::scope(|scope| {
        let (entered, arrival) = mpsc::channel();
        let (release, held) = mpsc::channel();
        let wire = Gated {
            entered,
            release: held,
        };
        let sent = scope.spawn(move || send(wire));
        let out = arrival.recv().is_ok().then(|| {
            inside(&|| {
                let _ = release.send(());
            })
        });
        drop(release);
        if let Err(panic) = sent.join() {
            std::panic::resume_unwind(panic);
        }
        out.expect("the send ended without entering its inner wire")
    })
}

fn put_request() -> (Vec<(String, String)>, Vec<u8>) {
    let headers = vec![(
        "x-amz-target".to_owned(),
        "DynamoDB_20120810.PutItem".to_owned(),
    )];
    let body = json!({
        "Item": {
            "pk": { "S": "shard#9" },
            "ver": { "N": "1" },
            "val": { "B": "" },
            "wid": { "B": "AAECAwQFBgcICQoLDA0ODw==" },
        },
        "ConditionExpression": "attribute_not_exists(pk)",
    });
    (headers, body.to_string().into_bytes())
}

fn request<'a>(headers: &'a [(String, String)], body: &'a [u8]) -> Request<'a> {
    Request {
        host: "localhost",
        headers,
        body,
        body_cap: DYNAMODB.body_cap,
    }
}

fn recorder<W>(inner: W, journal: &Journal) -> Recorder<W> {
    Recorder {
        inner,
        journal: journal.clone(),
        scenario: "flush".to_owned(),
        client: "c1".to_owned(),
        limit: DYNAMODB.deadline,
    }
}

#[test]
fn the_recorder_limits_only_item_exchanges_and_counts_signers_per_client() {
    let dir = campaign("limit");
    let journal = Journal::new(&dir);
    let limit = Duration::from_millis(30);
    let mut wire = recorder(Deadlines::default(), &journal);
    wire.limit = limit;
    let (mut headers, body) = put_request();
    let signed = |key: &str| {
        let value = format!(
            "AWS4-HMAC-SHA256 Credential={key}/20260101/us-east-1/dynamodb/aws4_request, SignedHeaders=host, Signature=0"
        );
        ("authorization".to_owned(), value)
    };
    headers.push(signed("AKIDONE"));
    let before = Instant::now();
    wire.send(&request(&headers, &body), before + Duration::from_secs(1))
        .unwrap();
    let after = Instant::now();
    headers.pop();
    headers.push(signed("AKIDTWO"));
    let early = Instant::now() + Duration::from_millis(5);
    wire.send(&request(&headers, &body), early).unwrap();
    wire.send(&request(&headers, &body), early).unwrap();
    let describe = [(
        "x-amz-target".to_owned(),
        "DynamoDB_20120810.DescribeTable".to_owned(),
    )];
    let far = Instant::now() + Duration::from_secs(1);
    wire.send(&request(&describe, b"{}"), far).unwrap();
    let seen = wire.inner.0.lock().unwrap().clone();
    assert!(seen[0].1 >= before + limit && seen[0].1 <= after + limit);
    assert_eq!(seen[1].1, early, "an earlier call deadline stands");
    assert_eq!(seen[3], ("DescribeTable".to_owned(), far));
    assert_eq!(journal.signers("c1"), 2);
    assert_eq!(journal.signers("c2"), 0);
    drop((wire, journal));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_recorder_stamps_its_interval_outside_the_journal_lock() {
    let dir = campaign("stamps");
    let journal = Journal::new(&dir);
    let (headers, body) = put_request();
    let request = request(&headers, &body);
    let hold = Duration::from_millis(200);

    let (entered, released) = while_sending(
        |wire| {
            recorder(wire, &journal)
                .send(&request, Instant::now() + DYNAMODB.deadline)
                .unwrap();
        },
        |release| {
            let entered = now();
            let held = journal.0.lines.lock().unwrap();
            release();
            thread::sleep(hold);
            let released = now();
            drop(held);
            (entered, released)
        },
    );
    let line = journal.line(0).unwrap();
    let (invoke, complete) = (
        line["invoke"].as_u64().unwrap(),
        line["complete"].as_u64().unwrap(),
    );
    assert!(invoke < entered, "invoke precedes the inner send: {line:?}");
    assert!(entered < complete, "complete follows the reply: {line:?}");
    assert!(complete < released, "{line:?}");

    let plain = recorder(Deadlines::default(), &journal);
    let held = journal.0.lines.lock().unwrap();
    let released = thread::scope(|scope| {
        let sent = scope.spawn(|| plain.send(&request, Instant::now() + DYNAMODB.deadline));
        thread::sleep(hold);
        let released = now();
        drop(held);
        sent.join().unwrap().unwrap();
        released
    });
    let line = journal.line(1).unwrap();
    assert!(line["invoke"].as_u64().unwrap() >= released, "{line:?}");
    drop((plain, journal));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_send_that_unwinds_before_its_inner_wire_ends_the_wait() {
    let dir = campaign("unwinds");
    let journal = Journal::new(&dir);
    let recording = journal.clone();
    let (done, waited) = mpsc::channel();
    let waiting = thread::spawn(move || {
        // The recorder panics on an action it cannot journal, before it
        // calls its inner wire.
        let scan = [(
            "x-amz-target".to_owned(),
            "DynamoDB_20120810.Scan".to_owned(),
        )];
        let ended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            while_sending(
                |wire| {
                    let request = request(&scan, b"{}");
                    let _ = recorder(wire, &recording)
                        .send(&request, Instant::now() + DYNAMODB.deadline);
                },
                |_release| (),
            );
        }));
        done.send(ended).unwrap();
    });
    let failed = waited
        .recv_timeout(Duration::from_secs(5))
        .expect("the send's panic ends the wait")
        .expect_err("the wait resumes the send's panic");
    let message = failed.downcast_ref::<String>().expect("a formatted panic");
    assert!(message.contains("cannot journal: Scan"), "{message}");
    waiting.join().unwrap();
    assert_eq!(journal.len(), 0, "the send journaled no line");
    drop(journal);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_pending_line_is_written_as_unknown_when_the_journal_drops() {
    let dir = campaign("flush");
    let journal = Journal::new(&dir);
    let wire = recorder(Unwinds, &journal);
    let (headers, body) = put_request();
    let request = request(&headers, &body);
    let sent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wire.send(&request, Instant::now() + DYNAMODB.deadline)
    }));
    assert!(sent.is_err());
    assert!(!dir.join("flush.jsonl").exists(), "the line is pending");
    let unwound = now();
    drop((wire, journal));
    let lines = read_lines(&dir, "flush.jsonl");
    assert_eq!(lines.len(), 1);
    let line = &lines[0];
    assert_eq!(line["outcome"], "unknown");
    assert_eq!(line["code"], PENDING);
    assert_eq!(line["wid"], "000102030405060708090a0b0c0d0e0f");
    assert_eq!(line["expect"], 0);
    assert!(line["complete"].as_u64().unwrap() >= unwound);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_failed_journal_write_fails_the_call_once() {
    let (headers, body) = put_request();
    let request = request(&headers, &body);
    let send = |wire: &dyn Wire| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            wire.send(&request, Instant::now() + DYNAMODB.deadline)
        }))
        .expect_err("the call fails")
    };
    for writable_at_drop in [false, true] {
        let dir = campaign("unwritable");
        let blocker = dir.join("flush.jsonl");
        std::fs::create_dir(&blocker).unwrap();
        let journal = Journal::new(&dir);
        let failed = send(&recorder(FakeTable::new(), &journal));
        let message = failed.downcast_ref::<String>().expect("a formatted panic");
        assert!(message.contains("flush.jsonl"), "{message}");
        send(&recorder(Unwinds, &journal));
        if writable_at_drop {
            std::fs::remove_dir(&blocker).unwrap();
        }
        let journal = std::panic::AssertUnwindSafe(journal);
        std::panic::catch_unwind(move || drop(journal)).expect("the drop does not panic");
        if writable_at_drop {
            let lines = read_lines(&dir, "flush.jsonl");
            assert_eq!(lines.len(), 1, "{lines:#?}");
            assert_eq!(lines[0]["code"], PENDING);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[test]
fn a_history_file_that_already_exists_is_refused_and_kept() {
    let dir = campaign("existing");
    let target = dir.join("target.txt");
    std::fs::write(&target, "kept").unwrap();
    std::fs::write(dir.join("flush.jsonl"), "kept").unwrap();
    std::os::unix::fs::symlink(&target, dir.join("linked.jsonl")).unwrap();
    let journal = Journal::new(&dir);
    let (headers, body) = put_request();
    let request = request(&headers, &body);
    for scenario in ["flush", "linked"] {
        let mut wire = recorder(FakeTable::new(), &journal);
        wire.scenario = scenario.to_owned();
        let sent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            wire.send(&request, Instant::now() + DYNAMODB.deadline)
        }));
        assert!(sent.is_err(), "{scenario}");
    }
    drop(journal);
    assert_eq!(
        std::fs::read_to_string(dir.join("flush.jsonl")).unwrap(),
        "kept"
    );
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "kept");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_stale_strong_read_through_the_recorder_has_no_linearization() {
    let fake = FakeTable::new();
    let dir = campaign("stale");
    let bench = Bench::new(Target::Fake(fake.clone()), &dir);
    let shard = Shard::new(1).unwrap();
    let key = text(&Key::Shard(shard));
    create(&bench, "stale", shard);
    let old = json!({ "Item": fake.item(&key).unwrap() }).to_string();
    let (mut writer, _) = bench.client("stale", "writer", DYNAMODB.deadline);
    let read = writer.read::<ShardRecord>(Key::Shard(shard)).unwrap();
    writer.bump(&read).unwrap();
    let (mut reader, _) = bench.client("stale", "reader", DYNAMODB.deadline);
    fake.plant(Plant::Reply {
        apply: false,
        status: 200,
        body: old,
    });
    reader.read::<ShardRecord>(Key::Shard(shard)).unwrap();
    let stale = bench.journal.line(bench.journal.len() - 1).unwrap();
    assert_eq!(
        (&stale["client"], &stale["ver"], &stale["consistent"]),
        (&json!("reader"), &json!(1), &json!(true))
    );
    drop((writer, reader, bench));
    write_commits(&fake, &dir);
    assert_eq!(
        check::violations(&dir),
        [format!(
            "ST1/ST3: {key} has no linearization: no point for version 2 satisfies every write, read and condition failure that bounds it"
        )]
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn spaced_reads_are_grouped_by_result_and_journal_line() {
    let fake = FakeTable::new();
    let dir = campaign("spaced");
    let bench = Bench::new(Target::Fake(fake.clone()), &dir);
    let shard = Shard::new(1).unwrap();
    let (mut client, _) = bench.client("spaced", "spaced", DYNAMODB.deadline);
    create(&bench, "spaced", shard);
    let mut call = |plant: Option<Plant>| {
        let before = bench.journal.len();
        if let Some(plant) = plant {
            fake.plant(plant);
        }
        let result = client.read::<ShardRecord>(Key::Shard(shard)).map(drop);
        spaced_call(&result, bench.journal.line(before).as_ref()).map(|(group, _)| group)
    };
    let reply = |status, body: &str| Plant::Reply {
        apply: false,
        status,
        body: body.to_owned(),
    };
    assert_eq!(call(None), None);
    assert_eq!(
        call(Some(reply(
            400,
            r#"{"__type":"com.amazon.coral.service#ExpiredTokenException"}"#
        ))),
        Some("refused for credentials")
    );
    assert_eq!(
        call(Some(Plant::Lose { apply: false })),
        Some("not ok at the wire")
    );
    assert_eq!(call(Some(reply(200, "[]"))), Some("not ok at the wire"));
    assert_eq!(call(Some(reply(200, "{}"))), Some("refused by the client"));
    assert_eq!(call(None), Some("ended before the wire"));
    let unavailable = Err(StoreError::Unavailable);
    assert_eq!(
        spaced_call(&unavailable, None).map(|(group, _)| group),
        Some("refused for credentials")
    );
    assert_eq!(bench.journal.signers("spaced"), 1);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_spaced_schedule_fits_its_hour_and_labels_reuse_eligibility() {
    let gaps = idle_gaps();
    assert_eq!(
        gaps[..6],
        [1, 5, 20, 60, 300, 1].map(Duration::from_secs),
        "the gaps in turn"
    );
    let total: Duration = gaps.iter().sum();
    assert!(total <= Duration::from_secs(3600), "{total:?}");
    assert!(gaps.iter().any(|gap| *gap < IDLE_AGE) && gaps.iter().any(|gap| *gap > IDLE_AGE));
    assert_eq!(
        pool(IDLE_AGE - Duration::from_nanos(1)),
        "eligible for reuse"
    );
    assert_eq!(pool(IDLE_AGE), "past the idle age");
    assert_eq!(pool(IDLE_AGE + Duration::from_secs(1)), "past the idle age");
}

#[test]
fn coverage_names_each_missing_witness() {
    let pages = Shard::new(2).unwrap();
    let page = |page| text(&Key::Page(pages, page));
    let cas = |fields: Value| {
        let mut line: Line =
            json!({ "op": "cas", "outcome": "ok", "code": "", "expect": 1, "wid": "w" })
                .as_object()
                .unwrap()
                .clone();
        line.extend(fields.as_object().unwrap().clone());
        line
    };
    let refused = |fields: Value| {
        let mut line = cas(fields);
        line.insert("outcome".into(), json!("fail"));
        line.insert("code".into(), json!(CONDITION_FAILED));
        line
    };
    let mut complete: Vec<Line> = ONE_ITEM_CLIENTS
        .iter()
        .map(|client| cas(json!({ "scenario": "one-item", "client": client, "key": "shard#1" })))
        .collect();
    complete.push(cas(
        json!({ "scenario": "one-item", "client": "init", "key": "shard#1" }),
    ));
    complete.push(refused(
        json!({ "scenario": "one-item", "client": "c1", "key": "shard#1" }),
    ));
    complete.push(refused(
        json!({ "scenario": "one-item", "client": "paused", "key": "shard#1" }),
    ));
    let mut lost = cas(json!({ "scenario": "one-item", "client": "short", "key": "shard#1" }));
    lost.insert("outcome".into(), json!("unknown"));
    lost.insert("code".into(), json!("lost Exchange TimedOut"));
    complete.push(lost);
    for (at, client) in (0..PAGES).zip(PAGE_CLIENTS.iter().cycle()) {
        complete.push(cas(
            json!({ "scenario": "page-fences", "client": client, "key": page(at) }),
        ));
    }
    for wid in ["a", "b"] {
        complete.push(refused(json!({
            "scenario": "page-fences", "client": "t1", "key": page(0), "expect": 2, "wid": wid,
        })));
    }
    assert_eq!(coverage(&complete, pages), Vec::<String>::new());

    let without = |dropped: &dyn Fn(&Line) -> bool| {
        let lines: Vec<Line> = complete
            .iter()
            .filter(|line| !dropped(line))
            .cloned()
            .collect();
        coverage(&lines, pages)
    };
    assert_eq!(
        without(&|line| line["client"] == "c2"),
        ["one-item: no write from c2"]
    );
    assert_eq!(
        without(&|line| line["client"] == "short" && line["outcome"] == "unknown"),
        ["one-item: no write from short left unknown by a lost exchange"]
    );
    assert_eq!(
        without(&|line| line["client"] == "paused" && line["outcome"] == "fail"),
        ["one-item: no refused write from paused"]
    );
    assert_eq!(
        without(&|line| line["key"] == page(3)),
        [format!("page-fences: no worker write on {}", page(3))]
    );
    assert_eq!(
        without(&|line| line["wid"] == "b"),
        ["page-fences: no refused write retried on its key and version"]
    );
    assert_eq!(
        without(&|line| {
            line["scenario"] == "one-item" && line["client"] != "init" && line["outcome"] == "ok"
        }),
        ["one-item: no ok worker write", "one-item: no write from c2"],
        "the setup client's write is no worker write"
    );
    assert_eq!(
        without(&|line| line["scenario"] == "page-fences" && line["outcome"] == "fail"),
        [
            "page-fences: no fail worker write",
            "page-fences: no refused write retried on its key and version"
        ]
    );
    let retried = ["page-fences: no refused write retried on its key and version"];
    let altered = |wid: &str, field: &str, value: Value| {
        let lines: Vec<Line> = complete
            .iter()
            .cloned()
            .map(|mut line| {
                if line["wid"] == wid {
                    line.insert(field.into(), value.clone());
                }
                line
            })
            .collect();
        coverage(&lines, pages)
    };
    assert_eq!(
        altered("b", "wid", json!("a")),
        retried,
        "the same write ID"
    );
    assert_eq!(altered("b", "expect", json!(3)), retried, "another version");
    assert_eq!(altered("b", "key", json!(page(1))), retried, "another key");
    // Only a write counts, and only `short`'s lost exchange counts as its
    // witness.
    let reassigned = |from: &dyn Fn(&Line) -> bool, field: &str, value: Value| {
        let lines: Vec<Line> = complete
            .iter()
            .cloned()
            .map(|mut line| {
                if from(&line) {
                    line.insert(field.into(), value.clone());
                }
                line
            })
            .collect();
        coverage(&lines, pages)
    };
    assert_eq!(
        reassigned(&|line| line["client"] == "c2", "op", json!("read")),
        ["one-item: no write from c2"],
        "a read is no write"
    );
    assert_eq!(
        reassigned(
            &|line| line["client"] == "short" && line["outcome"] == "unknown",
            "client",
            json!("c1")
        ),
        ["one-item: no write from short left unknown by a lost exchange"],
        "another client's lost exchange"
    );
    assert_eq!(
        altered("a", "code", json!("ValidationException")),
        retried,
        "a refusal that is no condition failure"
    );
    let connect: Vec<Line> = complete
        .iter()
        .cloned()
        .map(|mut line| {
            if line["outcome"] == "unknown" {
                line.insert("code".into(), json!("lost Connect TimedOut"));
            }
            line
        })
        .collect();
    assert_eq!(
        coverage(&connect, pages),
        ["one-item: no write from short left unknown by a lost exchange"]
    );
}

#[test]
fn latency_leaves_out_the_short_client() {
    let line = |client: &str, took: u64| -> Line {
        json!({ "scenario": "one-item", "client": client, "op": "read", "outcome": "ok", "invoke": 7_000_000, "complete": 7_000_000 + took })
            .as_object()
            .unwrap()
            .clone()
    };
    assert_eq!(
        latency(&[line("c1", 2_000_000), line("short", 1_000_000)]),
        [
            "one-item read: 1 ok calls outside short, recorder wire interval p50 2.00 ms, p99 2.00 ms"
        ]
    );
    let mut lines: Vec<Line> = [5, 1, 4, 2, 3]
        .map(|took| line("c1", took * 1_000_000))
        .into();
    let mut lost = line("c1", 9_000_000);
    lost.insert("outcome".into(), json!("unknown"));
    lines.push(lost);
    assert_eq!(
        latency(&lines),
        [
            "one-item read: 5 ok calls outside short, recorder wire interval p50 3.00 ms, p99 4.00 ms"
        ],
        "the sample at (n - 1) * q / 100 of the sorted ok calls"
    );
}

#[test]
fn a_history_missing_a_write_id_fails_the_check() {
    let fake = FakeTable::new();
    let dir = campaign("missing-wid");
    let bench = Bench::new(Target::Fake(fake.clone()), &dir);
    let shard = Shard::new(1).unwrap();
    let (mut client, _) = bench.client("missing-wid", "c1", DYNAMODB.deadline);
    create(&bench, "missing-wid", shard);
    client.read::<ShardRecord>(Key::Shard(shard)).unwrap();
    drop((client, bench));
    write_commits(&fake, &dir);
    assert_eq!(check::violations(&dir), Vec::<String>::new());
    let recorded = read_lines(&dir, "missing-wid.jsonl");
    let commits = std::fs::read_to_string(dir.join("commits.jsonl")).unwrap();
    for (op, refusal) in [
        ("cas", "carries no write ID"),
        (
            "read",
            "returns neither an absent item nor a version with its write ID",
        ),
    ] {
        let mut lines = recorded.clone();
        let at = lines
            .iter()
            .position(|l| l["op"] == op && l["outcome"] == "ok" && l.get("wid").is_some())
            .unwrap();
        lines[at].remove("wid");
        let text: String = lines
            .iter()
            .map(|line| format!("{}\n", serde_json::to_string(line).unwrap()))
            .collect();
        let copy = campaign(&format!("missing-wid-{op}"));
        write_new(&copy, "missing-wid.jsonl", &text);
        write_new(&copy, "commits.jsonl", &commits);
        let found = check::violations(&copy);
        assert!(found.iter().any(|v| v.contains(refusal)), "{found:#?}");
        std::fs::remove_dir_all(&copy).unwrap();
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn an_injected_client_retry_fails_st4() {
    let fake = FakeTable::new();
    let dir = campaign("retry");
    let bench = Bench::new(Target::Retry(fake.clone()), &dir);
    let (mut client, namespace) = bench.client("retry", "c1", DYNAMODB.deadline);
    assert_eq!(
        client
            .create_shard(record(Shard::new(1).unwrap(), namespace))
            .map(drop),
        Err(StoreError::Refused(Refusal::Condition))
    );
    write_commits(&fake, &dir);
    let found = check::violations(&dir);
    let writes = bench
        .journal
        .read(|lines| lines.iter().filter(|line| line["op"] == "cas").count());
    assert!(writes > 0);
    assert_eq!(found.len(), writes, "{found:#?}");
    assert!(
        found
            .iter()
            .all(|v| v.starts_with("ST4: ConditionalCheckFailedException write")),
        "{found:#?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `claim` reserves `dir` as this process's campaign directory. The returned
/// handle holds the lock on `dir`. `claim` creates an absent `dir` with mode
/// `0o700`, subject to the process umask. An existing `dir` retains its
/// mode. `claim` refuses a relative path, a directory another process holds
/// locked, and a nonempty directory.
fn claim(dir: &Path) -> Result<File, String> {
    let failed = |error: &dyn std::fmt::Display| format!("{}: {error}", dir.display());
    if !dir.is_absolute() {
        return Err(failed(&"not an absolute path"));
    }
    match DirBuilder::new().mode(0o700).create(dir) {
        Err(error) if error.kind() != ErrorKind::AlreadyExists => return Err(failed(&error)),
        _ => {}
    }
    let held = File::open(dir).map_err(|error| failed(&error))?;
    held.try_lock()
        .map_err(|error| failed(&format!("claimed by another process: {error}")))?;
    let mut entries = std::fs::read_dir(dir).map_err(|error| failed(&error))?;
    if entries.next().is_some() {
        return Err(failed(&"not empty"));
    }
    Ok(held)
}

/// Repeats `attempt`, a claim that follows a dropped one, for up to five
/// seconds while it finds the directory locked. A test that starts a child
/// process forks while the dropped claim's descriptor is open, and the
/// child's copy keeps the lock until the child calls exec.
fn after_release(mut attempt: impl FnMut() -> Result<File, String>) -> Result<File, String> {
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        match attempt() {
            Err(error) if error.contains("claimed by another process") && Instant::now() < end => {
                thread::sleep(Duration::from_millis(1));
            }
            claimed => return claimed,
        }
    }
}

#[test]
fn a_campaign_directory_is_claimed_once_and_must_be_empty() {
    let root = campaign("claim");
    let mode = std::fs::metadata(&root).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700, "a scratch directory is its owner's");
    let refusal = |dir: &Path| claim(dir).expect_err("a refused claim");
    assert!(refusal(Path::new("relative")).contains("not an absolute path"));
    let dir = root.join("campaign");
    let held = claim(&dir).expect("an absent directory is created and claimed");
    assert!(dir.is_dir());
    let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
    assert_eq!(
        mode & 0o777,
        0o700,
        "a directory the claim creates is its owner's"
    );
    assert!(refusal(&dir).contains("claimed by another process"));
    // A copy of the claim's descriptor, as a forked child holds one, keeps
    // the lock after the claim drops. The copy closes after the first
    // refused attempt, so the claim succeeds on a later one.
    let mut copy = Some(held.try_clone().unwrap());
    drop(held);
    assert!(refusal(&dir).contains("claimed by another process"));
    let mut attempts = 0;
    let reclaimed = after_release(|| {
        attempts += 1;
        let claimed = claim(&dir);
        if claimed.is_err() {
            copy.take();
        }
        claimed
    });
    drop(reclaimed.expect("an empty directory whose claim closed"));
    assert!(attempts >= 2, "the first attempt found the copy's lock");
    std::fs::write(dir.join("one-item.jsonl"), "").unwrap();
    let occupied = after_release(|| claim(&dir)).expect_err("a refused claim");
    assert!(occupied.contains("not empty"), "{occupied}");
    let file = root.join("file");
    std::fs::write(&file, "").unwrap();
    refusal(&file);
    let kept = root.join("kept");
    std::fs::create_dir(&kept).unwrap();
    std::fs::set_permissions(&kept, std::fs::Permissions::from_mode(0o755)).unwrap();
    drop(claim(&kept).expect("an existing empty directory is claimed"));
    let mode = std::fs::metadata(&kept).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o755, "an existing directory keeps its mode");
    std::fs::remove_dir_all(&root).unwrap();
}

fn history_dir() -> &'static Path {
    static CLAIM: OnceLock<(PathBuf, File)> = OnceLock::new();
    &CLAIM
        .get_or_init(|| {
            let dir = PathBuf::from(
                std::env::var_os("STORE_HISTORY_DIR").expect("STORE_HISTORY_DIR is unset"),
            );
            let held = claim(&dir).unwrap_or_else(|error| panic!("STORE_HISTORY_DIR {error}"));
            (dir, held)
        })
        .0
}

fn mark(test: &str) -> PathBuf {
    let path = history_dir().join(format!("{test}.recording"));
    File::create_new(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    path
}

fn aws() -> (Bench, u32) {
    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is unset"));
    let shard: u32 = var("STORE_RECORD_SHARD")
        .parse()
        .ok()
        .filter(|shard| *shard > 0)
        .expect("STORE_RECORD_SHARD is a positive shard number");
    shard
        .checked_add(2)
        .expect("STORE_RECORD_SHARD leaves room for three shards");
    let target = Target::Aws {
        table: var("STORE_RECORD_TABLE"),
        region: var("STORE_RECORD_REGION"),
    };
    (Bench::new(target, history_dir()), shard)
}

#[test]
#[ignore = "sends requests to the DynamoDB table STORE_RECORD_TABLE names with the qualification host's instance role; run it with --ignored"]
fn qualification_scenarios_record_their_histories() {
    let (bench, shard) = aws();
    let mark = mark("qualification");
    let plan = qualification();
    let pages = Shard::new(shard + 1).unwrap();
    let mut findings = one_item(&bench, &plan, Shard::new(shard).unwrap());
    findings.extend(page_fences(&bench, &plan, pages));
    let (refused, missing) = bench.journal.read(|lines| {
        for (key, count) in tally(lines) {
            println!("{key}: {count}");
        }
        for line in latency(lines) {
            println!("{line}");
        }
        let short_unknown = lines
            .iter()
            .filter(|line| line["client"] == "short" && line["op"] == "cas")
            .filter(|line| line["outcome"] == "unknown")
            .count();
        println!("one-item: {short_unknown} writes from short with an unknown outcome");
        let refused: Vec<String> = lines
            .iter()
            .filter(|line| line["code"] == "HTTP 200")
            .map(|line| serde_json::to_string(line).unwrap())
            .collect();
        (refused, coverage(lines, pages))
    });
    assert!(findings.is_empty(), "{findings:#?}");
    assert!(
        refused.is_empty(),
        "HTTP 200 replies the binding refuses: {refused:#?}"
    );
    assert!(missing.is_empty(), "incomplete coverage: {missing:#?}");
    drop(bench);
    std::fs::remove_file(&mark).unwrap();
}

#[test]
#[ignore = "sends requests to the DynamoDB table STORE_RECORD_TABLE names with the qualification host's instance role for eight hours; run it with --ignored"]
fn spaced_calls_record_transport_faults_and_credential_refusals() {
    let (bench, shard) = aws();
    let mark = mark("spaced");
    let shard = Shard::new(shard + 2).unwrap();
    let (mut client, _) = bench.client("spaced", "spaced", DYNAMODB.deadline);
    create(&bench, "spaced", shard);
    let mut groups: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let (mut calls, mut eligible) = (0, 0);
    let mut call = |gap: Duration| {
        let before = bench.journal.len();
        let result = client.read::<ShardRecord>(Key::Shard(shard)).map(drop);
        calls += 1;
        if gap < IDLE_AGE {
            eligible += 1;
        }
        if let Some((group, what)) = spaced_call(&result, bench.journal.line(before).as_ref()) {
            groups.entry(group).or_default().push(format!(
                "call {calls} after {gap:?} ({}): {what}",
                pool(gap)
            ));
        }
        !matches!(result, Err(StoreError::Withdrawn))
    };
    let mut going = true;
    for gap in idle_gaps() {
        if !going {
            break;
        }
        thread::sleep(gap);
        going = call(gap);
    }
    let tail = Instant::now();
    for minute in 1..=7 * 60 {
        if !going {
            break;
        }
        let slot = tail + Duration::from_secs(60 * minute);
        thread::sleep(slot.saturating_duration_since(Instant::now()));
        going = call(Duration::from_secs(60));
    }
    let signers = bench.journal.signers("spaced");
    println!(
        "{calls} calls, {eligible} after a gap below IDLE_AGE; connection reuse is unobserved; the spaced client's requests were signed by {signers} access keys"
    );
    for (group, calls) in &groups {
        println!("{group}: {}", calls.len());
    }
    assert!(groups.is_empty(), "{groups:#?}");
    assert!(
        signers >= 2,
        "credential rotation unobserved: every request was signed by one access key"
    );
    drop(bench);
    std::fs::remove_file(&mark).unwrap();
}
