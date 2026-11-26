//! Tests use the loopback server as an AWS endpoint or instance metadata
//! service. `Served::connections` counts the connections the server
//! accepted and `Served::requests` the complete request heads it read.

use std::cell::Cell;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::client::{Call, Client, Stage};
use crate::clock::{Clock, basic, parse_utc};
use crate::config::{Config, Service};
use crate::credentials::{REFRESH_WAIT, Role};
use crate::wire::{Lost, Reply, Request, Wire};

pub(crate) enum Answer {
    Reply(Vec<u8>),
    /// The server writes these bytes without reading the request body and
    /// closes the stream once a body byte has arrived, so on Linux the
    /// close sends a TCP reset over the unread body.
    Reset(Vec<u8>),
    Keep(Vec<u8>),
    /// The server writes these bytes, holds the connection open for the
    /// duration, then closes it.
    Stall(Vec<u8>, Duration),
    /// The server writes the head, then the body one byte per interval.
    Drip(Vec<u8>, Vec<u8>, Duration),
}

/// `silent` reads the request and writes nothing for `hold`.
pub(crate) fn silent(hold: Duration) -> Answer {
    Answer::Stall(Vec::new(), hold)
}

#[derive(Default)]
pub(crate) struct Served {
    connections: AtomicUsize,
    heads: Mutex<Vec<String>>,
    bodies: Mutex<Vec<Vec<u8>>>,
}

impl Served {
    pub(crate) fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    pub(crate) fn heads(&self) -> Vec<String> {
        self.heads.lock().unwrap().clone()
    }

    pub(crate) fn bodies(&self) -> Vec<Vec<u8>> {
        self.bodies.lock().unwrap().clone()
    }

    pub(crate) fn requests(&self) -> usize {
        self.heads.lock().unwrap().len()
    }

    /// `await_requests` waits up to two seconds for `count` request heads
    /// and returns the count it last read.
    pub(crate) fn await_requests(&self, count: usize) -> usize {
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            let read = self.requests();
            if read >= count || Instant::now() >= until {
                return read;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

pub(crate) struct Server {
    pub(crate) address: SocketAddr,
    pub(crate) served: Arc<Served>,
}

impl Server {
    pub(crate) fn host(&self) -> String {
        self.address.to_string()
    }
}

type Handler = dyn Fn(TcpStream, &Served) + Send + Sync;

/// The descriptor table size `presize` gives the process: twice the
/// 512-slot table the crate's tests grew it to when every test ran at once.
const DESCRIPTORS: usize = 1024;

/// `presize` grows the process's descriptor table to `DESCRIPTORS` slots
/// once and returns when the growth is done. Linux grows the table, from
/// 64 slots, to the next power of two when a descriptor opens past its
/// end. In a process of several threads each growth waits for an RCU grace
/// period, which took about
/// 100 ms in suite runs on a 16-CPU host, and every descriptor the process
/// opens meanwhile waits with it. A caller that waits here before its test
/// measures time keeps those waits outside the measured interval. Holding
/// `DESCRIPTORS / 2` files open at once places a descriptor past half the
/// table, which grows it to `DESCRIPTORS`; the table keeps its size after
/// the files close. At the process descriptor limit, the table already
/// covers every permitted descriptor number. After any other open error,
/// the table may still be smaller than `DESCRIPTORS`.
fn presize() {
    static PRESIZED: OnceLock<()> = OnceLock::new();
    PRESIZED.get_or_init(|| {
        let open: Vec<File> = (0..DESCRIPTORS / 2)
            .map_while(|_| File::open("/dev/null").ok())
            .collect();
        drop(open);
    });
}

fn listen(handler: Arc<Handler>) -> Server {
    presize();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let served = Arc::new(Served::default());
    let counts = Arc::clone(&served);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            counts.connections.fetch_add(1, Ordering::SeqCst);
            let (counts, handler) = (Arc::clone(&counts), Arc::clone(&handler));
            thread::spawn(move || handler(stream, &counts));
        }
    });
    Server { address, served }
}

/// `serve` answers each request with `script` applied to its head.
pub(crate) fn serve(script: impl Fn(&str) -> Answer + Send + Sync + 'static) -> Server {
    listen(Arc::new(move |mut stream: TcpStream, served: &Served| {
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        while let Some(head) = read_head(&mut stream) {
            served.heads.lock().unwrap().push(head.clone());
            let answer = script(&head);
            if let Answer::Reset(bytes) = &answer {
                let _ = stream.write_all(bytes);
                if content_length(&head) > 0 {
                    let _ = stream.peek(&mut [0]);
                }
                return;
            }
            if content_length(&head) > REQUEST_BODY_LIMIT {
                return;
            }
            if let Some(body) = read_body(&mut stream, &head) {
                served.bodies.lock().unwrap().push(body);
            }
            let keep = match answer {
                Answer::Reset(_) => unreachable!("a reset returned above"),
                Answer::Reply(bytes) => {
                    let _ = stream.write_all(&bytes);
                    false
                }
                Answer::Keep(bytes) => {
                    let _ = stream.write_all(&bytes);
                    true
                }
                Answer::Stall(bytes, hold) => {
                    let _ = stream.write_all(&bytes);
                    thread::sleep(hold);
                    false
                }
                Answer::Drip(head, body, interval) => {
                    let _ = stream.write_all(&head);
                    for byte in body {
                        thread::sleep(interval);
                        if stream.write_all(&[byte]).is_err() {
                            break;
                        }
                    }
                    false
                }
            };
            if !keep {
                return;
            }
        }
    }))
}

/// The TLS failure case uses `greet` to send plaintext during the
/// handshake; with no bytes, `greet` leaves the handshake unanswered.
pub(crate) fn greet(bytes: &'static [u8]) -> Server {
    listen(Arc::new(move |mut stream: TcpStream, served: &Served| {
        let _ = stream.write_all(bytes);
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        if let Some(head) = read_head(&mut stream) {
            served.heads.lock().unwrap().push(head);
        }
    }))
}

/// `accept_one` returns the next connection to `listener`, or `None` when
/// none arrives within two seconds, so a test whose client never connects
/// fails at its own assertion.
pub(crate) fn accept_one(listener: &TcpListener) -> Option<TcpStream> {
    listener.set_nonblocking(true).unwrap();
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                return Some(stream);
            }
            Err(_) if Instant::now() < until => thread::sleep(Duration::from_millis(2)),
            Err(_) => return None,
        }
    }
}

pub(crate) fn refused() -> SocketAddr {
    presize();
    SocketAddr::from(([127, 0, 0, 1], 1))
}

/// `read_head` reads one byte at a time, so the body stays in the socket.
fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return None,
        }
    }
    String::from_utf8(head).ok()
}

/// `header` returns the trimmed value of the first `name` field in a
/// request head.
pub(crate) fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(field, _)| field.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
}

/// The largest request body the server reads.
const REQUEST_BODY_LIMIT: usize = 1024 * 1024;

fn content_length(head: &str) -> usize {
    header(head, "content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

/// `read_body` returns the request body only when all of its declared
/// bytes arrive.
fn read_body(stream: &mut TcpStream, head: &str) -> Option<Vec<u8>> {
    let mut body = vec![0; content_length(head)];
    stream.read_exact(&mut body).ok().map(|()| body)
}

pub(crate) fn reply(status: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

#[derive(Clone)]
pub(crate) enum Credentials {
    Serve {
        key: &'static str,
        expiry: SystemTime,
    },
    Fail,
    Silent,
    /// The token and listing requests succeed and the document request
    /// gets no answer.
    StallDocument,
}

pub(crate) const TOKEN_PATH: &str = "/latest/api/token";
pub(crate) const LISTING_PATH: &str = "/latest/meta-data/iam/security-credentials/";
pub(crate) const DOCUMENT_PATH: &str = "/latest/meta-data/iam/security-credentials/cache-role";

/// `imds` plays IMDSv2's session rule: it passes `answer` a `PUT` of the
/// token path only with a lifetime of 1 to 21,600 seconds, and a `GET`
/// only with a token it issued, and answers any other request with 400 or
/// 401. `answer` answers each request by its path; when it answers the
/// token path with a 200, `imds` issues the next token, `token-1`,
/// `token-2` and so on, as the body.
pub(crate) fn imds(answer: impl Fn(&str) -> Answer + Send + Sync + 'static) -> Server {
    let issued = Mutex::new(Vec::<String>::new());
    serve(move |head| {
        let request = head.lines().next().unwrap_or("");
        if request == format!("PUT {TOKEN_PATH} HTTP/1.1") {
            let ttl = header(head, "x-aws-ec2-metadata-token-ttl-seconds")
                .and_then(|ttl| ttl.parse::<u32>().ok());
            if !ttl.is_some_and(|ttl| (1..=21_600).contains(&ttl)) {
                return Answer::Reply(reply("400 Bad Request", b""));
            }
            return match answer(TOKEN_PATH) {
                Answer::Reply(bytes) if bytes.starts_with(b"HTTP/1.1 200 ") => {
                    let mut issued = issued.lock().unwrap();
                    let token = format!("token-{}", issued.len() + 1);
                    issued.push(token.clone());
                    Answer::Reply(reply("200 OK", token.as_bytes()))
                }
                other => other,
            };
        }
        let token = header(head, "x-aws-ec2-metadata-token").unwrap_or("");
        match request.strip_prefix("GET ") {
            Some(rest) if issued.lock().unwrap().iter().any(|issued| issued == token) => {
                answer(rest.split(' ').next().unwrap_or(""))
            }
            _ => Answer::Reply(reply("401 Unauthorized", b"")),
        }
    })
}

/// `metadata` plays IMDSv2 for role `cache-role`, serving whatever
/// `credentials` holds at each request.
pub(crate) fn metadata(credentials: Arc<Mutex<Credentials>>) -> Server {
    imds(move |path| {
        let current = credentials.lock().unwrap().clone();
        match (current, path) {
            (Credentials::Silent, _) | (Credentials::StallDocument, DOCUMENT_PATH) => {
                silent(Duration::from_secs(5))
            }
            (Credentials::Fail, _) => Answer::Reply(reply("500 Internal Server Error", b"")),
            (_, TOKEN_PATH) => Answer::Reply(reply("200 OK", b"token")),
            (_, LISTING_PATH) => Answer::Reply(reply("200 OK", b"cache-role")),
            (Credentials::Serve { key, expiry }, DOCUMENT_PATH) => {
                Answer::Reply(reply("200 OK", document(key, expiry).as_bytes()))
            }
            _ => Answer::Reply(reply("404 Not Found", b"")),
        }
    })
}

pub(crate) fn document(key: &str, expiry: SystemTime) -> String {
    format!(
        r#"{{"Code":"Success","LastUpdated":"2026-01-01T00:00:00Z","Type":"AWS-HMAC","AccessKeyId":"{key}","SecretAccessKey":"secret-{key}","Token":"token-{key}","Expiration":"{}"}}"#,
        rfc3339(expiry)
    )
}

pub(crate) fn rfc3339(time: SystemTime) -> String {
    let basic = basic(time);
    format!(
        "{}-{}-{}T{}:{}:{}Z",
        &basic[0..4],
        &basic[4..6],
        &basic[6..8],
        &basic[9..11],
        &basic[11..13],
        &basic[13..15]
    )
}

/// `Manual` reads a set time and advances it by its step after each
/// reading; the step starts at zero.
#[derive(Clone)]
pub(crate) struct Manual(Arc<Mutex<(SystemTime, Duration)>>);

impl Manual {
    pub(crate) fn at(time: SystemTime) -> Self {
        Self(Arc::new(Mutex::new((time, Duration::ZERO))))
    }

    pub(crate) fn set(&self, time: SystemTime) {
        self.0.lock().unwrap().0 = time;
    }

    pub(crate) fn step(&self, step: Duration) {
        self.0.lock().unwrap().1 = step;
    }
}

impl Clock for Manual {
    fn now(&self) -> SystemTime {
        let mut state = self.0.lock().unwrap();
        let now = state.0;
        state.0 = now + state.1;
        now
    }
}

pub(crate) fn origin() -> SystemTime {
    parse_utc("2026-01-01T00:00:00Z").unwrap()
}

pub(crate) const CAP: usize = 1024;

pub(crate) fn service(deadline: Duration) -> Service {
    Service {
        name: "dynamodb",
        deadline,
        body_cap: CAP,
    }
}

/// `client` signs for DynamoDB in `us-east-1`, sends to `host`, and reads
/// credentials from the metadata double at `metadata`.
pub(crate) fn client<W: Wire>(
    wire: W,
    host: String,
    metadata: SocketAddr,
    clock: Manual,
    deadline: Duration,
) -> Client<W, Manual> {
    let config = Config::new(service(deadline), "us-east-1")
        .unwrap()
        .at(host);
    Client::new(config, wire, Role::at(metadata), clock)
}

/// `warmed` returns a role that holds the credentials the metadata double
/// at `metadata` serves, read at `clock`'s time. A client built on it signs
/// its first call with those held credentials. After each `Role::keys`
/// error, `warmed` checks a 60-second limit: it refreshes again before the
/// limit and panics at or after it.
pub(crate) fn warmed(metadata: SocketAddr, clock: &impl Clock) -> Role {
    let mut role = Role::at(metadata);
    let until = Instant::now() + Duration::from_secs(60);
    while let Err(kind) = role.keys(clock, Instant::now() + REFRESH_WAIT) {
        assert!(
            Instant::now() < until,
            "the metadata double at {metadata} served no credentials: {kind:?}"
        );
    }
    role
}

pub(crate) fn call() -> Call<'static> {
    Call {
        action: "GetItem",
        headers: &[
            ("content-type", "application/x-amz-json-1.0"),
            ("x-amz-target", "DynamoDB_20120810.GetItem"),
        ],
        body: b"{}",
    }
}

pub(crate) struct Counting<W> {
    pub(crate) inner: W,
    pub(crate) sends: Rc<Cell<usize>>,
}

impl<W> Counting<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self {
            inner,
            sends: Rc::default(),
        }
    }
}

impl<W: Wire> Wire for Counting<W> {
    fn send(&self, request: &Request<'_>, deadline: Instant) -> Result<Reply, Lost> {
        self.sends.set(self.sends.get() + 1);
        self.inner.send(request, deadline)
    }
}

/// The one-attempt tests use `Resend` to verify that they detect a retry:
/// it sends a request again after the first send fails.
pub(crate) struct Resend<W>(pub(crate) W);

impl<W: Wire> Wire for Resend<W> {
    fn send(&self, request: &Request<'_>, deadline: Instant) -> Result<Reply, Lost> {
        self.0
            .send(request, deadline)
            .or_else(|_| self.0.send(request, deadline))
    }
}

pub(crate) enum Expect {
    Reply(u16, &'static [u8]),
    Lost(Stage, ErrorKind),
}

pub(crate) struct Scripted {
    pub(crate) name: &'static str,
    pub(crate) host: String,
    pub(crate) served: Option<Arc<Served>>,
    pub(crate) tls: bool,
    pub(crate) requests: usize,
    pub(crate) expect: Expect,
}

impl Scripted {
    fn at(name: &'static str, server: Server, requests: usize, expect: Expect) -> Self {
        Self {
            name,
            host: server.host(),
            served: Some(server.served),
            tls: false,
            requests,
            expect,
        }
    }

    pub(crate) fn one_attempt(&self) -> Result<(), String> {
        settled(std::slice::from_ref(self))
    }

    /// An extra connection fails the check even if it carries no request.
    fn counted(&self) -> Result<(), String> {
        let read = self.served.as_ref().map_or(0, |served| served.requests());
        if read != self.requests {
            return Err(format!(
                "{}: {read} requests, expected {}",
                self.name, self.requests
            ));
        }
        match self.served.as_ref().map(|served| served.connections()) {
            None | Some(1) => Ok(()),
            Some(connections) => Err(format!(
                "{}: {connections} connections, expected 1",
                self.name
            )),
        }
    }
}

/// After waiting for expected requests, `settled` gives all faults one
/// shared 100 ms window for late requests or connections, then reports the
/// first count mismatch.
pub(crate) fn settled(faults: &[Scripted]) -> Result<(), String> {
    for fault in faults {
        if let Some(served) = &fault.served {
            served.await_requests(fault.requests);
        }
    }
    thread::sleep(Duration::from_millis(100));
    faults.iter().try_for_each(Scripted::counted)
}

/// `reset` closes the connection after reading the request head, with the
/// body unread.
pub(crate) fn reset() -> Scripted {
    Scripted::at(
        "reset after the request",
        serve(|_| Answer::Reset(Vec::new())),
        1,
        Expect::Lost(Stage::Exchange, ErrorKind::ConnectionReset),
    )
}

/// `faults` scripts each way an exchange can end, with the stalls measured
/// against `deadline` and the body limits against `CAP`.
pub(crate) fn faults(deadline: Duration) -> Vec<Scripted> {
    let throttled = br#"{"__type":"com.amazonaws.dynamodb.v20120810#ThrottlingException"}"#;
    let ok = |bytes: Vec<u8>| serve(move |_| Answer::Reply(bytes.clone()));
    let redirect = |status: &'static str| {
        serve(move |head| {
            Answer::Reply(if head.split(' ').nth(1) == Some("/done") {
                reply("200 OK", b"done")
            } else {
                format!(
                    "HTTP/1.1 {status}\r\nLocation: /done\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .into_bytes()
            })
        })
    };
    let chunked = |body: &[u8]| {
        let mut bytes = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
            body.len()
        )
        .into_bytes();
        bytes.extend_from_slice(body);
        bytes.extend_from_slice(b"\r\n0\r\n\r\n");
        bytes
    };
    let unframed = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"partial".to_vec();
    let unknown_coding =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: x-chunked\r\nConnection: close\r\n\r\n{\"partial"
            .to_vec();
    let mut chunked_with_length =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n", CAP + 1).into_bytes();
    chunked_with_length.extend_from_slice(&chunked(b"{}")[b"HTTP/1.1 200 OK\r\n".len()..]);
    let chunked_http10 =
        b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n".to_vec();
    let unknown_coding_with_length =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: x-chunked\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{\"partial"
            .to_vec();
    let chunked_http10_with_length =
        b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n2\r\n{}\r\n0\r\n\r\n"
            .to_vec();
    vec![
        Scripted {
            name: "connect refused",
            host: refused().to_string(),
            served: None,
            tls: false,
            requests: 0,
            expect: Expect::Lost(Stage::Connect, ErrorKind::ConnectionRefused),
        },
        Scripted {
            tls: true,
            ..Scripted::at(
                "TLS failure",
                greet(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
                0,
                Expect::Lost(Stage::Connect, ErrorKind::InvalidData),
            )
        },
        Scripted {
            tls: true,
            ..Scripted::at(
                "silent TLS peer",
                greet(b""),
                0,
                Expect::Lost(Stage::Connect, ErrorKind::TimedOut),
            )
        },
        reset(),
        Scripted::at(
            "no reply before the deadline",
            serve(move |_| silent(deadline * 2)),
            1,
            Expect::Lost(Stage::Exchange, ErrorKind::TimedOut),
        ),
        Scripted::at(
            "partial head",
            ok(b"HTTP/1.1 200 OK\r\nContent-".to_vec()),
            1,
            Expect::Lost(Stage::Exchange, ErrorKind::UnexpectedEof),
        ),
        Scripted::at(
            "malformed status line",
            ok(b"HTTP/1.1 2x0 OK\r\nContent-Length: 0\r\n\r\n".to_vec()),
            1,
            Expect::Lost(Stage::Exchange, ErrorKind::InvalidData),
        ),
        Scripted::at(
            "head past its limit",
            ok(format!(
                "HTTP/1.1 200 OK\r\nx-padding: {}\r\nContent-Length: 0\r\n\r\n",
                "a".repeat(128 * 1024)
            )
            .into_bytes()),
            1,
            Expect::Lost(Stage::Exchange, ErrorKind::FileTooLarge),
        ),
        Scripted::at(
            "truncated body",
            ok(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort".to_vec()),
            1,
            Expect::Lost(Stage::Exchange, ErrorKind::UnexpectedEof),
        ),
        Scripted::at(
            "unframed body then a clean close",
            ok(unframed.clone()),
            1,
            Expect::Lost(Stage::Exchange, ErrorKind::InvalidData),
        ),
        Scripted::at(
            "unframed body then a reset",
            serve(move |_| Answer::Reset(unframed.clone())),
            1,
            Expect::Lost(Stage::Exchange, ErrorKind::InvalidData),
        ),
        Scripted::at(
            "unknown coding then a clean close",
            ok(unknown_coding.clone()),
            1,
            Expect::Lost(Stage::Exchange, ErrorKind::InvalidData),
        ),
        Scripted::at(
            "unknown coding then a reset",
            serve(move |_| Answer::Reset(unknown_coding.clone())),
            1,
            Expect::Lost(Stage::Exchange, ErrorKind::InvalidData),
        ),
        Scripted::at(
            "HTTP/1.0 reply naming chunked then a clean close",
            ok(chunked_http10),
            1,
            Expect::Lost(Stage::Exchange, ErrorKind::InvalidData),
        ),
        Scripted::at(
            "unknown coding with a length field",
            ok(unknown_coding_with_length),
            1,
            Expect::Lost(Stage::Exchange, ErrorKind::InvalidData),
        ),
        Scripted::at(
            "HTTP/1.0 reply naming chunked with a length field",
            ok(chunked_http10_with_length),
            1,
            Expect::Lost(Stage::Exchange, ErrorKind::InvalidData),
        ),
        Scripted::at(
            "declared length past the cap",
            serve(move |_| {
                Answer::Stall(
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\na", CAP + 1).into_bytes(),
                    deadline * 2,
                )
            }),
            1,
            Expect::Lost(Stage::Exchange, ErrorKind::FileTooLarge),
        ),
        Scripted::at(
            "chunked body past the cap",
            ok(chunked(&vec![b'a'; CAP + 1])),
            1,
            Expect::Lost(Stage::Exchange, ErrorKind::FileTooLarge),
        ),
        Scripted::at(
            "chunked body",
            ok(chunked(b"{}")),
            1,
            Expect::Reply(200, b"{}"),
        ),
        Scripted::at(
            "chunked body with a length field past the cap",
            ok(chunked_with_length),
            1,
            Expect::Reply(200, b"{}"),
        ),
        Scripted::at(
            "chunked body cut inside a chunk",
            ok(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n10\r\nshort"
                    .to_vec(),
            ),
            1,
            Expect::Lost(Stage::Exchange, ErrorKind::UnexpectedEof),
        ),
        Scripted::at(
            "204 with no length",
            ok(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_vec()),
            1,
            Expect::Reply(204, b""),
        ),
        Scripted::at(
            "304 with no length",
            ok(b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".to_vec()),
            1,
            Expect::Reply(304, b""),
        ),
        Scripted::at(
            "agreeing length list",
            ok(b"HTTP/1.1 200 OK\r\nContent-Length: 2, 2\r\nConnection: close\r\n\r\n{}".to_vec()),
            1,
            Expect::Reply(200, b"{}"),
        ),
        Scripted::at(
            "head then stalled body",
            serve(move |_| {
                Answer::Stall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort".to_vec(),
                    deadline * 2,
                )
            }),
            1,
            Expect::Lost(Stage::Exchange, ErrorKind::TimedOut),
        ),
        Scripted::at(
            "head then a body that drips past the deadline",
            serve(move |_| {
                Answer::Drip(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n".to_vec(),
                    vec![b'a'; 20],
                    deadline / 10,
                )
            }),
            1,
            Expect::Lost(Stage::Exchange, ErrorKind::TimedOut),
        ),
        Scripted::at(
            "late head then a body whose sum passes the deadline",
            serve(move |_| {
                thread::sleep(deadline * 7 / 10);
                Answer::Drip(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n".to_vec(),
                    vec![b'a'; 20],
                    deadline / 40,
                )
            }),
            1,
            Expect::Lost(Stage::Exchange, ErrorKind::TimedOut),
        ),
        Scripted::at(
            "HTTP 500",
            ok(reply("500 Internal Server Error", b"")),
            1,
            Expect::Reply(500, b""),
        ),
        Scripted::at(
            "throttling code",
            ok(reply("400 Bad Request", throttled)),
            1,
            Expect::Reply(400, throttled),
        ),
        Scripted::at(
            "HTTP 302",
            redirect("302 Found"),
            1,
            Expect::Reply(302, b""),
        ),
        Scripted::at(
            "HTTP 307",
            redirect("307 Temporary Redirect"),
            1,
            Expect::Reply(307, b""),
        ),
    ]
}

#[cfg(test)]
#[path = "loopback_tests.rs"]
mod tests;
