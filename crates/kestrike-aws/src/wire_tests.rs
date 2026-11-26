use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use ureq::Agent;
use ureq::unversioned::transport::{ConnectionDetails, Connector, NextTimeout, Transport, time};

use super::{Https, IDLE_AGE, Lost, LostAt, Reply, Request, Wire, lost};
use crate::config::MAX_DEADLINE;
use crate::dial::{Dial, LOOKUPS, Lookup};
use crate::loopback::{Answer, CAP, Resend, accept_one, refused, reply, reset, serve, silent};

fn send_with(
    wire: &impl Wire,
    host: &str,
    headers: &[(String, String)],
    within: Duration,
) -> (Result<Reply, Lost>, Duration) {
    let request = Request {
        host,
        headers,
        body: b"{}",
        body_cap: CAP,
    };
    let start = Instant::now();
    let outcome = wire.send(&request, start + within);
    (outcome, start.elapsed())
}

fn send_to(wire: &impl Wire, host: &str, within: Duration) -> (Result<Reply, Lost>, Duration) {
    let headers = vec![
        ("host".to_owned(), host.to_owned()),
        (
            "content-type".to_owned(),
            "application/x-amz-json-1.0".to_owned(),
        ),
    ];
    send_with(wire, host, &headers, within)
}

#[test]
fn a_wire_that_sends_again_after_a_reset_fails_the_one_attempt_check() {
    let once = reset();
    let (outcome, _) = send_to(&Https::plain(), &once.host, Duration::from_secs(1));
    assert!(outcome.is_err(), "{outcome:?}");
    assert_eq!(once.one_attempt(), Ok(()));
    let twice = reset();
    let (outcome, _) = send_to(&Resend(Https::plain()), &twice.host, Duration::from_secs(1));
    assert!(outcome.is_err(), "{outcome:?}");
    assert_eq!(
        twice.one_attempt(),
        Err("reset after the request: 2 requests, expected 1".to_owned())
    );
}

fn reused_then_reset(wire: &impl Wire) -> (Result<Reply, Lost>, usize, usize) {
    let count = AtomicUsize::new(0);
    let server = serve(move |_| {
        let keep = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec();
        match count.fetch_add(1, Ordering::SeqCst) {
            0 => Answer::Keep(keep),
            1 => Answer::Reset(Vec::new()),
            _ => Answer::Reply(keep),
        }
    });
    let (first, _) = send_to(wire, &server.host(), Duration::from_secs(1));
    assert_eq!(first.unwrap().status, 200);
    let (second, _) = send_to(wire, &server.host(), Duration::from_secs(1));
    thread::sleep(Duration::from_millis(200));
    (
        second,
        server.served.connections(),
        server.served.requests(),
    )
}

#[test]
fn a_send_lost_on_a_reused_connection_is_not_sent_again() {
    let (second, connections, requests) = reused_then_reset(&Https::plain());
    assert_eq!(second.unwrap_err().at, LostAt::Exchange);
    assert_eq!((connections, requests), (1, 2));
    let (second, connections, requests) = reused_then_reset(&Resend(Https::plain()));
    assert_eq!(second.unwrap().status, 200);
    assert_eq!((connections, requests), (2, 3));
}

/// The 500 ms deadline leaves room for a loopback connection that
/// delivers its request 200 ms late, so the server reads the request
/// before the send ends.
#[test]
fn a_silent_server_ends_the_send_at_its_deadline_with_one_request_read() {
    let server = serve(|_| silent(Duration::from_secs(2)));
    let deadline = Duration::from_millis(500);
    let (outcome, elapsed) = send_to(&Https::plain(), &server.host(), deadline);
    assert_eq!(
        outcome,
        Err(Lost {
            at: LostAt::Exchange,
            kind: std::io::ErrorKind::TimedOut
        })
    );
    assert!(elapsed >= deadline, "{elapsed:?}");
    assert!(elapsed < Duration::from_millis(1000), "{elapsed:?}");
    assert_eq!(server.served.await_requests(1), 1);
    assert_eq!(server.served.connections(), 1);
}

#[test]
fn a_throttling_reply_returns_as_soon_as_it_is_parsed() {
    let body = br#"{"__type":"com.amazonaws.dynamodb.v20120810#ThrottlingException"}"#;
    let server = serve(move |_| {
        let mut bytes = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        bytes.extend_from_slice(body);
        Answer::Keep(bytes)
    });
    let (outcome, elapsed) = send_to(&Https::plain(), &server.host(), Duration::from_secs(5));
    assert_eq!(
        outcome,
        Ok(Reply {
            status: 400,
            body: body.to_vec()
        })
    );
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
    thread::sleep(Duration::from_millis(300));
    assert_eq!(server.served.requests(), 1);
}

#[test]
fn a_body_of_exactly_the_cap_is_read_whole() {
    let server = serve(|_| Answer::Reply(reply("200 OK", &[b'a'; CAP])));
    let (outcome, _) = send_to(&Https::plain(), &server.host(), Duration::from_secs(1));
    assert_eq!(outcome.unwrap().body.len(), CAP);
}

#[test]
fn a_send_whose_deadline_has_passed_writes_nothing() {
    let server = serve(|_| Answer::Reply(reply("200 OK", b"")));
    let (outcome, _) = send_to(&Https::plain(), &server.host(), Duration::ZERO);
    assert_eq!(
        outcome,
        Err(Lost {
            at: LostAt::Connect,
            kind: std::io::ErrorKind::TimedOut
        })
    );
    thread::sleep(Duration::from_millis(100));
    assert_eq!(server.served.connections(), 0);
}

#[test]
fn a_request_carrying_a_framing_header_is_refused_before_connecting() {
    let server = serve(|_| Answer::Reply(reply("200 OK", b"")));
    for (name, value) in [
        ("Content-Length", "0"),
        ("transfer-encoding", "chunked"),
        ("Expect", "100-continue"),
    ] {
        let headers = vec![(name.to_owned(), value.to_owned())];
        let (outcome, _) = send_with(
            &Https::plain(),
            &server.host(),
            &headers,
            Duration::from_secs(1),
        );
        assert_eq!(
            outcome,
            Err(Lost {
                at: LostAt::Connect,
                kind: std::io::ErrorKind::InvalidInput
            }),
            "{name}"
        );
    }
    thread::sleep(Duration::from_millis(100));
    assert_eq!(server.served.connections(), 0);
}

#[test]
fn an_idle_connection_carries_the_next_send_and_a_closed_one_is_replaced() {
    let count = AtomicUsize::new(0);
    let server = serve(move |_| {
        let keep = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec();
        match count.fetch_add(1, Ordering::SeqCst) {
            0 => Answer::Keep(keep),
            _ => Answer::Reply(keep),
        }
    });
    let wire = Https::plain();
    for _ in 0..2 {
        let (outcome, _) = send_to(&wire, &server.host(), Duration::from_secs(1));
        assert_eq!(outcome.unwrap().status, 200);
    }
    assert_eq!(
        (server.served.connections(), server.served.requests()),
        (1, 2)
    );
    thread::sleep(Duration::from_millis(100));
    let (outcome, _) = send_to(&wire, &server.host(), Duration::from_secs(1));
    assert_eq!(outcome.unwrap().status, 200);
    assert_eq!(
        (server.served.connections(), server.served.requests()),
        (2, 3)
    );
}

/// Both servers hold their connections open. The wire keeps one idle
/// connection, so the connection to the second server takes the place of
/// the first server's, and the next send to the first server opens a new
/// one.
#[test]
fn the_wire_keeps_one_idle_connection() {
    let keep =
        || serve(|_| Answer::Keep(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec()));
    let (first, second) = (keep(), keep());
    let wire = Https::plain();
    for server in [&first, &second, &first] {
        let (outcome, _) = send_to(&wire, &server.host(), Duration::from_secs(1));
        assert_eq!(outcome.unwrap().status, 200);
    }
    assert_eq!(
        (first.served.connections(), first.served.requests()),
        (2, 2)
    );
    assert_eq!(
        (second.served.connections(), second.served.requests()),
        (1, 1)
    );
}

/// The server holds the first connection open for ten seconds, so the
/// client alone decides whether the second send reuses it: the connection
/// has idled for longer than `IDLE_AGE`, and the second send opens a new
/// one.
#[test]
fn an_idle_connection_older_than_the_idle_age_is_replaced() {
    assert_eq!(IDLE_AGE, Duration::from_secs(5));
    let server =
        serve(|_| Answer::Keep(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec()));
    let wire = Https::plain();
    let (outcome, _) = send_to(&wire, &server.host(), Duration::from_secs(1));
    assert_eq!(outcome.unwrap().status, 200);
    thread::sleep(IDLE_AGE + Duration::from_millis(300));
    let (outcome, _) = send_to(&wire, &server.host(), Duration::from_secs(1));
    assert_eq!(outcome.unwrap().status, 200);
    assert_eq!(
        (server.served.connections(), server.served.requests()),
        (2, 2)
    );
}

const PROXY: &str = "KESTRIKE_AWS_PROXY";

const PROXY_VARIABLES: [&str; 6] = [
    "ALL_PROXY",
    "all_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
];

#[test]
fn proxy_variables_leave_the_send_direct() {
    if let Some(proxy) = std::env::var_os(PROXY) {
        assert!(
            proxy
                .to_str()
                .is_some_and(|url| url.starts_with("http://127.0.0.1:")),
            "{PROXY} names no loopback proxy"
        );
        for name in PROXY_VARIABLES {
            assert!(std::env::var_os(name) == Some(proxy.clone()), "{name}");
        }
        assert!(std::env::var_os("NO_PROXY").is_none(), "NO_PROXY");
        assert!(std::env::var_os("no_proxy").is_none(), "no_proxy");
        let server = serve(|_| Answer::Reply(reply("200 OK", b"")));
        let (outcome, _) = send_to(&Https::plain(), &server.host(), Duration::from_secs(1));
        assert_eq!(outcome.unwrap().status, 200);
        assert_eq!(server.served.requests(), 1);
        return;
    }
    let proxy = serve(|_| Answer::Reply(reply("502 Bad Gateway", b"")));
    let url = format!("http://{}", proxy.host());
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "wire::tests::proxy_variables_leave_the_send_direct",
            "--test-threads=1",
        ])
        .env(PROXY, &url)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy");
    for name in PROXY_VARIABLES {
        command.env(name, &url);
    }
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("1 passed"), "{stdout}");
    assert_eq!(proxy.served.connections(), 0);
}

#[test]
fn a_request_debug_shows_header_names_and_lengths_only() {
    let headers = vec![("x-amz-security-token".to_owned(), "secret-token".to_owned())];
    let request = Request {
        host: "h",
        headers: &headers,
        body: b"body",
        body_cap: 7,
    };
    assert_eq!(
        format!("{request:?}"),
        r#"Request { host: "h", headers: ["x-amz-security-token"], body: 4, body_cap: 7 }"#
    );
}

#[test]
fn a_lost_send_displays_its_stage_and_kind() {
    let lost: Box<dyn std::error::Error> = Box::new(Lost {
        at: LostAt::Exchange,
        kind: std::io::ErrorKind::TimedOut,
    });
    assert_eq!(lost.to_string(), "send lost at Exchange: timed out");
}

#[test]
fn a_deadline_past_the_bound_is_refused_before_connecting() {
    let server = serve(|_| Answer::Reply(reply("200 OK", b"")));
    let (outcome, _) = send_to(
        &Https::plain(),
        &server.host(),
        MAX_DEADLINE + Duration::from_secs(60),
    );
    assert_eq!(
        outcome,
        Err(Lost {
            at: LostAt::Connect,
            kind: std::io::ErrorKind::InvalidInput
        })
    );
    thread::sleep(Duration::from_millis(100));
    assert_eq!(server.served.connections(), 0);
}

#[test]
fn a_host_that_is_not_one_authority_is_refused_before_connecting() {
    let server = serve(|_| Answer::Reply(reply("200 OK", b"")));
    let address = server.host();
    for host in [
        format!("{address}/path"),
        format!("{address}?query"),
        format!("{address}#fragment"),
        format!("user@{address}"),
        String::new(),
    ] {
        let (outcome, _) = send_to(&Https::plain(), &host, Duration::from_secs(1));
        assert_eq!(
            outcome,
            Err(Lost {
                at: LostAt::Connect,
                kind: std::io::ErrorKind::InvalidInput
            }),
            "{host:?}"
        );
    }
    thread::sleep(Duration::from_millis(100));
    assert_eq!(server.served.connections(), 0);
    let (outcome, _) = send_to(&Https::plain(), &address, Duration::from_secs(1));
    assert_eq!(outcome.unwrap().status, 200);
    assert!(
        server.served.heads()[0].starts_with("POST / HTTP/1.1\r\n"),
        "{:?}",
        server.served.heads()
    );
}

static LOOKUPS_STARTED: AtomicUsize = AtomicUsize::new(0);

fn stalled_lookup(_: &str) -> io::Result<Vec<SocketAddr>> {
    LOOKUPS_STARTED.fetch_add(1, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(600));
    Err(std::io::ErrorKind::NotFound.into())
}

/// Each stalled lookup outlives its 50 ms send and holds its helper place
/// for 600 ms, so after `LOOKUPS` sends the next ones are refused without
/// a new helper, and a send after the helpers end starts one again. A
/// refusal waits for nothing, so the fastest of three returns within
/// 25 ms. A send to an IP-literal host needs no helper, so it goes out
/// while every helper place is held.
#[test]
fn stalled_lookups_keep_a_bounded_number_of_helpers() {
    let wire = Https::resolving(stalled_lookup);
    let send = || send_to(&wire, "stalled.invalid:80", Duration::from_millis(50)).0;
    for _ in 0..LOOKUPS {
        assert_eq!(
            send(),
            Err(Lost {
                at: LostAt::Connect,
                kind: std::io::ErrorKind::TimedOut
            })
        );
    }
    let fastest = (0..3)
        .map(|_| {
            let (refused, elapsed) =
                send_to(&wire, "stalled.invalid:80", Duration::from_millis(50));
            assert_eq!(
                refused,
                Err(Lost {
                    at: LostAt::Connect,
                    kind: std::io::ErrorKind::WouldBlock
                })
            );
            elapsed
        })
        .min()
        .unwrap();
    assert!(fastest < Duration::from_millis(25), "{fastest:?}");
    let server = serve(|_| Answer::Reply(reply("200 OK", b"")));
    let (literal, _) = send_to(&wire, &server.host(), Duration::from_secs(1));
    assert_eq!(literal.unwrap().status, 200);
    assert_eq!(LOOKUPS_STARTED.load(Ordering::SeqCst), LOOKUPS);
    thread::sleep(Duration::from_millis(900));
    assert_eq!(send().unwrap_err().at, LostAt::Connect);
    assert_eq!(LOOKUPS_STARTED.load(Ordering::SeqCst), LOOKUPS + 1);
}

/// A self-signed end-entity certificate for 127.0.0.1, valid from 2026 to
/// 2126, and its Ed25519 key in PKCS #8. No trust anchor signs it.
const UNTRUSTED_CERTIFICATE: [u8; 412] = [
    0x30, 0x82, 0x01, 0x98, 0x30, 0x82, 0x01, 0x4a, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x7b,
    0x56, 0x39, 0x36, 0x8e, 0x1d, 0x3e, 0x5a, 0xf8, 0x0b, 0x37, 0x03, 0x91, 0x28, 0xfa, 0xf8, 0x66,
    0xa5, 0xb3, 0x19, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x26, 0x31, 0x24, 0x30, 0x22,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1b, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x2d, 0x63, 0x61, 0x63,
    0x68, 0x65, 0x2d, 0x61, 0x77, 0x73, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x73, 0x65, 0x72, 0x76,
    0x65, 0x72, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x36, 0x31, 0x31, 0x32, 0x32, 0x30, 0x33, 0x34, 0x31,
    0x35, 0x38, 0x5a, 0x18, 0x0f, 0x32, 0x31, 0x32, 0x36, 0x31, 0x30, 0x32, 0x39, 0x30, 0x33, 0x34,
    0x31, 0x35, 0x38, 0x5a, 0x30, 0x26, 0x31, 0x24, 0x30, 0x22, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x1b, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2d, 0x61, 0x77, 0x73,
    0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x30, 0x2a, 0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0x6c, 0x47, 0xea, 0x1c, 0xc7, 0x80, 0xde, 0xb5,
    0xb5, 0x31, 0x72, 0x9d, 0x57, 0xc7, 0x2d, 0x3d, 0x56, 0x55, 0xa6, 0x5c, 0x4e, 0x42, 0x04, 0xbf,
    0x3c, 0xe1, 0x2d, 0x07, 0xd1, 0x5d, 0x24, 0x8f, 0xa3, 0x81, 0x87, 0x30, 0x81, 0x84, 0x30, 0x1d,
    0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xf0, 0x85, 0x34, 0x80, 0x08, 0x58, 0xe9,
    0x99, 0x64, 0x64, 0xe1, 0x95, 0xae, 0x30, 0xda, 0x14, 0x9a, 0x65, 0x6b, 0xbe, 0x30, 0x1f, 0x06,
    0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xf0, 0x85, 0x34, 0x80, 0x08, 0x58,
    0xe9, 0x99, 0x64, 0x64, 0xe1, 0x95, 0xae, 0x30, 0xda, 0x14, 0x9a, 0x65, 0x6b, 0xbe, 0x30, 0x0c,
    0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0f, 0x06, 0x03,
    0x55, 0x1d, 0x11, 0x04, 0x08, 0x30, 0x06, 0x87, 0x04, 0x7f, 0x00, 0x00, 0x01, 0x30, 0x0e, 0x06,
    0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x13, 0x06,
    0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
    0x03, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41, 0x00, 0xc8, 0x56, 0xbd, 0xe6,
    0x8c, 0x5a, 0x39, 0x41, 0x7b, 0xf2, 0x0d, 0x83, 0xff, 0x75, 0xda, 0x9d, 0x18, 0x9d, 0xf4, 0x77,
    0xa7, 0x0f, 0xf5, 0x4b, 0x28, 0xfa, 0x53, 0xd1, 0x32, 0x42, 0xca, 0x6c, 0xf2, 0xe6, 0x32, 0x9d,
    0x70, 0xfd, 0xc3, 0x55, 0x4f, 0x10, 0x07, 0x1d, 0xeb, 0x65, 0x18, 0xc8, 0x1c, 0xcc, 0x99, 0x85,
    0xfa, 0xd9, 0x9a, 0x0d, 0x9a, 0x69, 0x98, 0x07, 0xe6, 0x3d, 0x66, 0x0f,
];
const UNTRUSTED_KEY: [u8; 48] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    0xfb, 0xcb, 0x38, 0x35, 0xe1, 0x29, 0x94, 0xb6, 0x47, 0x4e, 0x77, 0x9f, 0x31, 0xf7, 0xe7, 0x5a,
    0x7e, 0x67, 0x58, 0xe4, 0xbd, 0x41, 0x6f, 0x49, 0x1d, 0x6e, 0x81, 0x23, 0x1c, 0x94, 0xa2, 0xfe,
];

/// `untrusted_tls` serves one TLS connection with `UNTRUSTED_CERTIFICATE`
/// and returns the error that ended the handshake, which for a client
/// that never connects is a `General` error. When the handshake completes
/// it reads one request head, answers 200 and returns `None`.
fn untrusted_tls() -> (SocketAddr, thread::JoinHandle<Option<rustls::Error>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(UNTRUSTED_CERTIFICATE.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(UNTRUSTED_KEY.to_vec())),
        )
        .unwrap();
    let handshake = thread::spawn(move || {
        let Some(mut stream) = accept_one(&listener) else {
            return Some(rustls::Error::General("no connection".to_owned()));
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut session = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        while session.is_handshaking() {
            if let Err(error) = session.complete_io(&mut stream) {
                let cause = error
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<rustls::Error>());
                return Some(
                    cause
                        .cloned()
                        .unwrap_or(rustls::Error::General(error.to_string())),
                );
            }
        }
        let mut tls = rustls::Stream::new(&mut session, &mut stream);
        let (mut head, mut byte) = (Vec::new(), [0]);
        while !head.ends_with(b"\r\n\r\n") && matches!(tls.read(&mut byte), Ok(1)) {
            head.push(byte[0]);
        }
        let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        None
    });
    (address, handshake)
}

/// `trusting` completes a TLS handshake with the server at `address` as a
/// client whose one trust anchor is `UNTRUSTED_CERTIFICATE`, posts an
/// empty request and returns the reply's bytes.
fn trusting(address: SocketAddr) -> Vec<u8> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(UNTRUSTED_CERTIFICATE.to_vec()))
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut session =
        rustls::ClientConnection::new(Arc::new(config), ServerName::from(address.ip())).unwrap();
    let mut stream = TcpStream::connect(address).unwrap();
    let mut tls = rustls::Stream::new(&mut session, &mut stream);
    tls.write_all(b"POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\r\n")
        .unwrap();
    let mut reply = Vec::new();
    let _ = tls.read_to_end(&mut reply);
    reply
}

/// The server holds the key of a certificate that no bundled trust anchor
/// signs. A client that trusts that certificate completes the handshake
/// and reads the reply, so the server and its certificate are sound, and
/// `Https::new` ends its handshake against the same server with nothing
/// sent: the signed request and its session token go only to a server
/// whose certificate chains to a trust anchor.
#[test]
fn a_certificate_from_no_trusted_root_is_refused_before_the_request() {
    let (address, handshake) = untrusted_tls();
    let reply = trusting(address);
    assert!(reply.starts_with(b"HTTP/1.1 200 OK\r\n"), "{reply:?}");
    assert_eq!(handshake.join().unwrap(), None);

    let (address, handshake) = untrusted_tls();
    let (outcome, _) = send_to(&Https::new(), &address.to_string(), Duration::from_secs(2));
    assert_eq!(
        outcome,
        Err(Lost {
            at: LostAt::Connect,
            kind: io::ErrorKind::InvalidData
        })
    );
    assert!(handshake.join().unwrap().is_some());
}

static REFUSED_LOOKUPS: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn refused_lookup(target: &str) -> io::Result<Vec<SocketAddr>> {
    REFUSED_LOOKUPS.lock().unwrap().push(target.to_owned());
    Ok(vec![refused()])
}

/// Every connection attempt starts with one lookup of the named host and
/// its port, so the lookups are the attempts the send made.
#[test]
fn a_refused_connect_is_tried_once() {
    let wire = Https::resolving(refused_lookup);
    let (outcome, _) = send_to(&wire, "refused.invalid:1", Duration::from_secs(1));
    assert_eq!(
        outcome,
        Err(Lost {
            at: LostAt::Connect,
            kind: io::ErrorKind::ConnectionRefused
        })
    );
    assert_eq!(*REFUSED_LOOKUPS.lock().unwrap(), ["refused.invalid:1"]);
}

/// `Https::plain` resolves `localhost` with the resolver `Https::new`
/// uses, the system's, and reaches the loopback server.
#[test]
fn a_named_host_resolves_through_the_system_resolver() {
    let server = serve(|_| Answer::Reply(reply("200 OK", b"")));
    let host = format!("localhost:{}", server.address.port());
    let (outcome, _) = send_to(&Https::plain(), &host, Duration::from_secs(2));
    assert_eq!(outcome.unwrap().status, 200);
    assert_eq!(server.served.requests(), 1);
}

fn failed_lookup(_: &str) -> io::Result<Vec<SocketAddr>> {
    Err(io::ErrorKind::HostUnreachable.into())
}

fn empty_lookup(_: &str) -> io::Result<Vec<SocketAddr>> {
    Ok(Vec::new())
}

/// `dying_lookup` ends its helper thread with no result and no panic
/// message.
fn dying_lookup(_: &str) -> io::Result<Vec<SocketAddr>> {
    std::panic::resume_unwind(Box::new("the lookup helper ends"))
}

/// A lookup that fails keeps its error kind, one that finds no address
/// reads as `NotFound`, and one whose helper ends without a result reads
/// as `Other`; each ends before any connection.
#[test]
fn a_lookup_that_fails_or_finds_no_address_reports_connect() {
    let send = |wire: Https| send_to(&wire, "absent.invalid:80", Duration::from_secs(1)).0;
    assert_eq!(
        send(Https::resolving(failed_lookup)),
        Err(Lost {
            at: LostAt::Connect,
            kind: io::ErrorKind::HostUnreachable
        })
    );
    assert_eq!(
        send(Https::resolving(empty_lookup)),
        Err(Lost {
            at: LostAt::Connect,
            kind: io::ErrorKind::NotFound
        })
    );
    assert_eq!(
        send(Https::resolving(dying_lookup)),
        Err(Lost {
            at: LostAt::Connect,
            kind: io::ErrorKind::Other
        })
    );
}

/// `Expired` passes `Dial` each connect with no time left, the state ureq
/// reaches when a send's deadline passes between its lookup and its
/// connect.
#[derive(Debug)]
struct Expired(Dial);

impl Connector<()> for Expired {
    type Out = Box<dyn Transport>;

    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<()>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        let mut addrs = details.resolver.empty();
        for address in details.addrs.iter() {
            addrs.push(*address);
        }
        let expired = ConnectionDetails {
            uri: details.uri,
            addrs,
            config: details.config,
            request_level: details.request_level,
            resolver: details.resolver,
            now: details.now,
            timeout: NextTimeout {
                after: time::Duration::Exact(Duration::ZERO),
                ..details.timeout
            },
            current_time: Arc::clone(&details.current_time),
            run_connector: Arc::clone(&details.run_connector),
            register_shutdown: Arc::clone(&details.register_shutdown),
        };
        self.0.connect(&expired, chained)
    }
}

/// With no time left ureq's connector would give the connect one second,
/// so `Dial` ends it as an unsent timeout before any connection.
#[test]
fn a_connect_with_no_time_left_opens_no_connection() {
    let server = serve(|_| Answer::Reply(reply("200 OK", b"")));
    let agent = Agent::with_parts(
        Agent::config_builder().build(),
        Expired(Dial::default()),
        Lookup::default(),
    );
    let error = agent
        .post(format!("http://{}/", server.host()))
        .send(&b"{}"[..])
        .unwrap_err();
    assert_eq!(
        lost(error),
        Lost {
            at: LostAt::Connect,
            kind: io::ErrorKind::TimedOut
        }
    );
    thread::sleep(Duration::from_millis(100));
    assert_eq!(server.served.connections(), 0);
}

#[test]
fn only_an_unsent_error_reports_connect() {
    use std::io::{Error, ErrorKind};
    assert_eq!(
        lost(ureq::Error::Io(Error::from(ErrorKind::ConnectionRefused))),
        Lost {
            at: LostAt::Exchange,
            kind: ErrorKind::ConnectionRefused
        }
    );
    assert_eq!(
        lost(ureq::Error::Timeout(ureq::Timeout::Global)),
        Lost {
            at: LostAt::Exchange,
            kind: ErrorKind::TimedOut
        }
    );
    assert_eq!(
        lost(ureq::Error::HostNotFound),
        Lost {
            at: LostAt::Connect,
            kind: ErrorKind::NotFound
        }
    );
    let before_the_request = [
        ureq::Error::ConnectionFailed,
        ureq::Error::RequireHttpsOnly(String::new()),
        ureq::Error::TlsRequired,
        ureq::Error::Tls("invalid name"),
    ];
    for error in before_the_request {
        let text = error.to_string();
        assert_eq!(
            lost(error),
            Lost {
                at: LostAt::Connect,
                kind: ErrorKind::Other
            },
            "{text}"
        );
    }
    let unnamed = [
        ureq::Error::StatusCode(500),
        ureq::Error::TooManyRedirects,
        ureq::Error::RedirectFailed,
        ureq::Error::InvalidProxyUrl,
    ];
    for error in unnamed {
        let text = error.to_string();
        assert_eq!(
            lost(error),
            Lost {
                at: LostAt::Exchange,
                kind: ErrorKind::Other
            },
            "{text}"
        );
    }
}
