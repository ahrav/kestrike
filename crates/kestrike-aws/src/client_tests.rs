//! `Client` tests send requests through ureq to loopback services.

use std::io::ErrorKind;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use super::{Call, Client, Stage};
use crate::clock::Clock;
use crate::config::{Config, Service};
use crate::credentials::Role;
use crate::loopback::{
    Answer, Counting, Credentials, Expect, Manual, Server, call, client, faults, metadata, origin,
    reply, serve, service,
};
use crate::sign::{Scope, canonical_request, signature, string_to_sign};
use crate::wire::Https;

fn fresh_metadata() -> Server {
    metadata(Arc::new(Mutex::new(Credentials::Serve {
        key: "AKIDFRESH",
        expiry: origin() + Duration::from_secs(3600),
    })))
}

#[test]
fn every_scripted_fault_through_the_client_writes_at_most_one_request() {
    let deadline = Duration::from_millis(500);
    let metadata = fresh_metadata();
    for fault in faults(deadline) {
        let wire = Counting::new(if fault.tls {
            Https::new()
        } else {
            Https::plain()
        });
        let mut client = client(
            wire,
            fault.host.clone(),
            metadata.address,
            Manual::at(origin()),
            deadline,
        );
        let start = Instant::now();
        let outcome = client.send(&call());
        let elapsed = start.elapsed();
        fault.one_attempt().unwrap();
        match (&fault.expect, &outcome) {
            (Expect::Reply(status, body), Ok(reply)) => {
                assert_eq!(
                    (reply.status, reply.body.as_slice()),
                    (*status, *body),
                    "{}",
                    fault.name
                );
            }
            (Expect::Lost(stage, kind), Err(got)) => {
                assert_eq!(
                    (got.action, got.stage, got.kind),
                    ("GetItem", *stage, *kind),
                    "{}",
                    fault.name
                );
                assert!(got.elapsed <= elapsed, "{}", fault.name);
                if *kind == ErrorKind::TimedOut {
                    assert!(got.elapsed >= deadline, "{}: {:?}", fault.name, got.elapsed);
                }
            }
            (_, outcome) => panic!("{}: {outcome:?}", fault.name),
        }
        assert_eq!(client.wire.sends.get(), 1, "{}", fault.name);
        assert!(
            elapsed < deadline + Duration::from_millis(250),
            "{}: {elapsed:?}",
            fault.name
        );
    }
}

#[test]
fn the_received_request_carries_one_host_and_a_valid_signature() {
    let metadata = fresh_metadata();
    let service = serve(|_| Answer::Reply(reply("200 OK", b"{}")));
    let mut client = client(
        Https::plain(),
        service.host(),
        metadata.address,
        Manual::at(origin()),
        Duration::from_secs(1),
    );
    let reply = client.send(&call()).unwrap();
    assert_eq!((reply.status, reply.body), (200, b"{}".to_vec()));
    let (heads, bodies) = (service.served.heads(), service.served.bodies());
    assert_eq!((heads.len(), bodies.as_slice()), (1, &[b"{}".to_vec()][..]));
    let mut lines = heads[0].lines();
    assert_eq!(lines.next(), Some("POST / HTTP/1.1"));
    let received: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(": "))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.to_owned()))
        .collect();
    let value = |name: &str| {
        let values: Vec<&str> = received
            .iter()
            .filter(|(header, _)| header == name)
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(values.len(), 1, "{name}: {values:?}");
        values[0].to_owned()
    };
    assert_eq!(value("host"), service.host());
    assert_eq!(value("x-amz-date"), "20260101T000000Z");
    assert_eq!(value("x-amz-security-token"), "token-AKIDFRESH");
    assert_eq!(value("x-amz-target"), "DynamoDB_20120810.GetItem");
    assert_eq!(value("content-type"), "application/x-amz-json-1.0");
    assert_eq!(value("content-length"), "2");
    let authorization = value("authorization");
    let (credential, rest) = authorization
        .strip_prefix("AWS4-HMAC-SHA256 Credential=")
        .unwrap()
        .split_once(", SignedHeaders=")
        .unwrap();
    let (names, sent) = rest.split_once(", Signature=").unwrap();
    assert_eq!(
        credential,
        "AKIDFRESH/20260101/us-east-1/dynamodb/aws4_request"
    );
    assert_eq!(
        names,
        "content-type;host;x-amz-date;x-amz-security-token;x-amz-target"
    );
    let signed: Vec<(String, String)> = names
        .split(';')
        .map(|name| (name.to_owned(), value(name)))
        .collect();
    let scope = Scope {
        region: "us-east-1",
        service: "dynamodb",
    };
    let text = string_to_sign(
        "20260101T000000Z",
        scope,
        &canonical_request(&signed, &bodies[0]),
    );
    assert_eq!(
        sent,
        signature("secret-AKIDFRESH", "20260101T000000Z", scope, &text)
    );
    assert!(
        received.iter().all(|(name, _)| name != "expect"),
        "{received:?}"
    );
}

#[test]
fn the_reply_cap_is_the_call_services_body_cap() {
    let metadata = fresh_metadata();
    let server = serve(|_| Answer::Reply(reply("200 OK", b"abc")));
    let send = |body_cap| {
        let service = Service {
            body_cap,
            ..service(Duration::from_secs(1))
        };
        let config = Config::new(service, "us-east-1").unwrap().at(server.host());
        let mut client = Client::new(
            config,
            Https::plain(),
            Role::at(metadata.address),
            Manual::at(origin()),
        );
        client.send(&call())
    };
    assert_eq!(send(3).unwrap().body, b"abc");
    let fault = send(2).unwrap_err();
    assert_eq!(
        (fault.stage, fault.kind),
        (Stage::Exchange, ErrorKind::FileTooLarge)
    );
}

#[test]
fn a_call_whose_header_names_collide_sends_nothing() {
    let metadata = fresh_metadata();
    let service = serve(|_| Answer::Reply(reply("200 OK", b"{}")));
    let mut client = client(
        Https::plain(),
        service.host(),
        metadata.address,
        Manual::at(origin()),
        Duration::from_secs(1),
    );
    let headers: [&[(&str, &str)]; 7] = [
        &[("Host", "elsewhere")],
        &[("X-Amz-Target", "a"), ("x-amz-target", "b")],
        &[("Authorization", "forged")],
        &[("X-Amz-Date", "20260101T000000Z")],
        &[("X-Amz-Security-Token", "forged")],
        &[("Content-Length", "0")],
        &[("Transfer-Encoding", "chunked")],
    ];
    for headers in headers {
        let call = Call {
            action: "GetItem",
            headers,
            body: b"{}",
        };
        let fault = client.send(&call).unwrap_err();
        assert_eq!(
            (fault.stage, fault.kind),
            (Stage::Connect, ErrorKind::InvalidInput),
            "{headers:?}"
        );
    }
    assert_eq!(metadata.served.connections(), 0);
    assert_eq!(service.served.connections(), 0);
}

#[test]
fn a_header_value_with_a_line_break_reaches_no_service() {
    let metadata = fresh_metadata();
    let service = serve(|_| Answer::Reply(reply("200 OK", b"{}")));
    let mut client = client(
        Https::plain(),
        service.host(),
        metadata.address,
        Manual::at(origin()),
        Duration::from_secs(1),
    );
    let call = Call {
        action: "GetItem",
        headers: &[("x-amz-target", "a\r\nx-injected: 1")],
        body: b"{}",
    };
    let fault = client.send(&call).unwrap_err();
    assert_eq!(
        (fault.stage, fault.kind),
        (Stage::Connect, ErrorKind::InvalidInput)
    );
    assert_eq!(service.served.connections(), 0);
}

#[derive(Clone)]
struct Sleepy(Arc<AtomicBool>);

impl Clock for Sleepy {
    fn now(&self) -> SystemTime {
        if self.0.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(450));
        }
        origin()
    }
}

#[test]
fn a_deadline_spent_choosing_credentials_ends_the_call_before_signing() {
    let metadata = fresh_metadata();
    let server = serve(|_| Answer::Reply(reply("200 OK", b"{}")));
    let config = Config::new(service(Duration::from_millis(400)), "us-east-1")
        .unwrap()
        .at(server.host());
    let slow = Arc::new(AtomicBool::new(false));
    let mut client = Client::new(
        config,
        Counting::new(Https::plain()),
        Role::at(metadata.address),
        Sleepy(Arc::clone(&slow)),
    );
    client.send(&call()).unwrap();
    slow.store(true, Ordering::SeqCst);
    let fault = client.send(&call()).unwrap_err();
    assert_eq!(
        (fault.stage, fault.kind),
        (Stage::Connect, ErrorKind::TimedOut)
    );
    assert_eq!(client.wire.sends.get(), 1);
    assert_eq!(server.served.requests(), 1);
}

/// Each reply is one a client with a retry or rate policy would act on: a
/// success, a redirect, a throttling or expired-token code, a timeout or
/// server error, with `Retry-After` where a service sends it. Six sends
/// read six requests, so no reply is followed or sent again. A pause
/// before a reply returns, or one that a reply leaves for the next call,
/// delays every send after the first, so the fastest of those five shows
/// it. A loopback exchange takes a few milliseconds, and the bound catches
/// a fixed pause of 25 ms or longer.
#[test]
fn every_coded_reply_returns_without_a_pause_or_a_second_request() {
    const THROTTLED: &[u8] =
        br#"{"__type":"com.amazonaws.dynamodb.v20120810#ThrottlingException"}"#;
    const PROVISIONED: &[u8] =
        br#"{"__type":"com.amazonaws.dynamodb.v20120810#ProvisionedThroughputExceededException"}"#;
    const LIMIT: &[u8] = br#"{"__type":"com.amazonaws.dynamodb.v20120810#RequestLimitExceeded"}"#;
    const EXPIRED: &[u8] = br#"{"__type":"com.amazon.coral.service#ExpiredTokenException"}"#;
    const EC2_LIMIT: &[u8] =
        b"<Response><Errors><Error><Code>RequestLimitExceeded</Code></Error></Errors></Response>";
    let replies: [(u16, &str, &str, &[u8]); 17] = [
        (200, "OK", "", b""),
        (200, "OK", "", b"{}"),
        (301, "Moved Permanently", "Location: /done\r\n", b""),
        (302, "Found", "Location: /done\r\n", b""),
        (307, "Temporary Redirect", "Location: /done\r\n", b""),
        (308, "Permanent Redirect", "Location: /done\r\n", b""),
        (400, "Bad Request", "", THROTTLED),
        (400, "Bad Request", "", PROVISIONED),
        (400, "Bad Request", "", LIMIT),
        (403, "Forbidden", "", EXPIRED),
        (408, "Request Timeout", "", b""),
        (429, "Too Many Requests", "Retry-After: 1\r\n", b""),
        (500, "Internal Server Error", "", b""),
        (502, "Bad Gateway", "", b""),
        (503, "Service Unavailable", "Retry-After: 1\r\n", b""),
        (503, "Service Unavailable", "", EC2_LIMIT),
        (504, "Gateway Timeout", "", b""),
    ];
    let metadata = fresh_metadata();
    for (status, reason, fields, body) in replies {
        let mut bytes = format!(
            "HTTP/1.1 {status} {reason}\r\n{fields}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        bytes.extend_from_slice(body);
        let server = serve(move |_| Answer::Reply(bytes.clone()));
        let mut client = client(
            Https::plain(),
            server.host(),
            metadata.address,
            Manual::at(origin()),
            Duration::from_secs(5),
        );
        let sends: Vec<Duration> = (0..6)
            .map(|_| {
                let start = Instant::now();
                let reply = client.send(&call()).unwrap();
                let elapsed = start.elapsed();
                assert_eq!((reply.status, reply.body.as_slice()), (status, body));
                elapsed
            })
            .collect();
        let fastest = sends[1..].iter().min().unwrap();
        assert!(*fastest < Duration::from_millis(25), "{status}: {sends:?}");
        thread::sleep(Duration::from_millis(50));
        assert_eq!(server.served.requests(), 6, "{status}");
    }
}

/// The server resets every other request, so each answered call follows
/// a lost one. A pause that a lost send leaves for the next call, such as
/// a backoff, delays each of them, so the fastest of five shows it.
#[test]
fn a_call_after_a_lost_send_returns_without_a_pause() {
    let metadata = fresh_metadata();
    let count = AtomicUsize::new(0);
    let server = serve(move |_| {
        if count.fetch_add(1, Ordering::SeqCst).is_multiple_of(2) {
            Answer::Reset(Vec::new())
        } else {
            Answer::Reply(reply("200 OK", b"{}"))
        }
    });
    let mut client = client(
        Https::plain(),
        server.host(),
        metadata.address,
        Manual::at(origin()),
        Duration::from_secs(5),
    );
    let fastest = (0..5)
        .map(|_| {
            let fault = client.send(&call()).unwrap_err();
            assert_eq!(fault.stage, Stage::Exchange);
            let start = Instant::now();
            assert_eq!(client.send(&call()).unwrap().status, 200);
            start.elapsed()
        })
        .min()
        .unwrap();
    assert!(fastest < Duration::from_millis(25), "{fastest:?}");
    thread::sleep(Duration::from_millis(50));
    assert_eq!(server.served.requests(), 10);
}

#[test]
fn a_fault_displays_its_action_stage_and_kind() {
    let fault = super::Fault {
        action: "GetItem",
        stage: Stage::Exchange,
        kind: ErrorKind::TimedOut,
        elapsed: Duration::from_millis(5),
    };
    let boxed: Box<dyn std::error::Error> = Box::new(fault);
    assert_eq!(
        boxed.to_string(),
        "GetItem failed at Exchange after 5ms: timed out"
    );
}

/// `send_until` cuts a deadline later than `Service::deadline` after the
/// call starts to that instant, and passes an earlier one unchanged.
#[test]
fn send_until_holds_a_deadline_within_the_service_deadline() {
    use crate::ec2::replay::{Replay, client, ok};
    let limit = Duration::from_secs(1);
    let replay = Replay::new([ok("a"), ok("b")]);
    let mut client = client(replay.clone(), "fake", limit);
    let start = Instant::now();
    client.send_until(&call(), start + limit * 10).unwrap();
    let end = Instant::now();
    let early = end + limit / 2;
    client.send_until(&call(), early).unwrap();
    let sent = replay.sent();
    assert!(start + limit <= sent[0].deadline && sent[0].deadline <= end + limit);
    assert_eq!(sent[1].deadline, early);
}

/// `send_from` measures `Fault::elapsed` from the start it is given, so a
/// fault reports the time since that start even when the call fails at
/// once, before credential lookup and the wire.
#[test]
fn a_fault_measures_its_elapsed_time_from_the_given_start() {
    let early = Duration::from_millis(50);
    let start = Instant::now()
        .checked_sub(early)
        .unwrap_or_else(Instant::now);
    let ahead = Instant::now() - start;
    let mut client = client(
        crate::ec2::replay::Replay::default(),
        "fake".to_owned(),
        crate::loopback::refused(),
        Manual::at(origin()),
        Duration::from_secs(1),
    );
    let call = Call {
        action: "GetItem",
        headers: &[("host", "other")],
        body: b"{}",
    };
    let fault = client
        .send_from(&call, start, start + Duration::from_secs(1))
        .unwrap_err();
    assert_eq!(
        (fault.stage, fault.kind),
        (Stage::Connect, ErrorKind::InvalidInput)
    );
    assert!(fault.elapsed >= ahead, "{:?} < {ahead:?}", fault.elapsed);
}
