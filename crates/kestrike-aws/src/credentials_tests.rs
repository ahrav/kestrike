//! `Role` tests refresh credentials from a loopback IMDSv2 double under a
//! manual clock and count the metadata and service requests.

use std::cell::Cell;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use super::{Role, is_role_name};
use crate::client::{Client, Stage};
use crate::loopback::{
    Answer, Counting, Credentials, DOCUMENT_PATH, LISTING_PATH, Manual, Server, TOKEN_PATH,
    accept_one, call, client, document, header, imds, metadata, origin, refused, reply, serve,
    silent,
};
use crate::wire::Https;

const MINUTE: Duration = Duration::from_secs(60);

/// The tests use an independent 500 ms expectation to detect changes to
/// `REFRESH_WAIT`.
const WAIT: Duration = Duration::from_millis(500);

#[test]
fn the_refresh_wait_is_500_ms() {
    assert_eq!(super::REFRESH_WAIT, WAIT);
}

#[test]
fn an_optional_refresh_waits_half_the_time_left_and_a_needed_one_all_of_it() {
    use super::refresh_wait;
    let ms = Duration::from_millis;
    assert_eq!(refresh_wait(ms(400), true), ms(200));
    assert_eq!(refresh_wait(ms(400), false), ms(400));
    assert_eq!(refresh_wait(ms(2000), true), WAIT);
    assert_eq!(refresh_wait(ms(2000), false), WAIT);
    assert_eq!(refresh_wait(Duration::ZERO, false), Duration::ZERO);
}

#[test]
fn collecting_a_helper_tells_a_timeout_from_a_helper_that_ended() {
    use super::collect;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let cutoff = Instant::now() + Duration::from_millis(20);
    assert_eq!(collect(&receiver, cutoff).unwrap_err(), ErrorKind::TimedOut);
    drop(sender);
    assert_eq!(collect(&receiver, cutoff).unwrap_err(), ErrorKind::Other);
}

#[test]
fn a_refresh_whose_cutoff_has_passed_connects_to_nothing() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let limits = kestrike::bind::Limits {
        io: WAIT,
        total: WAIT,
        bytes: kestrike::bind::LIMITS.bytes,
    };
    let read = super::read(listener.local_addr().unwrap(), limits, Instant::now());
    assert_eq!(read.unwrap_err(), ErrorKind::TimedOut);
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
}

/// The token reply arrives 250 ms into a request whose own envelope is
/// `WAIT`, so the session opens after the 100 ms cutoff, and the refresh
/// ends there with the listing unrequested.
#[test]
fn a_session_opened_after_the_cutoff_requests_no_listing() {
    let server = imds(|path| {
        if path == TOKEN_PATH {
            thread::sleep(Duration::from_millis(250));
        }
        Answer::Reply(match path {
            TOKEN_PATH => reply("200 OK", b"token"),
            LISTING_PATH => reply("200 OK", b"cache-role"),
            _ => reply(
                "200 OK",
                document("AKIDLATE", origin() + 60 * MINUTE).as_bytes(),
            ),
        })
    });
    let limits = kestrike::bind::Limits {
        io: WAIT,
        total: WAIT,
        bytes: kestrike::bind::LIMITS.bytes,
    };
    let cutoff = Instant::now() + Duration::from_millis(100);
    let read = super::read(server.address, limits, cutoff);
    assert_eq!(read.unwrap_err(), ErrorKind::TimedOut);
    thread::sleep(Duration::from_millis(100));
    let heads = server.served.heads();
    assert_eq!(heads.len(), 1, "{heads:?}");
}

#[test]
fn the_instance_role_reads_the_instance_metadata_address() {
    assert_eq!(
        Role::instance().endpoint,
        "169.254.169.254:80".parse().unwrap()
    );
}

struct Rig {
    credentials: Arc<Mutex<Credentials>>,
    metadata: Server,
    service: Server,
    silent: Arc<Mutex<bool>>,
    clock: Manual,
    sends: Rc<Cell<usize>>,
    client: Client<Counting<Https>, Manual>,
}

impl Rig {
    fn new(key: &'static str, expiry: SystemTime, deadline: Duration) -> Self {
        let credentials = Arc::new(Mutex::new(Credentials::Serve { key, expiry }));
        Self::over(
            Arc::clone(&credentials),
            metadata(credentials),
            Manual::at(origin()),
            deadline,
        )
    }

    fn over(
        credentials: Arc<Mutex<Credentials>>,
        metadata: Server,
        clock: Manual,
        deadline: Duration,
    ) -> Self {
        let silenced = Arc::new(Mutex::new(false));
        let quiet = Arc::clone(&silenced);
        let service = serve(move |_| {
            if *quiet.lock().unwrap() {
                silent(Duration::from_secs(2))
            } else {
                Answer::Reply(reply("200 OK", b"{}"))
            }
        });
        let wire = Counting::new(Https::plain());
        let sends = Rc::clone(&wire.sends);
        let client = client(
            wire,
            service.host(),
            metadata.address,
            clock.clone(),
            deadline,
        );
        Self {
            credentials,
            metadata,
            service,
            silent: silenced,
            clock,
            sends,
            client,
        }
    }

    fn serve(&self, credentials: Credentials) {
        *self.credentials.lock().unwrap() = credentials;
    }

    fn header(&self, request: usize, name: &str) -> String {
        let head = &self.service.served.heads()[request];
        header(head, name).unwrap().to_owned()
    }

    fn signer(&self, request: usize) -> String {
        let authorization = self.header(request, "authorization");
        let credential = authorization
            .split("Credential=")
            .nth(1)
            .unwrap()
            .split('/')
            .next()
            .unwrap();
        credential.to_owned()
    }
}

#[test]
fn credentials_with_more_than_the_margin_left_make_no_metadata_request() {
    let mut rig = Rig::new("AKIDFRESH", origin() + 60 * MINUTE, Duration::from_secs(1));
    rig.client.send(&call()).unwrap();
    assert_eq!(rig.metadata.served.requests(), 3);
    rig.clock.set(origin() + 49 * MINUTE);
    rig.client.send(&call()).unwrap();
    assert_eq!(rig.metadata.served.requests(), 3);
    assert_eq!(rig.service.served.requests(), 2);
}

#[test]
fn credentials_near_expiry_refresh_once_before_the_send() {
    let mut rig = Rig::new("AKIDOLD", origin() + 15 * MINUTE, Duration::from_secs(1));
    rig.client.send(&call()).unwrap();
    rig.serve(Credentials::Serve {
        key: "AKIDNEW",
        expiry: origin() + 60 * MINUTE,
    });
    rig.clock.set(origin() + 6 * MINUTE);
    rig.client.send(&call()).unwrap();
    assert_eq!(rig.metadata.served.requests(), 6);
    assert_eq!(rig.signer(1), "AKIDNEW");
    assert_eq!(rig.header(1, "x-amz-security-token"), "token-AKIDNEW");
    let sessions: Vec<Option<String>> = rig
        .metadata
        .served
        .heads()
        .iter()
        .map(|head| header(head, "x-aws-ec2-metadata-token").map(str::to_owned))
        .collect();
    let token = |name: &str| Some(name.to_owned());
    assert_eq!(
        sessions,
        [
            None,
            token("token-1"),
            token("token-1"),
            None,
            token("token-2"),
            token("token-2")
        ]
    );
}

/// The metadata service serves credentials with five minutes left, as it
/// can while it rotates them. The first call adopts them and sends, and
/// the next call refreshes again.
#[test]
fn a_first_call_adopts_credentials_with_less_than_the_margin_left() {
    let mut rig = Rig::new("AKIDLATE", origin() + 5 * MINUTE, Duration::from_secs(1));
    rig.client.send(&call()).unwrap();
    assert_eq!(rig.metadata.served.requests(), 3);
    assert_eq!(rig.signer(0), "AKIDLATE");
    rig.client.send(&call()).unwrap();
    assert_eq!(rig.metadata.served.requests(), 6);
    assert_eq!(rig.service.served.requests(), 2);
}

#[test]
fn each_call_refreshes_at_most_once() {
    let mut rig = Rig::new("AKIDSHORT", origin() + 12 * MINUTE, Duration::from_secs(1));
    rig.client.send(&call()).unwrap();
    rig.clock.set(origin() + 5 * MINUTE);
    rig.client.send(&call()).unwrap();
    assert_eq!(rig.metadata.served.requests(), 6);
    rig.client.send(&call()).unwrap();
    assert_eq!(rig.metadata.served.requests(), 9);
    assert_eq!(rig.service.served.requests(), 3);
}

#[test]
fn a_failed_refresh_keeps_unexpired_credentials_in_use() {
    let mut rig = Rig::new("AKIDOLD", origin() + 15 * MINUTE, Duration::from_secs(1));
    rig.client.send(&call()).unwrap();
    rig.serve(Credentials::Fail);
    rig.clock.set(origin() + 10 * MINUTE);
    rig.client.send(&call()).unwrap();
    assert_eq!(rig.metadata.served.requests(), 4);
    assert_eq!(rig.signer(1), "AKIDOLD");
    rig.client.send(&call()).unwrap();
    assert_eq!(rig.metadata.served.requests(), 5);
    assert_eq!(rig.signer(2), "AKIDOLD");
}

#[test]
fn a_failed_refresh_with_expired_credentials_sends_nothing() {
    let mut rig = Rig::new("AKIDOLD", origin() + 15 * MINUTE, Duration::from_secs(1));
    rig.client.send(&call()).unwrap();
    rig.serve(Credentials::Fail);
    rig.clock.set(origin() + 15 * MINUTE);
    let fault = rig.client.send(&call()).unwrap_err();
    assert_eq!(
        (fault.action, fault.stage, fault.kind),
        ("GetItem", Stage::Credentials, ErrorKind::InvalidData)
    );
    rig.clock.set(origin() + 6 * MINUTE);
    let fault = rig.client.send(&call()).unwrap_err();
    assert_eq!(fault.stage, Stage::Credentials);
    assert_eq!(rig.sends.get(), 1);
    assert_eq!(rig.service.served.connections(), 1);
}

#[test]
fn credentials_that_expire_during_a_failed_refresh_send_nothing() {
    let expiry = origin() + 15 * MINUTE;
    for (advance, sent) in [(true, false), (false, true)] {
        let credentials = Arc::new(Mutex::new(Credentials::Serve {
            key: "AKIDOLD",
            expiry,
        }));
        let clock = Manual::at(origin());
        let moved = clock.clone();
        let current = Arc::clone(&credentials);
        let server = imds(move |path| {
            let current = current.lock().unwrap().clone();
            match (current, path) {
                (Credentials::Serve { .. }, TOKEN_PATH) => Answer::Reply(reply("200 OK", b"token")),
                (Credentials::Serve { .. }, LISTING_PATH) => {
                    Answer::Reply(reply("200 OK", b"cache-role"))
                }
                (Credentials::Serve { key, expiry }, _) => {
                    Answer::Reply(reply("200 OK", document(key, expiry).as_bytes()))
                }
                _ => {
                    if advance {
                        moved.set(expiry);
                    }
                    Answer::Reply(reply("500 Internal Server Error", b""))
                }
            }
        });
        let mut rig = Rig::over(credentials, server, clock, Duration::from_secs(1));
        rig.client.send(&call()).unwrap();
        rig.serve(Credentials::Fail);
        rig.clock.set(expiry - Duration::from_secs(1));
        let outcome = rig.client.send(&call());
        assert_eq!(outcome.is_ok(), sent, "{outcome:?}");
        if !sent {
            assert_eq!(outcome.unwrap_err().stage, Stage::Credentials);
        }
        let sends = if sent { 2 } else { 1 };
        assert_eq!(rig.sends.get(), sends);
        assert_eq!(rig.service.served.requests(), sends);
    }
}

/// The first failed refresh moves the clock to the expiry, so the reading
/// after it finds the held credentials expired and drops them. The clock
/// then steps back to before the expiry, and the next call, whose refresh
/// also fails, has no credentials to fall back to.
#[test]
fn credentials_dropped_after_a_failed_refresh_stay_dropped_when_the_clock_steps_back() {
    let expiry = origin() + 15 * MINUTE;
    let credentials = Arc::new(Mutex::new(Credentials::Serve {
        key: "AKIDOLD",
        expiry,
    }));
    let clock = Manual::at(origin());
    let moved = clock.clone();
    let advance = AtomicBool::new(true);
    let current = Arc::clone(&credentials);
    let server = imds(move |path| match (current.lock().unwrap().clone(), path) {
        (Credentials::Serve { .. }, TOKEN_PATH) => Answer::Reply(reply("200 OK", b"token")),
        (Credentials::Serve { .. }, LISTING_PATH) => Answer::Reply(reply("200 OK", b"cache-role")),
        (Credentials::Serve { key, expiry }, _) => {
            Answer::Reply(reply("200 OK", document(key, expiry).as_bytes()))
        }
        _ => {
            if advance.swap(false, Ordering::SeqCst) {
                moved.set(expiry);
            }
            Answer::Reply(reply("500 Internal Server Error", b""))
        }
    });
    let mut rig = Rig::over(credentials, server, clock, Duration::from_secs(1));
    rig.client.send(&call()).unwrap();
    rig.serve(Credentials::Fail);
    rig.clock.set(expiry - Duration::from_secs(1));
    let fault = rig.client.send(&call()).unwrap_err();
    assert_eq!(fault.stage, Stage::Credentials);
    rig.clock.set(expiry - Duration::from_secs(2));
    let fault = rig.client.send(&call()).unwrap_err();
    assert_eq!(fault.stage, Stage::Credentials);
    assert_eq!(rig.sends.get(), 1);
    assert_eq!(rig.service.served.requests(), 1);
}

#[test]
fn the_signature_is_dated_by_the_reading_that_checked_the_credentials() {
    let expiry = origin() + 15 * MINUTE;
    let mut rig = Rig::new("AKIDOLD", expiry, Duration::from_secs(1));
    rig.client.send(&call()).unwrap();
    rig.serve(Credentials::Fail);
    rig.clock.set(expiry - Duration::from_secs(2));
    rig.clock.step(Duration::from_secs(1));
    rig.client.send(&call()).unwrap();
    assert_eq!(rig.header(1, "x-amz-date"), "20260101T001459Z");
}

#[test]
fn a_fetched_document_expired_by_the_reading_after_the_refresh_sends_nothing() {
    let mut rig = Rig::new(
        "AKIDBRIEF",
        origin() + Duration::from_secs(1),
        Duration::from_secs(1),
    );
    rig.clock.step(Duration::from_secs(1));
    let fault = rig.client.send(&call()).unwrap_err();
    assert_eq!(
        (fault.stage, fault.kind),
        (Stage::Credentials, ErrorKind::InvalidData)
    );
    assert_eq!(rig.sends.get(), 0);
}

#[test]
fn a_backward_step_during_a_failed_refresh_leaves_expired_credentials_refused() {
    let expiry = origin() + 15 * MINUTE;
    let credentials = Arc::new(Mutex::new(Credentials::Serve {
        key: "AKIDOLD",
        expiry,
    }));
    let clock = Manual::at(origin());
    let moved = clock.clone();
    let current = Arc::clone(&credentials);
    let server = imds(move |path| match (current.lock().unwrap().clone(), path) {
        (Credentials::Serve { .. }, TOKEN_PATH) => Answer::Reply(reply("200 OK", b"token")),
        (Credentials::Serve { .. }, LISTING_PATH) => Answer::Reply(reply("200 OK", b"cache-role")),
        (Credentials::Serve { key, expiry }, _) => {
            Answer::Reply(reply("200 OK", document(key, expiry).as_bytes()))
        }
        _ => {
            moved.set(expiry - Duration::from_secs(1));
            Answer::Reply(reply("500 Internal Server Error", b""))
        }
    });
    let mut rig = Rig::over(credentials, server, clock, Duration::from_secs(1));
    rig.client.send(&call()).unwrap();
    rig.serve(Credentials::Fail);
    rig.clock.set(expiry);
    let fault = rig.client.send(&call()).unwrap_err();
    assert_eq!(
        (fault.stage, fault.kind),
        (Stage::Credentials, ErrorKind::InvalidData)
    );
    assert_eq!(rig.sends.get(), 1);
    assert_eq!(rig.service.served.requests(), 1);
}

#[test]
fn a_first_call_whose_refresh_fails_sends_nothing() {
    let mut rig = Rig::new("AKIDNONE", origin(), Duration::from_secs(1));
    rig.serve(Credentials::Fail);
    let fault = rig.client.send(&call()).unwrap_err();
    assert_eq!(fault.stage, Stage::Credentials);
    assert_eq!(rig.sends.get(), 0);
    assert_eq!(rig.service.served.connections(), 0);
}

#[test]
fn a_silent_metadata_service_ends_the_refresh_within_its_wait() {
    let mut rig = Rig::new("AKIDNONE", origin(), Duration::from_secs(10));
    rig.serve(Credentials::Silent);
    let start = Instant::now();
    let fault = rig.client.send(&call()).unwrap_err();
    let elapsed = start.elapsed();
    assert_eq!(
        (fault.stage, fault.kind),
        (Stage::Credentials, ErrorKind::TimedOut)
    );
    assert!(elapsed >= WAIT, "{elapsed:?}");
    assert!(elapsed < WAIT + Duration::from_millis(400), "{elapsed:?}");
    assert!(fault.elapsed <= elapsed);
    assert_eq!(rig.sends.get(), 0);
}

#[test]
fn credentials_with_exactly_the_margin_left_make_no_metadata_request() {
    let mut rig = Rig::new("AKIDEDGE", origin() + 20 * MINUTE, Duration::from_secs(1));
    rig.client.send(&call()).unwrap();
    rig.clock.set(origin() + 10 * MINUTE);
    rig.client.send(&call()).unwrap();
    assert_eq!(rig.metadata.served.requests(), 3);
    rig.clock
        .set(origin() + 10 * MINUTE + Duration::from_secs(1));
    rig.client.send(&call()).unwrap();
    assert_eq!(rig.metadata.served.requests(), 6);
}

#[test]
fn a_stalled_document_request_ends_the_refresh_within_its_wait() {
    let mut rig = Rig::new("AKIDNONE", origin(), Duration::from_secs(10));
    rig.serve(Credentials::StallDocument);
    let start = Instant::now();
    let fault = rig.client.send(&call()).unwrap_err();
    let elapsed = start.elapsed();
    assert_eq!(
        (fault.stage, fault.kind),
        (Stage::Credentials, ErrorKind::TimedOut)
    );
    assert_eq!(rig.metadata.served.requests(), 3);
    assert!(elapsed >= WAIT, "{elapsed:?}");
    assert!(elapsed < WAIT + Duration::from_millis(400), "{elapsed:?}");
    assert_eq!(rig.sends.get(), 0);
}

/// `slow_refresh` makes a first call against a metadata service that
/// answers the token, listing and document requests after `delays`, in
/// that order, and returns the time the failed call took.
fn slow_refresh(deadline: Duration, delays: [Duration; 3]) -> (Rig, Duration) {
    let credentials = Arc::new(Mutex::new(Credentials::Fail));
    let server = imds(move |path| {
        let (delay, answer) = match path {
            TOKEN_PATH => (delays[0], reply("200 OK", b"token")),
            LISTING_PATH => (delays[1], reply("200 OK", b"cache-role")),
            _ => (
                delays[2],
                reply(
                    "200 OK",
                    document("AKIDSLOW", origin() + 60 * MINUTE).as_bytes(),
                ),
            ),
        };
        thread::sleep(delay);
        Answer::Reply(answer)
    });
    let mut rig = Rig::over(credentials, server, Manual::at(origin()), deadline);
    let start = Instant::now();
    let fault = rig.client.send(&call()).unwrap_err();
    let elapsed = start.elapsed();
    assert_eq!(
        (fault.stage, fault.kind),
        (Stage::Credentials, ErrorKind::TimedOut)
    );
    assert_eq!(rig.sends.get(), 0);
    (rig, elapsed)
}

/// The token reply takes 100 ms and the listing reply 450 ms, so the
/// listing arrives inside its own request's bound and 550 ms after the
/// refresh starts, past the 500 ms wait. The call ends at the wait and
/// the helper leaves the document unrequested. The token request has
/// 400 ms to spare, so a loopback connection that delivers it late still
/// lets the listing start.
#[test]
fn a_refresh_of_slow_requests_ends_at_its_wait_and_requests_no_document_after_it() {
    let ms = Duration::from_millis;
    let (rig, elapsed) = slow_refresh(Duration::from_secs(10), [ms(100), ms(450), ms(0)]);
    assert!(elapsed >= WAIT, "{elapsed:?}");
    assert!(elapsed < WAIT + Duration::from_millis(250), "{elapsed:?}");
    thread::sleep(Duration::from_millis(800));
    let heads = rig.metadata.served.heads();
    assert_eq!(heads.len(), 2, "{heads:?}");
    assert!(
        heads.iter().all(|head| !head.contains(DOCUMENT_PATH)),
        "{heads:?}"
    );
    assert_eq!(rig.service.served.connections(), 0);
}

/// Each metadata request takes 400 ms, so the listing request starts
/// before the 500 ms wait ends and is still in flight when it does. The
/// call ends at the wait and leaves the helper to finish alone.
#[test]
fn a_refresh_request_in_flight_at_the_end_of_the_wait_does_not_hold_the_call() {
    let (rig, elapsed) = slow_refresh(Duration::from_secs(10), [Duration::from_millis(400); 3]);
    assert!(elapsed >= WAIT, "{elapsed:?}");
    assert!(elapsed < WAIT + Duration::from_millis(250), "{elapsed:?}");
    assert_eq!(rig.service.served.connections(), 0);
}

#[test]
fn a_refresh_of_slow_requests_ends_by_a_call_deadline_shorter_than_its_wait() {
    let deadline = Duration::from_millis(300);
    let (_, elapsed) = slow_refresh(deadline, [Duration::from_millis(120); 3]);
    assert!(elapsed >= deadline, "{elapsed:?}");
    assert!(
        elapsed < deadline + Duration::from_millis(180),
        "{elapsed:?}"
    );
}

#[test]
fn a_refresh_ends_by_a_call_deadline_shorter_than_its_wait() {
    let deadline = Duration::from_millis(150);
    let mut rig = Rig::new("AKIDNONE", origin(), deadline);
    rig.serve(Credentials::Silent);
    let start = Instant::now();
    let fault = rig.client.send(&call()).unwrap_err();
    assert_eq!(fault.stage, Stage::Credentials);
    assert!(
        start.elapsed() < deadline + Duration::from_millis(300),
        "{:?}",
        start.elapsed()
    );
}

#[test]
fn an_optional_refresh_leaves_the_send_half_the_deadline() {
    let deadline = Duration::from_millis(400);
    let mut rig = Rig::new("AKIDOLD", origin() + 15 * MINUTE, deadline);
    rig.client.send(&call()).unwrap();
    rig.serve(Credentials::Silent);
    rig.clock.set(origin() + 6 * MINUTE);
    rig.client.send(&call()).unwrap();
    assert_eq!(rig.metadata.served.await_requests(4), 4);
    assert_eq!(rig.service.served.requests(), 2);
    assert_eq!(rig.signer(1), "AKIDOLD");
}

#[test]
fn a_stalled_refresh_and_a_silent_service_share_one_deadline() {
    let deadline = Duration::from_millis(600);
    let mut rig = Rig::new("AKIDOLD", origin() + 15 * MINUTE, deadline);
    rig.client.send(&call()).unwrap();
    rig.serve(Credentials::Silent);
    *rig.silent.lock().unwrap() = true;
    rig.clock.set(origin() + 6 * MINUTE);
    let start = Instant::now();
    let fault = rig.client.send(&call()).unwrap_err();
    let elapsed = start.elapsed();
    assert_eq!(
        (fault.stage, fault.kind),
        (Stage::Exchange, ErrorKind::TimedOut)
    );
    assert!(elapsed >= deadline, "{elapsed:?}");
    assert!(
        elapsed < deadline + Duration::from_millis(250),
        "{elapsed:?}"
    );
    assert!(fault.elapsed >= deadline, "{:?}", fault.elapsed);
    assert!(fault.elapsed <= elapsed, "{:?}", fault.elapsed);
    assert_eq!(rig.sends.get(), 2);
    assert_eq!(rig.service.served.await_requests(2), 2);
    assert_eq!(rig.signer(1), "AKIDOLD");
}

/// The held credentials have expired, so the call needs its refresh and
/// gives it the whole wait: with a 600 ms deadline and a silent metadata
/// service the refresh ends at `REFRESH_WAIT`, where an optional refresh
/// would end at 300 ms.
#[test]
fn a_refresh_that_replaces_expired_credentials_waits_the_whole_wait() {
    let deadline = Duration::from_millis(600);
    let expiry = origin() + 15 * MINUTE;
    let mut rig = Rig::new("AKIDOLD", expiry, deadline);
    rig.client.send(&call()).unwrap();
    rig.serve(Credentials::Silent);
    rig.clock.set(expiry);
    let start = Instant::now();
    let fault = rig.client.send(&call()).unwrap_err();
    let elapsed = start.elapsed();
    assert_eq!(
        (fault.stage, fault.kind),
        (Stage::Credentials, ErrorKind::TimedOut)
    );
    assert!(elapsed >= WAIT, "{elapsed:?}");
    assert!(
        elapsed < deadline + Duration::from_millis(250),
        "{elapsed:?}"
    );
    assert_eq!(rig.sends.get(), 1);
}

/// The call's 150 ms deadline is shorter than `REFRESH_WAIT`, and the
/// metadata service never completes its answer to the token request: it
/// stays silent, or it sends one byte of an unfinished reply every 20 ms,
/// which keeps each read short and leaves the whole request to its own
/// bound. The request runs under the wait clipped to the deadline, so the
/// helper closes its connection near the deadline and before
/// `REFRESH_WAIT`.
#[test]
fn a_refresh_request_ends_by_the_wait_clipped_to_the_call_deadline() {
    for drip in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let closed = thread::spawn(move || {
            let mut stream = accept_one(&listener)?;
            if drip {
                let until = Instant::now() + Duration::from_secs(5);
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nx-pad: ");
                while Instant::now() < until && stream.write_all(b"a").is_ok() {
                    thread::sleep(Duration::from_millis(20));
                }
            } else {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let _ = stream.read_to_end(&mut Vec::new());
            }
            Some(Instant::now())
        });
        let service = serve(|_| Answer::Reply(reply("200 OK", b"{}")));
        let deadline = Duration::from_millis(150);
        let mut client = client(
            Https::plain(),
            service.host(),
            address,
            Manual::at(origin()),
            deadline,
        );
        let start = Instant::now();
        let fault = client.send(&call()).unwrap_err();
        assert_eq!(
            (fault.stage, fault.kind),
            (Stage::Credentials, ErrorKind::TimedOut),
            "drip {drip}"
        );
        let closed = closed
            .join()
            .unwrap()
            .expect("the refresh connects to the metadata service");
        let open = closed.duration_since(start);
        assert!(
            open < deadline + Duration::from_millis(200),
            "drip {drip}: {open:?}"
        );
        assert!(deadline + Duration::from_millis(200) < WAIT);
        assert_eq!(service.served.connections(), 0);
    }
}

#[test]
fn an_unusable_listing_or_document_fails_the_refresh() {
    let expiry = origin() + 60 * MINUTE;
    let good = document("AKIDGOOD", expiry);
    let cases = [
        ("cache-role", good.replace("\"Success\"", "\"Failure\"")),
        ("cache-role", good.replace("\"Token\"", "\"Tokens\"")),
        (
            "cache-role",
            good.replace("\"AccessKeyId\":\"AKIDGOOD\"", "\"AccessKeyId\":\"\""),
        ),
        ("cache-role", good.replace("Z\"}", "\"}")),
        ("cache-role", document("AKIDGOOD", origin())),
        ("cache-role", "not json".to_owned()),
        (
            "cache-role",
            good.replace("\"token-AKIDGOOD\"", "\"token\\r\\nX-Injected: 1\""),
        ),
        ("cache-role\nother-role", good.clone()),
        ("cache-role\r\nother-role\r\n", good.clone()),
        ("../cache-role", good.clone()),
        ("cache role", good.clone()),
        ("..", good.clone()),
        (".", good.clone()),
        ("", good),
    ];
    for (role, body) in cases {
        let case = format!("{role:?} with {body}");
        let listing = role.to_owned();
        let metadata = imds(move |path| {
            Answer::Reply(match path {
                TOKEN_PATH => reply("200 OK", b"token"),
                LISTING_PATH => reply("200 OK", listing.as_bytes()),
                _ => reply("200 OK", body.as_bytes()),
            })
        });
        let service = serve(|_| Answer::Reply(reply("200 OK", b"{}")));
        let mut client = client(
            Https::plain(),
            service.host(),
            metadata.address,
            Manual::at(origin()),
            Duration::from_secs(1),
        );
        let outcome = client.send(&call());
        let Err(fault) = outcome else {
            panic!("{case}: {outcome:?}");
        };
        assert_eq!(
            (fault.stage, fault.kind),
            (Stage::Credentials, ErrorKind::InvalidData),
            "{case}"
        );
        assert_eq!(service.served.connections(), 0, "{role:?}");
        let requests = if role == "cache-role" { 3 } else { 2 };
        assert_eq!(metadata.served.requests(), requests, "{role:?}");
        let last = metadata.served.heads().pop().unwrap();
        let path = if requests == 3 {
            DOCUMENT_PATH
        } else {
            LISTING_PATH
        };
        assert!(
            last.starts_with(&format!("GET {path} ")),
            "{role:?}: {last}"
        );
    }
}

#[test]
fn a_listing_of_one_role_with_a_line_ending_is_read() {
    for listing in ["cache-role\n", "cache-role\r\n"] {
        let metadata = imds(move |path| {
            Answer::Reply(match path {
                TOKEN_PATH => reply("200 OK", b"token"),
                LISTING_PATH => reply("200 OK", listing.as_bytes()),
                DOCUMENT_PATH => reply(
                    "200 OK",
                    document("AKIDLINE", origin() + 60 * MINUTE).as_bytes(),
                ),
                _ => reply("404 Not Found", b""),
            })
        });
        let service = serve(|_| Answer::Reply(reply("200 OK", b"{}")));
        let mut client = client(
            Https::plain(),
            service.host(),
            metadata.address,
            Manual::at(origin()),
            Duration::from_secs(1),
        );
        client.send(&call()).unwrap();
        assert_eq!(service.served.requests(), 1, "{listing:?}");
    }
}

/// A document with an 8 KiB session token, twice the 4,096 bytes a
/// session token usually stays under, fits the refresh's response bound,
/// and the call sends the whole token.
#[test]
fn a_credential_document_with_a_long_session_token_is_read() {
    let token = "t".repeat(8 * 1024);
    let body =
        document("AKIDLONG", origin() + 60 * MINUTE).replace("token-AKIDLONG", token.as_str());
    let metadata = imds(move |path| {
        Answer::Reply(match path {
            TOKEN_PATH => reply("200 OK", b"token"),
            LISTING_PATH => reply("200 OK", b"cache-role"),
            _ => reply("200 OK", body.as_bytes()),
        })
    });
    let service = serve(|_| Answer::Reply(reply("200 OK", b"{}")));
    let mut client = client(
        Https::plain(),
        service.host(),
        metadata.address,
        Manual::at(origin()),
        Duration::from_secs(1),
    );
    client.send(&call()).unwrap();
    let heads = service.served.heads();
    assert_eq!(heads.len(), 1);
    assert_eq!(header(&heads[0], "x-amz-security-token"), Some(&*token));
}

#[test]
fn a_role_name_is_iams_alphabet_up_to_64_bytes() {
    assert!(is_role_name("Cache-Role_0+=,.@"));
    assert!(is_role_name(&"a".repeat(64)));
    assert!(!is_role_name(&"a".repeat(65)));
    for refused in ["", ".", "..", "a/b", "a b", "a:b", "é"] {
        assert!(!is_role_name(refused), "{refused:?}");
    }
}

const CHILD: &str = "KESTRIKE_AWS_ENVIRONMENT_CHILD";

const ENVIRONMENT: [(&str, &str); 3] = [
    ("AWS_ACCESS_KEY_ID", "AKIDENVIRONMENT"),
    ("AWS_SECRET_ACCESS_KEY", "environment-secret"),
    ("AWS_SESSION_TOKEN", "environment-token"),
];

#[test]
fn the_environment_is_no_credential_source() {
    if std::env::var_os(CHILD).is_some() {
        for (name, value) in ENVIRONMENT {
            assert!(std::env::var(name).is_ok_and(|set| set == value), "{name}");
        }
        let service = serve(|_| Answer::Reply(reply("200 OK", b"{}")));
        let wire = Counting::new(Https::plain());
        let sends = Rc::clone(&wire.sends);
        let mut client = client(
            wire,
            service.host(),
            refused(),
            Manual::at(origin()),
            Duration::from_secs(1),
        );
        let fault = client.send(&call()).unwrap_err();
        assert_eq!(fault.stage, Stage::Credentials);
        assert_eq!(sends.get(), 0);
        assert_eq!(service.served.connections(), 0);
        return;
    }
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "credentials::tests::the_environment_is_no_credential_source",
            "--test-threads=1",
        ])
        .env(CHILD, "1");
    for (name, value) in ENVIRONMENT {
        command.env(name, value);
    }
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("1 passed"), "{stdout}");
}
