//! `Imds` requests against a loopback server: the real connect, write, read
//! and framing path inside each bound of its envelope, at the bound and one
//! byte or one wait past it.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use super::metadata::{Imds, LIMITS, Limits, Metadata};

/// How the loopback server answers one request.
#[derive(Clone)]
enum Answer {
    /// Writes these bytes, then closes the connection.
    Whole(Vec<u8>),
    /// Writes one byte of these every `interval`, then closes.
    Drip(Vec<u8>, Duration),
    /// Holds the connection open for this long without writing.
    Silent(Duration),
    Sip(Duration),
}

/// A 200 response whose body is `body`.
fn ok(body: &[u8]) -> Vec<u8> {
    let mut response =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    response.extend_from_slice(body);
    response
}

/// A server on a loopback port that answers its first connection, the token
/// request, with a token, and each later one with `answer`.
fn serve(answer: Answer) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        for (index, stream) in listener.incoming().enumerate() {
            let Ok(stream) = stream else { return };
            let answer = match index {
                0 => Answer::Whole(ok(b"token")),
                _ => answer.clone(),
            };
            thread::spawn(move || reply(stream, &answer));
        }
    });
    address
}

/// Reads one request's head from `stream` and answers it.
fn reply(mut stream: TcpStream, answer: &Answer) {
    let (chunk, pause) = match answer {
        Answer::Sip(interval) => (64 * 1024, *interval),
        _ => (1, Duration::ZERO),
    };
    let mut request = Vec::new();
    let mut bytes = vec![0; chunk];
    while !request.ends_with(b"\r\n\r\n") {
        thread::sleep(pause);
        let Ok(read @ 1..) = stream.read(&mut bytes) else {
            break;
        };
        request.extend_from_slice(&bytes[..read]);
    }
    match answer {
        Answer::Sip(_) => {
            let _ = stream.write_all(&ok(b""));
        }
        Answer::Whole(bytes) => {
            let _ = stream.write_all(bytes);
        }
        Answer::Drip(bytes, interval) => {
            for byte in bytes {
                thread::sleep(*interval);
                if stream.write_all(&[*byte]).is_err() {
                    return;
                }
            }
        }
        Answer::Silent(hold) => thread::sleep(*hold),
    }
}

/// An `Imds` session with the server at `address` inside `limits`.
fn session(address: SocketAddr, limits: Limits) -> Imds {
    Imds::open(address, limits, 60).unwrap()
}

/// `Imds::open` refuses an envelope with a zero field or a field past the
/// production envelope's before it connects, so every session keeps the
/// `Metadata` bounds and no deadline sum or buffer size overflows.
#[test]
fn an_envelope_outside_the_production_one_is_refused_before_any_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let past = Duration::from_nanos(1);
    let cases = [
        Limits {
            total: Duration::MAX,
            ..LIMITS
        },
        Limits {
            total: LIMITS.total + past,
            ..LIMITS
        },
        Limits {
            total: Duration::ZERO,
            ..LIMITS
        },
        Limits {
            io: LIMITS.io + past,
            ..LIMITS
        },
        Limits {
            io: Duration::ZERO,
            ..LIMITS
        },
        Limits {
            bytes: usize::MAX,
            ..LIMITS
        },
        Limits {
            bytes: LIMITS.bytes + 1,
            ..LIMITS
        },
        Limits { bytes: 0, ..LIMITS },
    ];
    for limits in cases {
        let refused = Imds::open(address, limits, 60).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::InvalidInput, "{limits:?}");
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn a_session_debug_shows_no_token() {
    let address = serve(Answer::Whole(ok(b"")));
    let text = format!("{:?}", session(address, LIMITS));
    assert!(text.contains("endpoint"), "{text}");
    assert!(!text.contains("token"), "{text}");
}

/// The production envelope is a 2-second wait, a 6-second request and a
/// 64 KiB response.
#[test]
fn the_metadata_envelope_is_two_second_waits_six_second_requests_and_64_kib() {
    assert_eq!(
        LIMITS,
        Limits {
            io: Duration::from_secs(2),
            total: Duration::from_secs(6),
            bytes: 65_536,
        }
    );
}

/// A small valid response returns its body, whose buffer is the one
/// response buffer of at most the byte bound.
#[test]
fn ib_metadata_envelope_small_valid_response_succeeds() {
    let imds = session(serve(Answer::Whole(ok(b"eni-0abc"))), LIMITS);
    let body = imds.get("network/interfaces/macs/").unwrap();
    assert_eq!(body, "eni-0abc");
    assert!(body.capacity() <= LIMITS.bytes, "{}", body.capacity());
}

/// A response of exactly the byte bound, head included, succeeds; one byte
/// more refuses `FileTooLarge`, having allocated no more than the one
/// bounded buffer and the request's small strings.
#[test]
fn ib_metadata_envelope_oversized_body_refuses_at_the_first_byte_past_the_bound() {
    let head = b"HTTP/1.1 200 OK\r\n\r\n";
    let fits = [&head[..], &vec![b'a'; LIMITS.bytes - head.len()]].concat();
    assert_eq!(fits.len(), LIMITS.bytes);
    let whole = session(serve(Answer::Whole(fits.clone())), LIMITS)
        .get("x")
        .unwrap();
    assert_eq!(whole.len(), LIMITS.bytes - head.len());
    let over = [&fits[..], b"b"].concat();
    let imds = session(serve(Answer::Whole(over)), LIMITS);
    let before = crate::instrument::allocated_bytes();
    let refused = imds.get("x").unwrap_err();
    let allocated = crate::instrument::allocated_bytes().wrapping_sub(before);
    assert_eq!(refused.kind(), io::ErrorKind::FileTooLarge);
    assert!(allocated < LIMITS.bytes + 4096, "{allocated}");
}

/// A head that alone passes the byte bound refuses `FileTooLarge` before
/// any body is read.
#[test]
fn ib_metadata_envelope_oversized_headers_refuse() {
    let mut head = b"HTTP/1.1 200 OK\r\n".to_vec();
    while head.len() <= LIMITS.bytes {
        head.extend_from_slice(b"X-Padding: 0123456789abcdef0123456789abcdef\r\n");
    }
    head.extend_from_slice(b"\r\nabc");
    let refused = session(serve(Answer::Whole(head)), LIMITS)
        .get("x")
        .unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::FileTooLarge);
}

/// A response that drips one byte every 50 ms, inside the per-I/O wait of
/// 400 ms, refuses `TimedOut` at the request's 600 ms deadline: the
/// deadline runs from before the connect whatever each read's progress.
#[test]
fn ib_metadata_envelope_drip_below_the_inactivity_timeout_ends_at_the_deadline() {
    let limits = Limits {
        io: Duration::from_millis(400),
        total: Duration::from_millis(600),
        bytes: LIMITS.bytes,
    };
    let drip = Answer::Drip(ok(&[b'a'; 1000]), Duration::from_millis(50));
    let imds = session(serve(drip), limits);
    let started = Instant::now();
    let refused = imds.get("x").unwrap_err();
    let elapsed = started.elapsed();
    assert_eq!(refused.kind(), io::ErrorKind::TimedOut);
    assert!(
        elapsed >= limits.total - Duration::from_millis(100)
            && elapsed < limits.total + Duration::from_millis(400),
        "{elapsed:?}"
    );
    // A drip that ends before the deadline succeeds.
    let short = Answer::Drip(ok(b"ab"), Duration::from_millis(5));
    assert_eq!(session(serve(short), limits).get("x").unwrap(), "ab");
}

/// A complete 200 response whose body holds a byte outside UTF-8 refuses
/// `InvalidData`.
#[test]
fn ib_http_framing_invalid_text_refuses() {
    let mut response = ok(b"ab");
    let last = response.len() - 1;
    response[last] = 0xff;
    let imds = session(serve(Answer::Whole(response)), LIMITS);
    assert_eq!(
        imds.get("x").unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn ib_metadata_envelope_slowly_drained_request_ends_at_the_deadline() {
    let limits = Limits {
        io: Duration::from_millis(400),
        total: Duration::from_millis(600),
        bytes: LIMITS.bytes,
    };
    let imds = session(serve(Answer::Sip(Duration::from_millis(20))), limits);
    let path = "a".repeat(16 << 20);
    let started = Instant::now();
    let refused = imds.get(&path).unwrap_err();
    let elapsed = started.elapsed();
    assert_eq!(refused.kind(), io::ErrorKind::TimedOut);
    assert!(
        elapsed >= limits.total - Duration::from_millis(100)
            && elapsed < limits.total + Duration::from_millis(400),
        "{elapsed:?}"
    );
}

/// A server that answers nothing refuses `TimedOut` after one per-I/O wait.
#[test]
fn a_silent_server_refuses_after_one_wait() {
    let limits = Limits {
        io: Duration::from_millis(200),
        total: Duration::from_secs(5),
        bytes: LIMITS.bytes,
    };
    let imds = session(serve(Answer::Silent(Duration::from_secs(3))), limits);
    let started = Instant::now();
    assert_eq!(imds.get("x").unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
}

/// Each framing case: the response bytes and the body or error kind the
/// admitted grammar gives them.
#[test]
fn ib_http_framing_admits_only_complete_supported_responses() {
    use io::ErrorKind::{InvalidData, NotFound};
    let cases: [(&str, Result<&str, io::ErrorKind>); 37] = [
        ("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", Ok("abc")),
        ("HTTP/1.0 200 OK\r\n\r\nabc", Ok("abc")),
        ("HTTP/1.1 200\r\n\r\n", Ok("")),
        ("HTTP/1.1 200 OK\r\ncontent-length:3\r\n\r\nabc", Ok("abc")),
        (
            "HTTP/1.1 200 OK\r\nCONTENT-LENGTH: \t3 \r\n\r\nabc",
            Ok("abc"),
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
            Ok("abc"),
        ),
        (
            "HTTP/1.1 200 OK\r\nX: a\r\n\r\nline\r\n\r\nmore",
            Ok("line\r\n\r\nmore"),
        ),
        ("HTTP/1.1 404 Not Found\r\n\r\n", Err(NotFound)),
        (
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
            Err(NotFound),
        ),
        ("HTTP/1.1 401 Unauthorized\r\n\r\n", Err(InvalidData)),
        ("HTTP/1.1 500 Internal\r\n\r\nx", Err(InvalidData)),
        ("garbage", Err(InvalidData)),
        ("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n", Err(InvalidData)),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nab",
            Err(InvalidData),
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcd",
            Err(InvalidData),
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc",
            Err(InvalidData),
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: +3\r\n\r\nabc",
            Err(InvalidData),
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 3a\r\n\r\nabc",
            Err(InvalidData),
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\n",
            Err(InvalidData),
        ),
        (
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
            Err(InvalidData),
        ),
        (
            "HTTP/1.1 200 OK\r\ntransfer-encoding: identity\r\n\r\nabc",
            Err(InvalidData),
        ),
        ("HTTP/1.2 200 OK\r\n\r\nabc", Err(InvalidData)),
        ("HTTP/2 200 OK\r\n\r\nabc", Err(InvalidData)),
        ("http/1.1 200 OK\r\n\r\nabc", Err(InvalidData)),
        ("HTTP/1.1  200 OK\r\n\r\nabc", Err(InvalidData)),
        ("HTTP/1.1 2000 OK\r\n\r\nabc", Err(InvalidData)),
        ("HTTP/1.1 20 OK\r\n\r\nabc", Err(InvalidData)),
        ("HTTP/1.1 200OK\r\n\r\nabc", Err(InvalidData)),
        ("HTTP/1.1 200 OK\r\nno colon\r\n\r\nabc", Err(InvalidData)),
        (
            "HTTP/1.1 200 OK\r\nBad Name: 1\r\n\r\nabc",
            Err(InvalidData),
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 3\x0c\r\n\r\nabc",
            Err(InvalidData),
        ),
        (
            "HTTP/1.1 200 OK\r\nTab\tName: 1\r\n\r\nabc",
            Err(InvalidData),
        ),
        ("HTTP/1.1 200 OK\r\n: 1\r\n\r\nabc", Err(InvalidData)),
        ("HTTP/1.1 200 O\rK\r\n\r\nabc", Err(InvalidData)),
        ("HTTP/1.1 200 OK\r\nX: 1\r\r\n\r\nabc", Err(InvalidData)),
        ("HTTP/1.1 200 OK\r\nX: 1\n\nb\r\n\r\nr", Err(InvalidData)),
        (
            "HTTP/1.1 200 OK\r\nX: a\nTransfer-Encoding: chunked\r\n\r\nr",
            Err(InvalidData),
        ),
    ];
    for (response, expected) in cases {
        let decoded = super::metadata::body(response.to_owned());
        let decoded = decoded.as_deref().map_err(io::Error::kind);
        assert_eq!(decoded, expected, "{response:?}");
    }
}

/// The admitted grammar written over bytes alone, for the generated cases:
/// the version, one space, three digits and a space or the line's end; then
/// CRLF-ended header lines up to the first blank line, each `name:value`
/// with a name free of spaces and tabs and no bare CR or LF; every
/// `Content-Length` decimal and equal to the body's length; no `Transfer-Encoding`; 200 gives the body and 404
/// `NotFound`.
fn framed(response: &[u8]) -> Result<Vec<u8>, io::ErrorKind> {
    let invalid = io::ErrorKind::InvalidData;
    let end = (0..response.len().saturating_sub(3))
        .find(|&at| &response[at..at + 4] == b"\r\n\r\n")
        .ok_or(invalid)?;
    let (head, body) = (&response[..end], &response[end + 4..]);
    // The head's lines, each ended by CRLF except the last.
    let mut lines = Vec::new();
    let mut from = 0;
    for at in 0..head.len().saturating_sub(1) {
        if &head[at..at + 2] == b"\r\n" {
            lines.push(&head[from..at]);
            from = at + 2;
        }
    }
    lines.push(&head[from..]);
    let mut lines = lines.into_iter();
    let status = lines.next().ok_or(invalid)?;
    let version_ok = status.len() >= 12
        && (status.starts_with(b"HTTP/1.0 ") || status.starts_with(b"HTTP/1.1 "))
        && status[9..12].iter().all(u8::is_ascii_digit)
        && (status.len() == 12 || status[12] == b' ');
    if !version_ok {
        return Err(invalid);
    }
    for line in lines {
        let colon = line.iter().position(|&byte| byte == b':').ok_or(invalid)?;
        let name = String::from_utf8_lossy(&line[..colon]).to_ascii_lowercase();
        let bare = line.iter().any(|&byte| byte == b'\r' || byte == b'\n');
        if bare || name.is_empty() || name.contains([' ', '\t']) || name == "transfer-encoding" {
            return Err(invalid);
        }
        if name == "content-length" {
            let value = String::from_utf8_lossy(&line[colon + 1..]);
            let value = value.trim_matches([' ', '\t']);
            if value.is_empty()
                || !value.bytes().all(|byte| byte.is_ascii_digit())
                || value.parse::<usize>() != Ok(body.len())
            {
                return Err(invalid);
            }
        }
    }
    match &status[9..12] {
        b"200" => Ok(body.to_vec()),
        b"404" => Err(io::ErrorKind::NotFound),
        _ => Err(invalid),
    }
}

/// Every combination of version, status, `Content-Length` header (absent,
/// agreeing, short, long, duplicated, conflicting), `Transfer-Encoding`
/// and body length decodes as the byte-level grammar says.
#[test]
fn ib_http_framing_agrees_with_the_byte_grammar_over_generated_responses() {
    let versions = ["HTTP/1.0", "HTTP/1.1", "HTTP/1.2"];
    let statuses = ["200 OK", "200", "404 Not Found", "403 Forbidden", "20O OK"];
    let bodies = ["", "a", "eni-0abc\r\n", "a\r\n\r\nb"];
    let mut admitted = 0;
    for version in versions {
        for status in statuses {
            for body in bodies {
                let n = body.len();
                let lengths = [
                    String::new(),
                    format!("Content-Length: {n}\r\n"),
                    format!("Content-Length: {}\r\n", n + 1),
                    format!("Content-Length: {}\r\n", n.saturating_sub(1)),
                    format!("Content-Length: {n}\r\ncontent-length: {n}\r\n"),
                    format!("Content-Length: {n}\r\nContent-Length: {}\r\n", n + 2),
                ];
                for length in &lengths {
                    for encoding in ["", "Transfer-Encoding: chunked\r\n"] {
                        let response =
                            format!("{version} {status}\r\n{length}{encoding}\r\n{body}");
                        let decoded = super::metadata::body(response.clone())
                            .map(String::into_bytes)
                            .map_err(|error| error.kind());
                        assert_eq!(decoded, framed(response.as_bytes()), "{response:?}");
                        admitted += usize::from(decoded.is_ok());
                    }
                }
            }
        }
    }
    assert!(admitted > 0);
}
