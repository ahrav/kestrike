//! The EC2 instance id, read from the instance metadata service with an
//! IMDSv2 token.
//!
//! Each of the two requests sets a deadline [`TOTAL`] ahead before it
//! resolves the address. Its connect and every write and read wait at most
//! [`WAIT`], clipped to the time left before that deadline, and the reply
//! is read up to [`BOUND`] bytes.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// The environment variable that names the metadata service address in
/// `host:port` form. Unset, the address is [`DEFAULT`], the EC2 service.
pub const METADATA: &str = "SIM_HOST_METADATA";
pub const DEFAULT: &str = "169.254.169.254:80";
const WAIT: Duration = Duration::from_secs(2);
const TOTAL: Duration = Duration::from_secs(6);
const BOUND: usize = 64 << 10;

pub fn address() -> String {
    std::env::var(METADATA).unwrap_or_else(|_| DEFAULT.to_owned())
}

pub fn instance_id() -> Result<String, String> {
    instance_id_at(&address())
}

fn instance_id_at(address: &str) -> Result<String, String> {
    let token = request(
        address,
        "PUT",
        "/latest/api/token",
        "X-aws-ec2-metadata-token-ttl-seconds: 60",
    )
    .map_err(|error| format!("instance metadata at {address}: {error}"))?;
    let header = format!("X-aws-ec2-metadata-token: {}", token.trim());
    let id = request(address, "GET", "/latest/meta-data/instance-id", &header)
        .map_err(|error| format!("instance metadata at {address}: {error}"))?;
    let id = id.trim();
    if is_instance_id(id) {
        Ok(id.to_owned())
    } else {
        Err(format!(
            "instance metadata at {address} gave {id:?}, which is no instance id"
        ))
    }
}

pub fn is_instance_id(id: &str) -> bool {
    id.strip_prefix("i-")
        .is_some_and(|hex| (8..=17).contains(&hex.len()) && crate::file::is_hex(hex, hex.len()))
}

fn request(address: &str, method: &str, path: &str, header: &str) -> io::Result<String> {
    let deadline = Instant::now() + TOTAL;
    let wait = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .map(|left| left.min(WAIT))
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
    };
    let target = address
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::other("the address resolves to nothing"))?;
    let mut stream = TcpStream::connect_timeout(&target, wait()?)?;
    let text = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\n{header}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let mut unsent = text.as_bytes();
    while !unsent.is_empty() {
        stream.set_write_timeout(Some(wait()?))?;
        match stream.write(unsent) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => unsent = &unsent[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    let mut reply = vec![0; BOUND];
    let mut len = 0;
    while len < BOUND {
        stream.set_read_timeout(Some(wait()?))?;
        match stream.read(&mut reply[len..]) {
            Ok(0) => break,
            Ok(read) => len += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    body(&reply[..len])
        .map(str::to_owned)
        .map_err(|error| io::Error::other(format!("{method} {path}: {error}")))
}

fn body(reply: &[u8]) -> Result<&str, String> {
    let reply = std::str::from_utf8(reply).map_err(|_| "the reply is no text".to_owned())?;
    let (head, body) = reply
        .split_once("\r\n\r\n")
        .ok_or_else(|| "the reply has no header end".to_owned())?;
    let status = head.split_whitespace().nth(1).unwrap_or("");
    if status != "200" {
        return Err(format!("the reply has status {status}"));
    }
    let length = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().to_owned())
    });
    match length {
        None => Ok(body),
        Some(length) if length.parse::<usize>().ok() == Some(body.len()) => Ok(body),
        Some(length) => Err(format!(
            "the reply declares {length} body bytes and holds {}",
            body.len()
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    #[test]
    fn instance_ids_have_the_ec2_form() {
        assert!(super::is_instance_id("i-0c9d77352d2d68bfd"));
        assert!(super::is_instance_id("i-0123abcd"));
        assert!(!super::is_instance_id("i-0C9D77352D2D68BFD"));
        assert!(!super::is_instance_id("0c9d77352d2d68bfd"));
        assert!(!super::is_instance_id("i-"));
        assert!(!super::is_instance_id("i-0c9d77352d2d68bfd0"));
    }

    #[test]
    fn a_body_must_have_its_declared_length() {
        let reply = |head: &str, body: &str| format!("HTTP/1.1 200 OK\r\n{head}\r\n\r\n{body}");
        let id = "i-0123abcd";
        let exact = reply(&format!("Content-Length: {}", id.len()), id);
        assert_eq!(super::body(exact.as_bytes()), Ok(id));
        assert_eq!(super::body(reply("Server: x", id).as_bytes()), Ok(id));
        for refused in [
            reply("Content-Length: 20", id),
            reply("Content-Length: 6", id),
            reply("Content-Length: 1", "\u{e9}"),
            reply("Content-Length: many", id),
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_owned(),
            format!("HTTP/1.1 200 OK\r\n{id}"),
        ] {
            assert!(super::body(refused.as_bytes()).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn a_truncated_reply_to_either_request_yields_no_id() {
        for truncated in ["token", "id"] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
            let address = listener.local_addr().expect("its address").to_string();
            std::thread::spawn(move || {
                for stream in listener.incoming().take(2) {
                    let Ok(mut stream) = stream else { return };
                    let mut request = Vec::new();
                    let mut byte = [0u8; 1];
                    while !request.ends_with(b"\r\n\r\n") {
                        match stream.read(&mut byte) {
                            Ok(1) => request.push(byte[0]),
                            _ => break,
                        }
                    }
                    let token = request.starts_with(b"PUT");
                    let body = if token { "a-token" } else { "i-0123abcd" };
                    let length = if (truncated == "token") == token {
                        body.len() + 4
                    } else {
                        body.len()
                    };
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n{body}"
                    );
                }
            });
            let result = super::instance_id_at(&address);
            assert!(result.is_err(), "a truncated {truncated} reply: {result:?}");
        }
    }

    #[test]
    fn a_reply_that_trickles_ends_at_the_request_deadline() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let address = listener.local_addr().expect("its address").to_string();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            for _ in 0..150 {
                if stream.write_all(b"H").is_err() {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        });
        let (sent, received) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sent.send(super::instance_id_at(&address));
        });
        let result = received
            .recv_timeout(std::time::Duration::from_secs(9))
            .expect("the request ends within its 6 seconds and a margin");
        assert!(result.is_err(), "a trickled reply: {result:?}");
    }
}
