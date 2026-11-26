//! The bucket, reached through the `aws` CLI as a [`crate::capture`]
//! child. Every write carries a SHA-256 checksum, and a call ends by its
//! deadline or by the bucket's [`Halt`]. A failed call is classified only
//! from the service error the CLI reports with exit code 254, so a key or a
//! URL in a transport error never reads as a missing or present object.

use std::io::Read as _;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::capture::{self, Halt};

/// The largest body one `put-object` call stores: 5 GB, the service's
/// limit for a single put.
pub const PUT_BOUND: u64 = 5_000_000_000;
/// The wait of a call on a small object or a header.
pub const SHORT: Duration = Duration::from_secs(120);
/// The wait of a call that moves an archive or a binary.
pub const LONG: Duration = Duration::from_secs(1800);
const OUTPUT: u64 = 16 << 20;
/// `PAGE` bounds the object count per listing call independently of the
/// total number of objects under its prefix.
const PAGE: &str = "1000";
const SERVICE_ERROR: i32 = 254;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// The service answered that the key holds no object. A role without
    /// `s3:ListBucket` gets `AccessDenied` instead, a [`Error::Failed`].
    Missing,
    /// A create-once write found an object at the key, or a download
    /// conditioned on an ETag found another object there.
    Present,
    /// A listing held more objects than its caller's bound.
    Bound(String),
    Failed(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => formatter.write_str("the object is missing"),
            Self::Present => formatter.write_str("the object is already present"),
            Self::Bound(reason) | Self::Failed(reason) => formatter.write_str(reason),
        }
    }
}

/// An object's length and, when it was stored with one, its SHA-256 in
/// hexadecimal.
#[derive(Clone, Debug, PartialEq)]
pub struct Head {
    pub length: u64,
    pub etag: String,
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Bounded {
    /// The object's bytes, at most the bound.
    Read(Vec<u8>),
    /// The service answered that the key holds no object.
    Gone,
    /// The object holds more than the bound.
    Past,
}

#[derive(Clone, Debug)]
pub struct Bucket {
    pub name: String,
    pub halt: Halt,
    /// The `aws` calls this bucket and its copies have made.
    calls: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

/// The code inside the CLI's `An error occurred (CODE)` line.
fn service_code(stderr: &str) -> Option<&str> {
    stderr.lines().find_map(|line| {
        let line = line.trim();
        let line = line
            .strip_prefix("aws: [ERROR]:")
            .map_or(line, str::trim_start);
        let rest = line.strip_prefix("An error occurred (")?;
        rest.split_once(')').map(|(code, _)| code)
    })
}

impl Bucket {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            halt: Halt::OnStop,
            calls: std::sync::Arc::default(),
        }
    }

    /// This bucket with its calls halted by `halt` instead. The copy
    /// counts its calls with this bucket's.
    pub fn halted_by(&self, halt: Halt) -> Self {
        Self {
            name: self.name.clone(),
            halt,
            calls: std::sync::Arc::clone(&self.calls),
        }
    }

    /// The `aws` calls this bucket and its copies have started.
    pub fn calls(&self) -> u64 {
        self.calls.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn aws(&self, args: &[&str], wait: Duration) -> Result<Vec<u8>, Error> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut command = Command::new("aws");
        command
            .args(["--cli-connect-timeout", "10", "--cli-read-timeout", "60"])
            .args(["--output", "json", "s3api", args[0], "--bucket", &self.name])
            .args(&args[1..]);
        let name = format!("aws s3api {}", args[0]);
        let output =
            capture::run(&name, &mut command, wait, OUTPUT, self.halt).map_err(Error::Failed)?;
        if output.success() {
            return Ok(output.stdout);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let code = (output.code == SERVICE_ERROR)
            .then(|| service_code(&stderr))
            .flatten();
        match code {
            Some("PreconditionFailed") => Err(Error::Present),
            Some("NoSuchKey" | "404") => Err(Error::Missing),
            _ => Err(Error::Failed(format!(
                "{name} exited {}: {}",
                output.code,
                output.reason()
            ))),
        }
    }

    /// Downloads the whole object at `key` to `destination`, checked
    /// against its stored checksum.
    pub fn get(
        &self,
        key: &str,
        head: &Head,
        destination: &Path,
        wait: Duration,
    ) -> Result<(), Error> {
        let shown = destination.to_string_lossy();
        let got = self.aws(
            &[
                "get-object",
                "--key",
                key,
                "--if-match",
                &head.etag,
                "--checksum-mode",
                "ENABLED",
                &shown,
            ],
            wait,
        );
        let checked = match got {
            Ok(_) => match std::fs::symlink_metadata(destination) {
                Ok(meta) if meta.len() == head.length => Ok(()),
                Ok(meta) => Err(Error::Failed(format!(
                    "{key} downloaded {} bytes and its header named {}",
                    meta.len(),
                    head.length
                ))),
                Err(error) => Err(Error::Failed(format!("{key}: {error}"))),
            },
            Err(Error::Present) => Err(Error::Failed(format!(
                "{key} changed after its header was read"
            ))),
            Err(error) => Err(error),
        };
        if checked.is_err() {
            let _ = std::fs::remove_file(destination);
        }
        checked
    }

    /// The bytes of the object at `key`, refused past `bound` bytes. The
    /// download asks for at most `bound + 1` bytes, so a longer object
    /// takes no more disk than that; the scratch file's removal is tried on
    /// every path, and a failed removal is ignored. An empty object fails
    /// with [`Error::Failed`], since the service refuses a range of it; only
    /// an absent object is [`Error::Missing`].
    pub fn read(
        &self,
        key: &str,
        scratch: &Path,
        bound: u64,
        wait: Duration,
    ) -> Result<Vec<u8>, Error> {
        let path = scratch.join(key.replace('/', "_"));
        match self.read_bounded(key, &path, bound, wait)? {
            Bounded::Read(bytes) => Ok(bytes),
            Bounded::Gone => Err(Error::Missing),
            Bounded::Past => Err(Error::Failed(format!("holds more than {bound} bytes"))),
        }
    }

    /// Downloads the first `bound + 1` bytes of `key`, or all of a shorter
    /// object, to `destination`, so a reader that finds more than `bound`
    /// bytes there knows the object passes `bound`. The object must hold at
    /// least one byte: S3 refuses a range of an empty object.
    pub fn get_prefix(
        &self,
        key: &str,
        destination: &Path,
        bound: u64,
        wait: Duration,
    ) -> Result<(), Error> {
        self.get_prefix_of(key, None, destination, bound, wait)
    }

    /// [`Bucket::get_prefix`] of the object whose ETag is `etag`, when one
    /// is given; [`Error::Present`] when the key holds another object.
    pub fn get_prefix_of(
        &self,
        key: &str,
        etag: Option<&str>,
        destination: &Path,
        bound: u64,
        wait: Duration,
    ) -> Result<(), Error> {
        let destination = destination.to_string_lossy();
        let range = format!("bytes=0-{bound}");
        let mut args = vec!["get-object", "--key", key, "--range", &range];
        if let Some(etag) = etag {
            args.extend(["--if-match", etag]);
        }
        args.push(&destination);
        self.aws(&args, wait).map(drop)
    }

    pub fn read_bounded(
        &self,
        key: &str,
        destination: &Path,
        bound: u64,
        wait: Duration,
    ) -> Result<Bounded, Error> {
        self.read_bounded_of(key, None, destination, bound, wait)
    }

    /// [`Bucket::read_bounded`] of the object whose ETag is `etag`, when
    /// one is given; [`Error::Present`] when the key holds another object.
    pub fn read_bounded_of(
        &self,
        key: &str,
        etag: Option<&str>,
        destination: &Path,
        bound: u64,
        wait: Duration,
    ) -> Result<Bounded, Error> {
        let past = bound.saturating_add(1);
        let read = self
            .get_prefix_of(key, etag, destination, bound, wait)
            .map(|()| {
                crate::file::open_regular(destination)?
                    .map(|file| {
                        let mut bytes = Vec::new();
                        file.take(past).read_to_end(&mut bytes).map(|_| bytes)
                    })
                    .transpose()
            });
        let _ = std::fs::remove_file(destination);
        match read {
            Ok(Ok(Some(bytes))) if bytes.len() as u64 > bound => Ok(Bounded::Past),
            Ok(Ok(Some(bytes))) => Ok(Bounded::Read(bytes)),
            Ok(Ok(None)) => Err(Error::Failed("the download left no file".into())),
            Ok(Err(error)) => Err(Error::Failed(format!("{}: {error}", destination.display()))),
            Err(Error::Missing) => Ok(Bounded::Gone),
            Err(error) => Err(error),
        }
    }

    pub fn head(&self, key: &str) -> Result<Head, Error> {
        let out = self.aws(
            &["head-object", "--key", key, "--checksum-mode", "ENABLED"],
            SHORT,
        )?;
        let head: serde_json::Value = serde_json::from_slice(&out)
            .map_err(|error| Error::Failed(format!("head-object of {key}: {error}")))?;
        let length = head["ContentLength"]
            .as_u64()
            .ok_or_else(|| Error::Failed(format!("head-object of {key} gave no length")))?;
        let etag = head["ETag"]
            .as_str()
            .ok_or_else(|| Error::Failed(format!("head-object of {key} gave no ETag")))?
            .to_owned();
        let sha256 = head["ChecksumSHA256"]
            .as_str()
            .and_then(base64)
            .filter(|digest| digest.len() == 32)
            .map(|digest| crate::file::hex(&digest));
        Ok(Head {
            length,
            etag,
            sha256,
        })
    }

    /// The stored SHA-256 of the object at `key`, in hexadecimal.
    pub fn sha256(&self, key: &str) -> Result<String, Error> {
        self.head(key)?
            .sha256
            .ok_or_else(|| Error::Failed(format!("{key} carries no SHA-256 checksum")))
    }

    /// Writes `body` at `key` only when no object is there;
    /// [`Error::Present`] otherwise.
    pub fn put_once(&self, key: &str, body: &Path, wait: Duration) -> Result<(), Error> {
        let body = body.to_string_lossy();
        self.aws(
            &[
                "put-object",
                "--key",
                key,
                "--body",
                &body,
                "--checksum-algorithm",
                "SHA256",
                "--if-none-match",
                "*",
            ],
            wait,
        )
        .map(drop)
    }

    pub fn replace(&self, key: &str, body: &Path, wait: Duration) -> Result<(), Error> {
        let body = body.to_string_lossy();
        self.aws(
            &[
                "put-object",
                "--key",
                key,
                "--body",
                &body,
                "--checksum-algorithm",
                "SHA256",
            ],
            wait,
        )
        .map(drop)
    }

    /// The caller receives the complete listing or an error. `list`
    /// returns an error when a page is not a JSON object, fails
    /// validation, carries a `NextToken` that is neither null nor a
    /// string, or repeats a token from an earlier page, and when the
    /// listing holds more than `limit` objects.
    pub fn list(&self, prefix: &str, limit: usize) -> Result<Vec<Listed>, Error> {
        let refused = |what: &str| Error::Failed(format!("list-objects-v2 of {prefix}: {what}"));
        let mut objects = Vec::new();
        let mut token: Option<String> = None;
        let mut seen = std::collections::BTreeSet::new();
        loop {
            let out = {
                let mut args = vec!["list-objects-v2", "--prefix", prefix, "--max-items", PAGE];
                if let Some(token) = &token {
                    args.extend(["--starting-token", token.as_str()]);
                }
                self.aws(&args, LONG)?
            };
            if out.iter().all(u8::is_ascii_whitespace) {
                break;
            }
            let page: serde_json::Value =
                serde_json::from_slice(&out).map_err(|error| refused(&error.to_string()))?;
            if !page.is_object() {
                return Err(refused("a page is not an object"));
            }
            match page.get("Contents") {
                None | Some(serde_json::Value::Null) => {}
                Some(serde_json::Value::Array(contents)) => {
                    for object in contents {
                        let (Some(key), Some(size)) =
                            (object["Key"].as_str(), object["Size"].as_u64())
                        else {
                            return Err(refused("an entry without a Key and a Size"));
                        };
                        if objects.len() == limit {
                            return Err(Error::Bound(format!(
                                "list-objects-v2 of {prefix}: more than {limit} objects"
                            )));
                        }
                        objects.push(Listed {
                            key: key.to_owned(),
                            size,
                            etag: object["ETag"].as_str().map(str::to_owned),
                        });
                    }
                }
                Some(_) => return Err(refused("Contents is not an array")),
            }
            match page.get("NextToken") {
                None | Some(serde_json::Value::Null) => break,
                Some(serde_json::Value::String(next)) => {
                    if !seen.insert(next.clone()) {
                        return Err(refused("NextToken repeats an earlier page's"));
                    }
                    token = Some(next.clone());
                }
                Some(_) => return Err(refused("NextToken is not a string")),
            }
        }
        Ok(objects)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Listed {
    pub key: String,
    /// The object's length in bytes.
    pub size: u64,
    /// The ETag the listing gave the object, quotes included.
    pub etag: Option<String>,
}

/// Decodes standard padded base64, the form S3 gives checksums in.
pub fn base64(text: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    let text = text.trim_end_matches('=');
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_decodes_known_answers_with_every_symbol() {
        assert_eq!(super::base64("TWFu"), Some(b"Man".to_vec()));
        assert_eq!(super::base64("TWE="), Some(b"Ma".to_vec()));
        assert_eq!(super::base64("TQ=="), Some(b"M".to_vec()));
        assert_eq!(super::base64("+/+/"), Some(vec![0xfb, 0xff, 0xbf]));
        assert_eq!(super::base64("AAEC"), Some(vec![0, 1, 2]));
        assert_eq!(
            super::base64("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="),
            Some(
                super::super::file::sha256(b"")
                    .as_bytes()
                    .chunks(2)
                    .map(
                        |pair| u8::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16)
                            .expect("hex")
                    )
                    .collect()
            )
        );
        assert_eq!(super::base64("T!=="), None);
    }

    #[test]
    fn only_a_service_error_line_names_a_code() {
        let line = "\nAn error occurred (NoSuchKey) when calling the GetObject operation: x";
        assert_eq!(super::service_code(line), Some("NoSuchKey"));
        let url = "Could not connect to the endpoint URL: \"https://b.s3/NoSuchKey (404)\"";
        assert_eq!(super::service_code(url), None);
    }
}
