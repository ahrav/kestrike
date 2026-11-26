//! SigV4 (AWS Signature Version 4) for a POST to `/` with an empty query
//! string, signing the body's SHA-256 and the headers listed in
//! `SignedHeaders`.

use std::fmt;
use std::time::SystemTime;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use crate::clock;

/// The header names `sign` adds to a request.
pub(crate) const HOST: &str = "host";
pub(crate) const DATE: &str = "x-amz-date";
pub(crate) const TOKEN: &str = "x-amz-security-token";
pub(crate) const AUTHORIZATION: &str = "authorization";

/// Every name `sign` can add. `Client::send` keeps a caller's header names
/// distinct from these, the token's name included when the keys hold no
/// token.
pub(crate) const ADDED: [&str; 4] = [AUTHORIZATION, HOST, DATE, TOKEN];

pub(crate) struct Keys {
    pub(crate) access_key_id: String,
    pub(crate) secret_access_key: String,
    pub(crate) session_token: Option<String>,
}

/// `Debug` displays only `access_key_id`.
impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keys")
            .field("access_key_id", &self.access_key_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Scope<'a> {
    pub(crate) region: &'a str,
    pub(crate) service: &'a str,
}

/// `sign` returns the headers of a POST to `/` on `host` with `body`, signed
/// with `keys` at `at`: `host`, `x-amz-date`, `x-amz-security-token` when
/// `keys` holds a token, each of `headers`, and `authorization`, which
/// signs all the others. Header names are lowercase. The names in
/// `headers` must remain distinct after ASCII lowercasing, including from
/// the names in `ADDED` that `sign` emits.
pub(crate) fn sign(
    keys: &Keys,
    scope: Scope<'_>,
    at: SystemTime,
    host: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Vec<(String, String)> {
    let date = clock::basic(at);
    let mut signed = vec![
        (HOST.to_owned(), host.to_owned()),
        (DATE.to_owned(), date.clone()),
    ];
    if let Some(token) = &keys.session_token {
        signed.push((TOKEN.to_owned(), token.clone()));
    }
    signed.extend(
        headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), (*value).to_owned())),
    );
    let canonical = canonical_request(&signed, body);
    let names = signed_names(&signed);
    let text = string_to_sign(&date, scope, &canonical);
    let signature = signature(&keys.secret_access_key, &date, scope, &text);
    signed.push((
        AUTHORIZATION.to_owned(),
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={names}, Signature={signature}",
            keys.access_key_id,
            credential_scope(&date, scope)
        ),
    ));
    signed
}

/// `canonical_request` builds the canonical request of a POST to `/` with
/// an empty query string from `headers`, whose names are lowercase and
/// distinct. Each value is trimmed and each run of ASCII whitespace inside
/// it becomes one space; every other byte, a non-ASCII space included,
/// stays as the wire sends it.
pub(crate) fn canonical_request(headers: &[(String, String)], body: &[u8]) -> String {
    let mut sorted: Vec<_> = headers.iter().collect();
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
    let mut text = String::from("POST\n/\n\n");
    for (name, value) in &sorted {
        text.push_str(name);
        text.push(':');
        for (index, word) in value.split_ascii_whitespace().enumerate() {
            if index > 0 {
                text.push(' ');
            }
            text.push_str(word);
        }
        text.push('\n');
    }
    text.push('\n');
    text.push_str(&signed_names(headers));
    text.push('\n');
    text.push_str(&hex(&Sha256::digest(body)));
    text
}

fn signed_names(headers: &[(String, String)]) -> String {
    let mut names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();
    names.sort_unstable();
    names.join(";")
}

fn credential_scope(date: &str, scope: Scope<'_>) -> String {
    format!(
        "{}/{}/{}/aws4_request",
        &date[..8],
        scope.region,
        scope.service
    )
}

pub(crate) fn string_to_sign(date: &str, scope: Scope<'_>, canonical: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256\n{date}\n{}\n{}",
        credential_scope(date, scope),
        hex(&Sha256::digest(canonical.as_bytes()))
    )
}

/// `signature` derives the signing key from `secret` through the date,
/// region, service and `aws4_request` chain and returns the hex HMAC of
/// `text` under it.
pub(crate) fn signature(secret: &str, date: &str, scope: Scope<'_>, text: &str) -> String {
    let date_key = hmac(format!("AWS4{secret}").as_bytes(), &date.as_bytes()[..8]);
    let key = [scope.region, scope.service, "aws4_request"]
        .iter()
        .fold(date_key, |key, part| hmac(&key, part.as_bytes()));
    hex(&hmac(&key, text.as_bytes()))
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

#[cfg(test)]
#[path = "sign_tests.rs"]
mod tests;
