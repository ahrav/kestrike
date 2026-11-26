//! An EC2 Query request is a form-encoded POST body that names the action
//! and the API version, and its reply is an XML document.
//!
//! `exchange` sends one request through `Client::send_until` under the
//! caller's deadline, with no retry. It accepts only an HTTP 200 whose body
//! parses in full as one XML document rooted at `<action>Response`; every
//! other reply and every call fault give `Unlisted`, so a throttle, a timeout
//! or a not-found reaches the caller as no listing.

use std::fmt::Write as _;
use std::time::Instant;

use kestrike::failover::attachments::Unlisted;

use crate::client::{Call, Client, Fault};
use crate::clock::Clock;
use crate::ec2::xml::{self, Element};
use crate::wire::{Reply, Wire};

const VERSION: &str = "2016-11-15";

const CONTENT_TYPE: &str = "application/x-www-form-urlencoded; charset=utf-8";

/// The request body of `action`: `Action`, `Version`, then `params` in
/// order, with each name and value percent-encoded outside the RFC 3986
/// unreserved characters.
pub(crate) fn body(action: &str, params: &[(&str, &str)]) -> String {
    let mut body = String::new();
    let head = [("Action", action), ("Version", VERSION)];
    for (at, (name, value)) in head.iter().chain(params).enumerate() {
        if at > 0 {
            body.push('&');
        }
        encode(name, &mut body);
        body.push('=');
        encode(value, &mut body);
    }
    body
}

fn encode(text: &str, out: &mut String) {
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
}

/// Sends `action` with `params` as one request under `deadline`, with no
/// retry, and returns its reply of any status.
pub(crate) fn send<W: Wire, C: Clock>(
    client: &mut Client<W, C>,
    action: &'static str,
    params: &[(&str, &str)],
    deadline: Instant,
) -> Result<Reply, Fault> {
    let body = body(action, params);
    let call = Call {
        action,
        headers: &[("content-type", CONTENT_TYPE)],
        body: body.as_bytes(),
    };
    client.send_until(&call, deadline)
}

/// Sends `action` with `params` as one request and returns the root of its
/// reply's document.
pub(crate) fn exchange<W: Wire, C: Clock>(
    client: &mut Client<W, C>,
    action: &'static str,
    params: &[(&str, &str)],
    deadline: Instant,
) -> Result<Element, Unlisted> {
    let reply = send(client, action, params, deadline).map_err(|_| Unlisted)?;
    document(&reply, action).ok_or(Unlisted)
}

/// The root of `reply`'s document when `reply` is an HTTP 200 whose body
/// parses as one document rooted at `<action>Response`.
pub(crate) fn document(reply: &Reply, action: &str) -> Option<Element> {
    if reply.status != 200 {
        return None;
    }
    let document = xml::parse(&reply.body)?;
    (document.name.strip_suffix("Response") == Some(action)).then_some(document)
}

/// The continuation token of a describe reply, `None` on its last page,
/// where `nextToken` is absent or empty. `next_token` returns [`Unlisted`]
/// when `document` has multiple direct children named `nextToken` or its
/// one `nextToken` holds elements.
pub(crate) fn next_token(document: &Element) -> Result<Option<&str>, Unlisted> {
    let mut tokens = document
        .children
        .iter()
        .filter(|child| child.name == "nextToken");
    match (tokens.next(), tokens.next()) {
        (None, _) => Ok(None),
        (Some(token), None) => {
            let text = token.leaf_text().ok_or(Unlisted)?;
            Ok(Some(text).filter(|text| !text.is_empty()))
        }
        (Some(_), Some(_)) => Err(Unlisted),
    }
}

/// The code of an EC2 error reply: the text of `Response/Errors/Error/Code`
/// when `body` is that document with one error and a nonempty code.
pub fn error_code(body: &[u8]) -> Option<String> {
    error(body).map(|(code, _)| code)
}

/// The code and message of an EC2 error reply, under the rule of
/// `error_code`; the message is the text of `Response/Errors/Error/Message`,
/// empty when that element is absent or holds elements.
pub(crate) fn error(body: &[u8]) -> Option<(String, String)> {
    let document = xml::parse(body).filter(|document| document.name == "Response")?;
    let [error] = document.child("Errors")?.elements()? else {
        return None;
    };
    let code = (error.name == "Error")
        .then(|| error.text_of("Code"))
        .flatten()
        .filter(|code| !code.is_empty())?;
    let message = error.text_of("Message").unwrap_or_default();
    Some((code.to_owned(), message.to_owned()))
}

#[cfg(test)]
#[path = "query_tests.rs"]
mod tests;
