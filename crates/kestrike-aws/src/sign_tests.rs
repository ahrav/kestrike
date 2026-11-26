//! These SigV4 known-answer cases use fixed signing parameters: the key
//! `AKIDEXAMPLE`, the time 2015-08-30T12:36:00Z, service `service` and
//! region `us-east-1`.

use std::time::{Duration, UNIX_EPOCH};

use super::{ADDED, Keys, Scope, canonical_request, sign, string_to_sign};

const TOKEN: &str = "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==";

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

struct Case {
    name: &'static str,
    token: Option<&'static str>,
    headers: &'static [(&'static str, &'static str)],
    body: &'static [u8],
    canonical: String,
    hash: &'static str,
    signed: &'static str,
    signature: &'static str,
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "post-vanilla",
            token: None,
            headers: &[],
            body: b"",
            canonical: format!(
                "POST\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\n{EMPTY_SHA256}"
            ),
            hash: "553f88c9e4d10fc9e109e2aeb65f030801b70c2f6468faca261d401ae622fc87",
            signed: "host;x-amz-date",
            signature: "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b",
        },
        Case {
            name: "post-header-key-sort",
            token: None,
            headers: &[("My-Header1", "value1")],
            body: b"",
            canonical: format!(
                "POST\n/\n\nhost:example.amazonaws.com\nmy-header1:value1\nx-amz-date:20150830T123600Z\n\nhost;my-header1;x-amz-date\n{EMPTY_SHA256}"
            ),
            hash: "9368318c2967cf6de74404b30c65a91e8f6253e0a8659d6d5319f1a812f87d65",
            signed: "host;my-header1;x-amz-date",
            signature: "c5410059b04c1ee005303aed430f6e6645f61f4dc9e1461ec8f8916fdf18852c",
        },
        Case {
            name: "post-header-value-case",
            token: None,
            headers: &[("My-Header1", "VALUE1")],
            body: b"",
            canonical: format!(
                "POST\n/\n\nhost:example.amazonaws.com\nmy-header1:VALUE1\nx-amz-date:20150830T123600Z\n\nhost;my-header1;x-amz-date\n{EMPTY_SHA256}"
            ),
            hash: "d51ced243e649e3de6ef63afbbdcbca03131a21a7103a1583706a64618606a93",
            signed: "host;my-header1;x-amz-date",
            signature: "cdbc9802e29d2942e5e10b5bccfdd67c5f22c7c4e8ae67b53629efa58b974b7d",
        },
        Case {
            name: "post-x-www-form-urlencoded",
            token: None,
            headers: &[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Content-Length", "13"),
                (
                    "x-amz-content-sha256",
                    "9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e",
                ),
            ],
            body: b"Param1=value1",
            canonical: "POST\n/\n\ncontent-length:13\ncontent-type:application/x-www-form-urlencoded\nhost:example.amazonaws.com\nx-amz-content-sha256:9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e\nx-amz-date:20150830T123600Z\n\ncontent-length;content-type;host;x-amz-content-sha256;x-amz-date\n9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e".to_owned(),
            hash: "b1edd1d03544c25390e32085d55b57acc9a3961bb59415ff86c45c3d89d16cfb",
            signed: "content-length;content-type;host;x-amz-content-sha256;x-amz-date",
            signature: "d3875051da38690788ef43de4db0d8f280229d82040bfac253562e56c3f20e0b",
        },
        Case {
            name: "post-sts-header-before",
            token: Some(TOKEN),
            headers: &[],
            body: b"",
            canonical: format!(
                "POST\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\nx-amz-security-token:{TOKEN}\n\nhost;x-amz-date;x-amz-security-token\n{EMPTY_SHA256}"
            ),
            hash: "c237e1b440d4c63c32ca95b5b99481081cb7b13c7e40434868e71567c1a882f6",
            signed: "host;x-amz-date;x-amz-security-token",
            signature: "85d96828115b5dc0cfc3bd16ad9e210dd772bbebba041836c64533a82be05ead",
        },
    ]
}

const SCOPE: Scope<'static> = Scope {
    region: "us-east-1",
    service: "service",
};

fn keys(token: Option<&str>) -> Keys {
    Keys {
        access_key_id: "AKIDEXAMPLE".to_owned(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_owned(),
        session_token: token.map(str::to_owned),
    }
}

#[test]
fn the_signing_suite_cases_sign_to_their_published_answers() {
    let at = UNIX_EPOCH + Duration::from_secs(1_440_938_160);
    for case in cases() {
        let headers = sign(
            &keys(case.token),
            SCOPE,
            at,
            "example.amazonaws.com",
            case.headers,
            case.body,
        );
        let (authorization, signed) = headers.split_last().unwrap();
        assert_eq!(authorization.0, "authorization", "{}", case.name);
        let canonical = canonical_request(signed, case.body);
        assert_eq!(canonical, case.canonical, "{}", case.name);
        assert_eq!(
            string_to_sign("20150830T123600Z", SCOPE, &canonical),
            format!(
                "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n{}",
                case.hash
            ),
            "{}",
            case.name
        );
        assert_eq!(
            authorization.1,
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders={}, Signature={}",
                case.signed, case.signature
            ),
            "{}",
            case.name
        );
    }
}

#[test]
fn signed_headers_lead_with_host_date_and_token() {
    let headers = sign(
        &keys(Some("t")),
        SCOPE,
        UNIX_EPOCH,
        "h",
        &[("X-Amz-Target", "T")],
        b"",
    );
    let names: Vec<_> = headers.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(
        names,
        [
            "host",
            "x-amz-date",
            "x-amz-security-token",
            "x-amz-target",
            "authorization"
        ]
    );
}

#[test]
fn debug_shows_only_the_access_key_id() {
    let text = format!("{:?}", keys(Some(TOKEN)));
    assert!(text.contains("AKIDEXAMPLE"), "{text}");
    assert!(!text.contains("EXAMPLEKEY"), "{text}");
    assert!(!text.contains("AQoDYXdz"), "{text}");
}

/// Trimming and collapsing act on ASCII whitespace only, so a nonbreaking
/// space reaches the canonical request as the wire sends it.
#[test]
fn header_values_collapse_ascii_whitespace_and_keep_other_bytes() {
    let headers = [
        ("host".to_owned(), "h".to_owned()),
        ("x-a".to_owned(), "  a   b\tc  ".to_owned()),
        ("x-b".to_owned(), "x\u{a0}y \u{a0}".to_owned()),
    ];
    assert_eq!(
        canonical_request(&headers, b""),
        format!(
            "POST\n/\n\nhost:h\nx-a:a b c\nx-b:x\u{a0}y \u{a0}\n\nhost;x-a;x-b\n{EMPTY_SHA256}"
        )
    );
}

#[test]
fn the_names_sign_adds_with_a_token_are_the_reserved_names() {
    let headers = sign(&keys(Some("t")), SCOPE, UNIX_EPOCH, "h", &[], b"");
    let mut names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();
    let mut reserved = ADDED.to_vec();
    names.sort_unstable();
    reserved.sort_unstable();
    assert_eq!(names, reserved);
}
