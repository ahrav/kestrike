use super::{body, document, error_code, next_token};
use crate::ec2::xml::parse;
use crate::wire::Reply;

#[test]
fn parameter_values_are_percent_encoded_outside_the_unreserved_set() {
    assert_eq!(
        body("DescribeVolumes", &[("NextToken", "a+b/c=d e~f_g.h-i&j")]),
        "Action=DescribeVolumes&Version=2016-11-15&NextToken=a%2Bb%2Fc%3Dd%20e~f_g.h-i%26j"
    );
    assert_eq!(
        body("DescribeVolumes", &[("Filter.1.Value.1", "é")]),
        "Action=DescribeVolumes&Version=2016-11-15&Filter.1.Value.1=%C3%A9"
    );
    assert_eq!(
        body("DescribeVolumes", &[("NextToken", "100%25%2B")]),
        "Action=DescribeVolumes&Version=2016-11-15&NextToken=100%2525%252B"
    );
}

#[test]
fn an_absent_or_empty_token_ends_the_listing_and_a_repeated_one_is_unreadable() {
    let token = |inner: &str| {
        next_token(&parse(format!("<R>{inner}</R>").as_bytes()).unwrap())
            .map(|token| token.map(str::to_owned))
    };
    assert_eq!(token(""), Ok(None));
    assert_eq!(token("<nextToken/>"), Ok(None));
    assert_eq!(
        token("<nextToken>abc</nextToken>"),
        Ok(Some("abc".to_owned()))
    );
    assert!(token("<nextToken>a</nextToken><nextToken>b</nextToken>").is_err());
    assert!(token("<nextToken/><nextToken/>").is_err());
    assert!(token("<nextToken>a<b/></nextToken>").is_err());
    assert!(token("<nextToken><nextToken>a</nextToken></nextToken>").is_err());
}

/// A token is its element's text as the reply holds it: surrounding and
/// inner whitespace stay, and a token of whitespace alone is a token, so
/// it never reads as the last page.
#[test]
fn a_token_is_its_text_as_the_reply_holds_it() {
    let token = |inner: &str| {
        next_token(&parse(format!("<R>{inner}</R>").as_bytes()).unwrap())
            .map(|token| token.map(str::to_owned))
    };
    assert_eq!(
        token("<nextToken> a b\n</nextToken>"),
        Ok(Some(" a b\n".to_owned()))
    );
    assert_eq!(token("<nextToken> </nextToken>"), Ok(Some(" ".to_owned())));
    assert_eq!(
        token("<nextToken>a&amp;b&#x20;</nextToken>"),
        Ok(Some("a&b ".to_owned()))
    );
    assert_eq!(token("<NextToken>a</NextToken>"), Ok(None));
    let nested = "<set><item><nextToken>a</nextToken></item></set>";
    assert_eq!(token(nested), Ok(None));
    assert_eq!(
        token(&format!("{nested}<nextToken>b</nextToken>")),
        Ok(Some("b".to_owned()))
    );
}

/// A reply's document is its root only for an HTTP 200 whose root names
/// the action; each refused reply differs from the accepted one in one
/// respect.
#[test]
fn a_document_needs_a_200_and_the_root_of_its_action() {
    let listing = "<DescribeVolumesResponse><volumeSet/></DescribeVolumesResponse>";
    let reply = |status: u16, body: &str| Reply {
        status,
        body: body.as_bytes().to_vec(),
    };
    let root = document(&reply(200, listing), "DescribeVolumes").unwrap();
    assert_eq!(root.name, "DescribeVolumesResponse");
    assert_eq!(root.items("volumeSet"), Some(&[][..]));
    for status in (100..600).filter(|status| *status != 200) {
        assert_eq!(
            document(&reply(status, listing), "DescribeVolumes"),
            None,
            "{status}"
        );
    }
    for action in [
        "DescribeVolumeStatus",
        "Describe",
        "",
        "describeVolumes",
        "DESCRIBEVOLUMES",
        "DescribeVolumes ",
    ] {
        assert_eq!(document(&reply(200, listing), action), None, "{action}");
    }
    for root in [
        "DescribeVolumesresponse",
        "describeVolumesResponse",
        "DescribeVolumesResponses",
        "DescribeVolumes",
    ] {
        let renamed = listing.replace("DescribeVolumesResponse", root);
        assert_eq!(
            document(&reply(200, &renamed), "DescribeVolumes"),
            None,
            "{root}"
        );
    }
}

/// `error_code` reads only a `Response` holding one `Error` with a
/// nonempty `Code`; each refused document breaks one of those rules.
#[test]
fn an_error_code_needs_one_error_with_a_nonempty_code() {
    let error = "<Error><Code>Throttling</Code><Message>m</Message></Error>";
    let response = |errors: &str| {
        format!("<Response><Errors>{errors}</Errors><RequestID>r</RequestID></Response>")
    };
    assert_eq!(
        error_code(response(error).as_bytes()).as_deref(),
        Some("Throttling")
    );
    let padded = "<Error><Code> Throttling\n</Code></Error>";
    assert_eq!(
        error_code(response(padded).as_bytes()).as_deref(),
        Some(" Throttling\n")
    );
    let cases = [
        (
            "another root",
            format!("<ErrorResponse><Errors>{error}</Errors></ErrorResponse>"),
        ),
        (
            "no errors",
            "<Response><RequestID>r</RequestID></Response>".to_owned(),
        ),
        ("empty errors", response("")),
        ("two errors", response(&error.repeat(2))),
        (
            "another child",
            response("<Fault><Code>Throttling</Code></Fault>"),
        ),
        ("text beside the error", response(&format!("x{error}"))),
        ("no code", response("<Error><Message>m</Message></Error>")),
        ("empty code", response("<Error><Code/></Error>")),
    ];
    for (name, body) in cases {
        assert_eq!(error_code(body.as_bytes()), None, "{name}");
    }
}
