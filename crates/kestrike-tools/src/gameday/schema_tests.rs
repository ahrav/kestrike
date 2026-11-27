//! Each row's expected result is the judge's own function's at the base under Python 3.9.25, as the
//! expression beside it gives it.

use std::collections::BTreeSet;

use super::{Names, Scalar, Schema, conform};
use crate::gameday::layout::{WINDOW, layout};
use crate::gameday::test_support::value;
use crate::text::Text;

/// The names the rows are read against: `NAMES` of the recording.
fn names() -> Names {
    let mut names = Names::new();
    for (kind, members) in [
        ("host", &["h1", "h2"][..]),
        ("shard", &["s1", "s2"]),
        ("key", &["k1"]),
        ("budget", &["origin-load", "re-enrollment-drain"]),
        ("observation", &["origin", "provider", "re-enrollment"]),
        ("sealed", &["a.jsonl"]),
        ("observed", &["a.jsonl"]),
    ] {
        names.insert(
            kind,
            members
                .iter()
                .map(|name| Text::from(*name))
                .collect::<BTreeSet<_>>(),
        );
    }
    names
}

#[test]
fn each_scalar_passes_and_fails_at_its_bounds() {
    let names = names();
    #[rustfmt::skip]
    let rows: &[(&str, &str, Schema, Result<&str, &str>)] = &[
    (r#"conform("a", 'name')"#, r#""a""#, Schema::scalar(Scalar::Name), Ok(r#"None"#)),
    (r#"conform(" \u3000", 'name')"#, r#"" \u3000""#, Schema::scalar(Scalar::Name), Err(r#"f is no name of the layout: ' \u3000'"#)),
    (r#"conform("\ud800", 'name')"#, r#""\ud800""#, Schema::scalar(Scalar::Name), Err(r#"f is no name of the layout: '\ud800'"#)),
    (r#"conform("a\ud800", 'name')"#, r#""a\ud800""#, Schema::scalar(Scalar::Name), Err(r#"f is no name of the layout: 'a\ud800'"#)),
    (r#"conform(1, 'name')"#, r#"1"#, Schema::scalar(Scalar::Name), Err(r#"f is no name of the layout: 1"#)),
    (r#"conform(9007199254740992, 'time')"#, r#"9007199254740992"#, Schema::scalar(Scalar::Time), Ok(r#"None"#)),
    (r#"conform(9007199254740993, 'time')"#, r#"9007199254740993"#, Schema::scalar(Scalar::Time), Err(r#"f is no time of the layout: 9007199254740993"#)),
    (r#"conform(-9007199254740992, 'time')"#, r#"-9007199254740992"#, Schema::scalar(Scalar::Time), Ok(r#"None"#)),
    (r#"conform(-9007199254740993, 'time')"#, r#"-9007199254740993"#, Schema::scalar(Scalar::Time), Err(r#"f is no time of the layout: -9007199254740993"#)),
    (r#"conform(9007199254740992.0, 'time')"#, r#"9007199254740992.0"#, Schema::scalar(Scalar::Time), Ok(r#"None"#)),
    (r#"conform(-9007199254740994.0, 'time')"#, r#"-9007199254740994.0"#, Schema::scalar(Scalar::Time), Err(r#"f is no time of the layout: -9007199254740994.0"#)),
    (r#"conform(true, 'time')"#, r#"true"#, Schema::scalar(Scalar::Time), Err(r#"f is no time of the layout: True"#)),
    (r#"conform("1", 'time')"#, r#""1""#, Schema::scalar(Scalar::Time), Err(r#"f is no time of the layout: '1'"#)),
    (r#"conform(5e-324, 'positive')"#, r#"5e-324"#, Schema::scalar(Scalar::Positive), Ok(r#"None"#)),
    (r#"conform(1, 'positive')"#, r#"1"#, Schema::scalar(Scalar::Positive), Ok(r#"None"#)),
    (r#"conform(0, 'positive')"#, r#"0"#, Schema::scalar(Scalar::Positive), Err(r#"f is no positive of the layout: 0"#)),
    (r#"conform(-0.0, 'positive')"#, r#"-0.0"#, Schema::scalar(Scalar::Positive), Err(r#"f is no positive of the layout: -0.0"#)),
    (r#"conform(0.0, 'positive')"#, r#"0.0"#, Schema::scalar(Scalar::Positive), Err(r#"f is no positive of the layout: 0.0"#)),
    (r#"conform(-1, 'positive')"#, r#"-1"#, Schema::scalar(Scalar::Positive), Err(r#"f is no positive of the layout: -1"#)),
    (r#"conform(9007199254740993, 'positive')"#, r#"9007199254740993"#, Schema::scalar(Scalar::Positive), Err(r#"f is no positive of the layout: 9007199254740993"#)),
    (r#"conform(0, 'nonnegative')"#, r#"0"#, Schema::scalar(Scalar::Nonnegative), Ok(r#"None"#)),
    (r#"conform(-0.0, 'nonnegative')"#, r#"-0.0"#, Schema::scalar(Scalar::Nonnegative), Ok(r#"None"#)),
    (r#"conform(-5e-324, 'nonnegative')"#, r#"-5e-324"#, Schema::scalar(Scalar::Nonnegative), Err(r#"f is no nonnegative of the layout: -5e-324"#)),
    (r#"conform(-1, 'nonnegative')"#, r#"-1"#, Schema::scalar(Scalar::Nonnegative), Err(r#"f is no nonnegative of the layout: -1"#)),
    (r#"conform(9007199254740992, 'nonnegative')"#, r#"9007199254740992"#, Schema::scalar(Scalar::Nonnegative), Ok(r#"None"#)),
    (r#"conform(0, 'count')"#, r#"0"#, Schema::scalar(Scalar::Count), Ok(r#"None"#)),
    (r#"conform(9007199254740992, 'count')"#, r#"9007199254740992"#, Schema::scalar(Scalar::Count), Ok(r#"None"#)),
    (r#"conform(-1, 'count')"#, r#"-1"#, Schema::scalar(Scalar::Count), Err(r#"f is no count of the layout: -1"#)),
    (r#"conform(9007199254740993, 'count')"#, r#"9007199254740993"#, Schema::scalar(Scalar::Count), Err(r#"f is no count of the layout: 9007199254740993"#)),
    (r#"conform(1.0, 'count')"#, r#"1.0"#, Schema::scalar(Scalar::Count), Err(r#"f is no count of the layout: 1.0"#)),
    (r#"conform(true, 'count')"#, r#"true"#, Schema::scalar(Scalar::Count), Err(r#"f is no count of the layout: True"#)),
    (r#"conform(false, 'count')"#, r#"false"#, Schema::scalar(Scalar::Count), Err(r#"f is no count of the layout: False"#)),
    (r#"conform(1, 'generation')"#, r#"1"#, Schema::scalar(Scalar::Generation), Ok(r#"None"#)),
    (r#"conform(0, 'generation')"#, r#"0"#, Schema::scalar(Scalar::Generation), Err(r#"f is no generation of the layout: 0"#)),
    (r#"conform(4294967295, 'generation')"#, r#"4294967295"#, Schema::scalar(Scalar::Generation), Ok(r#"None"#)),
    (r#"conform(4294967296, 'generation')"#, r#"4294967296"#, Schema::scalar(Scalar::Generation), Err(r#"f is no generation of the layout: 4294967296"#)),
    (r#"conform(0, 'attempts')"#, r#"0"#, Schema::scalar(Scalar::Attempts), Ok(r#"None"#)),
    (r#"conform(2147483646, 'attempts')"#, r#"2147483646"#, Schema::scalar(Scalar::Attempts), Ok(r#"None"#)),
    (r#"conform(2147483647, 'attempts')"#, r#"2147483647"#, Schema::scalar(Scalar::Attempts), Err(r#"f is no attempts of the layout: 2147483647"#)),
    (r#"conform(4294967292, 'epoch')"#, r#"4294967292"#, Schema::scalar(Scalar::Epoch), Ok(r#"None"#)),
    (r#"conform(4294967293, 'epoch')"#, r#"4294967293"#, Schema::scalar(Scalar::Epoch), Err(r#"f is no epoch of the layout: 4294967293"#)),
    (r#"conform("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 'digest')"#, r#""0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef""#, Schema::scalar(Scalar::Digest), Ok(r#"None"#)),
    (r#"conform("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde", 'digest')"#, r#""0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde""#, Schema::scalar(Scalar::Digest), Err(r#"f is no digest of the layout: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde'"#)),
    (r#"conform("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeA", 'digest')"#, r#""0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeA""#, Schema::scalar(Scalar::Digest), Err(r#"f is no digest of the layout: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeA'"#)),
    (r#"conform("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", 'digest')"#, r#""0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0""#, Schema::scalar(Scalar::Digest), Err(r#"f is no digest of the layout: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0'"#)),
    (r#"conform("0123456789abcdef0123456789abcdef01234567", 'commit')"#, r#""0123456789abcdef0123456789abcdef01234567""#, Schema::scalar(Scalar::Commit), Ok(r#"None"#)),
    (r#"conform("0123456789abcdef0123456789abcdef012345678", 'commit')"#, r#""0123456789abcdef0123456789abcdef012345678""#, Schema::scalar(Scalar::Commit), Err(r#"f is no commit of the layout: '0123456789abcdef0123456789abcdef012345678'"#)),
    (r#"conform("0123456789abcdef0123456789abcdef0123456g", 'commit')"#, r#""0123456789abcdef0123456789abcdef0123456g""#, Schema::scalar(Scalar::Commit), Err(r#"f is no commit of the layout: '0123456789abcdef0123456789abcdef0123456g'"#)),
    (r#"conform("2024-02-29", 'date')"#, r#""2024-02-29""#, Schema::scalar(Scalar::Date), Ok(r#"None"#)),
    (r#"conform("2023-02-29", 'date')"#, r#""2023-02-29""#, Schema::scalar(Scalar::Date), Err(r#"f is no date of the layout: '2023-02-29'"#)),
    (r#"conform("0000-01-01", 'date')"#, r#""0000-01-01""#, Schema::scalar(Scalar::Date), Err(r#"f is no date of the layout: '0000-01-01'"#)),
    (r#"conform("0001-01-01", 'date')"#, r#""0001-01-01""#, Schema::scalar(Scalar::Date), Ok(r#"None"#)),
    (r#"conform("9999-12-31", 'date')"#, r#""9999-12-31""#, Schema::scalar(Scalar::Date), Ok(r#"None"#)),
    (r#"conform("2024-13-01", 'date')"#, r#""2024-13-01""#, Schema::scalar(Scalar::Date), Err(r#"f is no date of the layout: '2024-13-01'"#)),
    (r#"conform("2024-00-10", 'date')"#, r#""2024-00-10""#, Schema::scalar(Scalar::Date), Err(r#"f is no date of the layout: '2024-00-10'"#)),
    (r#"conform("2024-04-31", 'date')"#, r#""2024-04-31""#, Schema::scalar(Scalar::Date), Err(r#"f is no date of the layout: '2024-04-31'"#)),
    (r#"conform("2024-1-01", 'date')"#, r#""2024-1-01""#, Schema::scalar(Scalar::Date), Err(r#"f is no date of the layout: '2024-1-01'"#)),
    (r#"conform("\uff12024-01-01", 'date')"#, r#""\uff12024-01-01""#, Schema::scalar(Scalar::Date), Err(r#"f is no date of the layout: '２024-01-01'"#)),
    (r#"conform("2024-01-01 ", 'date')"#, r#""2024-01-01 ""#, Schema::scalar(Scalar::Date), Err(r#"f is no date of the layout: '2024-01-01 '"#)),
    (r#"conform(20240101, 'date')"#, r#"20240101"#, Schema::scalar(Scalar::Date), Err(r#"f is no date of the layout: 20240101"#)),
    (r#"conform("a", 'file-name')"#, r#""a""#, Schema::scalar(Scalar::FileName), Ok(r#"None"#)),
    (r#"conform("a._-Z9", 'file-name')"#, r#""a._-Z9""#, Schema::scalar(Scalar::FileName), Ok(r#"None"#)),
    (r#"conform("receipts", 'file-name')"#, r#""receipts""#, Schema::scalar(Scalar::FileName), Err(r#"f is no file-name of the layout: 'receipts'"#)),
    (r#"conform("receipts2", 'file-name')"#, r#""receipts2""#, Schema::scalar(Scalar::FileName), Ok(r#"None"#)),
    (r#"conform("-a", 'file-name')"#, r#""-a""#, Schema::scalar(Scalar::FileName), Err(r#"f is no file-name of the layout: '-a'"#)),
    (r#"conform(".", 'file-name')"#, r#"".""#, Schema::scalar(Scalar::FileName), Err(r#"f is no file-name of the layout: '.'"#)),
    (r#"conform("", 'file-name')"#, r#""""#, Schema::scalar(Scalar::FileName), Err(r#"f is no file-name of the layout: ''"#)),
    (r#"conform("a/b", 'file-name')"#, r#""a/b""#, Schema::scalar(Scalar::FileName), Err(r#"f is no file-name of the layout: 'a/b'"#)),
    (r#"conform("any generation change", 'guardrail')"#, r#""any generation change""#, Schema::scalar(Scalar::Guardrail), Ok(r#"None"#)),
    (r#"conform("any generation", 'guardrail')"#, r#""any generation""#, Schema::scalar(Scalar::Guardrail), Err(r#"f is no guardrail of the layout: 'any generation'"#)),
    (r#"conform(null, 'guardrail')"#, r#"null"#, Schema::scalar(Scalar::Guardrail), Err(r#"f is no guardrail of the layout: None"#)),
    (r#"conform("h1", 'host')"#, r#""h1""#, Schema::scalar(Scalar::Host), Ok(r#"None"#)),
    (r#"conform("h3", 'host')"#, r#""h3""#, Schema::scalar(Scalar::Host), Err(r#"f is no host of the layout: 'h3'"#)),
    (r#"conform(1, 'host')"#, r#"1"#, Schema::scalar(Scalar::Host), Err(r#"f is no host of the layout: 1"#)),
    (r#"conform("s2", 'shard')"#, r#""s2""#, Schema::scalar(Scalar::Shard), Ok(r#"None"#)),
    (r#"conform("s3", 'shard')"#, r#""s3""#, Schema::scalar(Scalar::Shard), Err(r#"f is no shard of the layout: 's3'"#)),
    (r#"conform("k1", 'key')"#, r#""k1""#, Schema::scalar(Scalar::Key), Ok(r#"None"#)),
    (r#"conform("k2", 'key')"#, r#""k2""#, Schema::scalar(Scalar::Key), Err(r#"f is no key of the layout: 'k2'"#)),
    (r#"conform(null, 'host?')"#, r#"null"#, Schema::nullable(Scalar::Host), Ok(r#"None"#)),
    (r#"conform("h2", 'host?')"#, r#""h2""#, Schema::nullable(Scalar::Host), Ok(r#"None"#)),
    (r#"conform("h9", 'host?')"#, r#""h9""#, Schema::nullable(Scalar::Host), Err(r#"f is no host of the layout: 'h9'"#)),
    ];
    for (expression, text, schema, expected) in rows {
        let found = conform(&value(text), schema, &Text::from("f"), &names)
            .map(|()| "None")
            .map_err(|r| r.to_string());
        assert_eq!(found, expected.map_err(str::to_owned), "{expression}");
    }
}

#[test]
fn each_schema_kind_refuses_with_its_sentence_and_key_path() {
    let names = names();
    #[rustfmt::skip]
    let rows: &[(&str, &str, Schema, Result<&str, &str>)] = &[
    (r#"conform(1, gj.WINDOW)"#, r#"1"#, WINDOW, Err(r#"f is no object"#)),
    (r#"conform({"start": 1}, gj.WINDOW)"#, r#"{"start": 1}"#, WINDOW, Err(r#"f holds the keys ['start'], not ['end', 'start']"#)),
    (r#"conform({"start": 1, "end": 2, "x": 3}, gj.WINDOW)"#, r#"{"start": 1, "end": 2, "x": 3}"#, WINDOW, Err(r#"f holds the keys ['end', 'start', 'x'], not ['end', 'start']"#)),
    (r#"conform({"start": "x", "end": 1}, gj.WINDOW)"#, r#"{"start": "x", "end": 1}"#, WINDOW, Err(r#"f start is no time of the layout: 'x'"#)),
    (r#"conform({"start": 1, "end": 2}, gj.WINDOW)"#, r#"{"start": 1, "end": 2}"#, WINDOW, Ok(r#"None"#)),
    (r#"conform({"event": "CreateVolume", "principal": "p", "time": 1}, gj.LAYOUT['provider.jsonl'][0])"#, r#"{"event": "CreateVolume", "principal": "p", "time": 1}"#, *layout("provider.jsonl").expect("a file of the layout").0, Ok(r#"None"#)),
    (r#"conform({"event": "volume", "principal": "p", "time": 1}, gj.LAYOUT['provider.jsonl'][0])"#, r#"{"event": "volume", "principal": "p", "time": 1}"#, *layout("provider.jsonl").expect("a file of the layout").0, Err(r#"f event 'volume' is none of ['CreateVolume']"#)),
    (r#"conform({"event": "CreateVolume", "principal": "p", "time": "t"}, gj.LAYOUT['provider.jsonl'][0])"#, r#"{"event": "CreateVolume", "principal": "p", "time": "t"}"#, *layout("provider.jsonl").expect("a file of the layout").0, Err(r#"f time is no time of the layout: 't'"#)),
    (r#"conform({"event": "volume", "volume": "v", "time": 1}, gj.LAYOUT['provider.jsonl'][0])"#, r#"{"event": "volume", "volume": "v", "time": 1}"#, *layout("provider.jsonl").expect("a file of the layout").0, Ok(r#"None"#)),
    (r#"conform([], gj.LAYOUT['provider.jsonl'][0])"#, r#"[]"#, *layout("provider.jsonl").expect("a file of the layout").0, Err(r#"f is no object"#)),
    (r#"conform({"event": "other", "volume": "v", "time": 1}, gj.LAYOUT['provider.jsonl'][0])"#, r#"{"event": "other", "volume": "v", "time": 1}"#, *layout("provider.jsonl").expect("a file of the layout").0, Err(r#"f event 'other' is none of ['volume']"#)),
    (r#"conform({"host": "h1", "activations": []}, gj.LAYOUT['activations.jsonl'][0])"#, r#"{"host": "h1", "activations": []}"#, *layout("activations.jsonl").expect("a file of the layout").0, Ok(r#"None"#)),
    (r#"conform({"host": "h1", "activations": {}}, gj.LAYOUT['activations.jsonl'][0])"#, r#"{"host": "h1", "activations": {}}"#, *layout("activations.jsonl").expect("a file of the layout").0, Err(r#"f activations is no list"#)),
    (r#"conform({"host": "h1", "activations": [{"shard": "s1", "generation": 1, "attempt": 0, "time": 1}, {"shard": "s1", "generation": 0, "attempt": 0, "time": 1}]}, gj.LAYOUT['activations.jsonl'][0])"#, r#"{"host": "h1", "activations": [{"shard": "s1", "generation": 1, "attempt": 0, "time": 1}, {"shard": "s1", "generation": 0, "attempt": 0, "time": 1}]}"#, *layout("activations.jsonl").expect("a file of the layout").0, Err(r#"f activations [1] generation is no generation of the layout: 0"#)),
    (r#"conform({"package_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "time": 1, "shards": {"s1": {"owner": "h1", "standby": null, "generation": 1, "volume": "v", "attempts": 1}}, "standbys": {}}, gj.LAYOUT['injection/roles.json'][0])"#, r#"{"package_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "time": 1, "shards": {"s1": {"owner": "h1", "standby": null, "generation": 1, "volume": "v", "attempts": 1}}, "standbys": {}}"#, *layout("injection/roles.json").expect("a file of the layout").0, Err(r#"f shards names ['s1'], not exactly the shards ['s1', 's2']"#)),
    (r#"conform({"package_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "time": 1, "shards": {"s1": {"owner": "h1", "standby": null, "generation": 1, "volume": "v", "attempts": 1}, "s2": {"owner": "h2", "standby": "h1", "generation": 1, "volume": "v", "attempts": 1}}, "standbys": {"h3": {}}}, gj.LAYOUT['injection/roles.json'][0])"#, r#"{"package_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "time": 1, "shards": {"s1": {"owner": "h1", "standby": null, "generation": 1, "volume": "v", "attempts": 1}, "s2": {"owner": "h2", "standby": "h1", "generation": 1, "volume": "v", "attempts": 1}}, "standbys": {"h3": {}}}"#, *layout("injection/roles.json").expect("a file of the layout").0, Err(r#"f standbys names ['h3'], not only the hosts ['h1', 'h2']"#)),
    (r#"conform({"package_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "time": 1, "shards": {"s1": {"owner": "h1", "standby": null, "generation": 1, "volume": "v", "attempts": 1}, "s2": {"owner": "h2", "standby": "h1", "generation": 1, "volume": "v", "attempts": 1}}, "standbys": {"h2": {"instance": "i", "instance_state": "running", "host_report": " "}}}, gj.LAYOUT['injection/roles.json'][0])"#, r#"{"package_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "time": 1, "shards": {"s1": {"owner": "h1", "standby": null, "generation": 1, "volume": "v", "attempts": 1}, "s2": {"owner": "h2", "standby": "h1", "generation": 1, "volume": "v", "attempts": 1}}, "standbys": {"h2": {"instance": "i", "instance_state": "running", "host_report": " "}}}"#, *layout("injection/roles.json").expect("a file of the layout").0, Err(r#"f standbys h2 host_report is no name of the layout: ' '"#)),
    (r#"conform({"package_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "time": 1, "shards": {"s1": {"owner": "h1", "standby": null, "generation": 1, "volume": "v", "attempts": 1}, "s2": {"owner": "h2", "standby": "h1", "generation": 1, "volume": "v", "attempts": 1}}, "standbys": []}, gj.LAYOUT['injection/roles.json'][0])"#, r#"{"package_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "time": 1, "shards": {"s1": {"owner": "h1", "standby": null, "generation": 1, "volume": "v", "attempts": 1}, "s2": {"owner": "h2", "standby": "h1", "generation": 1, "volume": "v", "attempts": 1}}, "standbys": []}"#, *layout("injection/roles.json").expect("a file of the layout").0, Err(r#"f standbys is no object"#)),
    (r#"conform({"package_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "time": 1, "shards": {"s1": {"owner": "h1", "standby": null, "generation": 1, "volume": "v", "attempts": 1}, "s2": {"owner": "h2", "standby": "h1", "generation": 1, "volume": "v", "attempts": 1}, "\ud800": 1}, "standbys": {}}, gj.LAYOUT['injection/roles.json'][0])"#, r#"{"package_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "time": 1, "shards": {"s1": {"owner": "h1", "standby": null, "generation": 1, "volume": "v", "attempts": 1}, "s2": {"owner": "h2", "standby": "h1", "generation": 1, "volume": "v", "attempts": 1}, "\ud800": 1}, "standbys": {}}"#, *layout("injection/roles.json").expect("a file of the layout").0, Err(r#"f shards names ['s1', 's2', '\ud800'], not exactly the shards ['s1', 's2']"#)),
    (r#"conform({"cause": "reach", "guardrail": null, "time": 1, "detail": null}, gj.LAYOUT['injection/abort.json'][0])"#, r#"{"cause": "reach", "guardrail": null, "time": 1, "detail": null}"#, *layout("injection/abort.json").expect("a file of the layout").0, Ok(r#"None"#)),
    (r#"conform({"cause": "x", "guardrail": null, "time": 1, "detail": null}, gj.LAYOUT['injection/abort.json'][0])"#, r#"{"cause": "x", "guardrail": null, "time": 1, "detail": null}"#, *layout("injection/abort.json").expect("a file of the layout").0, Err(r#"f cause 'x' is none of ['deadline', 'exception', 'guardrail', 'reach', 'signal', 'stop-not-shown']"#)),
    (r#"conform({"cause": 1, "guardrail": null, "time": 1, "detail": null}, gj.LAYOUT['injection/abort.json'][0])"#, r#"{"cause": 1, "guardrail": null, "time": 1, "detail": null}"#, *layout("injection/abort.json").expect("a file of the layout").0, Err(r#"f cause 1 is none of ['deadline', 'exception', 'guardrail', 'reach', 'signal', 'stop-not-shown']"#)),
    (r#"conform({"cause": "reach", "guardrail": "x", "time": 1, "detail": null}, gj.LAYOUT['injection/abort.json'][0])"#, r#"{"cause": "reach", "guardrail": "x", "time": 1, "detail": null}"#, *layout("injection/abort.json").expect("a file of the layout").0, Err(r#"f guardrail is no guardrail of the layout: 'x'"#)),
    (r#"conform({"a.jsonl": {"from": 0, "to": 1, "lines": 2}}, gj.LAYOUT['coverage.json'][0])"#, r#"{"a.jsonl": {"from": 0, "to": 1, "lines": 2}}"#, *layout("coverage.json").expect("a file of the layout").0, Ok(r#"None"#)),
    (r#"conform({}, gj.LAYOUT['coverage.json'][0])"#, r#"{}"#, *layout("coverage.json").expect("a file of the layout").0, Err(r#"f names [], not exactly the observeds ['a.jsonl']"#)),
    (r#"conform({"a.jsonl": {"from": 0, "to": 1, "lines": 2.0}}, gj.LAYOUT['coverage.json'][0])"#, r#"{"a.jsonl": {"from": 0, "to": 1, "lines": 2.0}}"#, *layout("coverage.json").expect("a file of the layout").0, Err(r#"f a.jsonl lines is no count of the layout: 2.0"#)),
    ];
    for (expression, text, schema, expected) in rows {
        let found = conform(&value(text), schema, &Text::from("f"), &names)
            .map(|()| "None")
            .map_err(|r| r.to_string());
        assert_eq!(found, expected.map_err(str::to_owned), "{expression}");
    }
}

#[test]
fn a_member_check_of_a_non_string_reads_no_names() {
    let found = conform(
        &value("1"),
        &Schema::scalar(Scalar::Host),
        &Text::from("f"),
        &Names::new(),
    );
    assert_eq!(
        found.map_err(|r| r.to_string()),
        Err("f is no host of the layout: 1".to_owned())
    );
}
