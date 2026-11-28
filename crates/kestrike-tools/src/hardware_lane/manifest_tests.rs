//! The manifest check over a base manifest and its changed copies, and the reader over the committed
//! manifest, over a document's own rules, and over bytes that are no UTF-8 JSON document.
//!
//! Each copy of `copies.json` lists its edits of the base, the sentence of its refusal (`lane`), the
//! sentence the module gives where it differs (`tool`), and the names of its platform rows where it passes.

use std::fs;
use std::path::{Path, PathBuf};

use crate::hardware_lane::{Error, check_manifest, manifest_path, read_manifest};
use crate::json::{self, Object, Value};
use crate::paths::tests::Scratch;
use crate::text::Text;

const COPIES: &str = include_str!("copies.json");

const COPY_COUNT: usize = 252;

fn top() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn text(value: &Value) -> &Text {
    match value {
        Value::String(text) => text,
        other => panic!("a string, not {other:?}"),
    }
}

fn place<'a, 'b>(document: &'a mut Value, path: &'b [Value]) -> (&'a mut Value, &'b Value) {
    let (last, parents) = path.split_last().expect("an edit names a key");
    let mut target = document;
    for key in parents {
        target = step(target, key);
    }
    (target, last)
}

fn step<'a>(target: &'a mut Value, key: &Value) -> &'a mut Value {
    match (target, key) {
        (Value::Object(object), Value::String(key)) => object
            .get_mut(key.to_str().expect("a fixture key is a scalar text"))
            .expect("the fixture's path stands in the base"),
        (Value::Array(items), Value::Integer(at)) => {
            &mut items[at.to_string().parse::<usize>().expect("an index")]
        }
        (target, key) => panic!("no step {key:?} into {target:?}"),
    }
}

/// `apply` preserves Python dict insertion order: new keys go last.
fn apply(document: &mut Value, edit: &[Value]) {
    let op = text(&edit[0]).to_str().expect("an operation name");
    let Value::Array(path) = &edit[1] else {
        panic!("an edit's path is an array")
    };
    let (target, last) = place(document, path);
    let value = match op {
        "set" => Some(edit[2].clone()),
        "set-float" => Some(Value::Float(
            text(&edit[2]).to_str().unwrap().parse().expect("a float"),
        )),
        "delete" => None,
        other => panic!("no operation {other}"),
    };
    match (target, last, value) {
        (Value::Object(object), Value::String(key), Some(value)) => {
            object.insert(key.clone(), value)
        }
        (Value::Object(object), Value::String(key), None) => {
            object
                .remove(key.to_str().unwrap())
                .expect("a deleted key stands");
        }
        (target, key, _) => panic!("no edit at {key:?} of {target:?}"),
    }
}

fn names(platforms: &Object) -> Vec<Text> {
    platforms.iter().map(|(name, _)| name.clone()).collect()
}

/// `UNASSIGNED` identifies the copy with U+0378 in a platform name.
const UNASSIGNED: &str =
    "a platform name holding an unassigned code point is refused with its repr";

/// These prefixes identify interpreter errors after `malformed hardware manifest: ` in a `lane` sentence.
const INTERPRETER_ERRORS: [&str; 4] = [
    "TypeError: ",
    "AttributeError: ",
    "KeyError: ",
    "OverflowError: ",
];

const TOOL_COUNT: usize = 33;

fn differs_as_stated(name: &Text, lane: Option<&Value>, tool: &Value) -> bool {
    let (Some(Value::String(lane)), Value::String(tool)) = (lane, tool) else {
        return false;
    };
    let raised = lane
        .to_str()
        .and_then(|lane| lane.strip_prefix("malformed hardware manifest: "))
        .is_some_and(|rest| {
            INTERPRETER_ERRORS
                .iter()
                .any(|class| rest.starts_with(class))
        });
    (raised || *name == UNASSIGNED) && lane != tool
}

/// Each copy passes with the platform rows of its document under the names it records, or is refused with
/// its sentence: the copy's `tool` sentence where it holds one, and its `lane` sentence otherwise. The 35
/// copies named `check N:` each fail the check of that number first; the copies named `order` fail two
/// checks and are refused with the first.
#[test]
fn each_copy_passes_or_is_refused_with_its_recorded_sentence() {
    let fixture = json::parse(COPIES).expect("the fixture is JSON");
    let Value::Object(fixture) = fixture else {
        panic!("the fixture is an object")
    };
    let base = fixture.get("base").expect("a base");
    let Some(Value::Array(copies)) = fixture.get("copies") else {
        panic!("the fixture lists its copies")
    };
    let mut checks = Vec::new();
    let mut tools = 0;
    for copy in copies {
        let Value::Object(copy) = copy else {
            panic!("a copy is an object")
        };
        let name = text(copy.get("name").expect("a name"));
        let Some(Value::Array(edits)) = copy.get("edits") else {
            panic!("{name}: edits")
        };
        let mut document = base.clone();
        for edit in edits {
            let Value::Array(edit) = edit else {
                panic!("{name}: an edit is an array")
            };
            apply(&mut document, edit);
        }
        let expected = match copy.get("tool") {
            Some(tool) => {
                assert!(
                    differs_as_stated(name, copy.get("lane"), tool),
                    "{name}: a tool sentence stands beside a lane sentence of the check's own"
                );
                tools += 1;
                tool
            }
            None => copy.get("lane").expect("an outcome"),
        };
        match (check_manifest(&document), expected) {
            (Ok(platforms), Value::Null) => {
                let Value::Object(top) = &document else {
                    unreachable!()
                };
                let Some(Value::Object(rows)) = top.get("platforms") else {
                    panic!("{name}: the platforms")
                };
                assert!(std::ptr::eq(platforms, rows), "{name}");
                let Some(Value::Array(recorded)) = copy.get("platforms") else {
                    panic!("{name}: a passing copy records its platform names")
                };
                let recorded: Vec<Text> = recorded.iter().map(|name| text(name).clone()).collect();
                assert_eq!(names(platforms), recorded, "{name}");
            }
            (Err(Error::Refused(sentence)), Value::String(expected)) => {
                assert_eq!(&sentence, expected, "{name}");
            }
            (outcome, expected) => panic!("{name}: {outcome:?}, recorded {expected:?}"),
        }
        if let Some(number) = name
            .to_str()
            .and_then(|name| name.strip_prefix("check "))
            .and_then(|rest| rest.split(':').next())
        {
            checks.push(number.parse::<usize>().expect("a check number"));
        }
    }
    assert_eq!(checks, (1..=35).collect::<Vec<_>>(), "one copy per check");
    assert_eq!(copies.len(), COPY_COUNT, "the fixture holds every copy");
    assert_eq!(tools, TOOL_COUNT, "the copies holding a tool sentence");
}

#[test]
fn a_tool_sentence_stands_only_where_the_lane_raised_an_interpreter_error() {
    let name = Text::from("a copy");
    let string = |text: &str| Value::String(Text::from(text));
    let tool =
        string("malformed hardware manifest: case a: an integer stands where items are read");
    let raised = string("malformed hardware manifest: TypeError: 'int' object is not iterable");
    let ordinary = string("malformed hardware manifest: case a inputs");
    assert!(differs_as_stated(&name, Some(&raised), &tool));
    assert!(!differs_as_stated(&name, Some(&ordinary), &tool));
    assert!(!differs_as_stated(&name, Some(&Value::Null), &tool));
    assert!(!differs_as_stated(&name, None, &tool));
    assert!(!differs_as_stated(&name, Some(&raised), &raised));
    assert!(differs_as_stated(
        &Text::from(UNASSIGNED),
        Some(&ordinary),
        &tool
    ));
}

/// The committed manifest passes with its three platform rows, all of them unsupported. A row added to the
/// manifest is added to the list of names here.
#[test]
fn the_committed_manifest_gives_its_platform_rows_in_document_order() {
    let path = manifest_path(&top());
    let platforms = read_manifest(&path).expect("the committed manifest passes");
    let names: Vec<Text> = [
        "x86_64-nitro-ebs",
        "aarch64-r8gb-4xlarge-ebs",
        "aarch64-r8gb-8xlarge-ebs",
    ]
    .into_iter()
    .map(Text::from)
    .collect();
    assert_eq!(self::names(&platforms), names);
    let bytes = fs::read(&path).unwrap();
    let Ok(Value::Object(document)) = json::parse(std::str::from_utf8(&bytes).unwrap()) else {
        panic!("the committed manifest is a JSON object")
    };
    assert_eq!(Some(&Value::Object(platforms)), document.get("platforms"));
}

fn written(scratch: &Scratch, name: &str, bytes: &[u8]) -> PathBuf {
    let path = scratch.0.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

const MINIMAL: &[u8] = br#"{"version": 1, "platforms": {}, "profiles": {}}"#;

/// One leading UTF-8 byte order mark is dropped before the document is read; a second stands as the
/// document's first character, which no JSON value starts with.
#[test]
fn one_byte_order_mark_is_dropped() {
    let scratch = Scratch::new("hardware-lane");
    let committed = fs::read(manifest_path(&top())).unwrap();
    let marked = written(
        &scratch,
        "bom.json",
        &[b"\xef\xbb\xbf", committed.as_slice()].concat(),
    );
    let expected = read_manifest(&manifest_path(&top())).unwrap();
    assert_eq!(read_manifest(&marked).unwrap(), expected);
    assert_eq!(
        read_manifest(&written(&scratch, "minimal.json", MINIMAL)).unwrap(),
        Object::new()
    );
    let twice = written(
        &scratch,
        "two.json",
        &[b"\xef\xbb\xbf\xef\xbb\xbf", MINIMAL].concat(),
    );
    let Err(Error::Refused(sentence)) = read_manifest(&twice) else {
        panic!("a second byte order mark is refused")
    };
    assert!(
        sentence
            .to_str()
            .unwrap()
            .starts_with("malformed hardware manifest: the bytes are no JSON document: "),
        "{sentence}"
    );
}

/// Bytes that are no UTF-8, the UTF-8 bytes of a surrogate, UTF-16 and text that is no JSON document are
/// each refused after `malformed hardware manifest: ` with the reader's statement.
#[test]
fn bytes_that_are_no_utf8_json_document_are_refused() {
    let scratch = Scratch::new("hardware-lane");
    let utf16: Vec<u8> = std::iter::once(0xfeff_u16)
        .chain(std::str::from_utf8(MINIMAL).unwrap().encode_utf16())
        .flat_map(u16::to_le_bytes)
        .collect();
    let surrogate: &[u8] =
        b"{\"version\": 1, \"platforms\": {}, \"profiles\": {}, \"packages\": {\"\xed\xa0\x80\": 1}}";
    let rows: [(&str, &[u8], &str); 5] = [
        (
            "not-utf8",
            &[b"\xff", MINIMAL].concat(),
            "the bytes are not UTF-8 from byte 0",
        ),
        (
            "surrogate",
            surrogate,
            "the bytes are not UTF-8 from byte 62",
        ),
        ("utf16", &utf16, "the bytes are not UTF-8 from byte 0"),
        (
            "not-json",
            b"{",
            "the bytes are no JSON document: expected a key at byte 1",
        ),
        (
            "empty",
            b"",
            "the bytes are no JSON document: expected a value at byte 0",
        ),
    ];
    for (name, bytes, statement) in rows {
        let Err(Error::Refused(sentence)) = read_manifest(&written(&scratch, name, bytes)) else {
            panic!("{name} is refused")
        };
        assert_eq!(
            sentence,
            format!("malformed hardware manifest: {statement}").as_str(),
            "{name}"
        );
    }
}

/// A document is read whole before its check: a manifest of version 2 is refused, a document that is an
/// array is refused by the first check, and a platform row named twice stands once, at its first place,
/// with its last value.
#[test]
fn the_reader_checks_the_document_it_decodes() {
    let scratch = Scratch::new("hardware-lane");
    let version = written(
        &scratch,
        "version.json",
        br#"{"version": 2, "platforms": {}, "profiles": {}}"#,
    );
    let array = written(&scratch, "array.json", b"[]");
    for (path, sentence) in [(version, "version 2"), (array, "top-level keys")] {
        let Err(Error::Refused(refused)) = read_manifest(&path) else {
            panic!("{} is refused", path.display())
        };
        assert_eq!(
            refused,
            format!("malformed hardware manifest: {sentence}").as_str()
        );
    }
    let repeated = written(
        &scratch,
        "repeated.json",
        br#"{"version": 1, "platforms": {"a": {"machine": "x86_64", "supported": false, "owner": "first"}, "b": {"machine": "aarch64", "supported": false, "owner": "b"}, "a": {"machine": "x86_64", "supported": false, "owner": "last"}}, "profiles": {}}"#,
    );
    let platforms = read_manifest(&repeated).expect("a repeated row name passes");
    assert_eq!(names(&platforms), [Text::from("a"), Text::from("b")]);
    let Some(Value::Object(first)) = platforms.get("a") else {
        panic!("the row a")
    };
    assert_eq!(first.get("owner"), Some(&Value::String(Text::from("last"))));
}

/// A path that names no file and a path that names a directory give the read's system error, numbers 2 and
/// 21.
#[test]
fn an_absent_path_and_a_directory_give_the_system_error() {
    let scratch = Scratch::new("hardware-lane");
    for (path, code) in [(scratch.0.join("absent.json"), 2), (scratch.0.clone(), 21)] {
        let Err(Error::System(error)) = read_manifest(&path) else {
            panic!("{} gives a system error", path.display())
        };
        assert_eq!(error.raw_os_error(), Some(code), "{}", path.display());
    }
}

const NESTED: &[u8] = br#"{"version": 1, "platforms": {"h": {"machine": "x86_64", "supported": false, "owner": "o"}}, "profiles": {"p": {"platforms": {"h": "runs"}, "retries": 0, "roles": {"r": {"cases": [{"id": "a", "expected": 1, "inputs": [], "deadline": 60, "grace": true, "witnesses": [], "restoration": "none", "closes_on_sigterm": false}]}}}}}"#;

/// The reader's refusals at the limits it reads: a check inside a profile, a version nested 999 lists deep
/// read and refused by the check, 1,001 levels refused by the reader, an integer of 4,300 digits read and
/// one of 4,301 refused, offsets counted from the file's first byte after a byte order mark, and UTF-16
/// with no mark read as UTF-8 text that is no JSON document.
#[test]
fn the_reader_refuses_at_its_limits_with_the_statements_it_composes() {
    let scratch = Scratch::new("hardware-lane");
    let deep = format!(
        r#"{{"version": {}{}, "platforms": {{}}, "profiles": {{}}}}"#,
        "[".repeat(999),
        "]".repeat(999)
    );
    let deeper = format!("{}{}", "[".repeat(1001), "]".repeat(1001));
    let digits = |count: usize| {
        format!(
            r#"{{"version": 1, "platforms": {{}}, "profiles": {{}}, "packages": {{"x": {}}}}}"#,
            "9".repeat(count)
        )
    };
    let utf16: Vec<u8> = std::str::from_utf8(MINIMAL)
        .unwrap()
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let version = format!("version {}{}", "[".repeat(999), "]".repeat(999));
    let rows: [(&str, Vec<u8>, &str); 7] = [
        (
            "nested",
            NESTED.to_vec(),
            "case a needs a finite positive deadline and grace",
        ),
        ("deep", deep.into_bytes(), &version),
        (
            "deeper",
            deeper.into_bytes(),
            "the bytes are no JSON document: nesting deeper than the reader takes at byte 1000",
        ),
        (
            "digits",
            digits(4301).into_bytes(),
            "the bytes are no JSON document: an integer of more digits than the reader takes at byte 66",
        ),
        (
            "marked-not-utf8",
            [b"\xef\xbb\xbf\xff".as_slice(), MINIMAL].concat(),
            "the bytes are not UTF-8 from byte 3",
        ),
        (
            "two-marks",
            [b"\xef\xbb\xbf\xef\xbb\xbf".as_slice(), MINIMAL].concat(),
            "the bytes are no JSON document: expected a value at byte 3",
        ),
        (
            "utf16-unmarked",
            utf16,
            "the bytes are no JSON document: expected a key at byte 1",
        ),
    ];
    for (name, bytes, statement) in rows {
        let Err(Error::Refused(sentence)) = read_manifest(&written(&scratch, name, &bytes)) else {
            panic!("{name} is refused")
        };
        assert_eq!(
            sentence,
            format!("malformed hardware manifest: {statement}").as_str(),
            "{name}"
        );
    }
    let held = written(&scratch, "held", digits(4300).as_bytes());
    assert_eq!(read_manifest(&held).unwrap(), Object::new());
}

/// The reader opens the path as it is spelled: a file's name with a trailing `/` gives error 20 and an
/// empty path gives error 2.
#[test]
fn the_reader_opens_the_path_as_spelled() {
    let scratch = Scratch::new("hardware-lane");
    let file = written(&scratch, "minimal.json", MINIMAL);
    let slashed = PathBuf::from(format!("{}/", file.display()));
    for (path, code) in [(slashed, 20), (PathBuf::new(), 2)] {
        let Err(Error::System(error)) = read_manifest(&path) else {
            panic!("{} gives a system error", path.display())
        };
        assert_eq!(error.raw_os_error(), Some(code), "{}", path.display());
    }
}
