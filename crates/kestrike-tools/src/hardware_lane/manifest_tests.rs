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

const COPY_COUNT: usize = 189;

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

/// `apply` sets a key's value or an array's item, appending a new key at the object's end as a Python
/// dict does, or deletes a key; `set-float` sets the float its text spells, such as `nan`.
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
        (Value::Array(items), Value::Integer(at), Some(value)) => {
            items[at.to_string().parse::<usize>().unwrap()] = value;
        }
        (target, key, _) => panic!("no edit at {key:?} of {target:?}"),
    }
}

fn names(platforms: &Object) -> Vec<Text> {
    platforms.iter().map(|(name, _)| name.clone()).collect()
}

/// Each copy passes with the platform rows of its document under the names it records, or is refused with
/// its sentence: the copy's `tool` sentence where it holds one, and its `lane` sentence otherwise. The 35
/// copies named `check N:` each fail the check of that number alone; the copies named `order` fail two
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
        let expected = copy
            .get("tool")
            .or_else(|| copy.get("lane"))
            .expect("an outcome");
        match (check_manifest(&document), expected) {
            (Ok(platforms), Value::Null) => {
                let Value::Object(top) = &document else {
                    unreachable!()
                };
                let Some(Value::Object(rows)) = top.get("platforms") else {
                    panic!("{name}: the platforms")
                };
                assert_eq!(platforms, rows, "{name}");
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
