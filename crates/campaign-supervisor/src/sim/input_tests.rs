//! The bundle reader over literal 48-byte records, written byte by byte
//! here: the leading manifest's chunk
//! offsets, the leading-record tags, and the read that stops one record
//! past the manifest's record maximum.

use std::io::{self, Read};

use super::input::{RECORD, Stager, Values};
use crate::record::{Digest, Pins, Text};

/// A record of `tag` and `sub` whose byte 4 is `length` and whose bytes
/// from offset 5 are `chunk`.
fn record(tag: u8, sub: u8, length: u8, chunk: &[u8]) -> [u8; 48] {
    let mut record = [0; 48];
    record[0] = tag;
    record[1] = sub;
    record[4] = length;
    record[5..5 + chunk.len()].copy_from_slice(chunk);
    record
}

/// `text` as manifest field records, 43 bytes a chunk, numbered in bytes
/// 2 and 3.
fn manifest(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for (at, chunk) in text.as_bytes().chunks(43).enumerate() {
        let mut field = record(2, 1, chunk.len() as u8, chunk);
        field[2..4].copy_from_slice(&(at as u16).to_le_bytes());
        out.extend_from_slice(&field);
    }
    out
}

const TEXT: &str = "version = 2\nprofile = upload\nexecutable = e\ntoolchain = t\nbuild = b\nplatform = p\nrecords = 8\nbytes = 4800\n";

/// A Begin record, `text`'s manifest chunks with a checkpoint between,
/// then `body` turn records (tag 4).
fn bundle(text: &str, body: usize) -> Vec<u8> {
    let mut out = record(1, 0, 0, &[]).to_vec();
    let chunks = manifest(text);
    let (first, rest) = chunks.split_at(RECORD);
    out.extend_from_slice(first);
    out.extend_from_slice(&record(9, 0, 0, &[]));
    out.extend_from_slice(rest);
    for _ in 0..body {
        out.extend_from_slice(&record(4, 0, 0, &[1]));
    }
    out
}

/// A source that counts the bytes read from it.
struct Counted<'a> {
    bytes: &'a [u8],
    read: usize,
}

impl Read for Counted<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let filled = (&self.bytes[self.read..]).read(buffer)?;
        self.read += filled;
        Ok(filled)
    }
}

fn staged(bytes: &[u8]) -> (Result<super::input::Staged, String>, usize, Vec<u8>) {
    let mut source = Counted { bytes, read: 0 };
    let mut stager = Stager::new(&mut source);
    let mut passed = Vec::new();
    stager.read_to_end(&mut passed).expect("the read succeeds");
    let result = stager.finish();
    (result, source.read, passed)
}

/// The fixture's layout: 48-byte records, the first chunk's length at
/// byte 4 and its text from byte 5, the third record a checkpoint.
#[test]
fn the_fixture_lays_records_out_at_48_byte_offsets() {
    let bytes = bundle(TEXT, 2);
    assert_eq!(bytes.len() % 48, 0);
    assert_eq!(&bytes[48..53], &[2, 1, 0, 0, 43]);
    assert_eq!(&bytes[53..53 + 11], b"version = 2");
    assert_eq!(bytes[96], 9);
    assert_eq!(&bytes[144..148], &[2, 1, 1, 0]);
}

/// A bundle within its maximum passes every byte, hashed, and yields the
/// manifest its leading chunks spell across a checkpoint.
#[test]
fn the_leading_chunks_spell_the_manifest_and_every_byte_is_hashed() {
    let bytes = bundle(TEXT, 2);
    let (result, read, passed) = staged(&bytes);
    let staged = result.expect("the bundle stages");
    assert_eq!(staged.manifest, TEXT);
    assert_eq!(staged.digest, Digest::of(&bytes));
    assert_eq!((read, passed), (bytes.len(), bytes));
}

/// Past the maximum, `min(records, bytes / 48)` records, the read stops
/// at exactly one record past it and the bundle is refused.
#[test]
fn the_read_stops_one_record_past_the_maximum() {
    for (text, maximum) in [
        (TEXT.to_owned(), 8),
        (TEXT.replace("bytes = 4800", "bytes = 335"), 6),
    ] {
        let bytes = bundle(&text, 100);
        let (result, read, passed) = staged(&bytes);
        assert_eq!(
            result.expect_err("the bundle is past its maximum"),
            format!("the bundle holds more than {maximum} records, its manifest's maximum")
        );
        assert_eq!(read, (maximum + 1) * 48, "{text}");
        assert_eq!(passed.len(), read);
    }
    let unbounded = TEXT
        .replace("records = 8", &format!("records = {}", u64::MAX))
        .replace("bytes = 4800", &format!("bytes = {}", u64::MAX));
    let bytes = bundle(&unbounded, 3);
    let (result, read, _) = staged(&bytes);
    result.expect("a bundle under the widest maximum stages");
    assert_eq!(read, bytes.len());
    let exact = bundle(TEXT, 8 - 5);
    assert_eq!(exact.len(), 8 * 48);
    staged(&exact).0.expect("a bundle at its maximum stages");
}

/// Leading manifest chunks past the leading-record bound end the scan,
/// so a bundle of chunks alone stops at the first record past that bound.
#[test]
fn chunks_past_the_leading_bound_end_the_scan() {
    let mut bytes = bundle(TEXT, 0);
    let head = 2 * 65536 * 48;
    while bytes.len() <= head + 48 {
        bytes.extend_from_slice(&record(2, 1, 43, &[b'x'; 43]));
    }
    let (result, read, _) = staged(&bytes);
    let refused = result.expect_err("the bundle is past its maximum");
    assert!(refused.contains("more than 8 records"), "{refused}");
    // The record that passes the bound is the last one read.
    assert_eq!(read, head + 48);
}

/// Chunks after the first record of another tag are no part of the
/// manifest, and a length byte past 43 reads the 43 bytes a record holds.
#[test]
fn only_leading_chunks_count_and_a_long_length_is_capped() {
    let mut bytes = bundle(TEXT, 1);
    bytes.extend_from_slice(&manifest("records = 1\n"));
    let (result, _, _) = staged(&bytes);
    assert_eq!(result.expect("the bundle stages").manifest, TEXT);
    let mut long = record(1, 0, 0, &[]).to_vec();
    long.extend_from_slice(&record(2, 1, 255, &[b'x'; 43]));
    long.extend_from_slice(&record(4, 0, 0, &[]));
    let (result, read, _) = staged(&long);
    let refused = result.expect_err("the manifest pins nothing");
    assert!(refused.contains("pins no build"), "{refused}");
    assert_eq!(read, long.len());
}

/// A bundle without leading manifest chunks, an empty one, and one
/// whose manifest names no record count are refused.
#[test]
fn a_bundle_without_a_manifest_or_a_maximum_is_refused() {
    let bare = [record(1, 0, 0, &[]), record(4, 0, 0, &[])].concat();
    for (bytes, reason) in [
        (bare, "pins no build, executable, platform, toolchain"),
        (Vec::new(), "pins no build"),
        (
            bundle(&TEXT.replace("records = 8\n", ""), 1),
            "names no records count",
        ),
    ] {
        let refused = staged(&bytes).0.expect_err("the bundle is refused");
        assert!(refused.contains(reason), "{refused}");
    }
}

fn pins() -> Pins {
    let text = |value: &str| Text::new(value).expect("ASCII");
    Pins {
        build: text("b"),
        executable: text("e"),
        platform: text("p"),
        toolchain: text("t"),
    }
}

/// Each pin must equal the archive's; a repeated key and a missing pin
/// are refused; the watchdog parses as positive seconds.
#[test]
fn manifest_values_name_the_archive_pins_once() {
    let values = Values::parse(TEXT, "manifest").expect("the manifest parses");
    values.pinned(&pins(), "manifest").expect("the pins match");
    values
        .versioned(2, "manifest")
        .expect("the version matches");
    let refused = values
        .versioned(3, "manifest")
        .expect_err("another version");
    assert!(refused.contains("names version Some(\"2\")"), "{refused}");
    assert_eq!(values.watchdog(), Ok(None));
    for key in ["build", "executable", "platform", "toolchain"] {
        let other = TEXT.replace(&format!("{key} = "), &format!("{key} = x"));
        let values = Values::parse(&other, "manifest").expect("the manifest parses");
        let refused = values
            .pinned(&pins(), "manifest")
            .expect_err("another build");
        assert!(
            refused.starts_with(&format!("the manifest pins {key} ")),
            "{refused}"
        );
    }
    let scenario = format!("{TEXT}scenario = ab\n");
    assert_eq!(
        Values::parse(&scenario, "manifest")
            .expect("scenario")
            .scenario(),
        Some("ab")
    );
    assert_eq!(
        Values::parse(&(scenario + "scenario = cd\n"), "manifest").map(drop),
        Err("the manifest names scenario twice".to_owned())
    );
    let twice = format!("{TEXT}profile = upload\n");
    assert_eq!(
        Values::parse(&twice, "manifest").map(drop),
        Err("the manifest names profile twice".to_owned())
    );
    assert_eq!(
        Values::parse("profile = upload\n", "manifest").map(drop),
        Err("the manifest pins no build, executable, platform, toolchain".to_owned())
    );
    let timed = format!("{TEXT}watchdog = 2\n");
    let values = Values::parse(&timed, "manifest").expect("the manifest parses");
    assert_eq!(
        values.watchdog(),
        Ok(Some(std::time::Duration::from_secs(2)))
    );
    for value in ["0", "+1", "01", "1.5", "1e-20", "4294967296"] {
        let timed = format!("{TEXT}watchdog = {value}\n");
        assert!(
            Values::parse(&timed, "manifest")
                .expect("pins")
                .watchdog()
                .is_err(),
            "{value}"
        );
    }
    for key in ["records", "bytes"] {
        for value in ["0", "+1", "01", "1.5", "18446744073709551616"] {
            let old = if key == "records" { "8" } else { "4800" };
            let text = TEXT.replace(&format!("{key} = {old}"), &format!("{key} = {value}"));
            assert!(
                Values::parse(&text, "manifest")
                    .expect("pins")
                    .maximum()
                    .is_err(),
                "{key} {value}"
            );
        }
    }
    assert_eq!(
        super::seconds("1.5"),
        Ok(std::time::Duration::from_millis(1500))
    );
    assert_eq!(
        super::seconds("0.000000001"),
        Ok(std::time::Duration::from_nanos(1))
    );
    assert!(super::seconds("4294967295").is_ok());
    for refused in [
        "0",
        "-1",
        "nan",
        "inf",
        "x",
        "4294967296",
        "1e19",
        "1e-20",
        "1e-10",
    ] {
        assert!(super::seconds(refused).is_err(), "{refused}");
    }
}

#[test]
fn a_source_read_failure_preserves_partial_input_and_a_healthy_store() {
    struct Broken(bool);
    impl Read for Broken {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if std::mem::replace(&mut self.0, true) {
                Err(io::Error::from_raw_os_error(libc::EIO))
            } else {
                buffer[..48].copy_from_slice(&record(1, 0, 0, &[]));
                Ok(48)
            }
        }
    }
    let case = crate::store::fixture::Case::new();
    let store = crate::store::Store::open(&case.state).expect("store");
    let name = crate::store::Name::new("input").expect("name");
    let mut stager = Stager::new(Broken(false));
    assert_eq!(
        store
            .copy_once(store.root(), &name, &mut stager, 0o400)
            .expect("copy"),
        crate::store::Creation::Created
    );
    assert_eq!(
        stager.read_error().expect("read failed").raw_os_error(),
        Some(libc::EIO)
    );
    assert!(
        stager
            .finish()
            .expect_err("refused source")
            .contains("bundle read failed")
    );
    assert_eq!(
        store
            .read(store.root(), &name, 48)
            .expect("read")
            .expect("partial input")
            .bytes(),
        record(1, 0, 0, &[])
    );
    let artifact = crate::store::Name::new("artifact").expect("name");
    assert_eq!(
        store
            .create_once(store.root(), &artifact, b"incomplete")
            .expect("healthy store"),
        crate::store::Creation::Created
    );
}
