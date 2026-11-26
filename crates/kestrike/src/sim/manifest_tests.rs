//! Strict manifest parsing, the canonical form and the recorder capacity.

use super::manifest::{KEYS, Manifest, ManifestError};
use super::trace::RECORD;

const EXECUTABLE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The build record digest every sample manifest pins.
const BUILD: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

/// Every key of a manifest for `profile` pinning `executable` on
/// `platform`, in schema order, each count at or above the mixed world's
/// own bound; `actors` and `upload_attempts` also cover every cluster
/// profile's.
pub(crate) fn sample_lines(
    profile: &str,
    executable: &str,
    platform: &str,
) -> Vec<(String, String)> {
    let values: [&str; KEYS.len()] = [
        "2",
        profile,
        "3",
        executable,
        "rustc 1.99.0 (00000000 2026-01-01)",
        BUILD,
        platform,
        "avx2,sse4.2",
        "base",
        "20000",
        "400",
        "5000",
        "32",
        "8",
        "32",
        "1048576",
        "1024",
        "32",
        "8",
        "4096",
        "65536",
        "4096",
        "32768",
        "65536",
        "1",
        "1",
        "1",
        "2",
        "3",
        "12",
        "16",
        "64",
        "64",
        "1000000",
        "48000000",
        "256",
        "600",
    ];
    KEYS.iter()
        .zip(values)
        .map(|(key, value)| ((*key).to_owned(), value.to_owned()))
        .collect()
}

/// [`sample_lines`] as manifest text.
pub(crate) fn sample(profile: &str, executable: &str, platform: &str) -> String {
    text(&sample_lines(profile, executable, platform))
}

fn lines() -> Vec<(String, String)> {
    sample_lines("upload", EXECUTABLE, "x86_64-linux")
}

pub(crate) fn text(lines: &[(String, String)]) -> String {
    lines
        .iter()
        .map(|(key, value)| format!("{key} = {value}\n"))
        .collect()
}

fn with(key: &str, value: &str) -> String {
    edited(lines(), &[(key, value)])
}

/// # Panics
///
/// If an edit names a key `lines` lacks.
pub(crate) fn edited(mut lines: Vec<(String, String)>, edits: &[(&str, &str)]) -> String {
    for (key, value) in edits {
        lines
            .iter_mut()
            .find(|(known, _)| known == key)
            .expect("a schema key")
            .1 = (*value).to_owned();
    }
    text(&lines)
}

/// A manifest with every key once parses to its values; its full text
/// parses back to it; its canonical form keeps every key but the CPU
/// feature set, so two manifests that differ only there share one
/// canonical form, which parses as a recorded manifest; the record maximum
/// is the smaller of the record count and the artifact bytes it fits.
#[test]
fn a_complete_manifest_parses_and_its_canonical_form_omits_cpu() {
    let manifest = Manifest::parse(&text(&lines())).unwrap();
    assert_eq!(manifest.profile, "upload");
    assert_eq!(manifest.root, 3);
    assert_eq!(manifest.count("tx_slots"), 1024);
    assert_eq!(manifest.executable, EXECUTABLE);
    assert_eq!(manifest.build, BUILD);
    assert_eq!(manifest.cpu, "avx2,sse4.2");
    let canonical = manifest.canonical();
    assert_eq!(
        canonical,
        text(
            &lines()
                .into_iter()
                .filter(|(key, _)| key != "cpu")
                .collect::<Vec<_>>()
        ),
        "the canonical form is every key but cpu in schema order"
    );
    assert_eq!(
        Manifest::parse(&manifest.text()).as_ref(),
        Ok(&manifest),
        "the full text parses back"
    );
    let recorded = Manifest::parse_canonical(&canonical).unwrap();
    assert_eq!(
        (recorded.cpu.as_str(), recorded.canonical()),
        ("unrecorded", canonical.clone())
    );
    let other = Manifest::parse(&with("cpu", "none")).unwrap();
    assert_eq!(other.canonical(), canonical);
    assert_ne!(
        Manifest::parse(&with("root", "8")).unwrap().canonical(),
        canonical
    );
    let rebuilt = "0".repeat(64);
    let pinned = Manifest::parse(&with("build", &rebuilt)).unwrap();
    assert_eq!(pinned.build, rebuilt);
    assert_eq!(
        pinned.canonical(),
        canonical.replacen(BUILD, &rebuilt, 1),
        "the canonical form carries the parsed build pin"
    );
    assert_eq!(manifest.capacity().records(), 48_000_000 / RECORD as u64);
    let small = manifest.clone().with("bytes", 4800);
    assert_eq!(small.capacity().records(), 4800 / RECORD as u64);
    assert_eq!(manifest.capacity().every(), 256);
}

/// Each malformation rejects with its own error: a line without ` = `, a
/// blank line, a first line naming another version or key, an unknown key, a
/// repeated key, a missing key, and values that do not parse.
#[test]
fn malformed_manifests_reject_with_their_own_errors() {
    let good = text(&lines());
    assert_eq!(
        Manifest::parse(&good.replacen("root = 3", "root: 3", 1)),
        Err(ManifestError::Syntax { line: 3 })
    );
    assert_eq!(
        Manifest::parse(&good.replacen("profile = upload\n", "profile = upload\n\n", 1)),
        Err(ManifestError::Syntax { line: 3 })
    );
    for version in ["1", "3"] {
        assert_eq!(
            Manifest::parse(&with("version", version)),
            Err(ManifestError::Version {
                found: Some(version.into())
            }),
            "version = {version}"
        );
    }
    let mut moved = lines();
    moved.swap(0, 1);
    assert_eq!(
        Manifest::parse(&text(&moved)),
        Err(ManifestError::Version { found: None })
    );
    assert_eq!(
        Manifest::parse(""),
        Err(ManifestError::Version { found: None })
    );
    assert_eq!(
        Manifest::parse(&format!("{good}color = blue\n")),
        Err(ManifestError::Unknown {
            key: "color".into()
        })
    );
    assert_eq!(
        Manifest::parse(&format!("{good}root = 3\n")),
        Err(ManifestError::Duplicate { key: "root" })
    );
    for key in &KEYS[1..] {
        let missing: Vec<_> = lines()
            .into_iter()
            .filter(|(known, _)| known != key)
            .collect();
        assert_eq!(
            Manifest::parse(&text(&missing)),
            Err(ManifestError::Missing { key }),
            "{key}"
        );
    }
    let (long_executable, long_build) = (format!("{EXECUTABLE}0"), format!("{BUILD}0"));
    let (odd_executable, odd_build) = (
        format!("g{}", &EXECUTABLE[1..]),
        format!("g{}", &BUILD[1..]),
    );
    for (key, value) in [
        ("root", "0"),
        ("root", "+7"),
        ("root", "07"),
        ("turns", "many"),
        ("every", "4294967296"),
        ("watchdog", "4294967296"),
        ("executable", &EXECUTABLE[1..]),
        ("executable", &EXECUTABLE.to_uppercase()),
        ("executable", &long_executable),
        ("executable", &odd_executable),
        ("build", &BUILD[1..]),
        ("build", &BUILD.to_uppercase()),
        ("build", &long_build),
        ("build", &odd_build),
        ("profile", " upload"),
        ("toolchain", ""),
        ("records", "9"),
    ] {
        let key = KEYS.iter().find(|known| **known == key).unwrap();
        assert_eq!(
            Manifest::parse(&with(key, value)),
            Err(ManifestError::Value { key }),
            "{key} = {value:?}"
        );
    }
    assert_eq!(
        Manifest::parse(&with("bytes", "432")),
        Err(ManifestError::Value { key: "records" }),
        "an artifact maximum without room reports the record maximum"
    );
}
