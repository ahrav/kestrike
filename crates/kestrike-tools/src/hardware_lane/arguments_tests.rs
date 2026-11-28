//! The episode name, the seconds reader, the platform refusal and the lane's constants.

use std::error::Error as _;
use std::io;
use std::path::Path;

use crate::hardware_lane::{
    CONTROLLER_SECONDS, CUSTODY_DIR, ENVELOPE_FIELDS, ENVIRONMENT_NAME, EPISODE_NAME, Error, HELD,
    IDENTITY_LINES, INTERRUPTED, MANIFEST, OBSERVED, OBSERVER_SECONDS, PLATFORM_NAMED_BY,
    STOP_SECONDS, episode_name, finite_seconds, identity_lines, manifest_path, platform_refusal,
};
use crate::text::Text;

const NOT_EPISODE: &str =
    " is not an episode name of letters, digits, '.', '_' and '-' starting with a letter or digit";

/// A name of one plain file name component passes as it is; an empty name, a leading `.`, a trailing line
/// feed and a letter outside ASCII are refused with the name's repr.
#[test]
fn an_episode_name_passes_whole_or_is_refused_with_its_repr() {
    for name in ["fis-1", "a.b_c-1"] {
        assert_eq!(episode_name(&Text::from(name)).unwrap(), &Text::from(name));
    }
    for (name, shown) in [
        ("", "''"),
        (".hidden", "'.hidden'"),
        ("name\n", r"'name\n'"),
        ("épisode", "'épisode'"),
    ] {
        let Err(Error::Refused(sentence)) = episode_name(&Text::from(name)) else {
            panic!("{name:?} is refused")
        };
        assert_eq!(
            sentence,
            format!("{shown}{NOT_EPISODE}").as_str(),
            "{name:?}"
        );
    }
}

/// The reader strips the white space `int()` strips, which holds U+00A0, U+0085 and U+2028 and leaves
/// U+001C to U+001F, reads Rust's float syntax, and refuses a value that is not finite or is below 0 with
/// the text's repr.
#[test]
fn finite_seconds_reads_a_finite_duration_of_zero_or_more_seconds() {
    for (seconds, value) in [
        ("0", 0.0),
        ("-0.0", -0.0),
        ("1e3", 1000.0),
        (" 2 ", 2.0),
        ("\u{a0}2", 2.0),
        ("\u{85}2", 2.0),
        ("\u{2028}2", 2.0),
    ] {
        let read = finite_seconds(&Text::from(seconds)).unwrap();
        assert_eq!(read.to_bits(), f64::to_bits(value), "{seconds:?}");
    }
    for (seconds, shown) in [
        ("inf", "'inf'"),
        ("nan", "'nan'"),
        ("NaN", "'NaN'"),
        ("+Infinity", "'+Infinity'"),
        ("-1", "'-1'"),
        ("1e400", "'1e400'"),
    ] {
        let Err(Error::Refused(sentence)) = finite_seconds(&Text::from(seconds)) else {
            panic!("{seconds:?} is refused")
        };
        assert_eq!(
            sentence,
            format!("{shown} is not a finite duration of zero or more seconds").as_str(),
            "{seconds:?}"
        );
    }
    for seconds in [
        "x", "", "\u{1c}2", "\u{1d}2", "\u{1e}2", "\u{1f}2", "1_0", "\u{661}",
    ] {
        assert!(
            matches!(finite_seconds(&Text::from(seconds)), Err(Error::NoNumber)),
            "{seconds:?} is no number"
        );
    }
}

#[test]
fn the_platform_refusal_names_the_row_or_none_and_where_the_name_comes_from() {
    let named = platform_refusal(Some(&Text::from("x")), "KESTRIKE_HARDWARE_PLATFORM");
    assert_eq!(
        named.sentence().unwrap(),
        &"no platform row 'x'; name the host's row with KESTRIKE_HARDWARE_PLATFORM"
    );
    let none = platform_refusal(None, PLATFORM_NAMED_BY);
    assert_eq!(
        none.sentence().unwrap(),
        &"no platform row named; name the host's row with --platform or KESTRIKE_HARDWARE_PLATFORM"
    );
}

#[test]
fn the_constants_hold_the_lanes_values() {
    assert_eq!(MANIFEST, "scripts/hardware-profiles.json");
    assert_eq!(
        manifest_path(Path::new("/top")),
        Path::new("/top/scripts/hardware-profiles.json")
    );
    assert_eq!(
        [CONTROLLER_SECONDS, STOP_SECONDS, OBSERVER_SECONDS].map(f64::to_bits),
        [30.0, 10.0, 5.0].map(f64::to_bits)
    );
    assert_eq!((HELD, INTERRUPTED), (4, 5));
    assert_eq!(CUSTODY_DIR, "/var/tmp/kestrike-hardware-custody");
    assert_eq!(EPISODE_NAME, "[A-Za-z0-9][A-Za-z0-9._-]*");
    assert_eq!(ENVIRONMENT_NAME, "KESTRIKE_[A-Z0-9_]+");
    assert_eq!(
        OBSERVED,
        [
            "instance_type",
            "cpu_features",
            "cpu_family",
            "kernel",
            "firmware",
            "vfio",
            "numa_nodes",
            "page_size",
            "hugepage_size",
            "devices",
        ]
    );
    assert_eq!(ENVELOPE_FIELDS[..OBSERVED.len()], OBSERVED);
    let lines: [(&str, &[&str]); 2] = [
        ("aarch64", &["CPU implementer", "CPU part"]),
        ("x86_64", &["vendor_id", "cpu family", "model"]),
    ];
    assert_eq!(IDENTITY_LINES, lines);
    assert_eq!(identity_lines(&Text::from("x86_64")), lines[1].1);
    assert_eq!(identity_lines(&Text::from("aarch64")), lines[0].1);
    assert!(identity_lines(&Text::from("riscv64")).is_empty());
}

/// A refusal writes its sentence, text that is no number writes its own statement, and a system error
/// writes the system's text and is the error's source.
#[test]
fn an_error_writes_its_kind_and_a_system_error_is_its_source() {
    let refused = platform_refusal(None, "X");
    assert_eq!(
        refused.to_string(),
        "no platform row named; name the host's row with X"
    );
    assert!(refused.source().is_none());
    assert_eq!(Error::NoNumber.to_string(), "the text is no number");
    let system = Error::System(io::Error::from_raw_os_error(2));
    assert_eq!(
        system.to_string(),
        io::Error::from_raw_os_error(2).to_string()
    );
    assert!(system.sentence().is_none());
    let source = system.source().expect("a system error has its source");
    assert_eq!(
        source
            .downcast_ref::<io::Error>()
            .and_then(io::Error::raw_os_error),
        Some(2)
    );
}
