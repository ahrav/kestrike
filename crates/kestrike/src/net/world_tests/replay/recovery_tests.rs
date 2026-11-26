//! Replaying a recovery-profile bundle: the recorded `recovery-cut-v1`
//! record replays to its digest, a record that fails to parse or differs
//! from the one this executable derives refuses before the first turn by
//! its own error, and a changed Config outside the record runs and reports
//! Diverged.

use crate::sim::manifest::{Manifest, ManifestError};
use crate::sim::recovery::{Mismatch, RecordError, Recovery, embedded};
use crate::sim::trace::{Field, LoadError, RECORD, load, reseal};

use super::super::bundle::{Unadmitted, admit, traced};
use super::{Refused, Replayed, replay};

const FIELD: u8 = 2;
const MANIFEST: u8 = Field::Manifest as u8;
const CONFIG: u8 = Field::Config as u8;

fn manifest_of(profile: &str) -> Manifest {
    let text = crate::sim::manifest_tests::sample(profile, &"a".repeat(64), "x86_64-linux");
    Manifest::parse(&text).unwrap()
}

fn recorded(profile: &str) -> (Manifest, Vec<u8>) {
    let manifest = manifest_of(profile);
    let bytes = traced(admit(&manifest).unwrap(), Vec::new()).sink;
    (manifest, bytes)
}

/// `bytes` with field `field`'s bytes rewritten by `edit` and rechunked.
fn rewritten(
    bytes: &[u8],
    manifest: &Manifest,
    field: u8,
    edit: impl FnOnce(&mut Vec<u8>),
) -> Vec<u8> {
    reseal(bytes, manifest.capacity(), |records| {
        let ours = |record: &[u8; RECORD]| record[0] == FIELD && record[1] == field;
        let mut data: Vec<u8> = records
            .iter()
            .filter(|record| ours(record))
            .flat_map(|record| record[5..5 + usize::from(record[4])].to_vec())
            .collect();
        edit(&mut data);
        let at = records.iter().position(ours).unwrap();
        records.retain(|record| !ours(record));
        let fields: Vec<[u8; RECORD]> = data
            .chunks(RECORD - 5)
            .enumerate()
            .map(|(chunk, bytes)| {
                let mut record = [0; RECORD];
                record[..2].copy_from_slice(&[FIELD, field]);
                record[2..4].copy_from_slice(&(chunk as u16).to_le_bytes());
                record[4] = bytes.len() as u8;
                record[5..5 + bytes.len()].copy_from_slice(bytes);
                record
            })
            .collect();
        records.splice(at..at, fields);
    })
}

/// `bytes` with the first occurrence of `from` in its Config field
/// replaced by `to`, of the same length.
fn config_edited(bytes: &[u8], manifest: &Manifest, from: &str, to: &str) -> Vec<u8> {
    assert_eq!(from.len(), to.len());
    rewritten(bytes, manifest, CONFIG, |config| {
        let at = config
            .windows(from.len())
            .position(|window| window == from.as_bytes())
            .unwrap_or_else(|| panic!("{from} in the Config field"));
        config[at..at + to.len()].copy_from_slice(to.as_bytes());
    })
}

/// A recovery run records the record its profile derives after the
/// profile record, loads, and replays to its digest, decision count and
/// terminal.
#[test]
fn a_recovery_bundle_records_its_record_and_replays() {
    for (profile, recovery) in [
        ("recovery-16k", Recovery::Kib16),
        ("recovery-512", Recovery::Sector),
    ] {
        let (_, bytes) = recorded(profile);
        let loaded = load(&bytes, u64::MAX).unwrap();
        let config = &loaded
            .fields
            .iter()
            .find(|(field, _)| *field == Field::Config)
            .unwrap()
            .1;
        assert_eq!(embedded(config), Ok(recovery.record()), "{profile}");
        assert_eq!(replay(&bytes).unwrap().0, Replayed::Reproduced, "{profile}");
    }
}

/// Each record field that differs from the one this executable derives
/// refuses the replay before its first turn, by the field's own mismatch,
/// and a record that does not parse refuses at load by its parse error.
#[test]
fn each_differing_record_field_refuses_before_the_first_turn() {
    let (manifest, bytes) = recorded("recovery-16k");
    let record = String::from_utf8(Recovery::Kib16.record().encode()).unwrap();
    let line = |key: &str| {
        record
            .lines()
            .find(|line| line.starts_with(&format!("{key} = ")))
            .unwrap()
            .to_owned()
    };
    let flipped = |line: &str| {
        let mut line = line.as_bytes().to_vec();
        let last = line.len() - 1;
        line[last] = if line[last] == b'1' { b'2' } else { b'1' };
        String::from_utf8(line).unwrap()
    };
    for (key, mismatch) in [
        ("protocol", Mismatch::Protocol),
        ("format", Mismatch::Format),
        ("profile", Mismatch::Profile),
        ("identify", Mismatch::Identify),
        ("descriptor", Mismatch::Descriptor),
        ("registry", Mismatch::Registry),
        ("workload", Mismatch::Workload),
        ("activation", Mismatch::Activation),
        ("bound", Mismatch::Bound),
    ] {
        let line = line(key);
        let edited = config_edited(&bytes, &manifest, &line, &flipped(&line));
        assert_eq!(
            replay(&edited).err(),
            Some(Refused::Recovery(Unadmitted::Mismatch(mismatch))),
            "{key}"
        );
    }
    let malformed = config_edited(&bytes, &manifest, "bound = ", "bound - ");
    assert_eq!(
        replay(&malformed).err(),
        Some(Refused::Recovery(Unadmitted::Record(RecordError::Syntax {
            line: 10
        })))
    );
}

/// A 16 KiB bundle replayed under the 512-byte profile refuses by its
/// profile before the first turn.
#[test]
fn a_bundle_under_another_recovery_profile_refuses() {
    let (manifest, bytes) = recorded("recovery-16k");
    let moved = rewritten(&bytes, &manifest, MANIFEST, |text| {
        let edited = String::from_utf8(text.clone())
            .unwrap()
            .replace("profile = recovery-16k", "profile = recovery-512");
        *text = edited.into_bytes();
    });
    assert_eq!(
        replay(&moved).err(),
        Some(Refused::Recovery(Unadmitted::Mismatch(Mismatch::Profile)))
    );
}

/// A changed Config byte outside the record runs the replay and reports
/// Diverged.
#[test]
fn a_changed_config_outside_the_record_diverges() {
    let (manifest, bytes) = recorded("recovery-16k");
    let changed = rewritten(&bytes, &manifest, CONFIG, |config| {
        let last = config.len() - 1;
        config[last] ^= 1;
    });
    assert!(matches!(
        replay(&changed),
        Ok((Replayed::Diverged { .. }, _))
    ));
}

/// A manifest with every schema key parses under a recovery profile, and
/// one key more is unknown.
#[test]
fn a_recovery_manifest_keeps_its_schema_keys() {
    let text = crate::sim::manifest_tests::sample("recovery-16k", &"a".repeat(64), "x86_64-linux");
    assert!(Manifest::parse(&text).is_ok());
    assert_eq!(
        Manifest::parse(&format!("{text}recovery = 1\n")),
        Err(ManifestError::Unknown {
            key: "recovery".into()
        })
    );
}

/// A recovery profile's recorder and replayer both run under the
/// profile's admission, the only path that lets a persistence-domain
/// decision through; a live profile's recorder uses the plain chooser.
#[test]
fn a_recovery_scenario_admits_its_cut_table_on_both_choosers() {
    let (manifest, bytes) = recorded("recovery-16k");
    let loaded = load(&bytes, u64::MAX).unwrap();
    let admitted = admit(&manifest).unwrap();
    let admission = Recovery::Kib16.admission();
    assert_eq!(admitted.recorder().admission(), Some(&admission));
    assert_eq!(
        admitted.replayer(&loaded).unwrap().admission(),
        Some(&admission)
    );
    let live = manifest_of("upload");
    assert_eq!(admit(&live).unwrap().recorder().admission(), None);
}

/// The replay chooser of a recovery profile reads the record from the
/// loaded Config field and refuses one that does not parse before any
/// decision.
#[test]
fn a_recovery_replayer_refuses_an_unparsed_record() {
    let (manifest, bytes) = recorded("recovery-16k");
    let mut loaded = load(&bytes, u64::MAX).unwrap();
    let admitted = admit(&manifest).unwrap();
    assert!(admitted.replayer(&loaded).is_ok());
    for (field, bytes) in &mut loaded.fields {
        if *field == Field::Config {
            bytes.truncate(bytes.len() / 2);
        }
    }
    assert!(matches!(
        admitted.replayer(&loaded),
        Err(Unadmitted::Record(_))
    ));
}

/// A recovery bundle relabelled with a live profile refuses to load, its
/// embedded record standing in a live Config; an unknown `recovery-` name
/// selects no scenario.
#[test]
fn a_recovery_bundle_under_a_live_profile_refuses() {
    let (manifest, bytes) = recorded("recovery-16k");
    let live = rewritten(&bytes, &manifest, MANIFEST, |text| {
        let edited = String::from_utf8(text.clone())
            .unwrap()
            .replace("profile = recovery-16k", "profile = upload");
        *text = edited.into_bytes();
    });
    assert!(matches!(
        load(&live, u64::MAX),
        Err(LoadError::Recovery {
            error: RecordError::Live,
            ..
        })
    ));
    assert_eq!(
        replay(&live).err(),
        Some(Refused::Recovery(Unadmitted::Record(RecordError::Live)))
    );
    let (_, upload) = recorded("upload");
    assert!(load(&upload, u64::MAX).is_ok());
    let unknown = manifest_of("recovery-foo");
    assert!(matches!(
        admit(&unknown).err(),
        Some(super::super::bundle::Refusal::Profile)
    ));
}
