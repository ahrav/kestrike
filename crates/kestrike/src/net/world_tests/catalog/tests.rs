//! The capability catalog names exactly the profiles admission accepts.

use super::super::bundle::{HELD, Refusal, TOPOLOGY, admit, held_by, named};
use super::{Class, FIXED, SETTLED, class, listed, listing};
use crate::sim::manifest::{Form, KEYS, Manifest, ManifestError, form};
use crate::sim::manifest_tests::{edited, sample, sample_lines};

fn manifest(profile: &str) -> Manifest {
    let text = sample(profile, &"a".repeat(64), "x86_64-linux");
    Manifest::parse(&text).unwrap()
}

/// Every listed name admits a manifest at the sample bounds: each fixed
/// name, each history and every subset of the `settled-` words in
/// [`SETTLED`] order, which takes the class the family line names.
#[test]
fn every_listed_profile_admits() {
    let histories = super::super::histories::every().map(|history| history.name);
    for name in FIXED.iter().map(|entry| entry.name).chain(histories) {
        assert!(admit(&manifest(name)).is_ok(), "{name} admits");
    }
    for name in settled_names() {
        let expected = if name.split('-').any(|word| word == "planted") {
            Class::Control
        } else {
            Class::Live
        };
        assert_eq!(class(&name), Some(expected), "{name}");
        assert!(admit(&manifest(&name)).is_ok(), "{name} admits");
    }
}

/// `settled` and every `settled-` name joining a nonempty subset of
/// [`SETTLED`] in its order.
fn settled_names() -> impl Iterator<Item = String> {
    (0..1_usize << SETTLED.len()).map(|mask| {
        let words: Vec<&str> = SETTLED
            .iter()
            .enumerate()
            .filter_map(|(at, &word)| (mask & (1 << at) != 0).then_some(word))
            .collect();
        if words.is_empty() {
            "settled".to_owned()
        } else {
            format!("settled-{}", words.join("-"))
        }
    })
}

/// A name outside the catalog refuses as an unknown profile, a `settled-`
/// name with an unknown word and a prefix of a listed name included.
#[test]
fn an_unlisted_profile_refuses() {
    for name in [
        "unknown",
        "settled-unknown",
        "settled-",
        "settledtwice",
        "boundary-unknown",
        "uploa",
    ] {
        assert!(!listed(name), "{name:?}");
        assert!(
            matches!(admit(&manifest(name)), Err(Refusal::Profile)),
            "{name:?}"
        );
    }
}

/// The listing names the forms of `every` and `build`, the record-room
/// constraint, every fixed profile and history with its least admitted
/// bounds in [`HELD`] order, the expected ending of one passing, one
/// violating and one unsuccessful history, every milestone, the `settled-`
/// family with its word rules, the branch bounds and the topology. A
/// manifest admits at each listed bound and, where that bound is above the
/// least count a manifest can declare, refuses one below it naming that
/// bound. A count at its listed maximum parses.
#[test]
fn the_listing_names_what_admission_accepts() {
    let text = listing();
    for other in ["cluster-broad", "recovery-512", "no-such-profile"] {
        assert_eq!(super::super::bundle::composed_by(other), None, "{other}");
    }
    assert!(text.contains("key: every count min=1 max=4294967295\n"));
    assert!(text.contains("key: build sha256\n"));
    assert!(text.contains("constraint: min(records, bytes/48) >= ring+6 (+1 when every=1)\n"));
    assert!(text.contains(&format!(
        "key: pending count min=1 max={}\n",
        (isize::MAX as u64) / 48
    )));
    assert!(text.contains(&format!("held: {}\n", HELD.join(","))));
    let histories = super::super::histories::every().map(|history| history.name);
    for name in FIXED.iter().map(|entry| entry.name).chain(histories) {
        let line = text
            .lines()
            .find(|line| line.starts_with(&format!("profile: {name} ")))
            .unwrap_or_else(|| panic!("{name} is listed"));
        assert!(
            line.contains(" support=implemented campaign=unqualified held="),
            "{line}"
        );
        let rest = line.split_once(" held=").unwrap().1;
        let (held, topology) = match rest.split_once(' ') {
            Some((held, topology)) => (held, Some(topology)),
            None => (rest, None),
        };
        let declared = super::super::bundle::composed_by(name)
            .filter(|composed| *composed != TOPOLOGY)
            .map(|composed| format!("owners={} clients={}", composed.0, composed.1));
        assert_eq!(topology, declared.as_deref(), "{name}");
        let pairs: Vec<(&str, u64)> = held
            .split(',')
            .map(|pair| {
                let (key, value) = pair.split_once('=').unwrap();
                (key, value.parse().unwrap())
            })
            .collect();
        assert_eq!(
            pairs.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
            HELD,
            "{name}"
        );
        for (key, least) in pairs {
            assert!(least >= 1, "{name}: {key}");
            assert!(
                admit(&manifest(name).with(key, least)).is_ok(),
                "{name}: {key}"
            );
            if least > 1 {
                let below = manifest(name).with(key, least - 1);
                assert!(
                    matches!(admit(&below), Err(Refusal::Bound(bound)) if bound == key),
                    "{name}: {key}"
                );
            }
        }
    }
    assert!(
        text.contains(" held=actors=13,"),
        "a two-owner history holds its peer's actors"
    );
    // The supervisor's control table records this count as each ordering
    // control's n.
    for depth in 1..=3 {
        let line = format!("profile: cluster-order-{depth} ");
        assert!(
            text.lines()
                .any(|listed| listed.starts_with(&line) && listed.contains(" held=actors=26,")),
            "{line}"
        );
    }
    assert!(
        text.lines()
            .any(|line| line.starts_with("profile: h6-get ")
                && line.ends_with(" owners=2 clients=4")),
        "a two-owner history lists its topology"
    );
    for (name, expected) in [
        ("h1-get", "pass"),
        ("h1-get-stale", "violation"),
        ("h1-get-unheld", "unsuccessful"),
    ] {
        assert!(
            text.contains(&format!(
                "profile: {name} class=history expected={expected} support=implemented "
            )),
            "{name}"
        );
    }
    for milestone in super::super::branch::MILESTONES {
        assert!(text.contains(&format!("milestone: {milestone}\n")));
    }
    assert!(text.contains(&format!(
        "family: settled-WORDS words={} each=at-most-once applied=left-to-right class=live,control-when-planted ",
        SETTLED.join(",")
    )));
    assert!(text.contains("branch: suffixes=1..16 siblings=1..4\n"));
    assert!(
        text.contains(
            "topology: owners=1 clients=2 configurable=no; cluster profiles draw theirs\n"
        )
    );
    assert!(text.contains(
        "\ncluster: cluster-broad generator=4 owners=2..4 keys=3..6 clients=2 sizes=4096,16384,24476 hot_slots=3 concurrency=2 phases=3 phase_ops=24 gap_us=0 window=1 compact=true faults=loss:10,duplicate:10,reorder:10,delay:2,stale:0,truncate:0,would_block:0,error:0 device=write_error:0,read_error:0,write_torn:0,read_partial:0 sustained=false delayed_returns=true invalidate=true versioned=false cancel=true minima=published:4,hits:1,cross:0,faults:1,healthy:3,reused:0 unavailable=node-lifecycle,session-lifecycle,membership,placement\n"
    ));
    assert!(text.contains(" phases=731 phase_ops=16 gap_us=86400000000 window=30 compact=true "));
    assert!(text.contains(" phases=12 phase_ops=24 gap_us=86400000000 window=2 compact=true "));
    let manifest_text = sample("upload", &"a".repeat(64), "x86_64-linux")
        .replace("every = 256", "every = 4294967295");
    assert!(Manifest::parse(&manifest_text).is_ok());
}

/// The listing declares one failure for each history that expects no
/// pass and none for a history that passes: a violation with the code its
/// failure identity holds for the obligation and its rule, or the witness
/// an unsuccessful run names. Each such witness is printable ASCII of
/// fewer than 41 bytes, so a summary prints it whole and a sweep can
/// credit it.
#[test]
fn the_listing_declares_the_failure_of_each_history_that_expects_no_pass() {
    let text = listing();
    for history in super::super::histories::every() {
        let declared = text
            .lines()
            .filter(|line| line.starts_with(&format!("fails: {} ", history.name)))
            .count();
        let passes = history.expect == super::super::histories::Expect::Pass;
        assert_eq!(declared, usize::from(!passes), "{}", history.name);
        if let super::super::histories::Expect::Unsuccessful(witness) = history.expect {
            assert!(witness.len() < 41, "{}: {witness}", history.name);
            assert!(
                witness.bytes().all(|byte| (b' '..=b'~').contains(&byte)),
                "{}",
                history.name
            );
        }
    }
    for line in [
        "fails: h1-get-stale violation 2 a qualified GET missed the visible version's exact bytes\n",
        "fails: h1-get-unheld unsuccessful old read held\n",
        "fails: i10-held-count-differs violation 8 an upload's held count left its lane ring's entries\n",
    ] {
        assert!(text.contains(line), "{line}");
    }
}

#[test]
fn the_listing_names_each_fact_once() {
    let text = listing();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[..3], ["capabilities: 5", "summary: 1", "manifest: 2"]);
    let mut seen = std::collections::HashSet::new();
    for line in &lines {
        assert!(seen.insert(*line), "{line} repeats");
    }
    let starting = |prefix: &str| lines.iter().filter(|line| line.starts_with(prefix)).count();
    for prefix in [
        "capabilities: ",
        "summary: ",
        "manifest: ",
        "held: ",
        "family: ",
        "branch: ",
        "topology: ",
    ] {
        assert_eq!(starting(prefix), 1, "{prefix}");
    }
    for key in KEYS {
        assert_eq!(starting(&format!("key: {key} ")), 1, "{key}");
    }
    assert_eq!(starting("key: "), KEYS.len());
    for line in [
        "key: version version=2",
        "key: profile text",
        "key: executable sha256",
        "key: root count min=1 max=18446744073709551615",
        "key: watchdog count min=1 max=4294967295",
    ] {
        assert!(seen.contains(line), "{line}");
    }
    let profiles: Vec<&str> = lines
        .iter()
        .filter_map(|line| line.strip_prefix("profile: "))
        .map(|rest| rest.split_once(' ').map_or(rest, |(name, _)| name))
        .collect();
    let mut expected: Vec<&str> = FIXED
        .iter()
        .map(|entry| entry.name)
        .chain(super::super::histories::every().map(|history| history.name))
        .collect();
    let mut sorted = profiles.clone();
    sorted.sort_unstable();
    expected.sort_unstable();
    assert_eq!(sorted, expected);
    sorted.dedup();
    assert_eq!(sorted.len(), profiles.len(), "a profile is listed twice");
    for (name, listed_class) in [
        ("upload", "live"),
        ("planted", "control"),
        ("recovery-512", "recovery"),
        ("h1-get", "history"),
    ] {
        assert_eq!(
            starting(&format!("profile: {name} class={listed_class} ")),
            1,
            "{name}"
        );
    }
}

#[test]
fn parse_refuses_a_value_outside_its_listed_form() {
    let parsed = |key: &str, value: &str| {
        let lines = sample_lines("upload", &"a".repeat(64), "x86_64-linux");
        Manifest::parse(&edited(lines, &[(key, value)]))
    };
    for key in KEYS {
        let refused = match form(key) {
            Form::Version => vec!["1".to_owned(), "3".to_owned()],
            Form::Text => vec![String::new(), " upload".to_owned()],
            Form::Digest => vec!["a".repeat(63), "A".repeat(64), "g".repeat(64)],
            Form::Count { max } => {
                let mut values = vec!["0".to_owned()];
                values.extend(max.checked_add(1).map(|past| past.to_string()));
                values
            }
        };
        for value in refused {
            let expected = if key == "version" {
                ManifestError::Version {
                    found: Some(value.clone()),
                }
            } else {
                ManifestError::Value { key }
            };
            assert_eq!(parsed(key, &value), Err(expected), "{key} = {value:?}");
        }
    }
}

/// Each fixed profile's listed class matches its scenario: a recovery
/// profile's cut table makes it a recovery run, a planted fault or a
/// corrupted resident a control, and any other scenario a live run.
#[test]
fn every_fixed_class_matches_its_scenario() {
    for entry in &FIXED {
        let (_, plan, _) = named(entry.name, 1).unwrap();
        let cluster_control = matches!(
            plan.world,
            super::super::WorldKind::Cluster(shape) if shape.control()
        );
        let expected = if plan.recovery().is_some() {
            Class::Recovery
        } else if cluster_control
            || plan.corrupt_resident
            || plan.plant != super::super::Plant::None
        {
            Class::Control
        } else {
            Class::Live
        };
        assert_eq!(entry.class, expected, "{}", entry.name);
    }
}

/// Every name of the `settled-` family shares the bounds reported in its
/// `held=` field.
#[test]
fn the_settled_family_lists_one_held_bound() {
    let settled = held_by("settled").unwrap();
    for name in settled_names() {
        assert_eq!(held_by(&name).unwrap(), settled, "{name}");
    }
    let line = listing()
        .lines()
        .find(|line| line.starts_with("family: settled-WORDS "))
        .map(str::to_owned)
        .expect("the family is listed");
    let pairs: Vec<&str> = line
        .split_once(" held=")
        .unwrap_or_else(|| panic!("{line}"))
        .1
        .split(',')
        .collect();
    let expected: Vec<String> = settled
        .iter()
        .map(|(key, least)| format!("{key}={}", (*least).max(1)))
        .collect();
    assert_eq!(pairs, expected);
}

#[test]
fn the_record_room_constraint_is_the_bound_parse_holds() {
    for every in [1_u64, 256] {
        for ring in [1_u64, 8] {
            let least = ring + 6 + u64::from(every == 1);
            for room in least - 2..=least + 2 {
                // One pair binds the record count, the other a byte count
                // 47 bytes past a whole record, which rounds down.
                for (records, bytes) in [(room, 48_000_000), (1_000_000, room * 48 + 47)] {
                    let values = [every, ring, records, bytes].map(|value| value.to_string());
                    let edits: Vec<(&str, &str)> = ["every", "ring", "records", "bytes"]
                        .into_iter()
                        .zip(values.iter().map(String::as_str))
                        .collect();
                    let lines = sample_lines("upload", &"a".repeat(64), "x86_64-linux");
                    let parsed = Manifest::parse(&edited(lines, &edits));
                    let case = format!("every={every} ring={ring} records={records} bytes={bytes}");
                    if room >= least {
                        assert!(parsed.is_ok(), "{case}: {parsed:?}");
                    } else {
                        assert_eq!(
                            parsed,
                            Err(ManifestError::Value { key: "records" }),
                            "{case}"
                        );
                    }
                }
            }
        }
    }
}

/// Admission holds the listed field constraint at every room from the
/// least the recorder opens with, for checkpoint intervals where the
/// `c/every` term binds, with the record count or the byte count limiting
/// the room.
#[test]
fn the_recorder_constraint_is_the_bound_admission_holds() {
    assert!(listing().contains(
        "constraint: min(records, bytes/48) >= c + c/every + ring+5, c = ceil(canonical bytes/43) <= 65536\n"
    ));
    let mut both = [false; 2];
    for every in [1_u64, 2, 4, 256] {
        for room in (7 + u64::from(every == 1))..=80 {
            for (records, bytes) in [(room, 48_000_000), (1_000_000, room * 48 + 47)] {
                let m = manifest("upload")
                    .with("ring", 1)
                    .with("records", records)
                    .with("bytes", bytes)
                    .with("every", every);
                let c = (m.canonical().len() as u64).div_ceil(43);
                let holds = room >= c + c / every + 1 + 5;
                both[usize::from(holds)] = true;
                let case = format!("every={every} records={records} bytes={bytes}");
                match admit(&m) {
                    Ok(_) => assert!(holds, "{case}"),
                    Err(refusal) => {
                        assert_eq!(refusal, Refusal::Bound("records"), "{case}");
                        assert!(!holds, "{case}");
                    }
                }
            }
        }
    }
    assert_eq!(both, [true, true], "the sweep admits and refuses");
}

/// A pending buffer or ring at its listed maximum, the most records whose
/// bytes `isize` holds, parses without allocating either buffer.
#[test]
fn a_buffer_at_its_listed_maximum_parses() {
    let Form::Count { max } = form("pending") else {
        panic!("pending is a count");
    };
    assert_eq!(max, (isize::MAX as u64) / 48);
    assert_eq!(max, crate::sim::trace::MAX_BUFFERED);
    assert_eq!(form("ring"), Form::Count { max });
    let (most, large) = (max.to_string(), u64::MAX.to_string());
    for edits in [
        vec![("pending", most.as_str())],
        vec![
            ("ring", most.as_str()),
            ("records", large.as_str()),
            ("bytes", large.as_str()),
        ],
    ] {
        let lines = sample_lines("upload", &"a".repeat(64), "x86_64-linux");
        let parsed = Manifest::parse(&edited(lines, &edits));
        assert!(parsed.is_ok(), "{edits:?}: {parsed:?}");
    }
}

/// A canonical manifest of [`FIELD_CHUNKS`](crate::sim::trace::FIELD_CHUNKS)
/// chunks admits under a record maximum that holds it, and one byte more
/// refuses, as the listed field constraint bounds `c`.
#[test]
fn a_manifest_past_the_field_chunk_bound_refuses() {
    let base = manifest("upload")
        .with("records", 1_000_000)
        .with("bytes", 48_000_000);
    let padding = 65_536 * 43 - base.canonical().len();
    for (extra, admitted) in [(0, true), (1, false)] {
        let toolchain = format!("{}{}", base.toolchain, "t".repeat(padding + extra));
        let lines = sample_lines("upload", &"a".repeat(64), "x86_64-linux");
        let text = edited(
            lines,
            &[
                ("toolchain", toolchain.as_str()),
                ("records", "1000000"),
                ("bytes", "48000000"),
            ],
        );
        let wide = Manifest::parse(&text).unwrap();
        assert_eq!(wide.canonical().len(), 65_536 * 43 + extra);
        let refusal = admit(&wide).err();
        let expected = (!admitted).then_some(Refusal::Field);
        assert_eq!(
            refusal,
            expected,
            "{} canonical bytes",
            wide.canonical().len()
        );
    }
}

/// The `settled-` words apply left to right, so of two geometry words the
/// later one sets the scenario's geometry.
#[test]
fn settled_words_apply_left_to_right() {
    let geometry = |name: &str| named(name, 1).unwrap().1.geometry;
    assert_eq!(
        geometry("settled-scaled-cramped"),
        geometry("settled-cramped")
    );
    assert_eq!(
        geometry("settled-cramped-scaled"),
        geometry("settled-scaled")
    );
    assert_ne!(geometry("settled-scaled"), geometry("settled-cramped"));
}

/// A `settled-` name that repeats a word is unlisted and refuses, so no
/// run of doubling words overflows the drain; one that names each word
/// once admits.
#[test]
fn a_repeated_settled_word_refuses() {
    let repeated = format!("settled{}", "-twice".repeat(27));
    for name in [
        "settled-twice-twice",
        "settled-planted-faulted-planted",
        &repeated,
    ] {
        assert!(!listed(name), "{name}");
        assert!(
            matches!(admit(&manifest(name)), Err(Refusal::Profile)),
            "{name}"
        );
    }
    assert!(admit(&manifest("settled-twice-invalidating")).is_ok());
}
