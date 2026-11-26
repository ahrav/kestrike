//! Sessions: windows committed durably with a chained digest, exact replay
//! from the origin, and refusal of changed, missing, torn or incomplete
//! windows.

use sha2::Digest;

use super::{
    BEGIN, Budget, END, Writer, chained, chunk, committed, divergence, ended, hex, origin,
};

/// A budget no test session reaches.
const AMPLE: Budget = Budget {
    records: u64::MAX,
    bytes: u64::MAX,
};

/// The admitted sample manifest of `name` from `root`, with the bounds a
/// cluster session needs.
fn manifest(name: &str, root: u64) -> crate::sim::manifest::Manifest {
    let text = crate::sim::manifest_tests::sample(name, &"a".repeat(64), "x86_64-linux")
        .replace("root = 3", &format!("root = {root}"));
    crate::sim::manifest::Manifest::parse(&text)
        .unwrap()
        .with("actors", 64)
        .with("turns", 1 << 40)
        .with("same_time", 4_000)
        .with("no_progress", 50_000)
}

/// Runs `name` from `root` as a session into a new directory `dir` within
/// `budget`, through the admitted manifest as the worker's session form
/// does.
fn session_within(
    name: &str,
    root: u64,
    dir: &std::path::Path,
    budget: Budget,
) -> (Writer, super::super::cluster::Ran) {
    std::fs::create_dir(dir).unwrap();
    let manifest = manifest(name, root);
    let admitted = super::super::bundle::admit(&manifest).unwrap();
    let mut writer = Writer::new(dir, &manifest.text(), budget).unwrap();
    let ran = super::super::cluster::session(&admitted, &mut writer).unwrap();
    writer.finish(&format!(
        "end: stop={} counts={}",
        ran.stop(),
        ran.judged().counts()
    ));
    (writer, ran)
}

fn session(name: &str, root: u64, dir: &std::path::Path) -> Writer {
    session_within(name, root, dir, AMPLE).0
}

fn scratch(name: &str) -> std::path::PathBuf {
    super::super::scratch(name).unwrap()
}

/// Two sessions of one root commit the same windows with the same chained
/// digests, 6 for 12 phases cut every 2, and every later chunk starts past
/// the run's first record; the first window's line names its known verdict
/// and healed count; every committed chunk checks against its index line
/// and the end against the windows and tail; a changed chunk byte, a
/// missing chunk, a changed chain, swapped lines, a repeated line, a line
/// or end naming a field twice, a torn last line, an index with carriage
/// returns, a changed tail, an end naming another chain or holding a
/// carriage return, a torn, empty or doubled end and a missing end refuse;
/// a session of another root first departs at its first record, the run's
/// record naming its root.
#[test]
fn windows_commit_replay_exactly_and_refuse_changes() {
    let base = scratch("session-windows");
    let (first, second) = (base.join("first"), base.join("second"));
    let one = session("cluster-late-stale", 4, &first);
    let two = session("cluster-late-stale", 4, &second);
    assert!(one.failed().is_none() && two.failed().is_none());
    assert_eq!(one.committed(), 6);
    let index = std::fs::read_to_string(first.join("index")).unwrap();
    assert_eq!(
        index,
        std::fs::read_to_string(second.join("index")).unwrap()
    );
    assert_eq!(one.chain(), two.chain());
    assert!(one.high_water > 0);
    let end = std::fs::read_to_string(first.join("end")).unwrap();
    assert!(
        end.starts_with("end: stop=goal counts=false windows=6 "),
        "{end}"
    );
    let (lines, chain) = committed(&first).unwrap();
    assert_eq!((lines.len(), chain), (6, one.chain()));
    assert!(ended(&first, lines.len(), &chain).is_ok());
    let line = &lines[0];
    assert!(
        line.contains(" verdict=pass ") && line.ends_with(" healed=1"),
        "{line}"
    );
    for (at, line) in lines.iter().enumerate().skip(1) {
        let bytes = chunk(&first, at, line).unwrap();
        assert!(!bytes.is_empty() && bytes[0] != BEGIN, "window {at}");
    }
    let refused = |dir: &std::path::Path| match committed(dir) {
        Ok((lines, chain)) => ended(dir, lines.len(), &chain).unwrap_err(),
        Err(reason) => reason,
    };
    let path = first.join("windows").join("000001.chunk");
    let saved = std::fs::read(&path).unwrap();
    let mut bytes = saved.clone();
    bytes[10] ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    assert_eq!(refused(&first), "window 1's chunk is truncated or changed");
    std::fs::remove_file(&path).unwrap();
    assert!(refused(&first).starts_with("window 1's chunk: "));
    std::fs::write(&path, &saved).unwrap();
    let edited = |index: &str, expected: &str| {
        std::fs::write(first.join("index"), index).unwrap();
        assert_eq!(refused(&first), expected);
    };
    let zero_chain = index.replacen(
        lines[0]
            .split(' ')
            .find(|field| field.starts_with("chain="))
            .unwrap(),
        &format!("chain={}", "00".repeat(32)),
        1,
    );
    edited(&zero_chain, "window 0 is out of its chain");
    let mut swapped: Vec<&str> = index.lines().collect();
    swapped.swap(0, 1);
    edited(&(swapped.join("\n") + "\n"), "index line 0 is out of order");
    edited(
        &format!("{}\n{index}", lines[0]),
        "index line 1 is out of order",
    );
    let twice = index.replacen('\n', &format!(" digest={}\n", "00".repeat(32)), 1);
    edited(&twice, "window 0 names digest twice");
    edited(
        index.strip_suffix('\n').unwrap(),
        "the session index ends in a torn line",
    );
    edited(
        &index.replace('\n', "\r\n"),
        "the session index holds a carriage return",
    );
    let dropped: String = index
        .lines()
        .take(5)
        .map(|line| format!("{line}\n"))
        .collect();
    edited(
        &dropped,
        "the session's end names other windows than its index",
    );
    std::fs::write(first.join("index"), &index).unwrap();
    let tail = first.join("windows").join("tail.chunk");
    let kept_tail = std::fs::read(&tail).unwrap();
    std::fs::write(&tail, b"other").unwrap();
    assert_eq!(
        refused(&first),
        "the session's tail chunk is truncated or changed"
    );
    std::fs::write(&tail, kept_tail).unwrap();
    let end_path = first.join("end");
    std::fs::write(&end_path, end.replacen('\n', " counts=true\n", 1)).unwrap();
    assert_eq!(refused(&first), "the session's end names counts twice");
    std::fs::write(&end_path, end.replace('\n', "\r\n")).unwrap();
    assert_eq!(refused(&first), "the session's end holds a carriage return");
    let other_chain = end.replacen(
        &format!("chain={}", hex(&chain)),
        &format!("chain={}", "00".repeat(32)),
        1,
    );
    assert_ne!(other_chain, end);
    std::fs::write(&end_path, other_chain).unwrap();
    assert_eq!(
        refused(&first),
        "the session's end names other windows than its index"
    );
    for torn in [end.trim_end(), "", &format!("{end}{end}")] {
        std::fs::write(&end_path, torn).unwrap();
        assert_eq!(
            refused(&first),
            "the session is incomplete: its end line is torn",
            "{torn:?}"
        );
    }
    std::fs::remove_file(&end_path).unwrap();
    assert!(refused(&first).starts_with("the session is incomplete: its end: "));
    let other = base.join("other");
    session("cluster-late-stale", 5, &other);
    let (theirs, _) = committed(&other).unwrap();
    let (ours, _) = committed(&second).unwrap();
    let (ours, theirs) = (
        chunk(&second, 0, &ours[0]).unwrap(),
        chunk(&other, 0, &theirs[0]).unwrap(),
    );
    let departed = divergence(&ours, &theirs).expect("another root departs");
    assert_eq!((departed.record, departed.tag), (0, BEGIN));
    assert_eq!(divergence(&ours, &ours), None);
    std::fs::remove_dir_all(base).unwrap();
}

/// A turn record whose body is shorter than its choices' length field
/// diverges at that record without a time or candidate, and a record
/// whose length passes the chunk ends with it.
#[test]
fn a_short_turn_record_diverges_without_a_turn() {
    let record = |tag: u8, body: &[u8]| {
        let mut out = vec![tag];
        out.extend((body.len() as u32).to_le_bytes());
        out.extend_from_slice(body);
        out
    };
    for body in [&[][..], &[1, 2], &[9, 0, 0, 0, 1]] {
        let ours = record(super::TURN, body);
        let theirs = record(super::TURN, &[7; 40]);
        let found = divergence(&ours, &theirs).unwrap();
        assert_eq!(
            (found.record, found.tag, found.turn),
            (0, super::TURN, None)
        );
    }
    let mut cut = record(END, &[1, 2, 3]);
    cut[1] = 200;
    assert_eq!(divergence(&cut, &cut), None);
}

/// A session whose run ends before its first window commits none: its
/// empty index reads as no window, and its end names the origin chain;
/// the end of a panicked run reads even when the panic's text repeats a
/// field.
#[test]
fn a_session_that_commits_no_window_reads_as_empty() {
    let dir = scratch("session-empty");
    let mut writer = Writer::new(&dir, "manifest text\n", AMPLE).unwrap();
    writer.finish("end: stop=goal");
    assert!(writer.failed().is_none());
    let (lines, chain) = committed(&dir).unwrap();
    assert_eq!((lines.len(), chain), (0, origin(b"manifest text\n")));
    let end = ended(&dir, 0, &chain).unwrap();
    assert!(end.starts_with("end: stop=goal windows=0 "), "{end}");
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::create_dir(&dir).unwrap();
    let mut panicked = Writer::new(&dir, "manifest text\n", AMPLE).unwrap();
    let text = "end: panicked left=1 left=2 tail=0 windows=9 chain=00";
    panicked.finish(text);
    let end = ended(&dir, 0, &chain).unwrap();
    assert!(end.starts_with(&format!("{text} windows=0 ")), "{end}");
    std::fs::remove_dir_all(dir).unwrap();
}

/// A commit that fails latches its reason and drops the open window, and
/// every later record, commit and the end write nothing.
#[test]
fn a_failed_commit_latches_before_later_writes() {
    let dir = scratch("session-failed-commit");
    let mut writer = Writer::new(&dir, "m\n", AMPLE).unwrap();
    let chunk = dir.join("windows").join("000000.chunk");
    std::fs::write(&chunk, b"existing").unwrap();
    use crate::sim::turn::Hook;
    writer.begin(b"record", b"");
    writer.commit([0; crate::sim::trace::PAYLOAD]);
    let failure = writer.failed().unwrap().to_owned();
    assert!(failure.starts_with("window 0: "), "{failure}");
    std::fs::remove_file(&chunk).unwrap();
    writer.end(b"choices");
    writer.commit([0; crate::sim::trace::PAYLOAD]);
    writer.finish("end: failed");
    assert_eq!(writer.failed(), Some(failure.as_str()));
    assert_eq!(writer.committed(), 0);
    assert_eq!(writer.window.capacity(), 0);
    assert_eq!(std::fs::read_to_string(dir.join("index")).unwrap(), "");
    for path in ["end", "windows/000000.chunk", "windows/tail.chunk"] {
        assert!(!dir.join(path).exists(), "{path}");
    }
    std::fs::remove_dir_all(dir).unwrap();
}

/// An index append that fails after its chunk and `windows/` synced
/// latches its reason, leaves that chunk without an index line and writes
/// no tail or end; the index as committed still reads its one window, and
/// the session reads as incomplete. An `end` that cannot be created after
/// its tail chunk synced latches its reason too.
#[test]
fn a_failure_after_a_synced_chunk_keeps_the_committed_prefix() {
    use crate::sim::turn::Hook;
    let dir = scratch("session-failed-index");
    let mut writer = Writer::new(&dir, "m\n", AMPLE).unwrap();
    writer.begin(b"record", b"");
    writer.commit([0; crate::sim::trace::PAYLOAD]);
    assert_eq!((writer.committed(), writer.failed()), (1, None));
    let index = std::fs::read_to_string(dir.join("index")).unwrap();
    std::fs::remove_file(dir.join("index")).unwrap();
    std::fs::create_dir(dir.join("index")).unwrap();
    writer.end(b"choices");
    writer.commit([0; crate::sim::trace::PAYLOAD]);
    let failure = writer.failed().unwrap().to_owned();
    assert!(failure.starts_with("window 1: "), "{failure}");
    assert!(dir.join("windows").join("000001.chunk").exists());
    writer.finish("end: failed");
    assert_eq!(writer.failed(), Some(failure.as_str()));
    assert_eq!(writer.committed(), 1);
    for path in ["end", "windows/tail.chunk"] {
        assert!(!dir.join(path).exists(), "{path}");
    }
    std::fs::remove_dir(dir.join("index")).unwrap();
    std::fs::write(dir.join("index"), &index).unwrap();
    let (lines, chain) = committed(&dir).unwrap();
    assert_eq!(lines, [index.trim_end()]);
    assert!(
        ended(&dir, lines.len(), &chain)
            .unwrap_err()
            .starts_with("the session is incomplete: its end: ")
    );
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::create_dir(&dir).unwrap();
    let mut writer = Writer::new(&dir, "m\n", AMPLE).unwrap();
    writer.begin(b"record", b"");
    std::fs::create_dir(dir.join("end")).unwrap();
    writer.finish("end: stop=goal");
    let failure = writer.failed().unwrap();
    assert!(failure.starts_with("end: "), "{failure}");
    assert!(dir.join("windows").join("tail.chunk").exists());
    std::fs::remove_dir_all(dir).unwrap();
}

/// When the session directory fails to sync after `end` is written,
/// `finish` records the failure and removes `end`, so readers report the
/// session as incomplete, matching the writer's failure. The sync fails on
/// a directory its owner may write and search but not read; root reads
/// through that mode, so the test runs only for non-root users.
#[test]
fn an_end_whose_directory_does_not_sync_leaves_no_end() {
    use std::os::unix::fs::PermissionsExt;
    // SAFETY: `geteuid` takes no arguments, touches no memory and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let dir = scratch("session-end-unsynced");
    let mut writer = Writer::new(&dir, "m\n", AMPLE).unwrap();
    let mode = |mode: u32| {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    mode(0o300);
    writer.finish("end: stop=goal");
    mode(0o700);
    let failure = writer.failed().unwrap();
    assert!(failure.starts_with("end: "), "{failure}");
    assert!(dir.join("windows").join("tail.chunk").exists());
    assert!(!dir.join("end").exists());
    let (lines, chain) = committed(&dir).unwrap();
    assert!(
        ended(&dir, lines.len(), &chain)
            .unwrap_err()
            .starts_with("the session is incomplete: its end: ")
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// A manifest longer than the byte budget writes no file: the writer
/// starts with its failure latched and halted, and its end writes
/// nothing either.
#[test]
fn a_manifest_past_the_byte_budget_writes_no_file() {
    use crate::sim::turn::Hook;
    let dir = scratch("session-manifest-budget");
    let budget = Budget {
        records: u64::MAX,
        bytes: 4,
    };
    let mut writer = Writer::new(&dir, "manifest text\n", budget).unwrap();
    let reason = "the session's byte budget of 4 is spent";
    assert_eq!(writer.failed(), Some(reason));
    assert!(writer.halted());
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    writer.begin(b"record", b"");
    writer.finish("end: stop=goal");
    assert_eq!(writer.failed(), Some(reason));
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    std::fs::remove_dir_all(dir).unwrap();
}

/// `BEGIN`, `TURN`, `CLOCK` and `END` records hold their inputs in the
/// documented order, each behind its tag and length; a copy whose turn
/// outcome differs diverges at that record and names the turn's time and
/// candidate, read past its variable-length choices.
#[test]
fn records_hold_their_inputs_and_a_turn_names_them_when_it_diverges() {
    use crate::sim::choice::{CANDIDATE_LEN, Candidate};
    use crate::sim::trace::{Event, PAYLOAD};
    use crate::sim::turn::{Hook, Turn};
    let dir = scratch("session-turn-record");
    let mut writer = Writer::new(&dir, "m\n", AMPLE).unwrap();
    let turn = Turn {
        now: 0x0102_0304_0506_0708,
        event: Candidate([5; CANDIDATE_LEN]),
        outcome: 0x1122_3344_5566_7788,
        observation: [9; 12],
    };
    let event = Event {
        kind: 9,
        payload: [3; PAYLOAD],
    };
    writer.begin(b"rec", b"ab");
    writer.turn(b"xyz", &turn, &[event]);
    let mut expected = vec![BEGIN];
    expected.extend(9u32.to_le_bytes());
    expected.extend(3u32.to_le_bytes());
    expected.extend(b"recab");
    expected.push(super::TURN);
    let body = 4 + 3 + 8 + CANDIDATE_LEN + 8 + 1 + PAYLOAD;
    expected.extend((body as u32).to_le_bytes());
    expected.extend(3u32.to_le_bytes());
    expected.extend(b"xyz");
    expected.extend(turn.now.to_le_bytes());
    expected.extend([5; CANDIDATE_LEN]);
    expected.extend(turn.outcome.to_le_bytes());
    expected.push(9);
    expected.extend([3; PAYLOAD]);
    assert_eq!(writer.window, expected);
    let mut changed = expected.clone();
    let outcome = expected.len() - 1 - PAYLOAD - 8;
    changed[outcome] ^= 1;
    let found = divergence(&expected, &changed).unwrap();
    assert_eq!(
        (found.record, found.tag, found.turn),
        (1, super::TURN, Some((turn.now, [5; CANDIDATE_LEN])))
    );
    let clock = Event {
        kind: 10,
        payload: [4; PAYLOAD],
    };
    writer.clock(b"qr", 0x0a0b_0c0d_0e0f_1011, &[clock]);
    writer.end(b"st");
    expected.push(super::CLOCK);
    expected.extend(((4 + 2 + 8 + 1 + PAYLOAD) as u32).to_le_bytes());
    expected.extend(2u32.to_le_bytes());
    expected.extend(b"qr");
    expected.extend(0x0a0b_0c0d_0e0f_1011u64.to_le_bytes());
    expected.push(10);
    expected.extend([4; PAYLOAD]);
    expected.push(END);
    expected.extend(2u32.to_le_bytes());
    expected.extend(b"st");
    assert_eq!(writer.window, expected);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A session that would pass its manifest's record or byte budget stops
/// at the record that would pass it, incomplete and not counting, with
/// nothing written after; the windows it committed before the stop still
/// verify as a prefix of the whole session's. A record budget of exactly
/// the whole session's records completes it, and one fewer leaves it
/// without its end.
#[test]
fn a_spent_budget_leaves_the_session_incomplete() {
    let base = scratch("session-budget");
    let (spent, whole) = session_within("cluster-late-stale", 4, &base.join("whole"), AMPLE);
    let (all, _) = committed(&base.join("whole")).unwrap();
    for (name, budget, reason) in [
        (
            "records",
            Budget {
                records: 100,
                bytes: u64::MAX,
            },
            "the session's record budget of 100 is spent",
        ),
        (
            "bytes",
            Budget {
                records: u64::MAX,
                bytes: 10_000,
            },
            "the session's byte budget of 10000 is spent",
        ),
    ] {
        let dir = base.join(name);
        let (writer, ran) = session_within("cluster-late-stale", 4, &dir, budget);
        assert_eq!(writer.failed(), Some(reason));
        assert!(!dir.join("end").exists(), "{name}");
        assert_eq!(ran.report.end, crate::sim::turn::End::Halted, "{name}");
        assert_eq!(ran.stop(), "halted");
        assert!(!ran.judged().counts(), "{name}");
        let (kept, _) = committed(&dir).unwrap();
        assert_eq!(kept[..], all[..kept.len()], "{name}");
        assert!(
            ran.report.turn_count < whole.report.turn_count,
            "{name}: {} of {} turns",
            ran.report.turn_count,
            whole.report.turn_count
        );
    }
    let records = spent.spent.records;
    for (name, records, completes) in [("exact", records, true), ("short", records - 1, false)] {
        let dir = base.join(name);
        let budget = Budget {
            records,
            bytes: u64::MAX,
        };
        let (writer, _) = session_within("cluster-late-stale", 4, &dir, budget);
        assert_eq!(
            writer.failed().is_none(),
            completes,
            "{name}: {:?}",
            writer.failed()
        );
        assert_eq!(dir.join("end").exists(), completes, "{name}");
    }
    std::fs::remove_dir_all(base).unwrap();
}

fn on_disk(dir: &std::path::Path) -> u64 {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                on_disk(&entry.path())
            } else {
                entry.metadata().unwrap().len()
            }
        })
        .sum()
}

/// A byte budget of the whole session's chunk bytes, or of every file's
/// bytes but one, stops it before its end, with at least one window
/// committed and verifying as a prefix of the whole session's and no tail
/// chunk; a budget of every file's bytes completes it; a budget of the
/// manifest and the first two windows stops the session in window 2 with
/// exactly those two committed, no third chunk, no end and no credit.
#[test]
fn the_byte_budget_bounds_every_session_file() {
    let base = scratch("session-files");
    let whole = base.join("whole");
    session_within("cluster-late-stale", 4, &whole, AMPLE);
    let chunks = on_disk(&whole.join("windows"));
    let files = on_disk(&whole);
    let (all, _) = committed(&whole).unwrap();
    assert!(chunks < files, "{chunks} chunk bytes of {files}");
    for (name, bytes, completes) in [
        ("chunks", chunks, false),
        ("short", files - 1, false),
        ("files", files, true),
    ] {
        let dir = base.join(name);
        let budget = Budget {
            records: u64::MAX,
            bytes,
        };
        let (writer, _) = session_within("cluster-late-stale", 4, &dir, budget);
        assert!(
            on_disk(&dir) <= bytes,
            "{name}: {} of {bytes}",
            on_disk(&dir)
        );
        assert_eq!(
            writer.failed().is_none(),
            completes,
            "{name}: {:?}",
            writer.failed()
        );
        assert_eq!(dir.join("end").exists(), completes, "{name}");
        assert_eq!(
            dir.join("windows").join("tail.chunk").exists(),
            completes,
            "{name}"
        );
        let (kept, chain) = committed(&dir).unwrap();
        assert!(!kept.is_empty(), "{name}");
        assert_eq!(kept[..], all[..kept.len()], "{name}");
        if !completes {
            assert!(
                ended(&dir, kept.len(), &chain)
                    .unwrap_err()
                    .starts_with("the session is incomplete: its end: "),
                "{name}"
            );
        }
    }
    assert_eq!(on_disk(&base.join("files")), files);
    let len = |path: std::path::PathBuf| std::fs::metadata(path).unwrap().len();
    let bytes = len(whole.join("manifest"))
        + (0..2)
            .map(|at| {
                len(whole.join("windows").join(format!("{at:06}.chunk"))) + all[at].len() as u64 + 1
            })
            .sum::<u64>();
    let dir = base.join("prefix");
    let budget = Budget {
        records: u64::MAX,
        bytes,
    };
    let (writer, ran) = session_within("cluster-late-stale", 4, &dir, budget);
    assert_eq!(
        writer.failed(),
        Some(format!("the session's byte budget of {bytes} is spent").as_str())
    );
    let (kept, chain) = committed(&dir).unwrap();
    assert_eq!(kept[..], all[..2]);
    assert!(!dir.join("windows").join("000002.chunk").exists());
    assert!(
        ended(&dir, kept.len(), &chain)
            .unwrap_err()
            .starts_with("the session is incomplete: its end: ")
    );
    assert_eq!(ran.report.end, crate::sim::turn::End::Halted);
    assert!(!ran.judged().counts());
    std::fs::remove_dir_all(base).unwrap();
}

/// The chain's known answer: the origin of the text `m`, then window 0
/// over the chunk `a` and window 1 over the chunk `b`.
#[test]
fn the_chain_matches_its_known_answer() {
    let digest = |bytes: &[u8]| -> [u8; 32] { sha2::Sha256::digest(bytes).into() };
    let first = chained(&origin(b"m"), 0, &digest(b"a"));
    let second = chained(&first, 1, &digest(b"b"));
    assert_eq!(hex(&second), KNOWN);
}

/// The index reader numbers windows from 0 and reads their `digest` and
/// `chain` fields: a session written by hand with the manifest `m`, chunks
/// `a` and `b` and their two index lines commits two windows chaining to
/// the known answer.
#[test]
fn the_index_reader_chains_to_the_known_answer() {
    let digest = |bytes: &[u8]| -> [u8; 32] { sha2::Sha256::digest(bytes).into() };
    let dir = scratch("session-known-answer");
    std::fs::write(dir.join("manifest"), "m").unwrap();
    std::fs::create_dir(dir.join("windows")).unwrap();
    std::fs::write(dir.join("windows").join("000000.chunk"), "a").unwrap();
    std::fs::write(dir.join("windows").join("000001.chunk"), "b").unwrap();
    let first = chained(&origin(b"m"), 0, &digest(b"a"));
    let index = format!(
        "window 0 digest={} chain={}\nwindow 1 digest={} chain={KNOWN}\n",
        hex(&digest(b"a")),
        hex(&first),
        hex(&digest(b"b")),
    );
    std::fs::write(dir.join("index"), &index).unwrap();
    let (lines, chain) = committed(&dir).unwrap();
    assert_eq!(lines.len(), 2);
    assert_eq!(hex(&chain), KNOWN);
    std::fs::remove_dir_all(dir).unwrap();
}

/// A window's index line names each payload word under its own field,
/// the verdict byte 1 as `pass` and 0 as `failed`, and its index, turns,
/// digest and chain.
#[test]
fn a_window_line_names_every_word_in_its_place() {
    let mut event = [0; crate::sim::trace::PAYLOAD];
    event[super::WINDOW_VERDICT] = 1;
    for n in 1..10u32 {
        let at = super::WINDOW_VERDICT + 1 + 4 * (n as usize - 1);
        event[at..at + 4].copy_from_slice(&(10 + n).to_le_bytes());
    }
    let window = super::Window {
        index: 3,
        turns: 7,
        digest: [0xab; 32],
        chain: [0xcd; 32],
        event,
    };
    assert_eq!(
        window.line(),
        format!(
            "window 3 turns=7 digest={} chain={} verdict=pass carried=11 registry=12 outstanding=13 kept=14 published=15 hits=16 faults=17 reused=18 healed=19",
            "ab".repeat(32),
            "cd".repeat(32)
        )
    );
    let failed = super::Window {
        event: {
            let mut event = window.event;
            event[super::WINDOW_VERDICT] = 0;
            event
        },
        ..window
    };
    assert!(failed.line().contains(" verdict=failed carried=11 "));
}

/// The chain of `the_chain_matches_its_known_answer`.
const KNOWN: &str = "bbc506115a4d4f65132cdeb3cdc6bc3ea3828892688515014e7810480e6b0a5e";

#[test]
fn a_failed_index_sync_restores_the_committed_prefix_before_latching() {
    use crate::sim::turn::Hook;
    for rollback_fails in [false, true] {
        let dir = scratch(if rollback_fails {
            "session-index-rollback-failed"
        } else {
            "session-index-sync-failed"
        });
        let mut writer = Writer::new(&dir, "m\n", AMPLE).unwrap();
        writer.begin(b"record", b"");
        writer.commit([0; crate::sim::trace::PAYLOAD]);
        let index = std::fs::read(dir.join("index")).unwrap();
        writer.end(b"choices");
        let mut syncs = 0;
        writer.commit_with_sync([0; crate::sim::trace::PAYLOAD], |file| {
            syncs += 1;
            if syncs == 1 {
                assert!(file.metadata().unwrap().len() > index.len() as u64);
                Err(std::io::Error::from_raw_os_error(libc::EIO))
            } else if rollback_fails {
                assert_eq!(file.metadata().unwrap().len(), index.len() as u64);
                Err(std::io::Error::from_raw_os_error(libc::EIO))
            } else {
                assert_eq!(file.metadata().unwrap().len(), index.len() as u64);
                file.sync_all()
            }
        });
        assert_eq!(syncs, 2);
        assert_eq!(writer.committed(), 1);
        let failure = writer.failed().unwrap().to_owned();
        assert!(failure.starts_with("window 1: "));
        assert_eq!(failure.contains("index rollback failed"), rollback_fails);
        assert_eq!(std::fs::read(dir.join("index")).unwrap(), index);
        let (lines, chain) = committed(&dir).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(chain, writer.chain());
        writer.finish("end: stop=halted");
        assert_eq!(writer.failed(), Some(failure.as_str()));
        assert!(!dir.join("end").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
