//! Session chains, record envelope bounds and durable publication barriers.

use super::*;
#[test]
fn window_links_match_the_known_answer() {
    let first = link(Digest::of(b"m"), 0, Digest::of(b"a"));
    let second = link(first, 1, Digest::of(b"b"));
    assert_eq!(
        second.to_string(),
        "bbc506115a4d4f65132cdeb3cdc6bc3ea3828892688515014e7810480e6b0a5e"
    );
}
#[test]
fn verified_window_files_sync_and_each_barrier_failure_poisons() {
    use crate::step::{Outcome, Step};
    use crate::store::fixture::{Case, name, scripted};
    use std::fs;
    use std::os::unix::fs::DirBuilderExt;
    let fixture = || {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        let dir = case.state.join("session");
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(dir.join("windows"))
            .unwrap();
        let manifest = "root = 3\n";
        let chunk = [3, 1, 0, 0, 0, 1];
        let digest = Digest::of(&chunk);
        let chain = link(Digest::of(manifest.as_bytes()), 0, digest);
        let tail = Digest::of(b"");
        fs::write(dir.join("manifest"), manifest).unwrap();
        fs::write(dir.join("windows/000000.chunk"), chunk).unwrap();
        fs::write(dir.join("index"), format!("window 0 turns=1 digest={digest} chain={chain} verdict=pass carried=0 registry=0 outstanding=0 kept=0 published=0 hits=0 faults=0 reused=0 healed=0\n")).unwrap();
        fs::write(dir.join("windows/tail.chunk"), b"").unwrap();
        fs::write(dir.join("end"), format!("end: stop=goal terminal=complete inconclusive fired=00 required=03 counts=false turns=1 virtual_us=0 skipped_us=0 rested_us=0 apply_ms=000000000001 failure=None carried=0 registry=0 outstanding=0 kept=0 window_bytes=6 windows=1 chain={chain} tail={tail}\n")).unwrap();
        let checked = check(&dir, manifest, (100, 48000), true);
        checked.valid().unwrap();
        assert_eq!(checked.evidence.verified_windows, 1);
        let paths: Vec<_> = checked
            .files
            .iter()
            .map(|file| file.path().to_owned())
            .collect();
        assert_eq!(
            paths,
            [
                "manifest",
                "index",
                "windows/000000.chunk",
                "end",
                "windows/tail.chunk"
            ]
            .map(|name| dir.join(name))
        );
        (case, store, checked)
    };
    let (_case, store, checked) = fixture();
    let (made, steps) = scripted(None, || checked.durable(&store));
    made.unwrap().unwrap();
    let syncs: Vec<_> = steps
        .iter()
        .enumerate()
        .filter_map(|(at, step)| (*step == Step::Sync).then_some(at))
        .collect();
    assert_eq!(syncs.len(), 3 * checked.files.len());
    for at in syncs {
        let (_case, store, checked) = fixture();
        let (result, reached) = scripted(Some((at, Outcome::Errno(libc::EIO))), || {
            checked.durable(&store)
        });
        assert_eq!(reached[at], Step::Sync);
        let Stop(class, reason) = result.unwrap().unwrap_err();
        assert_eq!(class, Sim::Incomplete);
        assert!(reason.contains("cannot be made durable"));
        assert!(matches!(
            store.create_once(store.root(), &name("artifact"), b"record"),
            Err(crate::store::Error::Poisoned)
        ));
    }
}

#[test]
fn phase_stop_classes_survive_a_later_barrier_failure() {
    for class in [Sim::Watchdog, Sim::Interrupted] {
        let ran = Err(Stop(class, "the phase stopped".into()));
        let barrier = Err(incomplete("the evidence barrier failed"));
        let Stop(observed, reason) = after_barrier(ran, &barrier).err().unwrap();
        assert_eq!(observed, class);
        assert_eq!(reason, "the phase stopped; the evidence barrier failed");
    }
}

#[test]
fn the_minimum_index_line_pins_the_envelope_window_bound() {
    let digest = "0".repeat(64);
    let line = format!(
        "window 0 turns=0 digest={digest} chain={digest} verdict=pass carried=0 registry=0 outstanding=0 kept=0 published=0 hits=0 faults=0 reused=0 healed=0"
    );
    WindowLine::parse(&line).unwrap();
    assert!(line.len() + 1 >= (INDEX_BYTES / MAX_WINDOWS) as usize);
}
