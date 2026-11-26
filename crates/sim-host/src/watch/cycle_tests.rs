use super::*;

fn alert(flag: &str, instance: &str) -> Alert {
    Alert {
        flag: flag.to_owned(),
        instance: instance.to_owned(),
    }
}

fn state(open: &[Alert], event: Option<u64>) -> Saved {
    Saved {
        format: 1,
        open: open.iter().cloned().collect(),
        event,
    }
}

#[test]
fn a_missing_alert_state_is_empty_and_a_malformed_one_is_an_error() {
    let dir = file::scratch("watch-alerts-load");
    let path = alerts_path(&dir);
    assert_eq!(load_alerts(&path), Ok(Saved::lost()), "no file, no alerts");
    for (bytes, what) in [
        (&b"null"[..], "JSON null"),
        (b"{\"format\": 2, \"open\": []}", "another format"),
        (
            b"{\"format\": 1, \"open\": 3}",
            "an open set of another shape",
        ),
        (b"{\"format\": 1", "a cut file"),
    ] {
        std::fs::write(&path, bytes).expect("a state file");
        assert!(load_alerts(&path).is_err(), "{what}");
    }
    std::fs::write(&path, b"{\"format\": 1, \"open\": []}").expect("a state without an event");
    assert_eq!(load_alerts(&path), Ok(Saved::lost()));
    let saved = state(
        &[
            alert("silent", "i-0000000a"),
            alert("missing", "i-0000000b"),
        ],
        Some(7),
    );
    save_alerts(&path, &saved);
    assert_eq!(load_alerts(&path), Ok(saved), "a saved state reads back");
    let elsewhere = dir.join("elsewhere.json");
    std::fs::rename(&path, &elsewhere).expect("the state moves");
    std::os::unix::fs::symlink(&elsewhere, &path).expect("a symlinked state");
    assert!(load_alerts(&path).is_err(), "a symlink is no saved state");
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn a_failed_alert_save_removes_the_older_file_and_keeps_a_directory() {
    let dir = file::scratch("watch-alerts-save");
    let path = alerts_path(&dir);
    let older = state(&[alert("silent", "i-0000000a")], Some(7));
    save_alerts(&path, &older);
    let staged = dir.join(".alerts.json.staged");
    std::fs::create_dir(&staged).expect("an entry no staged write can replace");
    std::fs::write(staged.join("held"), b"x").expect("a file under it");
    save_alerts(&path, &state(&[], Some(8)));
    assert!(
        !path.exists(),
        "a save that fails leaves no older state for a restart to trust"
    );
    assert_eq!(load_alerts(&path), Ok(Saved::lost()));
    std::fs::remove_dir_all(&staged).expect("the obstruction leaves");
    std::fs::create_dir(&path).expect("a directory at the state's name");
    std::fs::write(path.join("sentinel"), b"kept").expect("a sentinel");
    save_alerts(&path, &older);
    assert_eq!(
        std::fs::read(path.join("sentinel")).expect("the sentinel"),
        b"kept",
        "a directory at the state's name keeps what it holds"
    );
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn a_host_event_waits_for_a_second_past_the_last_one_stored() {
    assert_eq!(past_event(None, 5), Ok(()), "a lost state names no event");
    assert_eq!(past_event(Some(4), 5), Ok(()));
    for now in [3, 4] {
        assert!(
            past_event(Some(4), now).is_err(),
            "a clock at {now}, stepped back to or before the last event's second"
        );
    }
}
