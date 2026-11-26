use super::*;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;

#[test]
fn non_utf8_roles_refuse_before_run_allocation() {
    let case = Case::new("non-utf8-roles");
    let output = case
        .command()
        .env(
            "KESTRIKE_HARDWARE_ROLES",
            std::ffi::OsString::from_vec(vec![0xff]),
        )
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("KESTRIKE_HARDWARE_ROLES"));
    assert!(!case.dir(1).exists());
}

#[test]
fn absent_state_is_initialized_and_unmarked_dispose_preserves_state() {
    let case = Case::new("absent-state");
    fs::remove_dir(&case.state).unwrap();
    result(&case.run("exit", 0), 0);
    assert!(case.dir(1).join("ready").exists());
    let unmarked = Case::new("unmarked-dispose");
    assert_eq!(unmarked.dispose("receipt").status.code(), Some(4));
    assert_eq!(fs::read_dir(&unmarked.state).unwrap().count(), 0);
}

#[test]
fn symlinked_state_is_rejected_before_initialization() {
    let case = Case::new("symlink-state");
    let alias = case.root.join("alias");
    std::os::unix::fs::symlink(&case.state, &alias).unwrap();
    let output = case
        .options(&[("--state", Some(alias.to_str().unwrap()))])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read_dir(&case.state).unwrap().count(), 0);
}

#[test]
fn unsafe_custody_directories_refuse_before_controller_start() {
    for (label, mode) in [
        ("foreign-custody", None),
        ("shared-custody", Some(0o777)),
        ("traversable-custody", Some(0o755)),
        ("group-custody", Some(0o750)),
    ] {
        let case = Case::new(label);
        let custody = if let Some(mode) = mode {
            let path = case.root.join("shared");
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            path
        } else {
            let custody = PathBuf::from("/var/tmp");
            if fs::metadata(&custody).unwrap().uid() == fs::metadata(&case.state).unwrap().uid() {
                continue;
            }
            custody
        };
        let output = case
            .options(&[("--custody", Some(custody.to_str().unwrap()))])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("custody"));
        assert!(!case.dir(1).exists());
    }
}

#[test]
fn sticky_shared_ancestor_accepts_private_custody() {
    let case = Case::new("sticky-custody");
    let shared = case.root.join("shared");
    fs::create_dir(&shared).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
    let custody = shared.join("custody");
    fs::create_dir(&custody).unwrap();
    fs::set_permissions(&custody, fs::Permissions::from_mode(0o700)).unwrap();
    let output = case
        .options(&[("--custody", Some(custody.to_str().unwrap()))])
        .output()
        .unwrap();
    assert_eq!(result(&output, 0)["class"], "completed");
    assert!(case.dir(1).join("ready").exists());
}

#[test]
fn custody_permission_change_during_controller_run_is_held() {
    let case = Case::new("changed-custody");
    let row = result(&case.run("change-mode", 0), 4);
    assert_eq!(row["class"], "held");
    assert_eq!(row["exit"], 0);
    assert!(row["reason"].as_str().unwrap().contains("custody_scan="));
    assert!(
        row["reason"]
            .as_str()
            .unwrap()
            .contains("custody directory")
    );
    assert_eq!(case.run("exit", 0).status.code(), Some(4));
    assert!(!case.dir(2).exists());
}

#[test]
fn real_lane_marker_holds_an_exit_zero_controller() {
    let case = Case::new("real-lane-marker");
    let lane = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/hardware-lane.py");
    let custody = case.root.join("custody");
    fs::create_dir(&custody).unwrap();
    fs::set_permissions(&custody, fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new("python3")
        .args(["-c", "import runpy, sys; runpy.run_path(sys.argv[1])['write_custody_marker'](sys.argv[2], 'killed-fixture', pgid=None, episode='fixture', profile='profile', role='owner', case='fixture', custody='operator containment pending')"])
        .arg(lane).arg(&custody).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let marker = custody.join("killed-fixture.json");
    let bytes = fs::read(&marker).unwrap();
    let record: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(record["boot"].is_string());
    assert_eq!(record["pgid"], Value::Null);
    assert_eq!(result(&case.run("exit", 0), 4)["class"], "held");
    assert!(case.dir(1).join("ready").exists());
    assert_eq!(fs::read(marker).unwrap(), bytes);
    assert_eq!(case.run("exit", 0).status.code(), Some(4));
    assert!(!case.dir(2).exists());
}

#[test]
fn platform_environment_matches_explicit_and_ambient_selection() {
    for ambient_only in [false, true] {
        let case = Case::new(if ambient_only {
            "ambient-platform"
        } else {
            "explicit-platform"
        });
        let mut command = if ambient_only {
            case.options(&[("--platform", None)])
        } else {
            case.command()
        };
        command.env(
            "KESTRIKE_HARDWARE_PLATFORM",
            if ambient_only { "local" } else { "other" },
        );
        let row = result(&command.output().unwrap(), 0);
        assert_eq!(row["platform"], "local");
        assert_eq!(
            fs::read_to_string(case.dir(1).join("platform")).unwrap(),
            "local"
        );
    }
}

#[test]
fn repeated_ambient_environments_retain_lane_order_and_explicit_override() {
    let case = Case::new("ambient-environments");
    let first = case.root.join("first.json");
    let second = case.root.join("second.json");
    fs::write(&first, "{}").unwrap();
    fs::write(&second, "{}").unwrap();
    let ambient = format!(
        "profile/owner={} profile/owner={}",
        first.display(),
        second.display()
    );
    result(
        &case
            .command()
            .env("KESTRIKE_HARDWARE_ROLES", &ambient)
            .output()
            .unwrap(),
        0,
    );
    assert_eq!(
        fs::read_to_string(case.dir(1).join("roles")).unwrap(),
        ambient
    );
    let environment = format!("owner={}", first.display());
    result(
        &case
            .command()
            .env("KESTRIKE_HARDWARE_ROLES", &ambient)
            .args(["--environment", &environment])
            .output()
            .unwrap(),
        0,
    );
    assert_eq!(
        fs::read_to_string(case.dir(2).join("roles")).unwrap(),
        format!("profile/{environment}")
    );
}

#[test]
fn dispose_refuses_zero_completed_and_absent_runs() {
    let case = Case::new("dispose-refusals");
    result(&case.run("exit", 0), 0);
    for number in [0, 1, 2] {
        let output = Command::new(env!("CARGO_BIN_EXE_campaign"))
            .args(["hardware", "dispose", "--state"])
            .arg(&case.state)
            .args(["--run", &number.to_string(), "--evidence", "receipt"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        if number == 0 {
            assert!(String::from_utf8_lossy(&output.stderr).contains("positive integer"));
        }
        assert!(!case.dir(number).join("disposition").exists());
    }
    assert_eq!(case.report()["hardware"][0]["disposed"], false);
}

#[test]
fn fleet_manifest_raises_soft_limit_and_refuses_the_hard_limit() {
    for hard in [65536, 4096] {
        let case = Case::new(&format!("fleet-limit-{hard}"));
        let manifest = case.root.join("fleet.json");
        let mut bytes = br#"{"workload":{"profile":"profile"},"hosts":{"a":{}},"deadlines":{"grace_seconds":1}}"#.to_vec();
        bytes.resize(8192, b' ');
        fs::write(&manifest, &bytes).unwrap();
        let base = case.command();
        let output = Command::new("python3")
            .args(["-c", "import os, resource, sys; resource.setrlimit(resource.RLIMIT_FSIZE, (4096, int(sys.argv[1]))); os.execv(sys.argv[2], sys.argv[2:])"])
            .arg(hard.to_string()).arg(base.get_program()).args(base.get_args()).arg("--fleet").arg(&manifest)
            .env_remove("KESTRIKE_HARDWARE_ROLES").output().unwrap();
        if hard == 65536 {
            assert_eq!(result(&output, 0)["class"], "completed");
            assert_eq!(
                fs::read(case.dir(1).join("admitted-manifest")).unwrap(),
                bytes
            );
        } else {
            assert_eq!(
                output.status.code(),
                Some(2),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stderr).contains("file-size limit"));
            assert!(!case.dir(1).exists());
        }
    }
}

#[test]
fn hardware_controller_inherits_the_launchers_umask() {
    let case = Case::new("inherited-umask");
    let base = case.command();
    let output = Command::new("python3")
        .args([
            "-c",
            "import os, sys; os.umask(0o027); os.execv(sys.argv[1], sys.argv[1:])",
        ])
        .arg(base.get_program())
        .args(base.get_args())
        .env_remove("KESTRIKE_HARDWARE_ROLES")
        .output()
        .unwrap();
    result(&output, 0);
    assert_eq!(
        fs::metadata(case.dir(1).join("cwd")).unwrap().mode() & 0o777,
        0o640
    );
}

#[test]
fn canonical_custody_paths_refuse_alias_spelling_and_missing_parents() {
    for (label, suffix) in [
        ("trailing-custody", "custody/"),
        ("dot-custody", "./custody"),
        ("parent-custody", "state/../custody"),
        ("empty-custody", "state//custody"),
        ("missing-parent", "absent/custody"),
    ] {
        let case = Case::new(label);
        let custody = format!("{}/{suffix}", case.root.display());
        let output = case
            .options(&[("--custody", Some(&custody))])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!case.dir(1).exists());
        if label == "missing-parent" {
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains(case.root.join("absent").to_str().unwrap())
            );
            assert!(!case.root.join("absent").exists());
        }
    }
    let case = Case::new("relative-custody");
    assert_eq!(
        case.options(&[("--custody", Some("custody"))])
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
    assert!(!case.dir(1).exists());
}

#[test]
fn missing_custody_is_private_and_changes_to_the_pin_hold_the_run() {
    let case = Case::new("private-custody");
    let custody = case.root.join("custody");
    assert!(!custody.exists());
    result(&case.run("exit", 0), 0);
    assert_eq!(fs::metadata(&custody).unwrap().mode() & 0o777, 0o700);
    for mode in ["replace-custody", "remove-custody"] {
        let case = Case::new(mode);
        let row = result(&case.run(mode, 0), 4);
        assert_eq!(row["class"], "held");
        assert_eq!(row["exit"], 0);
        assert!(
            row["reason"]
                .as_str()
                .unwrap()
                .contains("custody_marker=unknown")
        );
        assert_eq!(case.run("exit", 0).status.code(), Some(4));
        assert!(!case.dir(2).exists());
    }
}

#[test]
fn sticky_custody_leaf_is_refused_at_admission_and_held_at_termination() {
    let case = Case::new("sticky-leaf-before");
    let custody = case.root.join("custody");
    fs::create_dir(&custody).unwrap();
    fs::set_permissions(&custody, fs::Permissions::from_mode(0o1777)).unwrap();
    assert_eq!(case.run("exit", 0).status.code(), Some(2));
    assert!(!case.dir(1).exists());
    let case = Case::new("sticky-leaf-after");
    let output = case
        .command()
        .env("FAKE_MODE", "change-mode")
        .env("FAKE_CUSTODY_MODE", "1777")
        .output()
        .unwrap();
    assert_eq!(result(&output, 4)["class"], "held");
}

#[test]
fn relative_state_is_accepted_and_noncanonical_components_are_refused() {
    let case = Case::new("relative-state");
    let output = case
        .options(&[("--state", Some("state"))])
        .current_dir(&case.root)
        .output()
        .unwrap();
    assert_eq!(result(&output, 0)["class"], "completed");
    for state in [
        format!("{}/", case.state.display()),
        format!("{}/./state", case.root.display()),
        format!("{}/state/../state", case.root.display()),
    ] {
        assert_eq!(
            case.options(&[("--state", Some(&state))])
                .output()
                .unwrap()
                .status
                .code(),
            Some(2)
        );
        assert!(!case.dir(2).exists());
    }
}

#[test]
fn a_pre_go_stop_with_zero_grace_is_interrupted_without_controller_execution() {
    let case = Case::new("pre-go-stop");
    let base = case.options(&[("--grace", Some("0"))]);
    let output = Command::new("python3")
        .args(["-c", "import os, signal, sys; signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGTERM]); os.kill(os.getpid(), signal.SIGTERM); os.execv(sys.argv[1], sys.argv[1:])"])
        .arg(base.get_program()).args(base.get_args()).env_remove("KESTRIKE_HARDWARE_ROLES").output().unwrap();
    let row = result(&output, 0);
    assert_eq!(row["class"], "interrupted");
    assert_eq!(row["exit"], 125);
    assert_eq!(row["stopped"], true);
    assert!(!case.dir(1).join("ready").exists());
    assert!(!case.dir(1).join("signals").exists());
    assert_eq!(result(&case.run("exit", 0), 0)["class"], "completed");
}

#[test]
fn hardware_state_initialization_and_dispose_raise_small_soft_limits() {
    let case = Case::new("early-file-limit");
    let base = case.command();
    let script = "import os, resource, sys; resource.setrlimit(resource.RLIMIT_FSIZE, (1, 65536)); os.execv(sys.argv[1], sys.argv[1:])";
    let output = Command::new("python3")
        .args(["-c", script])
        .arg(base.get_program())
        .args(base.get_args())
        .env_remove("KESTRIKE_HARDWARE_ROLES")
        .env("FAKE_MODE", "marker")
        .output()
        .unwrap();
    assert_eq!(result(&output, 4)["class"], "held");
    let output = Command::new("python3")
        .args(["-c", script])
        .arg(env!("CARGO_BIN_EXE_campaign"))
        .args(["hardware", "dispose", "--state"])
        .arg(&case.state)
        .args(["--run", "1", "--evidence", "receipt"])
        .output()
        .unwrap();
    assert_eq!(result(&output, 0)["recorded"], true);
}

#[test]
fn hardware_report_requires_its_marker_and_retains_rows_beside_foreign_names() {
    for damaged in [false, true] {
        let case = Case::new(if damaged {
            "damaged-hardware-marker"
        } else {
            "missing-hardware-marker"
        });
        result(&case.run("exit", 0), 0);
        let marker = case.state.join("hardware/.state");
        if damaged {
            fs::write(marker, "damaged").unwrap();
        } else {
            fs::remove_file(marker).unwrap();
        }
        let report = case.report();
        assert_eq!(report["hardware"], json!([]));
        assert_eq!(report["held"][0]["path"], "hardware");
        assert!(report["held"][0]["held_code"].is_string());
    }
    let case = Case::new("foreign-hardware-name");
    result(&case.run("exit", 0), 0);
    fs::create_dir(case.state.join("hardware/runs/bad name")).unwrap();
    let report = case.report();
    assert_eq!(report["hardware"][0]["class"], "completed");
    assert_eq!(report["held"][0]["path"], "hardware/runs/bad name");
    assert!(report["held"][0]["held_code"].is_string());
}

#[test]
fn startup_refuses_a_hard_limit_smaller_than_the_state_marker() {
    let case = Case::new("tiny-hard-limit");
    fs::remove_dir(&case.state).unwrap();
    let base = case.command();
    let output = Command::new("python3")
        .args(["-c", "import os, resource, sys; resource.setrlimit(resource.RLIMIT_FSIZE, (1, 1)); os.execv(sys.argv[1], sys.argv[1:])"])
        .arg(base.get_program()).args(base.get_args()).env_remove("KESTRIKE_HARDWARE_ROLES").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("file-size hard limit"));
    assert!(!case.state.exists());
}

#[test]
fn dispose_preserves_an_absent_or_unmarked_hardware_store() {
    let case = Case::alone("dispose-store-preservation");
    drop(Store::open(&case.state).unwrap());
    assert_eq!(case.dispose("receipt").status.code(), Some(2));
    let hardware = case.state.join("hardware");
    assert!(!hardware.exists());
    fs::create_dir(&hardware).unwrap();
    fs::set_permissions(&hardware, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(case.dispose("receipt").status.code(), Some(4));
    assert!(!hardware.join(".state").exists());
}

#[test]
fn a_regular_custody_parent_is_rejected_before_allocation() {
    let case = Case::new("regular-custody-parent");
    let parent = case.root.join("parent");
    fs::write(&parent, "regular file").unwrap();
    let custody = parent.join("custody");
    let output = case
        .options(&[("--custody", Some(custody.to_str().unwrap()))])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains(parent.to_str().unwrap()));
    assert!(!case.dir(1).exists());
}

#[test]
fn terminal_listing_permission_failure_is_held() {
    let case = Case::new("terminal-list-permission");
    if fs::metadata(&case.state).unwrap().uid() == 0 {
        return;
    }
    let output = case
        .command()
        .env("FAKE_MODE", "change-mode")
        .env("FAKE_CUSTODY_MODE", "300")
        .output()
        .unwrap();
    let custody = case.root.join("custody");
    fs::set_permissions(&custody, fs::Permissions::from_mode(0o700)).unwrap();
    let row = result(&output, 4);
    assert_eq!(row["class"], "held");
    assert_eq!(row["exit"], 0);
    assert!(
        row["reason"]
            .as_str()
            .unwrap()
            .contains("custody_marker=unknown")
    );
    assert_eq!(case.run("exit", 0).status.code(), Some(4));
    assert!(!case.dir(2).exists());
}

#[test]
fn report_orders_runs_numerically_and_held_entries_by_name() {
    let case = Case::new("report-ordering");
    result(&case.run("exit", 0), 0);
    for name in ["10000", "9999", "z name", "a name"] {
        fs::create_dir(case.state.join("hardware/runs").join(name)).unwrap();
    }
    let report = case.report();
    let runs: Vec<_> = report["hardware"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["run"].as_str().unwrap())
        .collect();
    assert_eq!(runs, ["0001", "9999", "10000"]);
    assert_eq!(report["held"][0]["path"], "hardware/runs/a name");
    assert_eq!(report["held"][1]["path"], "hardware/runs/z name");
}
