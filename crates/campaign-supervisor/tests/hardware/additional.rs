use super::*;

#[test]
fn malformed_hardware_directory_reports_a_held_row() {
    let case = Case::new("report-malformed-directory");
    result(&case.run("exit", 0), 0);
    fs::create_dir(case.state.join("hardware/runs/abc")).unwrap();
    let report = case.report();
    assert_eq!(
        report["held"],
        json!([{"held_code": "binding", "path": "hardware/runs/abc", "reason": "invalid hardware run directory abc"}])
    );
    assert_eq!(report["hardware"][0]["class"], "completed");
}

#[test]
fn hardware_report_preserves_scan_bound_as_exit_four() {
    let case = Case::new("report-scan-bound");
    result(&case.run("exit", 0), 0);
    let runs = case.state.join("hardware/runs");
    for index in 2..=campaign_supervisor::SCAN_BOUND + 1 {
        fs::write(runs.join(format!("{index:04}")), []).unwrap();
    }
    let output = case.report_output();
    assert_eq!(
        output.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn unknown_platform_row_is_gated_without_controller_spawn() {
    let case = Case::new("platform-absent");
    let output = case
        .options(&[("--platform", Some("absent"))])
        .output()
        .unwrap();
    let row = result(&output, 0);
    assert_eq!(row["class"], "gated");
    assert!(row["reason"].as_str().unwrap().contains("undeclared"));
    assert!(!case.dir(1).join("ready").exists());
}

use std::io::Write;

#[test]
fn malformed_ambient_platform_is_rejected_before_run_allocation() {
    let case = Case::new("ambient-platform-ascii");
    let output = case
        .options(&[("--platform", None)])
        .env("KESTRIKE_HARDWARE_PLATFORM", "invalid\nplatform")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!case.dir(1).exists());
}

#[test]
fn both_gates_require_the_go_byte_before_exec() {
    let _case = Case::new("both-gates");
    for gate in ["gate", "hardware-gate"] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_campaign"))
            .args([gate, "--", "/bin/sh", "-c", "printf launched"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(b"X").unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(125));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn current_controller_parsers_accept_recorded_sweep_and_episode_argv() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for kind in ["sweep", "episode"] {
        let mut case = Case::new(&format!("real-parser-{kind}"));
        let quoted = case.root.join("fake 'quoted controller.py");
        fs::rename(&case.lane, &quoted).unwrap();
        case.lane = quoted;
        let mut command = case.command();
        let script = if kind == "episode" {
            let manifest = case.root.join("fis.json");
            fs::write(
                &manifest,
                r#"{"profiles":{"profile":{"lane":{"profile":"profile"}}}}"#,
            )
            .unwrap();
            command
                .arg("--operator")
                .arg(case.root.join("operator.json"))
                .arg("--fis")
                .arg(&case.lane)
                .arg("--fis-manifest")
                .arg(&manifest);
            repository.join("scripts/fis-controller.py")
        } else {
            repository.join("scripts/hardware-lane.py")
        };
        result(&command.output().unwrap(), 0);
        let output = Command::new("python3").args(["-c", "import json, pathlib, runpy, shlex, sys; parser = runpy.run_path(sys.argv[1])['parser'](); args = parser.parse_args(json.loads(pathlib.Path(sys.argv[2]).read_text())); assert not hasattr(args, 'lane') or shlex.split(args.lane) == ['python3', sys.argv[3]]"]).arg(script).arg(case.dir(1).join("argv.json")).arg(&case.lane).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn fleet_gate_uses_the_selected_supported_machine_and_profile_status() {
    let case = Case::new("fleet-platform");
    let manifest = case.root.join("fleet.json");
    fs::write(
        &manifest,
        r#"{"workload":{"profile":"profile"},"hosts":{"a":{}},"deadlines":{"grace_seconds":1}}"#,
    )
    .unwrap();
    fs::write(&case.manifest, json!({"platforms": {"local": {"supported": true, "machine": "foreign"}}, "profiles": {"profile": {"platforms": {"local": "runs"}}}}).to_string()).unwrap();
    let output = case
        .command()
        .arg("--fleet")
        .arg(&manifest)
        .output()
        .unwrap();
    assert_eq!(result(&output, 0)["class"], "gated");
    assert!(!case.dir(1).join("ready").exists());
}

#[test]
fn ambient_role_files_pass_through_and_unprovisioned_sweeps_start_nothing() {
    let case = Case::new("ambient-pass");
    let output = case
        .command()
        .env("KESTRIKE_HARDWARE_ROLES", "profile/owner=/ambient.env")
        .output()
        .unwrap();
    result(&output, 0);
    assert_eq!(
        fs::read_to_string(case.dir(1).join("roles")).unwrap(),
        "profile/owner=/ambient.env"
    );
    let case = Case::new("ambient-missing");
    let output = case
        .command()
        .env("KESTRIKE_HARDWARE_ROLES", "foreign/x")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!case.dir(1).exists());
}

#[test]
fn hardware_gate_exec_failure_records_exit_125_without_controller_spawn() {
    let case = Case::new("gate-exec-failure");
    let output = case.command().env("PATH", "/nonexistent").output().unwrap();
    let row = result(&output, 0);
    assert_eq!(row["exit"], 125);
    assert_eq!(row["class"], "infrastructure");
    assert!(!case.dir(1).join("ready").exists());
}

#[test]
fn fleet_controller_rechecks_shared_custody_after_supervisor_disposition() {
    let case = Case::new("fleet-shared-custody");
    let manifest = case.root.join("fleet.json");
    fs::write(
        &manifest,
        r#"{"workload":{"profile":"profile"},"hosts":{"a":{}},"deadlines":{"grace_seconds":1}}"#,
    )
    .unwrap();
    let output = case
        .command()
        .arg("--fleet")
        .arg(&manifest)
        .env("FAKE_FLEET_HELD", "1")
        .env("FAKE_EXIT", "4")
        .output()
        .unwrap();
    assert_eq!(result(&output, 4)["class"], "held");
    let verdict = fs::read(case.state.join("hardware/fleet/verdict.json")).unwrap();
    result(&case.dispose("operator containment evidence"), 0);
    let output = case
        .command()
        .arg("--fleet")
        .arg(&manifest)
        .output()
        .unwrap();
    assert_eq!(result(&output, 4)["exit"], 4);
    assert!(case.dir(2).join("ready").exists());
    assert_eq!(
        fs::read(case.state.join("hardware/fleet/verdict.json")).unwrap(),
        verdict
    );
    assert!(case.state.join("hardware/fleet/held").exists());
}

#[test]
fn controller_owned_fifo_and_receipt_preserve_the_authoritative_exit() {
    let case = Case::new("controller-records");
    let output = case.run("controller-records", 0);
    assert_eq!(result(&output, 0)["class"], "completed");
    assert!(case.dir(1).join("artifacts/close.pipe").exists());
    assert_eq!(
        fs::read(case.dir(1).join("artifacts/receipt.json")).unwrap(),
        b"{\"controller\":\"authoritative\"}\n"
    );
    assert_eq!(case.report()["hardware"][0]["class"], "completed");
}

#[test]
fn provisioned_roles_override_environments_and_malformed_inputs_start_nothing() {
    let case = Case::new("role-override");
    let output = case
        .command()
        .env(
            "KESTRIKE_HARDWARE_ROLES",
            "profile/owner=/ambient.env foreign/client=/other.env",
        )
        .args(["--environment", "owner=/operator.env"])
        .output()
        .unwrap();
    result(&output, 0);
    assert_eq!(
        fs::read_to_string(case.dir(1).join("roles")).unwrap(),
        "profile/owner=/operator.env"
    );
    for (index, environment) in [
        "owner=relative",
        "other=/absolute.env",
        "owner=/file with space",
    ]
    .into_iter()
    .enumerate()
    {
        let case = Case::new(&format!("environment-refused-{index}"));
        let output = case
            .command()
            .args(["--environment", environment])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(!case.dir(1).exists());
    }
    let case = Case::new("fleet-empty");
    let output = case.command().args(["--fleet", ""]).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!case.state.join("hardware").exists());
}

#[test]
fn self_exited_controller_leaves_its_group_member_unsignalled() {
    let case = Case::new("self-exit-member");
    let output = case.command().env("FAKE_MEMBER", "1").output().unwrap();
    assert_eq!(result(&output, 0)["class"], "completed");
    wait(&case.dir(1).join("member-ready"));
    assert!(!case.dir(1).join("member-signals").exists());
    assert!(!case.dir(1).join("member-exit").exists());
    fs::write(case.dir(1).join("release"), "go").unwrap();
    wait(&case.dir(1).join("member-exit"));
    assert!(!case.dir(1).join("member-signals").exists());
}

#[test]
fn missing_lifecycle_prerequisites_hold_without_repair() {
    let case = Case::new("missing-phase");
    result(&case.run("exit", 0), 0);
    fs::remove_file(case.dir(1).join("started")).unwrap();
    let finished = fs::read(case.dir(1).join("finished")).unwrap();
    assert_eq!(case.run("exit", 0).status.code(), Some(4));
    assert_eq!(fs::read(case.dir(1).join("finished")).unwrap(), finished);
    assert!(!case.dir(2).exists());
}

#[test]
fn started_run_disposal_reconciles_directly_and_records_evidence_only() {
    let case = Case::new("dispose-started");
    let mut supervisor = case
        .options(&[("--wall", Some("10"))])
        .env("FAKE_MODE", "linger")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    wait(&case.dir(1).join("ready"));
    supervisor.kill().unwrap();
    supervisor.wait().unwrap();
    result(&case.dispose("host contained, see log /evidence/host"), 0);
    let envelope: Value =
        serde_json::from_slice(&fs::read(case.dir(1).join("disposition")).unwrap()).unwrap();
    assert_eq!(
        envelope["record"],
        json!({"run": 1, "evidence": "host contained, see log /evidence/host"})
    );
    assert_eq!(case.report()["hardware"][0]["class"], "held");
    assert!(!case.dir(1).join("signals").exists());
    result(&case.run("exit", 0), 0);
    fs::write(case.dir(1).join("release"), "go").unwrap();
    wait(&case.dir(1).join("exit-marker"));
}

#[test]
fn fleet_held_and_lost_controllers_refuse_successors_without_local_custody() {
    for mode in ["exit", "linger"] {
        let case = Case::new(&format!("fleet-held-{mode}"));
        fs::write(case.root.join("custody"), "unlistable local custody").unwrap();
        let manifest = case.root.join("fleet.json");
        fs::write(&manifest, r#"{"workload":{"profile":"profile"},"hosts":{"a":{}},"deadlines":{"grace_seconds":1}}"#).unwrap();
        let mut command = case.options(&[("--wall", Some("10"))]);
        command
            .arg("--fleet")
            .arg(&manifest)
            .env("FAKE_MODE", mode)
            .env("FAKE_EXIT", "4");
        if mode == "exit" {
            assert_eq!(result(&command.output().unwrap(), 4)["class"], "held");
        } else {
            let mut supervisor = command
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            wait(&case.dir(1).join("ready"));
            supervisor.kill().unwrap();
            supervisor.wait().unwrap();
        }
        assert_eq!(case.run("exit", 0).status.code(), Some(4));
        assert!(!case.dir(2).exists());
        assert!(!case.dir(1).join("signals").exists());
        if mode == "linger" {
            fs::write(case.dir(1).join("release"), "go").unwrap();
            wait(&case.dir(1).join("exit-marker"));
        }
    }
    let case = Case::new("fleet-local-ignore");
    fs::write(case.root.join("custody"), "unlistable local custody").unwrap();
    let manifest = case.root.join("fleet.json");
    fs::write(
        &manifest,
        r#"{"workload":{"profile":"profile"},"hosts":{"a":{}},"deadlines":{"grace_seconds":1}}"#,
    )
    .unwrap();
    let output = case
        .command()
        .arg("--fleet")
        .arg(&manifest)
        .output()
        .unwrap();
    assert_eq!(result(&output, 0)["class"], "completed");
}

#[test]
fn mismatched_disposition_refuses_replacement_and_every_successor() {
    let case = Case::alone("disposition-number");
    result(&case.run("marker", 0), 4);
    let store = Store::open(&case.state.join("hardware")).unwrap();
    let runs = store
        .open_dir(store.root(), &Name::new("runs").unwrap())
        .unwrap()
        .unwrap();
    let dir = store
        .open_dir(&runs, &Name::new("0001").unwrap())
        .unwrap()
        .unwrap();
    let record = HardwareDisposition::new(
        2,
        campaign_supervisor::record::Text::new("evidence").unwrap(),
    )
    .unwrap();
    store
        .create_record(&dir, &Name::new("disposition").unwrap(), &record)
        .unwrap();
    drop(store);
    let bytes = fs::read(case.dir(1).join("disposition")).unwrap();
    assert_eq!(case.dispose("replacement").status.code(), Some(4));
    assert_eq!(fs::read(case.dir(1).join("disposition")).unwrap(), bytes);
    assert_eq!(case.run("exit", 0).status.code(), Some(4));
    assert!(!case.dir(2).exists());
}

impl Case {
    pub fn options(&self, replacements: &[(&str, Option<&str>)]) -> Command {
        let base = self.command();
        let args: Vec<_> = base.get_args().collect();
        let mut command = Command::new(base.get_program());
        let mut index = 0;
        while index < args.len() {
            if let Some((_, value)) = replacements.iter().find(|(key, _)| args[index] == *key) {
                if let Some(value) = value {
                    command.arg(args[index]).arg(value);
                }
                index += 2;
            } else {
                command.arg(args[index]);
                index += 1;
            }
        }
        command.env_remove("KESTRIKE_HARDWARE_ROLES");
        command
    }
    pub(super) fn report_output(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_campaign"))
            .args(["report", "--state"])
            .arg(&self.state)
            .output()
            .unwrap()
    }
}

#[test]
fn wall_stop_delivers_one_sigterm_and_holds_live_custody() {
    let case = Case::new("wall");
    let output = case
        .options(&[("--wall", Some("5"))])
        .env("FAKE_MODE", "linger-marker")
        .output()
        .unwrap();
    assert!(
        case.dir(1).join("ready").exists(),
        "controller startup witness"
    );
    let row = result(&output, 4);
    assert_eq!(row["class"], "held");
    assert_eq!(row["stopped"], true);
    assert_eq!(
        fs::read_to_string(case.dir(1).join("signals")).unwrap(),
        "15\n"
    );
    assert!(case.root.join("custody/held.json").exists());
    assert!(!case.dir(1).join("exit-marker").exists());
    fs::write(case.dir(1).join("release"), "go").unwrap();
    wait(&case.dir(1).join("exit-marker"));
}

#[test]
fn stopped_controller_exit_preserves_status_and_interruption() {
    let case = Case::new("stopped-exit");
    let output = case
        .options(&[("--wall", Some("5"))])
        .env("FAKE_MODE", "term-exit")
        .output()
        .unwrap();
    assert!(
        case.dir(1).join("ready").exists(),
        "controller startup witness"
    );
    let row = result(&output, 0);
    assert_eq!(row["class"], "interrupted");
    assert_eq!(row["exit"], 3);
    assert_eq!(row["stopped"], true);
    assert_eq!(
        fs::read_to_string(case.dir(1).join("signals")).unwrap(),
        "15\n"
    );
}

#[test]
fn unreadable_custody_holds_and_lock_file_allows_completion() {
    let case = Case::new("unlisted");
    fs::write(case.root.join("custody"), "a regular file").unwrap();
    assert_eq!(case.run("exit", 0).status.code(), Some(2));
    assert!(!case.dir(1).exists());
    let case = Case::new("lock-file");
    fs::create_dir(case.root.join("custody")).unwrap();
    fs::set_permissions(case.root.join("custody"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(case.root.join("custody/fis.lock"), "reservation").unwrap();
    assert_eq!(result(&case.run("exit", 0), 0)["class"], "completed");
}

#[test]
fn sweep_argv_and_environment_are_exact() {
    let case = Case::new("argv-sweep");
    result(&case.run("exit", 0), 0);
    let dir = case.dir(1);
    assert_eq!(
        fs::read_to_string(dir.join("cwd")).unwrap(),
        std::env::current_dir().unwrap().to_str().unwrap()
    );
    let argv: Value = serde_json::from_slice(&fs::read(dir.join("argv.json")).unwrap()).unwrap();
    assert_eq!(
        argv,
        json!([
            "sweep",
            "--manifest",
            case.manifest,
            "--platform",
            "local",
            "--artifacts",
            dir.join("artifacts"),
            "--custody",
            case.root.join("custody"),
            "--cargo",
            "cargo",
            "--budget-seconds",
            "30"
        ])
    );
    assert_eq!(
        fs::read_to_string(dir.join("roles")).unwrap(),
        "profile/owner"
    );
    let case = Case::new("no-sweep-grace");
    let output = case.options(&[("--grace", None)]).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!case.dir(1).exists());
}

#[test]
fn fis_episode_argv_uses_mapped_profile_default_grace_and_quoted_lane() {
    let case = Case::new("argv-fis");
    let fis_manifest = case.root.join("fis.json");
    let operator = case.root.join("operator.json");
    fs::write(
        &fis_manifest,
        r#"{"profiles":{"fis":{"lane":{"profile":"profile"}}}}"#,
    )
    .unwrap();
    let output = case
        .options(&[("--grace", None), ("--profile", Some("fis"))])
        .arg("--operator")
        .arg(&operator)
        .arg("--fis-manifest")
        .arg(&fis_manifest)
        .arg("--fis")
        .arg(&case.lane)
        .output()
        .unwrap();
    let row = result(&output, 0);
    assert_eq!(row["class"], "completed");
    assert_eq!(row["kind"], "episode");
    assert_eq!(
        fs::read_to_string(case.dir(1).join("platform")).unwrap(),
        "local"
    );
    let dir = case.dir(1);
    let argv: Value = serde_json::from_slice(&fs::read(dir.join("argv.json")).unwrap()).unwrap();
    assert_eq!(
        argv,
        json!([
            "episode",
            "--profile",
            "fis",
            "--operator",
            operator,
            "--manifest",
            fis_manifest,
            "--hardware-manifest",
            case.manifest,
            "--custody",
            case.root.join("custody"),
            "--artifacts",
            dir.join("artifacts"),
            "--observer",
            dir.join("observer"),
            "--kill-grace-seconds",
            "900",
            "--lane",
            format!("python3 '{}'", case.lane.display())
        ])
    );
}

#[test]
fn fleet_argv_uses_the_immutable_manifest_and_records_directory() {
    let case = Case::new("argv-fleet");
    let manifest = case.root.join("fleet.json");
    fs::write(
        &manifest,
        r#"{"workload":{"profile":"profile"},"hosts":{"a":{}},"deadlines":{"grace_seconds":1}}"#,
    )
    .unwrap();
    let output = case
        .options(&[("--grace", None)])
        .arg("--fleet")
        .arg(&manifest)
        .output()
        .unwrap();
    result(&output, 0);
    let dir = case.dir(1);
    let argv: Value = serde_json::from_slice(&fs::read(dir.join("argv.json")).unwrap()).unwrap();
    assert_eq!(
        argv,
        json!([
            "fleet",
            "--episode-manifest",
            dir.join("episode-manifest.json"),
            "--manifest",
            case.manifest,
            "--fis-manifest",
            std::env::current_dir()
                .unwrap()
                .join("scripts/fis-profiles.json"),
            "--state",
            case.state.join("hardware/fleet")
        ])
    );
}

#[test]
fn hardware_lock_is_independent_parent_startup_preserves_subtree_and_census_counts_it() {
    let case = Case::alone("independent");
    let parent = Store::open(&case.state).unwrap();
    assert_eq!(result(&case.run("exit", 0), 0)["class"], "completed");
    let before = parent.usage(65_536).unwrap();
    let staging = case.state.join("hardware/.staging/pending");
    let bytes = b"hardware staged evidence";
    fs::write(&staging, bytes).unwrap();
    let after = parent.usage(65_536).unwrap();
    assert_eq!(after.bytes - before.bytes, bytes.len() as u64);
    assert_eq!(after.inodes - before.inodes, 1);
    drop(parent);
    drop(Store::open(&case.state).unwrap());
    assert_eq!(fs::read(&staging).unwrap(), bytes);
    let finished = fs::read(case.dir(1).join("finished")).unwrap();
    let hardware = Store::open(&case.state.join("hardware")).unwrap();
    assert_eq!(case.report_output().status.code(), Some(3));
    assert_eq!(fs::read(case.dir(1).join("finished")).unwrap(), finished);
    drop(hardware);
    assert_eq!(case.report()["hardware"][0]["class"], "completed");
}

#[test]
fn competing_hardware_admission_is_busy_and_starts_nothing() {
    let case = Case::new("competing");
    let supervisor = case
        .options(&[("--wall", Some("10"))])
        .env("FAKE_MODE", "linger")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    wait(&case.dir(1).join("ready"));
    assert_eq!(case.run("exit", 0).status.code(), Some(3));
    assert_eq!(case.report_output().status.code(), Some(3));
    assert!(!case.dir(2).exists());
    fs::write(case.dir(1).join("release"), "go").unwrap();
    assert_eq!(
        result(&supervisor.wait_with_output().unwrap(), 0)["class"],
        "completed"
    );
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn hardware_and_dispatch_run_concurrently() {
    let case = Case::new("dispatch-concurrent");
    let supervisor = case
        .options(&[("--wall", Some("10"))])
        .env("FAKE_MODE", "linger")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    wait(&case.dir(1).join("ready"));
    let delegated = std::env::var_os("CAMPAIGN_CGROUP_ROOT").expect("delegated custody scope");
    let root = PathBuf::from(delegated).join(format!(
        "hardware-dispatch-concurrent-{}",
        std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_campaign"))
        .args(["dispatch", "--state"])
        .arg(&case.state)
        .arg("--archive")
        .arg(case.root.join("unused-archive"))
        .arg("--cgroup-root")
        .arg(&root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!case.dir(1).join("exit-marker").exists());
    fs::write(case.dir(1).join("release"), "go").unwrap();
    assert_eq!(
        result(&supervisor.wait_with_output().unwrap(), 0)["class"],
        "completed"
    );
    fs::remove_dir(root.join("controller")).unwrap();
    fs::remove_dir(root).unwrap();
}

#[test]
fn intent_only_reconciles_unrun_empty_admission_allows_retry_and_wrong_number_holds() {
    let case = Case::alone("intent-only");
    result(&case.run("exit", 0), 0);
    fs::remove_file(case.dir(1).join("started")).unwrap();
    fs::remove_file(case.dir(1).join("finished")).unwrap();
    fs::create_dir(case.dir(2)).unwrap();
    let snapshot = case.report();
    assert_eq!(snapshot["hardware"][0]["class"], "unrun");
    assert_eq!(snapshot["hardware"][0]["phase"], "intent");
    assert!(!case.dir(1).join("finished").exists());
    result(&case.run("exit", 0), 0);
    assert_eq!(case.report()["hardware"][0]["class"], "unrun");
    assert_eq!(case.report()["hardware"][1]["class"], "unrun");
    assert!(case.dir(3).join("ready").exists());
    let store = Store::open(&case.state.join("hardware")).unwrap();
    let runs = store
        .open_dir(store.root(), &Name::new("runs").unwrap())
        .unwrap()
        .unwrap();
    let run = store
        .open_dir(&runs, &Name::new("0003").unwrap())
        .unwrap()
        .unwrap();
    let mut record = store
        .read_record::<Hardware>(&run, &Name::new("finished").unwrap())
        .unwrap()
        .unwrap()
        .record()
        .clone();
    record.number = 9;
    fs::remove_file(case.dir(3).join("finished")).unwrap();
    store
        .create_record(&run, &Name::new("finished").unwrap(), &record)
        .unwrap();
    drop(store);
    assert_eq!(case.run("exit", 0).status.code(), Some(4));
    assert!(!case.dir(4).exists());
    assert_eq!(case.report()["hardware"][2]["class"], "held");
}

fn configure(case: &Case, overrides: &[(&str, u64)]) {
    let mut settings = std::collections::BTreeMap::from([
        ("slots", 1),
        ("reserve_slots", 1),
        ("cores", 4),
        ("memory", 1024),
        ("cpu", 60),
        ("tree_memory", 128),
        ("attempt_output", 100),
        ("attempt_inodes", 10),
        ("wall", 60),
        ("processes", 64),
        ("artifact_bytes", 50_000_000),
        ("artifact_inodes", 100),
        ("backlog", 10),
        ("retained_builds", 1),
    ]);
    settings.extend(overrides.iter().copied());
    let config = campaign_supervisor::record::Configuration::new(
        settings
            .into_iter()
            .map(|(key, value)| (campaign_supervisor::record::Text::new(key).unwrap(), value))
            .collect(),
    )
    .unwrap();
    let store = Store::open(&case.state).unwrap();
    store
        .create_record(store.root(), &Name::new("config.json").unwrap(), &config)
        .unwrap();
}

fn fill(case: &Case, count: usize) {
    let filler = case.state.join("filler");
    fs::create_dir(&filler).unwrap();
    for index in 0..count {
        fs::write(filler.join(index.to_string()), b"").unwrap();
    }
}

#[test]
fn campaign_storage_budget_refuses_hardware_admission_before_allocation() {
    let case = Case::alone("budget");
    configure(&case, &[]);
    assert_eq!(result(&case.run("exit", 0), 0)["class"], "completed");
    fill(&case, 100);
    let refused = case.run("exit", 0);
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("artifact_inodes"));
    assert!(!case.dir(2).exists());
    let mut deep = case.state.join("deep");
    fs::create_dir(&deep).unwrap();
    for _ in 0..64 {
        deep = deep.join("n");
        fs::create_dir(&deep).unwrap();
    }
    let held = case.run("exit", 0);
    assert_eq!(held.status.code(), Some(4));
    assert!(!case.dir(2).exists());
    assert_eq!(case.report()["hardware"][0]["class"], "completed");
}

#[test]
fn campaign_storage_budget_charges_every_slot_for_hardware_admission() {
    let case = Case::alone("budget-slots");
    configure(&case, &[("slots", 2), ("artifact_inodes", 150)]);
    fill(&case, 50);
    let refused = case.run("exit", 0);
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("artifact_inodes"));
    assert!(!case.dir(1).exists());
}
