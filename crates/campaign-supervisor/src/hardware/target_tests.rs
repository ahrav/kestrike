use super::cli::Args;
use super::target::Target;
use crate::store::fixture::Case;
use std::time::Duration;

fn args(case: &Case) -> Args {
    let manifest = case.root.join("hardware.json");
    std::fs::write(&manifest, serde_json::json!({"platforms": {"local": {"supported": true, "machine": std::env::consts::ARCH}}, "profiles": {"profile": {"platforms": {"local": "runs"}, "roles": {"owner": {}}}}}).to_string()).unwrap();
    Args {
        values: [
            ("--profile".into(), "profile".into()),
            ("--platform".into(), "local".into()),
            ("--wall".into(), "2".into()),
            ("--manifest".into(), manifest.to_str().unwrap().into()),
            (
                "--custody".into(),
                case.root.join("custody").to_str().unwrap().into(),
            ),
        ]
        .into(),
        environments: Vec::new(),
        ambient_roles: String::new(),
    }
}

#[test]
fn controller_classification_keeps_custody_precedence_and_controller_exits() {
    use crate::record::HardwareClass::*;
    for (exit, signal, stopped, marker, expected) in [
        (None, None, false, false, Held),
        (None, Some(15), false, false, Held),
        (Some(4), None, true, false, Held),
        (Some(0), None, false, true, Held),
        (Some(1), None, false, true, Held),
        (Some(5), None, false, true, Held),
        (Some(2), None, true, true, Held),
        (Some(0), None, true, false, Completed),
        (Some(1), None, true, false, Uncredited),
        (Some(2), None, false, false, Rejected),
        (Some(2), None, true, false, Interrupted),
        (Some(3), None, true, false, Interrupted),
        (Some(9), None, false, false, Infrastructure),
    ] {
        assert_eq!(
            super::controller::classify(exit, signal, stopped, marker),
            expected
        );
    }
}

#[test]
fn sweep_requires_an_explicit_finite_grace() {
    let case = Case::new();
    let mut args = args(&case);
    assert!(Target::parse(&args).is_err());
    for value in ["NaN", "inf", "-1", "1e300"] {
        args.values.insert("--grace".into(), value.into());
        assert!(Target::parse(&args).is_err());
    }
    args.values.insert("--grace".into(), "0.125".into());
    assert_eq!(
        Target::parse(&args).unwrap().grace,
        Duration::from_millis(125)
    );
}

#[test]
fn fis_defaults_to_900_seconds_and_accepts_override() {
    let case = Case::new();
    let mut args = args(&case);
    let manifest = case.root.join("fis.json");
    std::fs::write(
        &manifest,
        r#"{"profiles":{"fis":{"lane":{"profile":"profile"}}}}"#,
    )
    .unwrap();
    args.values.insert("--profile".into(), "fis".into());
    args.values
        .insert("--fis-manifest".into(), manifest.to_str().unwrap().into());
    args.values
        .insert("--operator".into(), "/operator.json".into());
    assert_eq!(
        Target::parse(&args).unwrap().grace,
        Duration::from_secs(900)
    );
    args.values.insert("--grace".into(), "3".into());
    assert_eq!(Target::parse(&args).unwrap().grace, Duration::from_secs(3));
}

#[test]
fn fleet_close_bound_uses_the_admitted_manifest_and_rejects_bad_fields() {
    let case = Case::new();
    let mut args = args(&case);
    let manifest = case.root.join("fleet.json");
    args.values
        .insert("--fleet".into(), manifest.to_str().unwrap().into());
    let bytes = br#"{"workload":{"profile":"profile"},"hosts":{"a":{},"b":{}},"deadlines":{"grace_seconds":4}}"#;
    std::fs::write(&manifest, bytes).unwrap();
    let target = Target::parse(&args).unwrap();
    assert_eq!(target.grace, Duration::from_secs(68));
    assert_eq!(target.fleet.as_deref(), Some(bytes.as_slice()));
    for (hosts, expected) in [(1, 38), (3, 98)] {
        let hosts: serde_json::Map<String, serde_json::Value> = (0..hosts)
            .map(|n| (n.to_string(), serde_json::json!({})))
            .collect();
        std::fs::write(&manifest, serde_json::json!({"workload": {"profile": "profile"}, "hosts": hosts, "deadlines": {"grace_seconds": 4}}).to_string()).unwrap();
        assert_eq!(
            Target::parse(&args).unwrap().grace,
            Duration::from_secs(expected)
        );
    }
    for document in [
        r#"{"workload":{"profile":"profile"},"hosts":{},"deadlines":{"grace_seconds":4}}"#,
        r#"{"workload":{"profile":"profile"},"hosts":[],"deadlines":{"grace_seconds":4}}"#,
        r#"{"workload":{"profile":"profile"},"hosts":{"a":{}},"deadlines":{}}"#,
        r#"{"workload":{"profile":"profile"},"hosts":{"a":{}},"deadlines":{"grace_seconds":-1}}"#,
        r#"{"workload":{"profile":"profile"},"hosts":{"a":{}},"deadlines":{"grace_seconds":"4"}}"#,
    ] {
        std::fs::write(&manifest, document).unwrap();
        assert!(Target::parse(&args).is_err());
    }
}

#[test]
fn catalog_read_fault_remains_a_host_fault() {
    use crate::step::{Outcome, Step};
    use crate::store::fixture::scripted;
    let case = Case::new();
    let mut args = args(&case);
    args.values.insert("--grace".into(), "1".into());
    let (result, steps) = scripted([], || Target::parse(&args));
    assert!(result.unwrap().is_ok());
    let index = steps.iter().position(|step| *step == Step::Read).unwrap();
    let (result, _) = scripted([(index, Outcome::Errno(libc::EIO))], || {
        Target::parse(&args)
    });
    let error = result.unwrap().err().unwrap();
    assert!(matches!(error, super::Error::Unreadable(_)));
    assert!(error.host_fault());
    assert_eq!(error.exit(), crate::exit::Supervisor::Held);
}

#[test]
fn expanded_roles_are_bounded_before_allocation() {
    let case = Case::new();
    let mut args = args(&case);
    let profile = "p".repeat(10_000);
    let roles: serde_json::Map<String, serde_json::Value> = (0..200)
        .map(|n| (format!("role{n}"), serde_json::json!({})))
        .collect();
    let catalog = serde_json::json!({"platforms": {"local": {"supported": true, "machine": std::env::consts::ARCH}}, "profiles": {&profile: {"platforms": {"local": "runs"}, "roles": roles}}});
    std::fs::write(args.values.get("--manifest").unwrap(), catalog.to_string()).unwrap();
    args.values.insert("--profile".into(), profile);
    args.values.insert("--grace".into(), "1".into());
    let error = Target::parse(&args).err().unwrap();
    assert!(error.to_string().contains("expanded roles"));
    assert_eq!(error.exit(), crate::exit::Supervisor::Rejected);
    assert!(!case.state.join("runs").exists());
}

#[test]
fn oversized_terminal_record_refuses_before_intent_or_spawn() {
    const CHILD: &str = "CAMPAIGN_HARDWARE_TERMINAL_BOUND_TEST";
    if std::env::var_os(CHILD).is_some() {
        crate::sys::restrict_file_limit(4096, 4096).unwrap();
        let case = Case::new();
        let mut args = args(&case);
        args.values.insert("--grace".into(), "1".into());
        args.values.insert("--cargo".into(), "\\".repeat(8192));
        let target = Target::parse(&args).unwrap();
        let store = crate::store::Store::open(&case.state).unwrap();
        let error = super::controller::run(&store, target).unwrap_err();
        assert_eq!(error.exit(), crate::exit::Supervisor::Rejected);
        assert!(error.to_string().contains("terminal record"));
        assert!(!case.state.join("runs/0001/intent").exists());
        assert!(!case.state.join("runs/0001/started").exists());
        assert!(!case.state.join("runs/0001/stdout").exists());
        return;
    }
    let _processes = crate::store::fixture::processes();
    use std::os::unix::process::CommandExt;
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "hardware::target_tests::oversized_terminal_record_refuses_before_intent_or_spawn",
        ])
        .process_group(0)
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{:?}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custody_stat_fault_remains_a_host_fault_before_allocation() {
    use crate::step::{Outcome, Step};
    use crate::store::fixture::scripted;
    let case = Case::new();
    let mut args = args(&case);
    args.values.insert("--grace".into(), "1".into());
    drop(Target::parse(&args).unwrap());
    let (result, steps) = scripted([], || Target::parse(&args));
    assert!(result.unwrap().is_ok());
    let index = steps.iter().rposition(|step| *step == Step::Stat).unwrap();
    let (result, _) = scripted([(index, Outcome::Errno(libc::EIO))], || {
        Target::parse(&args)
    });
    let error = result.unwrap().err().unwrap();
    assert_eq!(error.exit(), crate::exit::Supervisor::Held);
    assert!(error.host_fault());
    assert!(!case.state.join("runs").exists());
}

#[test]
fn repeated_marker_reads_preserve_the_pinned_directory_observation() {
    let case = Case::new();
    let mut args = args(&case);
    args.values.insert("--grace".into(), "1".into());
    let target = Target::parse(&args).unwrap();
    std::fs::write(target.custody.as_ref().unwrap().join("held.json"), "{}").unwrap();
    let pin = target.custody_pin.as_ref().unwrap();
    assert!(crate::store::hardware_markers(pin).unwrap());
    assert!(crate::store::hardware_markers(pin).unwrap());
}

#[test]
fn descriptor_permissions_are_checked_after_pathname_admission() {
    use crate::step::{Script, Step};
    use std::os::unix::fs::PermissionsExt;
    let case = Case::new();
    let mut args = args(&case);
    args.values.insert("--grace".into(), "1".into());
    drop(Target::parse(&args).unwrap());
    let (_, steps) = crate::store::fixture::scripted([], || Target::parse(&args));
    let index = steps.iter().rposition(|step| *step == Step::Stat).unwrap();
    let path = case.root.join("custody");
    let mut count = 0;
    crate::step::install(Some(Script {
        observe: Some(Box::new(move |_| {
            if count == index {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o1777)).unwrap();
            }
            count += 1;
        })),
        ..Script::default()
    }));
    let result = Target::parse(&args);
    crate::step::install(None);
    assert_eq!(
        result.err().unwrap().exit(),
        crate::exit::Supervisor::Rejected
    );
    assert!(!case.state.join("runs").exists());
}

#[test]
fn expanded_role_budget_distinguishes_exec_safe_and_record_only_sizes() {
    let case = Case::new();
    let mut args = args(&case);
    args.values.insert("--grace".into(), "1".into());
    for (length, accepted) in [(120000, true), (140000, false)] {
        let role = "r".repeat(length);
        let catalog = serde_json::json!({"platforms": {"local": {"supported": true, "machine": std::env::consts::ARCH}}, "profiles": {"profile": {"platforms": {"local": "runs"}, "roles": {role: {}}}}});
        std::fs::write(args.values.get("--manifest").unwrap(), catalog.to_string()).unwrap();
        let result = Target::parse(&args);
        assert_eq!(result.is_ok(), accepted);
        if !accepted {
            assert_eq!(
                result.err().unwrap().exit(),
                crate::exit::Supervisor::Rejected
            );
        }
        assert!(!case.state.join("runs").exists());
    }
}

#[test]
fn platform_environment_is_bounded_before_allocation() {
    let case = Case::new();
    let mut args = args(&case);
    args.values.insert("--grace".into(), "1".into());
    args.values.insert("--platform".into(), "p".repeat(131071));
    let error = Target::parse(&args).err().unwrap();
    assert_eq!(error.exit(), crate::exit::Supervisor::Rejected);
    assert!(
        error
            .to_string()
            .contains("platform exceeds exec byte bound")
    );
    assert!(!case.state.join("runs").exists());
}

#[test]
fn argv_strings_are_bounded_before_allocation() {
    let case = Case::new();
    let mut args = args(&case);
    args.values.insert("--grace".into(), "1".into());
    for (length, accepted) in [(131_071, true), (131_072, false)] {
        args.values.insert("--cargo".into(), "c".repeat(length));
        let result = Target::parse(&args);
        assert_eq!(result.is_ok(), accepted, "cargo of {length} bytes");
        if let Err(error) = result {
            assert_eq!(error.exit(), crate::exit::Supervisor::Rejected);
            assert!(error.to_string().contains("exceeds exec byte bound"));
        }
        assert!(!case.state.join("runs").exists());
    }
    let mut args = self::args(&case);
    let manifest = case.root.join("fis.json");
    std::fs::write(
        &manifest,
        r#"{"profiles":{"fis":{"lane":{"profile":"profile"}}}}"#,
    )
    .unwrap();
    args.values.insert("--profile".into(), "fis".into());
    args.values
        .insert("--fis-manifest".into(), manifest.to_str().unwrap().into());
    args.values
        .insert("--operator".into(), "/operator.json".into());
    for (length, accepted) in [(131_060, true), (131_061, false)] {
        args.values
            .insert("--lane".into(), format!("/{}", "l".repeat(length)));
        let result = Target::parse(&args);
        assert_eq!(result.is_ok(), accepted, "episode lane of {length} bytes");
        if let Err(error) = result {
            assert_eq!(error.exit(), crate::exit::Supervisor::Rejected);
            assert!(error.to_string().contains("exceeds exec byte bound"));
        }
        assert!(!case.state.join("runs").exists());
    }
}
