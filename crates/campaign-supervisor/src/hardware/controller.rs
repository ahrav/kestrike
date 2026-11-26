use std::ffi::OsString;
use std::io::Write;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::target::Target;
use super::{Error, name, runs, text};
use crate::record::{Hardware, HardwareClass, HardwareKind, HardwarePhase, Record};
use crate::store::Store;
use crate::sys;

const SCAN_REASON_BOUND: usize = 512;

fn finish_reason(
    record: &Hardware,
    marker: &str,
    scan: &str,
    directory: &std::path::Path,
) -> Result<crate::record::Text, Error> {
    text(&format!(
        "controller exit={:?}, signal={:?}, stopped={}, custody_marker={marker}, custody_scan={scan}; controller records under {}",
        record.exit,
        record.signal,
        record.stopped,
        directory.display()
    ))
}

fn argv(
    target: &Target,
    path: &std::path::Path,
    fleet_state: &std::path::Path,
) -> Result<Vec<OsString>, Error> {
    let mut argv: Vec<OsString> = vec!["python3".into()];
    let artifacts = path.join("artifacts");
    let observer = path.join("observer");
    let grace = target.grace.as_secs_f64().to_string();
    match target.kind {
        HardwareKind::Fleet => {
            let snapshot = path.join("episode-manifest.json");
            let state = fleet_state.to_path_buf();
            argv.extend([
                target.lane.clone().into(),
                "fleet".into(),
                "--episode-manifest".into(),
                snapshot.into(),
                "--manifest".into(),
                target.manifest.clone().into(),
                "--fis-manifest".into(),
                target.fis_manifest.clone().into(),
                "--state".into(),
                state.into(),
            ]);
        }
        HardwareKind::Episode => {
            let lane = super::target::quoted_lane(&target.lane)?;
            argv.extend([
                target.fis.clone().into(),
                "episode".into(),
                "--profile".into(),
                target.profile.clone().into(),
                "--operator".into(),
                target
                    .operator
                    .as_ref()
                    .expect("episode operator")
                    .clone()
                    .into(),
                "--manifest".into(),
                target.fis_manifest.clone().into(),
                "--hardware-manifest".into(),
                target.manifest.clone().into(),
                "--custody".into(),
                target
                    .custody
                    .as_ref()
                    .expect("episode custody")
                    .clone()
                    .into(),
                "--artifacts".into(),
                artifacts.into(),
                "--observer".into(),
                observer.into(),
                "--kill-grace-seconds".into(),
                grace.into(),
                "--lane".into(),
                lane.into(),
            ]);
        }
        HardwareKind::Sweep => {
            argv.extend([
                target.lane.clone().into(),
                "sweep".into(),
                "--manifest".into(),
                target.manifest.clone().into(),
                "--platform".into(),
                target.platform.clone().into(),
                "--artifacts".into(),
                artifacts.into(),
                "--custody".into(),
                target
                    .custody
                    .as_ref()
                    .expect("sweep custody")
                    .clone()
                    .into(),
                "--cargo".into(),
                target.cargo.clone().into(),
                "--budget-seconds".into(),
                target.wall.as_secs_f64().to_string().into(),
            ]);
        }
    }
    Ok(argv)
}

pub(super) fn run(store: &Store, target: Target) -> Result<Hardware, Error> {
    text(
        store
            .path()
            .to_str()
            .ok_or_else(|| Error::Rejected("state path requires ASCII".into()))?,
    )?;
    let file_limit = sys::controller_file_limit()?;
    if target
        .fleet
        .as_ref()
        .is_some_and(|document| document.len() as u64 > file_limit)
    {
        return Err(Error::Rejected(
            "fleet document exceeds controller file-size limit".into(),
        ));
    }
    let (number, dir, path) = runs::allocate(store)?;
    let argv = argv(&target, &path, &store.path().join("fleet"))?;
    let mut record = Hardware {
        argv: argv
            .iter()
            .map(|value| {
                value
                    .to_str()
                    .ok_or_else(|| Error::Rejected("argv requires ASCII".into()))
                    .and_then(text)
            })
            .collect::<Result<_, _>>()?,
        class: None,
        custody_directory: target
            .custody
            .as_ref()
            .map(|p| text(p.to_str().expect("controller paths were validated")))
            .transpose()?,
        directory: text(
            path.to_str()
                .ok_or_else(|| Error::Rejected("state path requires ASCII".into()))?,
        )?,
        exit: None,
        kind: target.kind,
        number,
        phase: HardwarePhase::Intent,
        platform: text(&target.platform)?,
        profile: text(&target.profile)?,
        reason: text("admitted")?,
        signal: None,
        stopped: false,
    };
    let controller_records = if record.kind == HardwareKind::Fleet {
        store.path().join("fleet")
    } else {
        path.clone()
    };
    let mut terminal = record.clone();
    terminal.phase = HardwarePhase::Finished;
    terminal.class = Some(HardwareClass::Infrastructure);
    terminal.exit = Some(u64::MAX);
    terminal.signal = Some(u64::MAX);
    terminal.reason = if let Some(reason) = &target.gate {
        text(reason)?
    } else {
        finish_reason(
            &terminal,
            "not applicable",
            &"\\".repeat(SCAN_REASON_BOUND),
            &controller_records,
        )?
    };
    let terminal_bytes = terminal.encoded_len() as u64;
    if terminal_bytes > Hardware::BOUND || terminal_bytes > file_limit {
        return Err(Error::Rejected(
            "hardware terminal record exceeds byte bound".into(),
        ));
    }
    if let Some(document) = &target.fleet {
        store.create_once(&dir, &name("episode-manifest.json"), document)?;
    }
    if let Some(reason) = target.gate {
        record.phase = HardwarePhase::Finished;
        record.class = Some(HardwareClass::Gated);
        record.reason = text(&reason)?;
        runs::write(store, &dir, "finished", &record)?;
        return Ok(record);
    }
    let signals = sys::Signals::open()?;
    runs::write(store, &dir, "intent", &record)?;
    let mut command = Command::new(crate::store::canonical_host(std::path::Path::new(
        "/proc/self/exe",
    ))?);
    command
        .args([OsString::from("hardware-gate"), OsString::from("--")])
        .args(&argv)
        .stdin(Stdio::piped());
    command.stdout(
        store
            .launcher_output(&dir, &name("stdout"))?
            .ok_or_else(|| Error::Held("stdout already present".into()))?,
    );
    command.stderr(
        store
            .launcher_output(&dir, &name("stderr"))?
            .ok_or_else(|| Error::Held("stderr already present".into()))?,
    );
    if let Some(roles) = target.roles {
        command.env("KESTRIKE_HARDWARE_ROLES", roles);
    }
    command.env("KESTRIKE_HARDWARE_PLATFORM", record.platform.as_str());
    let working_directory = crate::store::absolute_host(std::path::Path::new("."))?;
    sys::hardware_setup(&mut command, &working_directory)?;
    let mut child = command.spawn()?;
    record.phase = HardwarePhase::Started;
    runs::write(store, &dir, "started", &record)?;
    let mut go = child.stdin.take().expect("gate stdin is piped");
    let interrupted = signals.take()?.is_some();
    let released = !interrupted && go.write_all(b"G").is_ok();
    drop(go);
    if !released {
        record.stopped = interrupted;
        child.wait()?;
    }
    let began = Instant::now();
    let mut stopped_at = (!released).then(Instant::now);
    loop {
        if let Some(status) = child.try_wait()? {
            record.exit = status.code().map(|code| code as u64);
            record.signal = status.signal().map(|signal| signal as u64);
            break;
        }
        let interrupted = signals.take()?.is_some();
        if stopped_at.is_none() && (interrupted || began.elapsed() >= target.wall) {
            stopped_at = Some(Instant::now());
            record.stopped = sys::terminate_child(&mut child)?;
        }
        if stopped_at.is_some_and(|at| at.elapsed() >= target.grace) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if record.exit.is_none()
        && record.signal.is_none()
        && let Some(status) = child.try_wait()?
    {
        record.exit = status.code().map(|code| code as u64);
        record.signal = status.signal().map(|signal| signal as u64);
    }
    let (hold, marker, mut scan_reason) = match target
        .custody_pin
        .as_ref()
        .map(crate::store::hardware_markers)
    {
        Some(Ok(marker)) => (
            marker,
            if marker { "true" } else { "false" },
            "readable".to_owned(),
        ),
        Some(Err(error)) => (true, "unknown", error.to_string()),
        None => (false, "not applicable", "not applicable".to_owned()),
    };
    if scan_reason.len() > SCAN_REASON_BOUND {
        let mut bound = SCAN_REASON_BOUND;
        while !scan_reason.is_char_boundary(bound) {
            bound -= 1;
        }
        scan_reason.truncate(bound);
    }
    let class = classify(record.exit, record.signal, record.stopped, hold);
    record.phase = HardwarePhase::Finished;
    record.class = Some(class);
    record.reason = finish_reason(&record, marker, &scan_reason, &controller_records)?;
    if record.exit.is_some() || record.signal.is_some() {
        for file in ["stdout", "stderr"] {
            let output = store
                .open_file(&dir, &name(file))?
                .ok_or_else(|| Error::Held("controller log vanished".into()))?;
            store.sync_file(&dir, &output)?;
        }
    }
    runs::write(store, &dir, "finished", &record)?;
    Ok(record)
}

pub(super) fn classify(
    exit: Option<u64>,
    signal: Option<u64>,
    stopped: bool,
    marker: bool,
) -> HardwareClass {
    if exit.is_none() || signal.is_some() || exit == Some(4) || marker {
        HardwareClass::Held
    } else {
        match exit {
            Some(0) => HardwareClass::Completed,
            Some(1) => HardwareClass::Uncredited,
            Some(5) => HardwareClass::Interrupted,
            _ if stopped => HardwareClass::Interrupted,
            Some(2) => HardwareClass::Rejected,
            _ => HardwareClass::Infrastructure,
        }
    }
}

pub(crate) fn gate(args: &[OsString]) -> std::io::Result<std::convert::Infallible> {
    let (program, rest) = crate::custody::gate::released(args)?;
    sys::clear_parent_death()?;
    Err(Command::new(program).args(rest).stdin(Stdio::null()).exec())
}
