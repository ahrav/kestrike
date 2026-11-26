//! `kestrike-soak` refuses a usage error before it touches the mappings
//! record or the hardware. These tests spawn the binary, so they run in
//! their own test process.
#![cfg(all(target_os = "linux", target_pointer_width = "64"))]
#![allow(
    clippy::disallowed_methods,
    reason = "these integration tests launch the host soak tool"
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A fresh 0700 state directory under a unique name in a private parent, created exclusively so the test owns
/// everything under it; the run's state-directory rule admits it, and dropping the guard removes it.
fn scratch(name: &str) -> Scratch {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::var_os("HOME")
        .map_or_else(|| std::env::current_dir().unwrap(), PathBuf::from)
        .join(".tmp/kestrike-soak-cli-tests");
    let owner = fs::metadata("/proc/self").unwrap().uid();
    kestrike::bind::prepare_state_dir(&base, owner).unwrap();
    let dir = base.join(format!("{name}-{}-{nanos}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    Scratch(dir)
}

struct Scratch(PathBuf);

impl std::ops::Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn soak_command(mappings: &Path, receipt: &Path, seconds: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kestrike-soak"));
    command
        .env_clear()
        .env("KESTRIKE_MAPPINGS", mappings)
        .env("KESTRIKE_SOAK_RECEIPT", receipt)
        .env("KESTRIKE_SOAK_SECONDS", seconds)
        .env("KESTRIKE_N_REG", "3")
        .env("KESTRIKE_N_RESV", "2")
        .env("KESTRIKE_T_REPORT", "10")
        .env("KESTRIKE_T_PA", "20")
        .env("KESTRIKE_N_RETRY", "1")
        .env("KESTRIKE_SERVING_WINDOW_US", "1000")
        .env("KESTRIKE_REPORT_PERIOD_US", "100")
        .env("KESTRIKE_CLOCK_ERROR_US", "0");
    command
}

fn soak(mappings: &Path, receipt: &Path, seconds: &str) -> Output {
    soak_command(mappings, receipt, seconds).output().unwrap()
}

#[test]
fn a_zero_second_run_is_a_usage_error_before_the_receipt_exists() {
    let dir = scratch("zero");
    let receipt = dir.join("receipt");
    let output = soak(&dir.join("absent-mappings"), &receipt, "0");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("KESTRIKE_SOAK_SECONDS"), "{stderr}");
    assert!(!receipt.exists(), "no receipt for a refused run");
}

#[test]
fn a_receipt_that_aliases_the_mappings_record_is_refused_before_truncation() {
    let dir = scratch("alias");
    let mappings = dir.join("mappings");
    fs::write(&mappings, b"the binding record").unwrap();
    let link = dir.join("receipt-link");
    std::os::unix::fs::symlink(&mappings, &link).unwrap();
    for receipt in [mappings.clone(), link] {
        let output = soak(&mappings, &receipt, "1");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{stderr}");
        assert!(stderr.contains("KESTRIKE_SOAK_RECEIPT"), "{stderr}");
        assert_eq!(
            fs::read(&mappings).unwrap(),
            b"the binding record",
            "the mappings record keeps its bytes"
        );
    }
}

#[test]
fn a_mappings_path_that_is_not_the_state_directory_s_record_is_refused_before_the_receipt() {
    let dir = scratch("sibling");
    let record = dir.join("mappings");
    fs::write(&record, b"the binding record").unwrap();
    let sibling = dir.join("notes");
    fs::write(&sibling, b"a sibling file").unwrap();
    let output = soak(&sibling, &record, "1");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("KESTRIKE_MAPPINGS"), "{stderr}");
    assert_eq!(fs::read(&record).unwrap(), b"the binding record");
}

#[test]
fn a_run_refused_the_owner_lock_leaves_the_active_receipt_untouched() {
    let dir = scratch("locked");
    let record = dir.join("mappings");
    fs::write(&record, b"the binding record").unwrap();
    let receipt = dir.join("receipt");
    fs::write(&receipt, b"{\"line\": \"the active run's evidence\"}\n").unwrap();
    let held = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join("bind.lock"))
        .unwrap();
    held.try_lock().unwrap();
    let output = soak(&record, &receipt, "1");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("owner lock"), "{stderr}");
    assert_eq!(
        fs::read(&receipt).unwrap(),
        b"{\"line\": \"the active run's evidence\"}\n",
        "the refused run wrote nothing to the active receipt"
    );
}

#[test]
fn a_receipt_on_a_character_device_streams_without_truncation() {
    let dir = scratch("device");
    let record = dir.join("mappings");
    fs::write(&record, b"not a mappings record").unwrap();
    let output = soak(&record, Path::new("/dev/null"), "1");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("mappings:"),
        "the receipt opened and the run went on to the record: {stderr}"
    );
}

#[test]
fn a_numeric_override_that_is_not_utf_8_is_a_usage_error() {
    use std::os::unix::ffi::OsStrExt;
    let dir = scratch("bytes");
    let output = Command::new(env!("CARGO_BIN_EXE_kestrike-soak"))
        .env_clear()
        .env("KESTRIKE_MAPPINGS", dir.join("mappings"))
        .env("KESTRIKE_SOAK_RECEIPT", dir.join("receipt"))
        .env("KESTRIKE_SOAK_SEED", std::ffi::OsStr::from_bytes(b"\xff7"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("give numbers"), "{stderr}");
}

#[test]
fn a_receipt_on_a_block_device_is_refused() {
    let Some(device) = fs::read_dir("/sys/block")
        .ok()
        .and_then(|entries| entries.flatten().next())
        .map(|entry| Path::new("/dev").join(entry.file_name()))
        .filter(|device| device.exists())
    else {
        eprintln!("this host exposes no block device; the check is unexercised here");
        return;
    };
    let dir = scratch("block");
    let record = dir.join("mappings");
    fs::write(&record, b"not a mappings record").unwrap();
    let output = soak(&record, &device, "1");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("block device"), "{stderr}");
}

#[test]
fn missing_or_invalid_reservation_and_serving_inputs_preserve_the_receipt_before_locking() {
    let dir = scratch("reservation-inputs");
    let record = dir.join("mappings");
    let receipt = dir.join("receipt");
    fs::write(&record, b"the binding record").unwrap();
    fs::write(&receipt, b"the previous receipt").unwrap();
    for (name, invalid) in [
        ("KESTRIKE_N_REG", None),
        ("KESTRIKE_N_RESV", None),
        ("KESTRIKE_T_REPORT", None),
        ("KESTRIKE_T_PA", None),
        ("KESTRIKE_N_REG", Some("32768")),
        ("KESTRIKE_N_RESV", Some("3")),
        ("KESTRIKE_N_RESV", Some("4294967295")),
        ("KESTRIKE_N_RETRY", None),
        ("KESTRIKE_SERVING_WINDOW_US", None),
        ("KESTRIKE_REPORT_PERIOD_US", None),
        ("KESTRIKE_CLOCK_ERROR_US", None),
        ("KESTRIKE_N_RETRY", Some("0")),
        ("KESTRIKE_SERVING_WINDOW_US", Some("110")),
        ("KESTRIKE_REPORT_PERIOD_US", Some("0")),
        ("KESTRIKE_CLOCK_ERROR_US", Some("a microsecond")),
    ] {
        let mut command = soak_command(&record, &receipt, "1");
        if let Some(value) = invalid {
            command.env(name, value);
        } else {
            command.env_remove(name);
        }
        let output = command.output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{stderr}");
        assert!(stderr.contains(name), "{stderr}");
        assert_eq!(fs::read(&record).unwrap(), b"the binding record");
        assert_eq!(fs::read(&receipt).unwrap(), b"the previous receipt");
        assert!(!dir.join("bind.lock").exists());
    }
}

#[test]
fn receipt_aliases_preserve_each_authority_file_before_truncation() {
    for name in ["host.key", "assignment", "authority"] {
        let dir = scratch(name);
        let mappings = dir.join("mappings");
        let record = dir.join(name);
        fs::write(&mappings, b"the binding record").unwrap();
        fs::write(&record, b"private authority bytes").unwrap();
        let symlink = dir.join("receipt-symlink");
        let hardlink = dir.join("receipt-hardlink");
        std::os::unix::fs::symlink(&record, &symlink).unwrap();
        fs::hard_link(&record, &hardlink).unwrap();
        for receipt in [record.clone(), symlink, hardlink] {
            let output = soak(&mappings, &receipt, "1");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(2), "{stderr}");
            assert!(stderr.contains("KESTRIKE_SOAK_RECEIPT"), "{stderr}");
            assert!(stderr.contains(name), "{stderr}");
            assert_eq!(fs::read(&record).unwrap(), b"private authority bytes");
        }
    }
}

#[test]
fn receipt_aliases_preserve_each_soak_store_record_before_truncation() {
    for name in ["shard-1", "page-1-0", "watermark"] {
        let dir = scratch(&format!("store-{name}"));
        let mappings = dir.join("mappings");
        fs::write(&mappings, b"the binding record").unwrap();
        fs::create_dir(dir.join("soak-store")).unwrap();
        let record = dir.join("soak-store").join(name);
        fs::write(&record, b"soak store bytes").unwrap();
        let symlink = dir.join("receipt-symlink");
        let hardlink = dir.join("receipt-hardlink");
        std::os::unix::fs::symlink(&record, &symlink).unwrap();
        fs::hard_link(&record, &hardlink).unwrap();
        for receipt in [record.clone(), symlink, hardlink] {
            let output = soak(&mappings, &receipt, "1");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(2), "{stderr}");
            assert!(stderr.contains("KESTRIKE_SOAK_RECEIPT"), "{stderr}");
            assert!(stderr.contains(name), "{stderr}");
            assert_eq!(fs::read(&record).unwrap(), b"soak store bytes");
        }
    }
}

#[test]
fn a_receipt_the_open_creates_inside_the_soak_store_is_refused_and_removed() {
    let dir = scratch("store-new");
    let mappings = dir.join("mappings");
    fs::write(&mappings, b"the binding record").unwrap();
    let store = dir.join("soak-store");
    fs::create_dir(&store).unwrap();
    let record = store.join("shard-1");
    fs::write(&record, b"soak store bytes").unwrap();
    for name in ["watermark", "shard-1.tmp", "fresh"] {
        let receipt = store.join(name);
        let output = soak(&mappings, &receipt, "1");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{stderr}");
        assert!(stderr.contains("soak-store"), "{stderr}");
        assert!(!receipt.exists(), "{name}: the created receipt is removed");
        assert_eq!(fs::read(&record).unwrap(), b"soak store bytes");
    }
}

#[test]
fn a_receipt_naming_the_target_of_a_linked_soak_store_entry_is_refused() {
    let dir = scratch("store-link");
    let mappings = dir.join("mappings");
    fs::write(&mappings, b"the binding record").unwrap();
    let store = dir.join("soak-store");
    fs::create_dir(&store).unwrap();
    let target = dir.join("elsewhere");
    fs::write(&target, b"linked bytes").unwrap();
    std::os::unix::fs::symlink(&target, store.join("shard-1")).unwrap();
    let output = soak(&mappings, &target, "1");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("soak-store/shard-1"), "{stderr}");
    assert_eq!(fs::read(&target).unwrap(), b"linked bytes");
}

#[test]
fn an_unlistable_soak_store_refuses_the_receipt_before_truncation() {
    let dir = scratch("store-unlistable");
    let mappings = dir.join("mappings");
    fs::write(&mappings, b"the binding record").unwrap();
    // A regular file in the store directory's place fails the listing for every user, root included.
    fs::write(dir.join("soak-store"), b"not a directory").unwrap();
    let receipt = dir.join("receipt");
    fs::write(&receipt, b"the previous receipt").unwrap();
    let output = soak(&mappings, &receipt, "1");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("soak-store"), "{stderr}");
    assert_eq!(fs::read(&receipt).unwrap(), b"the previous receipt");
}

#[test]
fn a_receipt_through_a_dangling_link_is_refused_before_any_file_appears() {
    let dir = scratch("store-dangling");
    let mappings = dir.join("mappings");
    fs::write(&mappings, b"the binding record").unwrap();
    fs::create_dir(dir.join("soak-store")).unwrap();
    let target = dir.join("soak-store").join("shard-1");
    let link = dir.join("receipt-link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let output = soak(&mappings, &link, "1");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("cannot be created"), "{stderr}");
    assert!(!target.exists(), "the link's target stays absent");
}

#[test]
fn a_receipt_at_a_staging_name_is_refused_and_removed() {
    let dir = scratch("staging");
    let mappings = dir.join("mappings");
    fs::write(&mappings, b"the binding record").unwrap();
    let staging = dir.join("authority.tmp");
    let output = soak(&mappings, &staging, "1");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("authority.tmp"), "{stderr}");
    assert!(!staging.exists(), "the created receipt is removed");
}

#[test]
fn a_state_directory_open_to_others_refuses_before_the_receipt() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("shared-state");
    let mappings = dir.join("mappings");
    fs::write(&mappings, b"the binding record").unwrap();
    fs::set_permissions(&*dir, fs::Permissions::from_mode(0o755)).unwrap();
    let receipt = dir.join("receipt");
    let output = soak(&mappings, &receipt, "1");
    fs::set_permissions(&*dir, fs::Permissions::from_mode(0o700)).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("state directory"), "{stderr}");
    assert!(
        !receipt.exists(),
        "no receipt opens before the state directory check"
    );
}

#[test]
fn an_unreadable_store_entry_refuses_the_receipt_before_truncation() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // Root reads every entry whatever the directory's mode, so only another user reaches the refusal.
    if fs::metadata("/proc/self").unwrap().uid() == 0 {
        return;
    }
    let dir = scratch("store-unreadable");
    let mappings = dir.join("mappings");
    fs::write(&mappings, b"the binding record").unwrap();
    let store = dir.join("soak-store");
    fs::create_dir(&store).unwrap();
    let record = store.join("shard-1");
    fs::write(&record, b"soak store bytes").unwrap();
    let hardlink = dir.join("receipt-hardlink");
    fs::hard_link(&record, &hardlink).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o400)).unwrap();
    let output = soak(&mappings, &hardlink, "1");
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("soak-store"), "{stderr}");
    assert_eq!(fs::read(&record).unwrap(), b"soak store bytes");
}

/// The crate's non-test binaries against the chaos catalog.
mod chaos {
    use std::fs;
    use std::path::Path;

    fn name_of(path: &Path) -> String {
        path.file_stem().unwrap().to_str().unwrap().to_owned()
    }

    /// The binary sources under `dir`, by target name: each entry is a
    /// regular `NAME.rs` file or a directory `NAME` that holds a regular
    /// `main.rs`, the two layouts Cargo builds a binary from, with a UTF-8
    /// name. Any other entry is refused by its path.
    fn bin_sources(dir: &Path) -> Result<Vec<String>, String> {
        let mut sources = Vec::new();
        for entry in fs::read_dir(dir).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|error| format!("{}: {error}", path.display()))?;
            let name =
                if kind.is_file() && path.extension().is_some_and(|extension| extension == "rs") {
                    path.file_stem()
                } else if kind.is_dir()
                    && fs::symlink_metadata(path.join("main.rs")).is_ok_and(|meta| meta.is_file())
                {
                    path.file_name()
                } else {
                    None
                };
            let name = name.and_then(|name| name.to_str()).ok_or_else(|| {
                format!("{} is not a regular .rs source or a directory with a regular main.rs, named in UTF-8", path.display())
            })?;
            sources.push(name.to_owned());
        }
        sources.sort();
        Ok(sources)
    }

    /// Whether `manifest` may declare a binary target: after a leading byte
    /// order mark, a line other than a comment that, without whitespace and
    /// quotes, opens a `[[bin]]` table or sets `bin`, or a table header or
    /// key that holds a backslash, an escape this reading leaves undecoded.
    fn declares_bin(manifest: &str) -> bool {
        let lines = manifest.trim_start_matches('\u{feff}').lines();
        lines
            .filter(|line| !line.trim_start().starts_with('#'))
            .any(|line| {
                let bare: String = line
                    .chars()
                    .filter(|c| !c.is_whitespace() && !matches!(c, '"' | '\''))
                    .collect();
                let key = bare.split('=').next().unwrap_or_default();
                let escaped = (bare.starts_with('[') || bare.contains('=')) && key.contains('\\');
                bare.starts_with("[[bin]]") || bare.starts_with("bin=") || escaped
            })
    }

    /// The bytes of the regular file at `path`, opened once without
    /// following a symlink at its last component or waiting on a FIFO: a
    /// little-endian ELF64 executable or shared object, whose 64-byte
    /// header is complete and whose section header table, a nonzero count
    /// of 64-byte entries, starts past the header and ends at the last byte
    /// read. Linkers write that table last, so every shorter copy of an
    /// accepted file is refused, and so is a file with bytes after its
    /// table.
    fn artifact(path: &Path) -> Result<Vec<u8>, String> {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let mut bytes = Vec::new();
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .and_then(|mut file| match file.metadata()?.is_file() {
                true => file.read_to_end(&mut bytes),
                false => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "not a regular file",
                )),
            })
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let whole = bytes.get(..64).is_some_and(|header| {
            let field = |at: usize, width: usize| {
                header[at..at + width]
                    .iter()
                    .rev()
                    .fold(0u64, |value, &byte| value << 8 | u64::from(byte))
            };
            let (offset, entry, count) = (field(0x28, 8), field(0x3A, 2), field(0x3C, 2));
            let end = offset.checked_add(entry * count);
            header.starts_with(b"\x7fELF\x02\x01")
                && matches!(field(0x10, 2), 2 | 3)
                && field(0x34, 2) == 64
                && entry == 64
                && offset >= 64
                && count > 0
                && end.is_some_and(|end| end == bytes.len() as u64)
        });
        match whole {
            true => Ok(bytes),
            false => Err(format!("{} is not a whole ELF file", path.display())),
        }
    }

    /// The chaos catalog's mark, reversed. The scan reverses it at run time, so
    /// this test executable holds no copy of the needle, and a library guard
    /// checks that it reverses to the catalog's mark.
    const REVERSED_MARK: &str = "golatac tniop soahc ekirtsek";

    /// The simulated worlds' control mark, reversed for the same reason, and
    /// held equal to the library's reversed copy by a guard in the library's
    /// bundle tests.
    const REVERSED_CONTROL_MARK: &str = "kram eliforp lortnoc ekirtsek";

    /// Cargo builds the crate's three binaries without `cfg(test)`, so none
    /// compiles the chaos points' catalog, decisions or armed state, or the
    /// simulated worlds whose scenario lookup every control run passes, and
    /// none holds the bytes of the catalog's mark or the worlds' control mark.
    #[test]
    fn no_binary_holds_a_chaos_point() {
        let needle: String = REVERSED_MARK.chars().rev().collect();
        let control: String = REVERSED_CONTROL_MARK.chars().rev().collect();
        // A reversed needle could make the scan pass even when a binary
        // contains the forward mark.
        assert!(
            needle.starts_with("kestrike ") && needle.ends_with(" catalog"),
            "the scan searches for the forward mark, not for {needle:?}"
        );
        assert!(
            control.starts_with("kestrike ") && control.ends_with(" mark"),
            "the scan searches for the forward control mark, not for {control:?}"
        );
        let scanned = [
            env!("CARGO_BIN_EXE_kestrike-bind"),
            env!("CARGO_BIN_EXE_kestrike-inspect"),
            env!("CARGO_BIN_EXE_kestrike-soak"),
        ];
        let names: Vec<String> = scanned
            .iter()
            .map(|binary| name_of(Path::new(binary)))
            .collect();
        let sources =
            bin_sources(Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin"))).unwrap();
        let manifest =
            fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
        assert!(
            !declares_bin(&manifest)
                && !Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs")).exists(),
            "every binary of the crate is a source under src/bin"
        );
        assert_eq!(
            sources, names,
            "the scan reads {names:?}, one binary per source under src/bin"
        );
        for binary in scanned {
            let bytes = artifact(Path::new(binary)).unwrap();
            assert!(
                memchr::memmem::find(&bytes, needle.as_bytes()).is_none(),
                "{binary} holds the chaos catalog's mark"
            );
            assert!(
                memchr::memmem::find(&bytes, control.as_bytes()).is_none(),
                "{binary} holds the simulated worlds' control mark"
            );
        }
    }

    /// A binary is read whole, and so is a small executable header with two
    /// section entries and nothing after them. That binary without its last
    /// byte, and copies of the header that differ in one checked field, end
    /// short of the header, inside the table or one byte before its end, or
    /// hold a byte after the table, are each refused as not a whole ELF
    /// file, and a symlink to it is refused. A FIFO with no writer is
    /// refused as not a regular file within a deadline.
    #[test]
    fn the_scan_refuses_an_artifact_it_cannot_read_whole() {
        let dir = super::scratch("artifact");
        {
            let binary = Path::new(env!("CARGO_BIN_EXE_kestrike-inspect"));
            let read = artifact(binary).unwrap();
            assert!(
                read == fs::read(binary).unwrap(),
                "{} is read whole",
                binary.display()
            );
            fs::write(dir.join("binary"), &read[..read.len() - 1]).unwrap();
            let refusal = artifact(&dir.join("binary"));
            assert!(
                refusal
                    .as_ref()
                    .is_err_and(|error| error.ends_with("is not a whole ELF file")),
                "the binary without its last byte: {:?}",
                refusal.map(|bytes| bytes.len())
            );
        }
        let mut elf = vec![0; 64 + 2 * 64];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[0x10] = 3;
        elf[0x28] = 64;
        elf[0x34] = 64;
        elf[0x3A] = 64;
        elf[0x3C] = 2;
        fs::write(dir.join("elf"), &elf).unwrap();
        let read = artifact(&dir.join("elf")).unwrap();
        assert!(read == elf, "the header is read whole");
        let changed = |at: usize, value: &[u8]| {
            let mut copy = elf.clone();
            copy[at..at + value.len()].copy_from_slice(value);
            copy
        };
        for (case, bytes) in [
            ("short", elf[..60].to_vec()),
            ("magic", changed(1, b"G")),
            ("class", changed(4, &[1])),
            ("order", changed(5, &[2])),
            ("type", changed(0x10, &[1])),
            ("header", changed(0x34, &[0])),
            ("entry", changed(0x3A, &[0])),
            ("width", changed(0x3A, &[32])),
            ("count", changed(0x3C, &[0])),
            ("overlap", changed(0x28, &[0])),
            ("overflow", changed(0x28, &(u64::MAX - 63).to_le_bytes())),
            ("cut", elf[..64 + 64 + 1].to_vec()),
            ("shorter", elf[..elf.len() - 1].to_vec()),
            ("trailing", [&elf[..], &[0xAB]].concat()),
        ] {
            fs::write(dir.join(case), bytes).unwrap();
            let refusal = artifact(&dir.join(case));
            assert!(
                refusal
                    .as_ref()
                    .is_err_and(|error| error.ends_with("is not a whole ELF file")),
                "{case}: {:?}",
                refusal.map(|bytes| bytes.len())
            );
        }
        std::os::unix::fs::symlink(dir.join("elf"), dir.join("link")).unwrap();
        assert!(artifact(&dir.join("link")).is_err(), "the link is read");
        let fifo = dir.join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `name` is a NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let (send, refused) = std::sync::mpsc::channel();
        std::thread::spawn(move || send.send(artifact(&fifo)));
        let refusal = refused
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the FIFO's open waits for a writer");
        assert!(
            refusal
                .as_ref()
                .is_err_and(|error| error.ends_with("not a regular file")),
            "{:?}",
            refusal.map(|bytes| bytes.len())
        );
    }

    /// `NAME.rs` and `NAME/main.rs` each name one binary. A directory
    /// without a regular `main.rs`, a symlink, a file other than `.rs` and a
    /// source whose name is not UTF-8 are each refused beside a regular
    /// source.
    #[test]
    fn the_scan_refuses_a_bin_entry_other_than_a_rust_source() {
        use std::os::unix::ffi::OsStrExt;
        let nested = super::scratch("nested");
        fs::create_dir(nested.join("tool")).unwrap();
        fs::write(nested.join("tool/main.rs"), "").unwrap();
        assert_eq!(bin_sources(&nested), Ok(vec!["tool".to_owned()]));
        let unnamed = std::ffi::OsStr::from_bytes(b"\xff.rs");
        for case in ["dir.rs", "link.rs", "text.txt", "unnamed"] {
            let dir = super::scratch(case);
            fs::write(dir.join("main.rs"), "").unwrap();
            assert_eq!(bin_sources(&dir), Ok(vec!["main".to_owned()]));
            match case {
                "dir.rs" => fs::create_dir(dir.join(case)).unwrap(),
                "link.rs" => {
                    std::os::unix::fs::symlink(dir.join("main.rs"), dir.join(case)).unwrap()
                }
                "unnamed" => fs::write(dir.join(unnamed), "").unwrap(),
                _ => fs::write(dir.join(case), "").unwrap(),
            }
            assert!(bin_sources(&dir).is_err(), "{case} passes as a source");
        }
    }

    /// Every spelling of a binary target the manifest can hold is refused,
    /// an escaped key and a header after a byte order mark included.
    #[test]
    fn the_scan_refuses_every_spelling_of_a_bin_target() {
        for manifest in [
            "[[bin]]",
            "[[ bin ]]",
            "[[\"bin\"]]",
            "bin = [{ name = \"x\" }]",
            "\"bin\" = []",
            "[[\"b\\u0069n\"]]",
            "\"b\\u0069n\" = []",
            "\u{feff}[[bin]]",
        ] {
            assert!(declares_bin(manifest), "{manifest:?} passes");
        }
        assert!(!declares_bin(
            "[package]\nname = \"kestrike\"\nautobins = true\n# a \\ b = c\n"
        ));
    }
}
