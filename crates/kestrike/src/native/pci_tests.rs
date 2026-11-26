use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use super::pci::Function;

/// A scratch function directory whose `config` is 256 bytes with the command register `command` and, when `capabilities` is `Some(flr)`, a power-management capability then a PCI Express capability whose function-level-reset bit is `flr`.
pub(super) struct Dir(pub(super) PathBuf);

impl Dir {
    pub(super) fn new(command: u16, capabilities: Option<bool>) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pci-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        let mut config = [0u8; 256];
        config[4..6].copy_from_slice(&command.to_le_bytes());
        if let Some(flr) = capabilities {
            config[6] = 1 << 4;
            config[0x34] = 0x40;
            config[0x40..0x42].copy_from_slice(&[0x01, 0x50]);
            config[0x50..0x52].copy_from_slice(&[0x10, 0x00]);
            let caps: u32 = if flr { 1 << 28 } else { 0 };
            config[0x54..0x58].copy_from_slice(&caps.to_le_bytes());
        }
        fs::write(dir.join("config"), config).unwrap();
        fs::write(dir.join("reset"), "").unwrap();
        fs::set_permissions(dir.join("reset"), fs::Permissions::from_mode(0o200)).unwrap();
        Self(dir)
    }

    pub(super) fn command(&self) -> u16 {
        let config = fs::read(self.0.join("config")).unwrap();
        u16::from_le_bytes([config[4], config[5]])
    }

    pub(super) fn reset_written(&self) -> String {
        let reset = self.0.join("reset");
        fs::set_permissions(&reset, fs::Permissions::from_mode(0o600)).unwrap();
        fs::read_to_string(reset).unwrap()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Clearing bus mastering clears only its bit and reads back; setting it restores the bit; the command reader reports the register either way.
#[test]
fn bus_master_changes_only_its_bit() {
    let dir = Dir::new(0x0406, None);
    let function = Function::open(&dir.0).unwrap();
    assert_eq!(function.command().unwrap(), 0x0406);
    function.set_bus_master(false).unwrap();
    assert_eq!(dir.command(), 0x0402);
    assert_eq!(function.command().unwrap(), 0x0402);
    function.set_bus_master(true).unwrap();
    assert_eq!(dir.command(), 0x0406);
    assert_eq!(function.command().unwrap(), 0x0406);
}

/// Function-level reset is found through the capability list, absent without the PCI Express bit or the list, and a reset without it is refused with nothing written.
#[test]
fn reset_requires_advertised_function_level_reset() {
    let capable = Dir::new(0, Some(true));
    let function = Function::open(&capable.0).unwrap();
    assert!(function.flr());
    function.reset().unwrap();
    assert_eq!(capable.reset_written(), "1");
    for capabilities in [Some(false), None] {
        let dir = Dir::new(0, capabilities);
        let function = Function::open(&dir.0).unwrap();
        assert!(!function.flr());
        assert_eq!(
            function.reset().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(dir.reset_written(), "");
    }
}

/// A capability list that loops never resolves to function-level reset.
#[test]
fn a_looping_capability_list_ends() {
    let dir = Dir::new(0, None);
    let mut config = fs::read(dir.0.join("config")).unwrap();
    config[6] = 1 << 4;
    config[0x34] = 0x40;
    config[0x40..0x42].copy_from_slice(&[0x01, 0x40]);
    fs::write(dir.0.join("config"), config).unwrap();
    assert!(!Function::open(&dir.0).unwrap().flr());
}

/// A function without its control files is refused at open.
#[test]
fn a_missing_function_is_refused() {
    let dir = Dir::new(0, None);
    fs::remove_file(dir.0.join("reset")).unwrap();
    assert_eq!(
        Function::open(&dir.0).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

/// A command register reading all zeroes is no live function's, so the change is refused in either direction before any write; here the backend answers every read with zeroes.
#[test]
fn an_all_zero_command_register_is_refused() {
    let dir = Dir::new(0, None);
    fs::remove_file(dir.0.join("config")).unwrap();
    std::os::unix::fs::symlink("/dev/zero", dir.0.join("config")).unwrap();
    let function = Function::open(&dir.0).unwrap();
    assert_eq!(
        function.set_bus_master(true).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        function.set_bus_master(false).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        function.command().unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

/// A clear whose read-back is all zeroes proves no stop: the command reader refuses that register as no live function's, so the stop proof refuses it too, though zero is what the clear wrote.
#[test]
fn an_all_zero_read_back_proves_no_stop() {
    let dir = Dir::new(0x0004, None);
    let function = Function::open(&dir.0).unwrap();
    assert_eq!(
        function.set_bus_master(false).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        function.command().unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}
